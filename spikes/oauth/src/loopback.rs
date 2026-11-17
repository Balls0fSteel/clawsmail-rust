//! The loopback redirect listener (RFC 8252 section 7.3).
//!
//! It binds `127.0.0.1` on a random free port. When the redirect URI uses
//! `localhost`, it also tries `[::1]` on the same port, because a browser may
//! resolve `localhost` to IPv6 first. Browsers also open speculative empty
//! connections and ask for `/favicon.ico`, so each connection is handled in its
//! own task and anything without `code` or `error` gets a 404 while the
//! listener keeps waiting, under one overall timeout.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::provider::RedirectHost;
use crate::{Error, Result};

const MAX_REQUEST: usize = 16 * 1024;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LoopbackListener {
    v4: TcpListener,
    v6: Option<TcpListener>,
    redirect_uri: String,
}

impl LoopbackListener {
    pub async fn bind(host: RedirectHost) -> Result<Self> {
        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let (v6, host_name) = match host {
            RedirectHost::Loopback127 => (None, "127.0.0.1"),
            RedirectHost::Localhost => (
                TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
                    .await
                    .ok(),
                "localhost",
            ),
        };
        // No path: Entra matches `http://localhost` (port ignored) and Google
        // matches any loopback port for Desktop clients. The identical string is
        // sent in the authorize and token requests.
        let redirect_uri = format!("http://{host_name}:{port}");
        Ok(Self {
            v4,
            v6,
            redirect_uri,
        })
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn port(&self) -> u16 {
        self.v4.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    pub fn has_ipv6(&self) -> bool {
        self.v6.is_some()
    }

    /// Waits for the redirect and returns the authorization code.
    pub async fn wait_for_code(self, expected_state: &str, timeout: Duration) -> Result<String> {
        let (tx, mut rx) = mpsc::channel::<Result<String>>(4);
        let expected_state: std::sync::Arc<str> = expected_state.into();
        let accept_loop = async {
            loop {
                let accepted = match &self.v6 {
                    Some(v6) => tokio::select! {
                        r = self.v4.accept() => r,
                        r = v6.accept() => r,
                        Some(res) = rx.recv() => return res,
                    },
                    None => tokio::select! {
                        r = self.v4.accept() => r,
                        Some(res) = rx.recv() => return res,
                    },
                };
                if let Ok((stream, _)) = accepted {
                    let tx = tx.clone();
                    let state = expected_state.clone();
                    tokio::spawn(async move {
                        if let Some(res) = handle_connection(stream, &state).await {
                            let _ = tx.send(res).await;
                        }
                    });
                }
            }
        };
        tokio::time::timeout(timeout, accept_loop)
            .await
            .unwrap_or(Err(Error::Timeout))
    }
}

/// Serves one connection. Returns `Some` when it carried the OAuth redirect.
async fn handle_connection(mut stream: TcpStream, expected_state: &str) -> Option<Result<String>> {
    let target = tokio::time::timeout(PER_CONNECTION_TIMEOUT, read_request_target(&mut stream))
        .await
        .ok()
        .flatten()?;
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let path = target.split('?').next().unwrap_or("");
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        match &*k {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    if path != "/" || (code.is_none() && error.is_none()) {
        let _ = respond(&mut stream, "404 Not Found", "Not found", "").await;
        return None;
    }
    // Check state first, on errors too (RFC 6749 4.1.2.1 includes it there).
    let result = if state.as_deref() != Some(expected_state) {
        Err(Error::StateMismatch)
    } else if let Some(error) = error {
        let description = error_description.unwrap_or_default();
        if error == "access_denied" {
            Err(Error::AccessDenied(description))
        } else {
            Err(Error::Authorization { error, description })
        }
    } else {
        Ok(code.unwrap_or_default())
    };
    let (status, title, body) = match &result {
        Ok(_) => (
            "200 OK",
            "Signed in",
            "Clawsmail received the sign-in. You can close this tab and return to the app.",
        ),
        Err(Error::AccessDenied(_)) => (
            "200 OK",
            "Sign-in cancelled",
            "Access was not granted. You can close this tab.",
        ),
        Err(Error::StateMismatch) => (
            "400 Bad Request",
            "Sign-in rejected",
            "This response did not belong to the sign-in Clawsmail started. Close this tab and try again.",
        ),
        Err(_) => (
            "200 OK",
            "Sign-in failed",
            "The provider reported an error. You can close this tab; details are in Clawsmail.",
        ),
    };
    let _ = respond(&mut stream, status, title, body).await;
    Some(result)
}

/// Reads the request head and returns the request target of a GET.
async fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = std::str::from_utf8(&buf).ok()?;
    let mut parts = head.lines().next()?.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Some(target.to_owned()),
        _ => None,
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: &str,
    title: &str,
    body: &str,
) -> std::io::Result<()> {
    // Titles and bodies are fixed strings above, so no HTML escaping is needed.
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:32em;margin:4em auto;padding:0 1em}}</style>\
         </head><body><h1>{title}</h1><p>{body}</p></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.shutdown().await
}
