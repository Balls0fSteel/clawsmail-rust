//! A fake OAuth authorization server and token endpoint on 127.0.0.1, and a
//! fake browser that follows its redirect to the app's loopback listener.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use oauth_spike::{Provider, ProviderKind, RedirectHost};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthorizeMode {
    Approve,
    Deny,
    WrongState,
}

struct Pending {
    challenge: String,
    redirect_uri: String,
    client_id: String,
}

pub struct FakeState {
    pub mode: AuthorizeMode,
    /// Microsoft behaviour: every refresh returns a new refresh token and the
    /// old one stops working.
    pub rotate_refresh_tokens: bool,
    pub email: String,
    pub expires_in: u64,
    pending: HashMap<String, Pending>,
    valid_refresh: Vec<String>,
    counter: u32,
    /// Every token request's form fields, for assertions.
    pub token_requests: Vec<HashMap<String, String>>,
    pub authorize_requests: Vec<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct FakeProvider {
    pub base: String,
    pub state: Arc<Mutex<FakeState>>,
}

impl FakeProvider {
    pub async fn start(mode: AuthorizeMode, rotate: bool, email: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(FakeState {
            mode,
            rotate_refresh_tokens: rotate,
            email: email.into(),
            expires_in: 3600,
            pending: HashMap::new(),
            valid_refresh: Vec::new(),
            counter: 0,
            token_requests: Vec::new(),
            authorize_requests: Vec::new(),
        }));
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = st.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, st).await;
                });
            }
        });
        FakeProvider { base, state }
    }

    /// A provider preset pointed at this fake server.
    pub fn provider(&self, kind: ProviderKind, redirect_host: RedirectHost) -> Provider {
        let mut p = Provider::preset(kind);
        p.authorize_url = format!("{}/authorize", self.base);
        p.token_url = format!("{}/token", self.base);
        p.redirect_host = redirect_host;
        p
    }

    pub fn token_requests(&self) -> Vec<HashMap<String, String>> {
        self.state.lock().unwrap().token_requests.clone()
    }
}

fn id_token(email: &str) -> String {
    let e = |s: &str| URL_SAFE_NO_PAD.encode(s);
    format!(
        "{}.{}.fake-signature",
        e(r#"{"alg":"RS256","typ":"JWT"}"#),
        e(&format!(
            r#"{{"iss":"fake","email":"{email}","preferred_username":"{email}"}}"#
        ))
    )
}

async fn serve(mut stream: TcpStream, st: Arc<Mutex<FakeState>>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = &buf[head_end..];
    let mut first = head.lines().next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("");
    let target = first.next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let parse = |b: &[u8]| -> HashMap<String, String> {
        url::form_urlencoded::parse(b).into_owned().collect()
    };

    let response = match (method, path) {
        ("GET", "/authorize") => authorize(&st, parse(query.as_bytes())),
        ("POST", "/token") => token(&st, parse(body)),
        _ => (404, vec![], "not found".to_string()),
    };
    let (status, headers, body) = response;
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(&body);
    stream.write_all(out.as_bytes()).await?;
    stream.shutdown().await
}

type Resp = (u16, Vec<(&'static str, String)>, String);

fn json_error(error: &str, desc: &str) -> Resp {
    (
        400,
        vec![("Content-Type", "application/json".into())],
        serde_json::json!({"error": error, "error_description": desc}).to_string(),
    )
}

fn authorize(st: &Mutex<FakeState>, q: HashMap<String, String>) -> Resp {
    let mut s = st.lock().unwrap();
    s.authorize_requests.push(q.clone());
    if q.get("response_type").map(String::as_str) != Some("code")
        || q.get("code_challenge_method").map(String::as_str) != Some("S256")
        || !q.contains_key("code_challenge")
        || !q.contains_key("state")
    {
        return (400, vec![], "bad authorize request".into());
    }
    let redirect = q["redirect_uri"].clone();
    let state = q["state"].clone();
    let mut loc = url::Url::parse(&redirect).unwrap();
    match s.mode {
        AuthorizeMode::Approve | AuthorizeMode::WrongState => {
            s.counter += 1;
            let code = format!("code-{}", s.counter);
            s.pending.insert(
                code.clone(),
                Pending {
                    challenge: q["code_challenge"].clone(),
                    redirect_uri: redirect.clone(),
                    client_id: q["client_id"].clone(),
                },
            );
            let st = if s.mode == AuthorizeMode::WrongState {
                "forged-state".to_string()
            } else {
                state
            };
            loc.query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &st);
        }
        AuthorizeMode::Deny => {
            loc.query_pairs_mut()
                .append_pair("error", "access_denied")
                .append_pair("error_description", "The user declined.")
                .append_pair("state", &state);
        }
    }
    (302, vec![("Location", loc.to_string())], String::new())
}

fn token(st: &Mutex<FakeState>, f: HashMap<String, String>) -> Resp {
    let mut s = st.lock().unwrap();
    s.token_requests.push(f.clone());
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();
    match get("grant_type").as_str() {
        "authorization_code" => {
            let Some(p) = s.pending.remove(&get("code")) else {
                return json_error("invalid_grant", "unknown or used code");
            };
            if p.client_id != get("client_id") || p.redirect_uri != get("redirect_uri") {
                return json_error("invalid_grant", "client_id or redirect_uri mismatch");
            }
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(get("code_verifier").as_bytes()));
            if computed != p.challenge {
                return json_error("invalid_grant", "PKCE verification failed");
            }
            s.counter += 1;
            let n = s.counter;
            let rt = format!("rt-{n}");
            s.valid_refresh.push(rt.clone());
            ok_tokens(&s, n, Some(rt), true)
        }
        "refresh_token" => {
            let rt = get("refresh_token");
            if !s.valid_refresh.contains(&rt) {
                return json_error("invalid_grant", "refresh token revoked or unknown");
            }
            s.counter += 1;
            let n = s.counter;
            let new_rt = if s.rotate_refresh_tokens {
                s.valid_refresh.retain(|t| *t != rt);
                let new_rt = format!("rt-{n}");
                s.valid_refresh.push(new_rt.clone());
                Some(new_rt)
            } else {
                None
            };
            ok_tokens(&s, n, new_rt, false)
        }
        _ => json_error("unsupported_grant_type", ""),
    }
}

fn ok_tokens(s: &FakeState, n: u32, refresh_token: Option<String>, with_id_token: bool) -> Resp {
    let mut v = serde_json::json!({
        "access_token": format!("at-{n}"),
        "token_type": "Bearer",
        "expires_in": s.expires_in,
        "scope": "fake-scope",
    });
    if let Some(rt) = refresh_token {
        v["refresh_token"] = rt.into();
    }
    if with_id_token {
        v["id_token"] = id_token(&s.email).into();
    }
    (
        200,
        vec![("Content-Type", "application/json".into())],
        v.to_string(),
    )
}

/// A fake browser: follows the provider's redirect to the loopback listener
/// and returns the final page. It never touches a real browser.
pub fn fake_browser(
    url: &url::Url,
) -> tokio::task::JoinHandle<Result<(u16, String), reqwest::Error>> {
    let url = url.clone();
    tokio::spawn(async move {
        let c = reqwest::Client::builder().no_proxy().build().unwrap();
        let r = c.get(url).send().await?;
        let status = r.status().as_u16();
        Ok((status, r.text().await?))
    })
}

/// The port of the loopback redirect inside an authorize URL.
pub fn redirect_port(url: &url::Url) -> u16 {
    let r = url
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .unwrap()
        .1
        .into_owned();
    url::Url::parse(&r).unwrap().port().unwrap()
}
