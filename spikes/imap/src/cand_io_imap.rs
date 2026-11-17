//! Candidate C (probe only): `io-imap`, the successor of imap-client (pimalaya moved the
//! project there on 2026-05-17 and archived imap-client). I/O-free coroutines over imap-codec;
//! the caller owns the socket and pumps them. This module is the tokio pump `cm-imap` would
//! need: one `ImapClientAsync::run` implementation, plus a hand-written IDLE pump (IDLE has its
//! own yield type and is deliberately not covered by `run`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use io_imap::client::{ImapClientAsync, ImapClientError};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::codec::imap_types::core::TagGenerator;
use io_imap::codec::imap_types::response::Data;
use io_imap::coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield};
use io_imap::rfc2177::idle::{ImapIdle, ImapIdleOptions, ImapIdleYield};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Largest single response the fragmentizer accepts (whole message incl. literals).
pub const MAX_MESSAGE: u32 = 64 * 1024 * 1024;

/// A tokio transport for io-imap: any `AsyncRead + AsyncWrite` stream we opened ourselves
/// (plain TCP for the fake server, rustls with the platform verifier in production).
pub struct TokioImap<S> {
    pub stream: S,
    fragmentizer: Fragmentizer,
    tags: TagGenerator,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TokioImap<S> {
    pub fn new(stream: S) -> Self {
        Self { stream, fragmentizer: Fragmentizer::new(MAX_MESSAGE), tags: TagGenerator::new() }
    }

    /// Requirement 6: IDLE until `want` data responses arrived or `stop` resolves, then DONE.
    /// The read and the stop signal race in `select!`; `AsyncReadExt::read` is cancel-safe.
    pub async fn idle_until(
        &mut self,
        want: usize,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<(Vec<Data<'static>>, bool), Error> {
        let done = Arc::new(AtomicBool::new(false));
        let mut co = ImapIdle::new(done.clone(), ImapIdleOptions::default());
        let mut stop = std::pin::pin!(stop);
        let mut stopped = false;
        let mut data = Vec::new();
        let mut buf = vec![0u8; 8192];
        let mut arg: Option<Vec<u8>> = None;
        loop {
            match co.resume(&mut self.fragmentizer, arg.take().as_deref()) {
                ImapCoroutineState::Complete(Ok(())) => return Ok((data, stopped)),
                ImapCoroutineState::Complete(Err(e)) => return Err(e.into()),
                ImapCoroutineState::Yielded(ImapIdleYield::WantsTag) => {
                    arg = Some(self.tags.generate().as_ref().as_bytes().to_vec());
                }
                ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes).await?;
                    self.stream.flush().await?;
                }
                ImapCoroutineState::Yielded(ImapIdleYield::Event(ev)) => {
                    data.extend(ev.data);
                    if data.len() >= want {
                        done.store(true, Ordering::SeqCst);
                    }
                }
                ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                    if done.load(Ordering::SeqCst) {
                        // DONE already requested: just read the completion.
                        let n = self.stream.read(&mut buf).await?;
                        arg = Some(buf[..n].to_vec());
                        continue;
                    }
                    tokio::select! {
                        r = self.stream.read(&mut buf) => {
                            let n = r?;
                            arg = Some(buf[..n].to_vec());
                        }
                        () = &mut stop => {
                            stopped = true;
                            done.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> ImapClientAsync for TokioImap<S> {
    #[allow(clippy::manual_async_fn)]
    fn run<C, T, E>(&mut self, mut coroutine: C) -> impl Future<Output = Result<T, ImapClientError>> + Send
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>> + Send,
        T: Send,
        E: Send,
        ImapClientError: From<E>,
    {
        async move {
            let mut buf = vec![0u8; 8192];
            let mut arg: Option<Vec<u8>> = None;
            loop {
                match coroutine.resume(&mut self.fragmentizer, arg.take().as_deref()) {
                    ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                    ImapCoroutineState::Complete(Err(e)) => return Err(e.into()),
                    ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                        arg = Some(self.tags.generate().as_ref().as_bytes().to_vec());
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.stream.write_all(&bytes).await.map_err(io_err)?;
                        self.stream.flush().await.map_err(io_err)?;
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        let n = self.stream.read(&mut buf).await.map_err(io_err)?;
                        arg = Some(buf[..n].to_vec());
                    }
                }
            }
        }
    }
}

fn io_err(e: std::io::Error) -> ImapClientError {
    ImapClientError::from(e)
}

pub async fn connect_plain(host: &str, port: u16) -> Result<TokioImap<TcpStream>, Error> {
    let mut c = TokioImap::new(TcpStream::connect((host, port)).await?);
    c.greeting().await?;
    Ok(c)
}

/// Requirement 1: our own rustls stream (platform verifier) handed to io-imap.
pub async fn connect_tls(
    host: &str,
    port: u16,
) -> Result<TokioImap<tokio_rustls::client::TlsStream<TcpStream>>, Error> {
    use tokio_rustls::rustls::pki_types::ServerName;
    let config = crate::tls::client_config()?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port)).await?;
    let tls = connector.connect(ServerName::try_from(host.to_string())?, tcp).await?;
    let mut c = TokioImap::new(tls);
    c.greeting().await?;
    Ok(c)
}
