//! Spike C: OAuth2 (auth code + PKCE, loopback redirect) for Gmail and Microsoft,
//! XOAUTH2 strings for IMAP/SMTP, and refresh-token storage on Windows.
//!
//! The library never opens a browser by itself: [`flow::login`] takes an `open`
//! callback. Only the `oauth-spike` binary passes one that launches the system
//! browser; the tests pass a fake browser that talks HTTP.

pub mod config;
pub mod flow;
pub mod loopback;
pub mod pkce;
pub mod provider;
pub mod token;
pub mod xoauth2;

#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod store;

pub use config::ClientConfig;
pub use flow::{LoginOptions, http_client, login, refresh, refresh_if_needed};
pub use provider::{Provider, ProviderKind, RedirectHost};
pub use token::TokenSet;

/// Errors from the OAuth flow and the token store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no OAuth client ID for {provider}: build with {env_var} set or pass a client ID")]
    MissingClientId {
        provider: &'static str,
        env_var: &'static str,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("timed out waiting for the browser to return to the app")]
    Timeout,
    #[error(
        "the redirect's state parameter did not match this sign-in (possible CSRF); sign-in aborted"
    )]
    StateMismatch,
    #[error("the user declined access: {0}")]
    AccessDenied(String),
    #[error("authorization server returned {error}: {description}")]
    Authorization { error: String, description: String },
    #[error("token endpoint returned HTTP {status}: {error} {description}")]
    TokenEndpoint {
        status: u16,
        error: String,
        description: String,
    },
    #[error("unexpected response: {0}")]
    InvalidResponse(String),
    #[error("refusing to send secrets to a non-HTTPS, non-loopback endpoint: {0}")]
    InsecureEndpoint(String),
    #[error("no refresh token available; the user must sign in again")]
    NoRefreshToken,
    #[error("could not open the browser: {0}")]
    Browser(String),
    #[cfg(windows)]
    #[error("credential store: {0}")]
    Keyring(#[from] keyring_core::Error),
    #[cfg(windows)]
    #[error("DPAPI: {0}")]
    Dpapi(#[from] windows::core::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Random bytes from the OS, base64url-encoded without padding.
pub(crate) fn random_urlsafe(len: usize) -> String {
    use base64::Engine as _;
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}
