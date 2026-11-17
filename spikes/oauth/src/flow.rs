//! The authorization-code flow with PKCE, code exchange and refresh.

use std::time::{Duration, SystemTime};

use url::Url;

use crate::config::ClientConfig;
use crate::loopback::LoopbackListener;
use crate::pkce::Pkce;
use crate::provider::Provider;
use crate::token::{ErrorResponse, TokenResponse, TokenSet};
use crate::{Error, Result};

/// An HTTP client for token requests: no redirects (a redirected token request
/// could leak the code or refresh token), and finite timeouts.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!(
            "clawsmail-rust-oauth-spike/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .expect("reqwest client configuration is valid")
}

/// Everything needed to send the user to the provider and finish afterwards.
#[derive(Debug)]
pub struct AuthorizationRequest {
    pub url: Url,
    pub state: String,
    pub pkce: Pkce,
    pub redirect_uri: String,
}

pub fn authorization_request(
    provider: &Provider,
    client: &ClientConfig,
    redirect_uri: &str,
    login_hint: Option<&str>,
) -> Result<AuthorizationRequest> {
    let pkce = Pkce::generate();
    let state = crate::random_urlsafe(16);
    let mut url = Url::parse(&provider.authorize_url)
        .map_err(|e| Error::InvalidResponse(format!("bad authorize URL: {e}")))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &client.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &provider.scope_string())
            .append_pair("state", &state)
            .append_pair("code_challenge", pkce.challenge())
            .append_pair("code_challenge_method", Pkce::METHOD);
        for (k, v) in &provider.extra_authorize_params {
            q.append_pair(k, v);
        }
        if let Some(hint) = login_hint {
            q.append_pair("login_hint", hint);
        }
    }
    Ok(AuthorizationRequest {
        url,
        state,
        pkce,
        redirect_uri: redirect_uri.to_owned(),
    })
}

/// Options for [`login`].
#[derive(Debug, Clone)]
pub struct LoginOptions {
    pub login_hint: Option<String>,
    /// How long to wait for the browser to come back.
    pub timeout: Duration,
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            login_hint: None,
            timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Runs the whole interactive flow. `open` is given the authorize URL and must
/// send the user there. The library has no default: only the CLI passes a
/// function that starts the system browser.
pub async fn login<F>(
    http: &reqwest::Client,
    provider: &Provider,
    client: &ClientConfig,
    options: &LoginOptions,
    open: F,
) -> Result<TokenSet>
where
    F: FnOnce(&Url) -> Result<()>,
{
    let listener = LoopbackListener::bind(provider.redirect_host).await?;
    let req = authorization_request(
        provider,
        client,
        listener.redirect_uri(),
        options.login_hint.as_deref(),
    )?;
    open(&req.url)?;
    let code = listener.wait_for_code(&req.state, options.timeout).await?;
    exchange_code(
        http,
        provider,
        client,
        &code,
        req.pkce.verifier(),
        &req.redirect_uri,
    )
    .await
}

pub async fn exchange_code(
    http: &reqwest::Client,
    provider: &Provider,
    client: &ClientConfig,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet> {
    let scope = provider.scope_string();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &client.client_id),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = &client.client_secret {
        form.push(("client_secret", secret));
    }
    if provider.scope_on_token_requests {
        form.push(("scope", &scope));
    }
    let resp = post_token(http, &provider.token_url, &form).await?;
    TokenSet::from_response(resp, None, SystemTime::now())
}

/// Refreshes the access token. If the response has a new refresh token
/// (Microsoft rotates them), the returned set carries it and the caller must
/// store it; otherwise the old one is kept.
pub async fn refresh(
    http: &reqwest::Client,
    provider: &Provider,
    client: &ClientConfig,
    current: &TokenSet,
) -> Result<TokenSet> {
    let refresh_token = current
        .refresh_token
        .as_deref()
        .ok_or(Error::NoRefreshToken)?;
    let scope = provider.scope_string();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &client.client_id),
    ];
    if let Some(secret) = &client.client_secret {
        form.push(("client_secret", secret));
    }
    if provider.scope_on_token_requests {
        form.push(("scope", &scope));
    }
    let resp = post_token(http, &provider.token_url, &form).await?;
    TokenSet::from_response(resp, Some(current), SystemTime::now())
}

/// Refreshes only when the access token is within the default skew of expiry.
/// Returns `None` when the current token is still good.
pub async fn refresh_if_needed(
    http: &reqwest::Client,
    provider: &Provider,
    client: &ClientConfig,
    current: &TokenSet,
) -> Result<Option<TokenSet>> {
    if current.needs_refresh() {
        refresh(http, provider, client, current).await.map(Some)
    } else {
        Ok(None)
    }
}

fn check_endpoint(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|_| Error::InsecureEndpoint(url.to_owned()))?;
    let loopback = matches!(
        parsed.host(),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback()
    ) || matches!(parsed.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
        || parsed.host_str() == Some("localhost");
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(Error::InsecureEndpoint(url.to_owned()))
    }
}

async fn post_token(
    http: &reqwest::Client,
    token_url: &str,
    form: &[(&str, &str)],
) -> Result<TokenResponse> {
    check_endpoint(token_url)?;
    let resp = http
        .post(token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if status.is_success() {
        serde_json::from_slice(&body)
            .map_err(|e| Error::InvalidResponse(format!("token response: {e}")))
    } else {
        match serde_json::from_slice::<ErrorResponse>(&body) {
            Ok(err) => Err(Error::TokenEndpoint {
                status: status.as_u16(),
                error: err.error,
                description: err.error_description.unwrap_or_default(),
            }),
            Err(_) => Err(Error::TokenEndpoint {
                status: status.as_u16(),
                error: "unparseable error response".into(),
                description: String::from_utf8_lossy(&body).chars().take(200).collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderKind;

    fn client() -> ClientConfig {
        ClientConfig {
            client_id: "test-client".into(),
            client_secret: None,
        }
    }

    #[test]
    fn google_authorize_url() {
        let p = Provider::google();
        let r = authorization_request(&p, &client(), "http://127.0.0.1:5555", Some("me@gmail.com"))
            .unwrap();
        let q: std::collections::HashMap<_, _> = r.url.query_pairs().into_owned().collect();
        assert_eq!(
            r.url.as_str().split('?').next(),
            Some("https://accounts.google.com/o/oauth2/v2/auth")
        );
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5555");
        assert_eq!(q["scope"], "https://mail.google.com/ openid email");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], r.pkce.challenge());
        assert_eq!(q["state"], r.state);
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["login_hint"], "me@gmail.com");
    }

    #[test]
    fn microsoft_authorize_url() {
        let p = Provider::preset(ProviderKind::Microsoft);
        let r = authorization_request(&p, &client(), "http://localhost:5555", None).unwrap();
        let q: std::collections::HashMap<_, _> = r.url.query_pairs().into_owned().collect();
        assert!(
            r.url
                .as_str()
                .starts_with("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")
        );
        assert_eq!(
            q["scope"],
            "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access openid email"
        );
        assert!(!q.contains_key("access_type"));
        assert!(!q.contains_key("client_secret"));
    }

    #[test]
    fn endpoint_policy() {
        assert!(check_endpoint("https://oauth2.googleapis.com/token").is_ok());
        assert!(check_endpoint("http://127.0.0.1:9/token").is_ok());
        assert!(check_endpoint("http://[::1]:9/token").is_ok());
        assert!(check_endpoint("http://example.com/token").is_err());
    }
}
