//! The full flow against the local fake provider. No real browser, no network
//! beyond 127.0.0.1 / ::1.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use common::{AuthorizeMode, FakeProvider, fake_browser, redirect_port};
use oauth_spike::flow::{authorization_request, exchange_code};
use oauth_spike::loopback::LoopbackListener;
use oauth_spike::{ClientConfig, Error, LoginOptions, ProviderKind, RedirectHost, TokenSet};
use tokio::task::JoinHandle;

type BrowserSlot = Arc<Mutex<Option<JoinHandle<Result<(u16, String), reqwest::Error>>>>>;

fn opts(timeout_ms: u64) -> LoginOptions {
    LoginOptions {
        login_hint: None,
        timeout: Duration::from_millis(timeout_ms),
    }
}

fn google_client() -> ClientConfig {
    ClientConfig {
        client_id: "fake-google.apps.googleusercontent.com".into(),
        client_secret: Some("not-really-secret".into()),
    }
}

fn ms_client() -> ClientConfig {
    ClientConfig {
        client_id: "00000000-0000-0000-0000-00000000fake".into(),
        client_secret: None,
    }
}

/// An `open` callback that plays the browser and keeps its task handle.
fn browser_opener(slot: &BrowserSlot) -> impl FnOnce(&url::Url) -> oauth_spike::Result<()> + use<> {
    let slot = slot.clone();
    move |url| {
        *slot.lock().unwrap() = Some(fake_browser(url));
        Ok(())
    }
}

async fn browser_page(slot: &BrowserSlot) -> (u16, String) {
    let h = slot.lock().unwrap().take().expect("browser was opened");
    h.await.unwrap().unwrap()
}

#[tokio::test]
async fn google_success_path() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, false, "someone@gmail.com").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let slot = BrowserSlot::default();
    let http = oauth_spike::http_client();

    let tokens = oauth_spike::login(
        &http,
        &provider,
        &google_client(),
        &opts(10_000),
        browser_opener(&slot),
    )
    .await
    .unwrap();

    assert!(tokens.access_token.starts_with("at-"));
    assert!(tokens.refresh_token.as_deref().unwrap().starts_with("rt-"));
    assert_eq!(tokens.email.as_deref(), Some("someone@gmail.com"));
    assert!(!tokens.needs_refresh());

    let (status, page) = browser_page(&slot).await;
    assert_eq!(status, 200);
    assert!(page.contains("You can close this tab"), "{page}");

    let state = fake.state.lock().unwrap();
    let auth = &state.authorize_requests[0];
    assert_eq!(auth["scope"], "https://mail.google.com/ openid email");
    assert_eq!(auth["access_type"], "offline");
    assert!(auth["redirect_uri"].starts_with("http://127.0.0.1:"));
    let tok = &state.token_requests[0];
    assert_eq!(tok["grant_type"], "authorization_code");
    assert_eq!(tok["client_secret"], "not-really-secret");
    assert_eq!(
        tok["redirect_uri"], auth["redirect_uri"],
        "identical redirect_uri"
    );
    assert!(!tok.contains_key("scope"));
}

#[tokio::test]
async fn microsoft_success_localhost_and_refresh_rotation() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, true, "someone@outlook.com").await;
    let provider = fake.provider(ProviderKind::Microsoft, RedirectHost::Localhost);
    let slot = BrowserSlot::default();
    let http = oauth_spike::http_client();
    let client = ms_client();

    let first = oauth_spike::login(
        &http,
        &provider,
        &client,
        &opts(10_000),
        browser_opener(&slot),
    )
    .await
    .unwrap();
    assert_eq!(browser_page(&slot).await.0, 200);
    assert_eq!(first.email.as_deref(), Some("someone@outlook.com"));
    let rt1 = first.refresh_token.clone().unwrap();

    let second = oauth_spike::refresh(&http, &provider, &client, &first)
        .await
        .unwrap();
    let rt2 = second.refresh_token.clone().unwrap();
    assert_ne!(rt1, rt2, "Microsoft-style refresh must rotate");
    assert_ne!(first.access_token, second.access_token);
    assert_eq!(second.email, first.email, "email carried over");

    // The old refresh token is now rejected, so the new one must be stored.
    match oauth_spike::refresh(&http, &provider, &client, &first).await {
        Err(Error::TokenEndpoint {
            status: 400, error, ..
        }) => assert_eq!(error, "invalid_grant"),
        other => panic!("expected invalid_grant, got {other:?}"),
    }
    let third = oauth_spike::refresh(&http, &provider, &client, &second)
        .await
        .unwrap();
    assert_ne!(third.refresh_token.unwrap(), rt2);

    let state = fake.state.lock().unwrap();
    assert!(state.authorize_requests[0]["redirect_uri"].starts_with("http://localhost:"));
    for req in &state.token_requests {
        assert!(
            !req.contains_key("client_secret"),
            "public client sends no secret"
        );
        assert!(req["scope"].contains("https://outlook.office.com/IMAP.AccessAsUser.All"));
    }
}

#[tokio::test]
async fn google_refresh_without_rotation_keeps_refresh_token() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, false, "someone@gmail.com").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let slot = BrowserSlot::default();
    let http = oauth_spike::http_client();
    let first = oauth_spike::login(
        &http,
        &provider,
        &google_client(),
        &opts(10_000),
        browser_opener(&slot),
    )
    .await
    .unwrap();
    let second = oauth_spike::refresh(&http, &provider, &google_client(), &first)
        .await
        .unwrap();
    assert_eq!(second.refresh_token, first.refresh_token);
    assert_ne!(second.access_token, first.access_token);
}

#[tokio::test]
async fn refresh_only_near_expiry() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, true, "x@outlook.com").await;
    let provider = fake.provider(ProviderKind::Microsoft, RedirectHost::Loopback127);
    let slot = BrowserSlot::default();
    let http = oauth_spike::http_client();
    let mut t = oauth_spike::login(
        &http,
        &provider,
        &ms_client(),
        &opts(10_000),
        browser_opener(&slot),
    )
    .await
    .unwrap();
    assert!(
        oauth_spike::refresh_if_needed(&http, &provider, &ms_client(), &t)
            .await
            .unwrap()
            .is_none()
    );
    t.expires_at = SystemTime::now() + Duration::from_secs(60);
    let r = oauth_spike::refresh_if_needed(&http, &provider, &ms_client(), &t)
        .await
        .unwrap();
    assert!(r.is_some_and(|n| n.refresh_token != t.refresh_token));
}

#[tokio::test]
async fn state_mismatch_is_rejected() {
    let fake = FakeProvider::start(AuthorizeMode::WrongState, false, "a@b.c").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let slot = BrowserSlot::default();
    let r = oauth_spike::login(
        &oauth_spike::http_client(),
        &provider,
        &google_client(),
        &opts(10_000),
        browser_opener(&slot),
    )
    .await;
    assert!(matches!(r, Err(Error::StateMismatch)), "{r:?}");
    let (status, page) = browser_page(&slot).await;
    assert_eq!(status, 400);
    assert!(page.contains("did not belong"));
    assert!(
        fake.token_requests().is_empty(),
        "no code exchange after a state mismatch"
    );
}

#[tokio::test]
async fn access_denied_is_reported() {
    let fake = FakeProvider::start(AuthorizeMode::Deny, false, "a@b.c").await;
    let provider = fake.provider(ProviderKind::Microsoft, RedirectHost::Localhost);
    let slot = BrowserSlot::default();
    let r = oauth_spike::login(
        &oauth_spike::http_client(),
        &provider,
        &ms_client(),
        &opts(10_000),
        browser_opener(&slot),
    )
    .await;
    match r {
        Err(Error::AccessDenied(d)) => assert_eq!(d, "The user declined."),
        other => panic!("expected AccessDenied, got {other:?}"),
    }
    let (_, page) = browser_page(&slot).await;
    assert!(page.contains("Sign-in cancelled"));
    assert!(fake.token_requests().is_empty());
}

#[tokio::test]
async fn timeout_when_browser_never_returns() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, false, "a@b.c").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let start = std::time::Instant::now();
    let r = oauth_spike::login(
        &oauth_spike::http_client(),
        &provider,
        &google_client(),
        &opts(300),
        |_| Ok(()),
    )
    .await;
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn junk_connections_do_not_break_the_listener() {
    use tokio::io::AsyncWriteExt;
    let fake = FakeProvider::start(AuthorizeMode::Approve, false, "a@gmail.com").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let slot = BrowserSlot::default();
    let slot2 = slot.clone();
    let open = move |url: &url::Url| {
        let url = url.clone();
        let port = redirect_port(&url);
        let h = tokio::spawn(async move {
            // A speculative connection that never sends anything.
            let _idle = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            // A favicon request and a request without code or error.
            for path in ["/favicon.ico", "/?foo=bar"] {
                let r = reqwest::get(format!("http://127.0.0.1:{port}{path}"))
                    .await
                    .unwrap();
                assert_eq!(r.status().as_u16(), 404);
            }
            // Garbage bytes.
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            s.write_all(b"\x16\x03\x01garbage\r\n\r\n").await.unwrap();
            drop(s);
            common::fake_browser(&url).await.unwrap()
        });
        *slot2.lock().unwrap() = Some(h);
        Ok(())
    };
    let tokens = oauth_spike::login(
        &oauth_spike::http_client(),
        &provider,
        &google_client(),
        &opts(10_000),
        open,
    )
    .await
    .unwrap();
    assert!(tokens.access_token.starts_with("at-"));
    assert_eq!(browser_page(&slot).await.0, 200);
}

#[tokio::test]
async fn wrong_pkce_verifier_is_rejected_by_token_endpoint() {
    let fake = FakeProvider::start(AuthorizeMode::Approve, false, "a@gmail.com").await;
    let provider = fake.provider(ProviderKind::Google, RedirectHost::Loopback127);
    let client = google_client();
    let http = oauth_spike::http_client();
    let listener = LoopbackListener::bind(RedirectHost::Loopback127)
        .await
        .unwrap();
    let req = authorization_request(&provider, &client, listener.redirect_uri(), None).unwrap();
    let browser = fake_browser(&req.url);
    let code = listener
        .wait_for_code(&req.state, Duration::from_secs(10))
        .await
        .unwrap();
    browser.await.unwrap().unwrap();
    let wrong = oauth_spike::pkce::Pkce::generate();
    match exchange_code(
        &http,
        &provider,
        &client,
        &code,
        wrong.verifier(),
        &req.redirect_uri,
    )
    .await
    {
        Err(Error::TokenEndpoint {
            error, description, ..
        }) => {
            assert_eq!(error, "invalid_grant");
            assert!(description.contains("PKCE"));
        }
        other => panic!("expected invalid_grant, got {other:?}"),
    }
}

#[tokio::test]
async fn xoauth2_string_from_token_set() {
    let t = TokenSet {
        access_token: "at-42".into(),
        refresh_token: None,
        expires_at: SystemTime::now(),
        scope: None,
        email: None,
    };
    let encoded = t.xoauth2("user@example.com");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    assert_eq!(raw, b"user=user@example.com\x01auth=Bearer at-42\x01\x01");
}
