//! Provider presets for Google and Microsoft.
//!
//! Sources (checked 2026-11-17) are listed in `FINDINGS.md`.

/// Which host name goes into the loopback redirect URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectHost {
    /// `http://127.0.0.1:<port>`: Google's recommendation for desktop apps.
    Loopback127,
    /// `http://localhost:<port>`: matches the `http://localhost` redirect URI that
    /// the Entra portal lets you register (it cannot add `http://127.0.0.1`
    /// without a manifest edit). Entra ignores the port for localhost.
    Localhost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Google,
    Microsoft,
}

impl ProviderKind {
    pub fn name(self) -> &'static str {
        match self {
            ProviderKind::Google => "google",
            ProviderKind::Microsoft => "microsoft",
        }
    }
}

impl std::str::FromStr for ProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "google" | "gmail" => Ok(ProviderKind::Google),
            "microsoft" | "outlook" | "office365" | "m365" => Ok(ProviderKind::Microsoft),
            other => Err(format!(
                "unknown provider {other:?}; use google or microsoft"
            )),
        }
    }
}

/// Endpoints and parameters for one OAuth provider.
#[derive(Debug, Clone)]
pub struct Provider {
    pub kind: ProviderKind,
    pub authorize_url: String,
    pub token_url: String,
    /// Scopes for the authorize request.
    pub scopes: Vec<String>,
    /// Extra authorize parameters, such as Google's `access_type=offline`.
    pub extra_authorize_params: Vec<(String, String)>,
    pub redirect_host: RedirectHost,
    /// Send `scope` in code-exchange and refresh requests too. Microsoft accepts
    /// it (optional, must be the same or a subset); Google ignores it.
    pub scope_on_token_requests: bool,
}

pub const GOOGLE_MAIL_SCOPE: &str = "https://mail.google.com/";
pub const MS_IMAP_SCOPE: &str = "https://outlook.office.com/IMAP.AccessAsUser.All";
pub const MS_SMTP_SCOPE: &str = "https://outlook.office.com/SMTP.Send";

impl Provider {
    pub fn preset(kind: ProviderKind) -> Self {
        match kind {
            ProviderKind::Google => Self::google(),
            ProviderKind::Microsoft => Self::microsoft("common"),
        }
    }

    /// Gmail over IMAP/SMTP. `openid email` is added so the token response carries
    /// an ID token with the address. Those two scopes are non-sensitive.
    pub fn google() -> Self {
        Provider {
            kind: ProviderKind::Google,
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            scopes: vec![GOOGLE_MAIL_SCOPE.into(), "openid".into(), "email".into()],
            // The current native-app page says installed apps always get a
            // refresh token and no longer lists these. They are harmless, and
            // `prompt=consent` makes a re-login reliably return a new refresh token.
            extra_authorize_params: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
            redirect_host: RedirectHost::Loopback127,
            scope_on_token_requests: false,
        }
    }

    /// Outlook.com and Microsoft 365 over IMAP/SMTP. `tenant` is normally
    /// `common`; `consumers` or `organizations` (or a tenant ID) restrict it.
    pub fn microsoft(tenant: &str) -> Self {
        let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
        Provider {
            kind: ProviderKind::Microsoft,
            authorize_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            scopes: vec![
                MS_IMAP_SCOPE.into(),
                MS_SMTP_SCOPE.into(),
                "offline_access".into(),
                "openid".into(),
                "email".into(),
            ],
            extra_authorize_params: vec![("response_mode".into(), "query".into())],
            redirect_host: RedirectHost::Localhost,
            scope_on_token_requests: true,
        }
    }

    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}
