//! Token responses and the in-memory token set.

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use serde::Deserialize;

use crate::{Error, Result};

/// Access and refresh tokens for one account. `Debug` never prints tokens.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: SystemTime,
    pub scope: Option<String>,
    /// The address from the ID token, if one was returned.
    pub email: Option<String>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field(
                "access_token",
                &format_args!("<{} bytes>", self.access_token.len()),
            )
            .field(
                "refresh_token",
                &self
                    .refresh_token
                    .as_ref()
                    .map(|t| format!("<{} bytes>", t.len())),
            )
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .field("email", &self.email)
            .finish()
    }
}

/// Refresh this long before expiry, to cover clock skew and a slow IMAP login.
pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);

impl TokenSet {
    /// True when the access token expires within `skew` of `now`.
    pub fn needs_refresh_at(&self, now: SystemTime, skew: Duration) -> bool {
        now + skew >= self.expires_at
    }

    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_at(SystemTime::now(), DEFAULT_REFRESH_SKEW)
    }

    /// The base64 XOAUTH2 initial response for IMAP/SMTP.
    pub fn xoauth2(&self, user: &str) -> String {
        crate::xoauth2::encode(user, &self.access_token)
    }

    /// Builds a token set from a token-endpoint response. On refresh, `previous`
    /// supplies the refresh token and email when the response omits them
    /// (Google does not rotate; Microsoft does and the new one must be kept).
    pub(crate) fn from_response(
        resp: TokenResponse,
        previous: Option<&TokenSet>,
        now: SystemTime,
    ) -> Result<Self> {
        if !resp.token_type.eq_ignore_ascii_case("bearer") {
            return Err(Error::InvalidResponse(format!(
                "token_type {:?}, expected Bearer",
                resp.token_type
            )));
        }
        let expires_in = resp.expires_in.map(|e| e.0).unwrap_or(3600);
        let email = resp
            .id_token
            .as_deref()
            .and_then(email_from_id_token)
            .or_else(|| previous.and_then(|p| p.email.clone()));
        Ok(TokenSet {
            access_token: resp.access_token,
            refresh_token: resp
                .refresh_token
                .filter(|t| !t.is_empty())
                .or_else(|| previous.and_then(|p| p.refresh_token.clone())),
            expires_at: now + Duration::from_secs(expires_in),
            scope: resp
                .scope
                .or_else(|| previous.and_then(|p| p.scope.clone())),
            email,
        })
    }
}

/// A successful token-endpoint response (RFC 6749 section 5.1).
#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<Seconds>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// An error response (RFC 6749 section 5.2).
#[derive(Deserialize)]
pub(crate) struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// `expires_in` as a number, or as a string (old Azure AD v1 endpoints did that).
pub(crate) struct Seconds(pub u64);

impl<'de> Deserialize<'de> for Seconds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumOrStr {
            Num(u64),
            Str(String),
        }
        match NumOrStr::deserialize(d)? {
            NumOrStr::Num(n) => Ok(Seconds(n)),
            NumOrStr::Str(s) => s
                .trim()
                .parse()
                .map(Seconds)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Reads `email` (Google, Microsoft when present) or `preferred_username`
/// (Microsoft) from an ID token's payload.
///
/// The signature is not checked. That is acceptable here because the token came
/// straight from the token endpoint over TLS (OpenID Connect Core 3.1.3.7), and
/// the address is only a default for the account's user name, which the user
/// can edit. It is never used for an authorization decision.
pub fn email_from_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    ["email", "preferred_username"]
        .iter()
        .filter_map(|k| claims.get(*k)?.as_str())
        .find(|v| v.contains('@'))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: &str) -> String {
        let e = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!("{}.{}.sig", e(r#"{"alg":"none"}"#), e(claims))
    }

    #[test]
    fn email_claims() {
        assert_eq!(
            email_from_id_token(&jwt(r#"{"email":"a@gmail.com"}"#)).as_deref(),
            Some("a@gmail.com")
        );
        assert_eq!(
            email_from_id_token(&jwt(r#"{"preferred_username":"b@outlook.com"}"#)).as_deref(),
            Some("b@outlook.com")
        );
        assert_eq!(email_from_id_token("garbage"), None);
    }

    #[test]
    fn near_expiry() {
        let now = SystemTime::now();
        let t = TokenSet {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: now + Duration::from_secs(120),
            scope: None,
            email: None,
        };
        assert!(t.needs_refresh_at(now, DEFAULT_REFRESH_SKEW));
        assert!(!t.needs_refresh_at(now, Duration::from_secs(60)));
        assert!(!format!("{t:?}").contains("access_token: \"a\""));
    }

    #[test]
    fn expires_in_as_string() {
        let r: TokenResponse = serde_json::from_str(
            r#"{"access_token":"x","token_type":"Bearer","expires_in":"3599"}"#,
        )
        .unwrap();
        assert_eq!(r.expires_in.unwrap().0, 3599);
    }
}
