//! OAuth client IDs: compiled in from the environment, overridable per account.
//!
//! Release builds set `CM_GOOGLE_CLIENT_ID`, `CM_GOOGLE_CLIENT_SECRET` and
//! `CM_MS_CLIENT_ID` when running `cargo build`. Nothing real is ever committed.
//! Cargo records `option_env!` reads in its dep-info, so changing a variable
//! triggers a rebuild of this crate.

use crate::provider::ProviderKind;
use crate::{Error, Result};

const BUILD_GOOGLE_CLIENT_ID: Option<&str> = option_env!("CM_GOOGLE_CLIENT_ID");
const BUILD_GOOGLE_CLIENT_SECRET: Option<&str> = option_env!("CM_GOOGLE_CLIENT_SECRET");
const BUILD_MS_CLIENT_ID: Option<&str> = option_env!("CM_MS_CLIENT_ID");

/// The OAuth client used for one account.
#[derive(Clone)]
pub struct ClientConfig {
    pub client_id: String,
    /// Google "Desktop app" clients get a secret that is not confidential (it
    /// ships in the binary); Microsoft public clients must not send one.
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<set>"),
            )
            .finish()
    }
}

fn non_empty(v: Option<&str>) -> Option<String> {
    v.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The client ID compiled into this build, if any.
pub fn build_client_id(kind: ProviderKind) -> Option<String> {
    match kind {
        ProviderKind::Google => non_empty(BUILD_GOOGLE_CLIENT_ID),
        ProviderKind::Microsoft => non_empty(BUILD_MS_CLIENT_ID),
    }
}

pub fn build_client_secret(kind: ProviderKind) -> Option<String> {
    match kind {
        ProviderKind::Google => non_empty(BUILD_GOOGLE_CLIENT_SECRET),
        ProviderKind::Microsoft => None,
    }
}

impl ClientConfig {
    /// Per-account overrides win over the build-time values. The secret falls
    /// back to the build value only when the ID did too, so an overridden ID is
    /// never paired with another client's secret.
    pub fn resolve(
        kind: ProviderKind,
        id_override: Option<&str>,
        secret_override: Option<&str>,
    ) -> Result<Self> {
        let (client_id, default_secret) = match non_empty(id_override) {
            Some(id) => (id, None),
            None => (
                build_client_id(kind).ok_or(Error::MissingClientId {
                    provider: kind.name(),
                    env_var: match kind {
                        ProviderKind::Google => "CM_GOOGLE_CLIENT_ID",
                        ProviderKind::Microsoft => "CM_MS_CLIENT_ID",
                    },
                })?,
                build_client_secret(kind),
            ),
        };
        let client_secret = non_empty(secret_override).or(default_secret);
        Ok(ClientConfig {
            client_id,
            client_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_and_secret_is_not_mixed() {
        let c = ClientConfig::resolve(ProviderKind::Google, Some("my-id"), None).unwrap();
        assert_eq!(c.client_id, "my-id");
        assert!(c.client_secret.is_none());
        let c = ClientConfig::resolve(ProviderKind::Google, Some("my-id"), Some("s")).unwrap();
        assert_eq!(c.client_secret.as_deref(), Some("s"));
        let c = ClientConfig::resolve(ProviderKind::Microsoft, Some(" ms-id "), None).unwrap();
        assert_eq!(c.client_id, "ms-id");
    }

    #[test]
    fn missing_build_id_is_an_error_unless_compiled_in() {
        let r = ClientConfig::resolve(ProviderKind::Microsoft, None, None);
        match build_client_id(ProviderKind::Microsoft) {
            Some(id) => {
                println!("CM_MS_CLIENT_ID compiled in: {id}");
                assert_eq!(r.unwrap().client_id, id)
            }
            None => assert!(matches!(r, Err(Error::MissingClientId { .. }))),
        }
    }
}
