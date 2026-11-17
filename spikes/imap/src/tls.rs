//! rustls client configuration shared by both candidates' TLS connect code.

use std::sync::Arc;

use rustls_platform_verifier::BuilderVerifierExt;
use tokio_rustls::rustls::{self, ClientConfig};

/// A rustls `ClientConfig` that verifies server certificates with the operating system
/// (on Windows: CryptoAPI and the Windows certificate store, so enterprise roots and user-added
/// roots work), with the `ring` provider chosen explicitly so that a second provider elsewhere
/// in the dependency tree cannot cause a "no process-level CryptoProvider" panic.
pub fn client_config() -> Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth();
    // IANA ALPN id for IMAP over implicit TLS (RFC 9051 section 7.1 / IANA registry).
    config.alpn_protocols = vec![b"imap".to_vec()];
    Ok(config)
}
