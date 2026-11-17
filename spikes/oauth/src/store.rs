//! Refresh-token storage: Windows Credential Manager first, a DPAPI-encrypted
//! file when the token is too large for a credential or the store fails.
//!
//! Credential Manager limits a credential blob to `CRED_MAX_CREDENTIAL_BLOB_SIZE`
//! (5 * 512 = 2560 bytes). The `windows-native-keyring-store` crate's
//! `set_password` stores UTF-16, which halves that to 1280 characters, so this
//! module stores the token's UTF-8 bytes with `set_secret` instead: OAuth tokens
//! are ASCII, so up to 2560 characters fit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// `CRED_MAX_CREDENTIAL_BLOB_SIZE` from wincred.h.
pub const CRED_MAX_BLOB: usize = 5 * 512;

/// Serialises Credential Manager calls within this process.
///
/// The spike found that concurrent `CredWriteW`/`CredDeleteW` calls from several
/// threads (on different targets) sometimes lose a delete: the call succeeds,
/// an immediate `CredReadW` reports not-found, yet the credential is back
/// afterwards (2 of 5 parallel test runs leaked entries; 0 of 5 serial runs did).
/// Everything that touches Credential Manager takes this lock.
static CRED_LOCK: Mutex<()> = Mutex::new(());

/// Runs `f` while holding the process-wide Credential Manager lock. Public so
/// that tests probing Credential Manager directly can share it.
pub fn with_credential_lock<T>(f: impl FnOnce() -> T) -> T {
    let _g = CRED_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    f()
}

const FILE_MAGIC: &[u8] = b"CMRT-DPAPI-1\n";
const DPAPI_ENTROPY: &[u8] = b"clawsmail-rust refresh token v1";

/// Where a secret ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    CredentialManager,
    DpapiFile { reason: String },
}

pub struct TokenStore {
    service: String,
    fallback_dir: PathBuf,
    store: Arc<windows_native_keyring_store::Store>,
}

impl TokenStore {
    /// `service` names the Credential Manager entries (`<account>.<service>`);
    /// `fallback_dir` holds the DPAPI files.
    pub fn new(service: impl Into<String>, fallback_dir: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            service: service.into(),
            fallback_dir: fallback_dir.into(),
            store: windows_native_keyring_store::Store::new()?,
        })
    }

    /// The default fallback directory, `%LOCALAPPDATA%\clawsmail-rust\tokens`.
    pub fn default_fallback_dir() -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("clawsmail-rust")
            .join("tokens")
    }

    fn entry(&self, account: &str) -> Result<Entry> {
        // "Local" persistence: kept on this machine, not roamed with a domain
        // profile ("Enterprise", the crate's default).
        let mods = HashMap::from([("persistence", "Local")]);
        Ok(self.store.build(&self.service, account, Some(&mods))?)
    }

    pub fn fallback_path(&self, account: &str) -> PathBuf {
        let mut h = Sha256::new();
        h.update(self.service.as_bytes());
        h.update([0]);
        h.update(account.as_bytes());
        let name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&h.finalize()[..18]);
        self.fallback_dir.join(format!("{name}.dpapi"))
    }

    /// Saves the secret and removes any copy in the other backend, so a rotated
    /// token never leaves a stale one behind.
    ///
    /// Invariant: the DPAPI file exists only when the latest save went there, so
    /// [`load`](Self::load) prefers the file. A Credential Manager failure
    /// therefore never shadows a newer token in the file.
    pub fn save(&self, account: &str, secret: &str) -> Result<Backend> {
        let reason = if secret.len() > CRED_MAX_BLOB {
            format!(
                "{} bytes exceeds the Credential Manager limit of {CRED_MAX_BLOB}",
                secret.len()
            )
        } else {
            match self.entry(account) {
                Err(e) => format!("Credential Manager cannot hold this account: {e}"),
                Ok(entry) => match with_credential_lock(|| entry.set_secret(secret.as_bytes())) {
                    Ok(()) => {
                        remove_file_if_exists(&self.fallback_path(account))?;
                        return Ok(Backend::CredentialManager);
                    }
                    Err(e) => format!("Credential Manager failed: {e}"),
                },
            }
        };
        self.write_file(account, secret)?;
        // Best effort: the file now wins on load, so a stale keyring copy that
        // cannot be deleted (the keyring is failing) is harmless.
        let _ = self.delete_keyring(account);
        Ok(Backend::DpapiFile { reason })
    }

    pub fn load(&self, account: &str) -> Result<Option<(String, Backend)>> {
        let path = self.fallback_path(account);
        match std::fs::read(&path) {
            Ok(data) => {
                let body = data.strip_prefix(FILE_MAGIC).ok_or_else(|| {
                    Error::InvalidResponse(format!("{} is not a token file", path.display()))
                })?;
                let plain = crate::dpapi::unprotect(body, DPAPI_ENTROPY)?;
                let s = String::from_utf8(plain)
                    .map_err(|_| Error::InvalidResponse("stored token is not UTF-8".into()))?;
                return Ok(Some((
                    s,
                    Backend::DpapiFile {
                        reason: "loaded from file".into(),
                    },
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // An account the store cannot even address has no keyring entry.
        let Ok(entry) = self.entry(account) else {
            return Ok(None);
        };
        match with_credential_lock(|| entry.get_secret()) {
            Ok(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|_| Error::InvalidResponse("stored token is not UTF-8".into()))?;
                Ok(Some((s, Backend::CredentialManager)))
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes both copies; missing ones are not an error. The file is removed
    /// even when the keyring fails, and the keyring error is then reported.
    pub fn delete(&self, account: &str) -> Result<()> {
        let file = remove_file_if_exists(&self.fallback_path(account));
        self.delete_keyring(account)?;
        file
    }

    fn delete_keyring(&self, account: &str) -> Result<()> {
        // An account the store cannot address cannot have an entry.
        let Ok(entry) = self.entry(account) else {
            return Ok(());
        };
        match with_credential_lock(|| entry.delete_credential()) {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn write_file(&self, account: &str, secret: &str) -> Result<()> {
        std::fs::create_dir_all(&self.fallback_dir)?;
        let enc = crate::dpapi::protect(secret.as_bytes(), DPAPI_ENTROPY)?;
        let path = self.fallback_path(account);
        let tmp = path.with_extension("dpapi.tmp");
        let mut data = Vec::with_capacity(FILE_MAGIC.len() + enc.len());
        data.extend_from_slice(FILE_MAGIC);
        data.extend_from_slice(&enc);
        std::fs::write(&tmp, &data)?;
        // std::fs::rename replaces an existing file on Windows (MoveFileExW with
        // MOVEFILE_REPLACE_EXISTING).
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
