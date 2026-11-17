//! Credential Manager and DPAPI fallback tests. Every entry uses the service
//! name `clawsmail-rust-spike-test` (raw probes: target prefix
//! `clawsmail-rust-spike-test-raw-`) and is deleted by a Drop guard, so nothing
//! is left behind even when an assertion fails.
#![cfg(windows)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use keyring_core::api::CredentialStoreApi;
use oauth_spike::store::{Backend, CRED_MAX_BLOB, TokenStore, with_credential_lock};

const TEST_SERVICE: &str = "clawsmail-rust-spike-test";
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}@test.invalid",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Deletes the accounts' credentials and files, and the temp dir, on drop.
struct Guard {
    store: TokenStore,
    dir: PathBuf,
    accounts: Vec<String>,
}

impl Guard {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{TEST_SERVICE}-{}", unique(label)));
        Self {
            store: TokenStore::new(TEST_SERVICE, &dir).unwrap(),
            dir,
            accounts: Vec::new(),
        }
    }
    fn account(&mut self, label: &str) -> String {
        let a = unique(label);
        self.accounts.push(a.clone());
        a
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        for a in &self.accounts {
            if let Err(e) = self.store.delete(a) {
                eprintln!("cleanup of {a} failed: {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A token-shaped ASCII string of `n` characters.
fn token(n: usize) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!*$";
    let mut seed = [0u8; 64];
    getrandom::fill(&mut seed).unwrap();
    (0..n)
        .map(|i| ALPHA[(seed[i % 64] as usize + i * 7) % ALPHA.len()] as char)
        .collect()
}

#[test]
fn small_token_goes_to_credential_manager_and_round_trips() {
    let mut g = Guard::new("small");
    let acct = g.account("small");
    let t = token(1200);
    assert_eq!(g.store.save(&acct, &t).unwrap(), Backend::CredentialManager);
    let (loaded, backend) = g.store.load(&acct).unwrap().unwrap();
    assert_eq!(loaded, t);
    assert_eq!(backend, Backend::CredentialManager);
    assert!(!g.store.fallback_path(&acct).exists());
    g.store.delete(&acct).unwrap();
    assert!(g.store.load(&acct).unwrap().is_none());
}

#[test]
fn rotation_moves_between_backends_without_leaving_stale_copies() {
    let mut g = Guard::new("rotate");
    let acct = g.account("rotate");
    let small = token(900);
    let large = token(6000);

    assert_eq!(
        g.store.save(&acct, &small).unwrap(),
        Backend::CredentialManager
    );

    // A larger rotated token moves to the DPAPI file; the keyring copy goes.
    assert!(matches!(
        g.store.save(&acct, &large).unwrap(),
        Backend::DpapiFile { .. }
    ));
    assert!(g.store.fallback_path(&acct).exists());
    let raw_file = std::fs::read(g.store.fallback_path(&acct)).unwrap();
    assert!(
        !raw_file.windows(32).any(|w| w == &large.as_bytes()[..32]),
        "file must not contain the plaintext token"
    );
    let (loaded, backend) = g.store.load(&acct).unwrap().unwrap();
    assert_eq!(loaded, large);
    assert!(matches!(backend, Backend::DpapiFile { .. }));

    // And back: the file goes.
    let small2 = token(1000);
    assert_eq!(
        g.store.save(&acct, &small2).unwrap(),
        Backend::CredentialManager
    );
    assert!(!g.store.fallback_path(&acct).exists());
    assert_eq!(g.store.load(&acct).unwrap().unwrap().0, small2);
}

/// Probes the limit at three levels and prints a table: the keyring crate's
/// `set_password` (UTF-16), its `set_secret` (raw bytes), and `CredWriteW`
/// called directly (bypassing the crate's own length check). Then checks that
/// `TokenStore` stores every size, falling back to DPAPI where needed.
#[test]
fn credential_manager_size_limit_report() {
    let mut g = Guard::new("size");
    let ks = windows_native_keyring_store::Store::new().unwrap();
    let mods = HashMap::from([("persistence", "Local")]);
    let sizes = [1000usize, 1280, 1281, 2000, 2048, 2560, 2561, 4096, 8192];
    let mut report = String::from(
        "\nchars | set_password (UTF-16) | set_secret (UTF-8)    | raw CredWriteW        | TokenStore\n",
    );
    for &n in &sizes {
        let t = token(n);
        let acct = g.account(&format!("size{n}"));
        let entry = ks.build(TEST_SERVICE, &acct, Some(&mods)).unwrap();

        // Direct Credential Manager calls share the store's process-wide lock
        // (parallel calls were seen to lose deletes; see store.rs).
        let (pw, sec, raw) = with_credential_lock(|| {
            let pw = entry.set_password(&t);
            if pw.is_ok() {
                assert_eq!(entry.get_password().unwrap(), t);
            }
            let sec = entry.set_secret(t.as_bytes());
            if sec.is_ok() {
                assert_eq!(entry.get_secret().unwrap(), t.as_bytes());
            }
            let _ = entry.delete_credential();
            let raw = raw::probe(&format!("{TEST_SERVICE}-raw-{acct}"), t.as_bytes());
            (pw, sec, raw)
        });
        let (pw_ok, sec_ok) = (pw.is_ok(), sec.is_ok());

        let backend = g.store.save(&acct, &t).unwrap();
        assert_eq!(
            g.store.load(&acct).unwrap().unwrap().0,
            t,
            "round trip at {n}"
        );

        let show = |r: Result<(), String>| match r {
            Ok(()) => "ok".to_string(),
            Err(e) => e.chars().take(20).collect(),
        };
        report.push_str(&format!(
            "{n:>5} | {:<21} | {:<21} | {:<21} | {}\n",
            show(pw.map_err(|e| e.to_string())),
            show(sec.map_err(|e| e.to_string())),
            show(raw.clone()),
            match &backend {
                Backend::CredentialManager => "Credential Manager".to_string(),
                Backend::DpapiFile { .. } => "DPAPI file".to_string(),
            }
        ));

        assert_eq!(pw_ok, n * 2 <= CRED_MAX_BLOB, "set_password at {n}");
        assert_eq!(sec_ok, n <= CRED_MAX_BLOB, "set_secret at {n}");
        assert_eq!(
            raw.is_ok(),
            n <= CRED_MAX_BLOB,
            "raw CredWriteW at {n}: {raw:?}"
        );
        assert_eq!(
            backend == Backend::CredentialManager,
            n <= CRED_MAX_BLOB,
            "backend at {n}"
        );
    }
    println!("{report}");
}

/// The "keyring fails" fallback, without touching Credential Manager: a user
/// name over `CRED_MAX_USERNAME_LENGTH` (513) makes the keyring store refuse to
/// build the entry at all, so a small token must still land in the DPAPI file,
/// load back, and be deleted.
#[test]
fn keyring_failure_falls_back_to_dpapi_file() {
    let mut g = Guard::new("kfail");
    let base = g.account("kfail");
    let acct = format!("{}{base}", "x".repeat(600));
    g.accounts.push(acct.clone());
    let t = token(500);
    match g.store.save(&acct, &t).unwrap() {
        Backend::DpapiFile { reason } => {
            assert!(reason.contains("cannot hold this account"), "{reason}")
        }
        other => panic!("expected the DPAPI file, got {other:?}"),
    }
    let (loaded, backend) = g.store.load(&acct).unwrap().unwrap();
    assert_eq!(loaded, t);
    assert!(matches!(backend, Backend::DpapiFile { .. }));
    g.store.delete(&acct).unwrap();
    assert!(!g.store.fallback_path(&acct).exists());
    assert!(g.store.load(&acct).unwrap().is_none());
}

/// Direct `CredWriteW` calls, to see what Windows itself does past the limit.
mod raw {
    use windows::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredWriteW,
    };
    use windows::core::{PCWSTR, PWSTR};

    struct Delete(Vec<u16>);
    impl Drop for Delete {
        fn drop(&mut self) {
            // SAFETY: a NUL-terminated wide string; a missing credential just errors.
            let _ = unsafe { CredDeleteW(PCWSTR(self.0.as_ptr()), CRED_TYPE_GENERIC, None) };
        }
    }

    pub fn probe(target: &str, blob: &[u8]) -> Result<(), String> {
        let mut target_w: Vec<u16> = target.encode_utf16().chain([0]).collect();
        let mut user_w: Vec<u16> = "spike-test".encode_utf16().chain([0]).collect();
        let _cleanup = Delete(target_w.clone());
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_w.as_mut_ptr()),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: PWSTR(user_w.as_mut_ptr()),
            ..Default::default()
        };
        // SAFETY: every pointer refers to live buffers for the call's duration.
        unsafe { CredWriteW(&cred, 0) }.map_err(|e| format!("{:#010x} {}", e.code().0, e.message()))
    }
}
