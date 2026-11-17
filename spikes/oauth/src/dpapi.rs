//! DPAPI (`CryptProtectData`) wrappers, bound to the current Windows user.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::PCWSTR;

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copies a DPAPI output blob and frees it with `LocalFree`.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if out.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with LocalAlloc.
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: the pointer came from DPAPI and is freed exactly once.
    unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
    v
}

/// Encrypts `data` for the current user. `entropy` is an extra app-specific
/// secret that other programs running as the same user would also need.
pub fn protect(data: &[u8], entropy: &[u8]) -> windows::core::Result<Vec<u8>> {
    let input = blob(data);
    let ent = blob(entropy);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input blobs point at live slices; `out` is a valid out-pointer.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&ent),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )?;
    }
    Ok(take(out))
}

pub fn unprotect(data: &[u8], entropy: &[u8]) -> windows::core::Result<Vec<u8>> {
    let input = blob(data);
    let ent = blob(entropy);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&ent),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )?;
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_entropy() {
        let secret = vec![b'x'; 20_000];
        let enc = protect(&secret, b"e1").unwrap();
        assert_ne!(&enc[..], &secret[..]);
        assert_eq!(unprotect(&enc, b"e1").unwrap(), secret);
        assert!(unprotect(&enc, b"e2").is_err());
    }
}
