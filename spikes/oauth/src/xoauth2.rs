//! The XOAUTH2 SASL initial response used by Gmail and Exchange/Outlook.com for
//! IMAP `AUTHENTICATE XOAUTH2` and SMTP `AUTH XOAUTH2`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The raw SASL string: `user=<email>\x01auth=Bearer <token>\x01\x01`.
pub fn raw(user: &str, access_token: &str) -> String {
    format!("user={user}\x01auth=Bearer {access_token}\x01\x01")
}

/// The base64 form sent on the wire (standard alphabet, with padding).
pub fn encode(user: &str, access_token: &str) -> String {
    STANDARD.encode(raw(user, access_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from
    /// https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
    #[test]
    fn google_documented_example() {
        let token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
        assert_eq!(
            raw("someuser@example.com", token),
            "user=someuser@example.com\u{1}auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\u{1}\u{1}"
        );
        assert_eq!(
            encode("someuser@example.com", token),
            "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52\
             YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="
        );
    }
}
