# Spike C findings: OAuth2 for Gmail and Microsoft, token storage

Date: 2026-11-17. Rust 1.100.0, edition 2024, Windows 11 LTSC 2024 (10.0.26100).

## Result

The flow works end to end against a local fake provider:
- authorization code with PKCE (S256), a loopback redirect, the state check, `access_denied` and a timeout;
- the code exchange, refresh with and without token rotation, and the XOAUTH2 string.

Refresh tokens are kept in Windows Credential Manager when they fit. A larger token, or a Credential Manager failure,
sends them to a DPAPI-encrypted file instead.

`cargo test` passes 26 tests (12 unit, 10 flow, 4 storage). The tests open no browser or window, and no real account
or client ID was used. Real-provider testing is left to the `oauth-spike` CLI (see the last section).

| Area | Where |
|---|---|
| PKCE S256, checked against the RFC 7636 Appendix B vector | `src/pkce.rs` |
| Provider presets | `src/provider.rs` |
| Client IDs built in through `option_env!`, with a per-account override | `src/config.rs` |
| Loopback listener: 127.0.0.1 plus [::1] best effort; ignores favicon and junk connections; overall timeout | `src/loopback.rs` |
| Authorize URL, code exchange, refresh, `refresh_if_needed` (5-minute margin), HTTPS-or-loopback guard on the token endpoint | `src/flow.rs` |
| Token set with a redacted `Debug`; email address from the ID token | `src/token.rs` |
| XOAUTH2, checked against Google's worked example | `src/xoauth2.rs` |
| Credential Manager and DPAPI file store | `src/store.rs`, `src/dpapi.rs` |
| Fake authorization server, PKCE-checking token endpoint, fake browser | `tests/common/mod.rs` |

## Crate choices (versions checked 2026-11-17)

| Crate | Version | Why |
|---|---|---|
| `reqwest` | 0.13.5, `default-features = false`, features `rustls` and `form` | The only HTTP needed is two form POSTs. reqwest uses aws-lc-rs and `rustls-platform-verifier` (the Windows certificate store), and it built here without NASM or CMake. |
| `oauth2` | not used | 5.0.0 depends on reqwest 0.12, which would add a second HTTP/TLS stack. The hand-written client is about 150 lines and handles Microsoft's token rotation, the ID-token email and a string-valued `expires_in`. |
| `tokio` | 1.54 | Async runtime; the loopback listener is a raw `TcpListener`. |
| `keyring-core` + `windows-native-keyring-store` | 1.0.1 / 1.1.0 | keyring 4.x is split into these crates. Entries are created from a `Store` instance. |
| `windows` | 0.62.2 | DPAPI, plus `CredWriteW` probes in the tests. |
| `sha2`, `base64`, `getrandom`, `url`, `serde_json`, `thiserror` | current | PKCE, encoding, randomness, URL parsing, JSON, errors. |
| `webbrowser` | 1.2.7 | Used by the CLI only. The library's `login()` takes an `open` callback instead. |

## Verified endpoints and parameters

### Google

Source: <https://developers.google.com/identity/protocols/oauth2/native-app>

- **Endpoints:** authorize at `https://accounts.google.com/o/oauth2/v2/auth`, token at
  `https://oauth2.googleapis.com/token`.
- **Scope:** `https://mail.google.com/` covers IMAP, POP and SMTP
  (<https://developers.google.com/workspace/gmail/imap/xoauth2-protocol>). We add `openid email` to get an
  `id_token` that carries the address.
- **Redirect:** `http://127.0.0.1:<random port>` or `[::1]`. Custom schemes and OOB are no longer supported for desktop
  apps.
- **`client_secret`:** "optional" for desktop apps, which are public clients. Community reports say the token endpoint
  rejects Desktop clients without it, so it is sent when configured. This is unverified.
- **Secret visibility:** the full client secret is shown only once, when it is created
  (<https://support.google.com/cloud/answer/15549257>).
- **Changed:** the page no longer documents `access_type=offline`, and it says installed apps always get refresh
  tokens. We still send `access_type=offline` and `prompt=consent`; they are harmless.

### Microsoft identity platform

Sources:
- <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>
- <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>
- <https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth>

- **Endpoints:** `https://login.microsoftonline.com/common/oauth2/v2.0/{authorize,token}`. PKCE S256 is recommended for
  all app types. As a public client we send no secret, and the tests check that.
- **Scopes:** `https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access`,
  plus `openid email`. The same full URIs apply to Microsoft 365 and Outlook.com. Do not use `wl.imap`, short names
  or Graph-style IMAP scopes. IMAP and SMTP share the `outlook.office.com` resource, so one access token serves both.
- **Rotation:** refresh tokens rotate ("replace the old refresh token"). The tests prove that after a rotation the
  old token is rejected.
- **Changed:** the docs no longer give a refresh-token lifetime (the 90 days is gone). Expect revocation at any time.
- **Redirect:** a `localhost` redirect matches regardless of port. The docs prefer `127.0.0.1`, but the portal cannot
  add it without editing the manifest, and `[::1]` is not supported. The preset therefore uses
  `http://localhost:<port>`, and the listener binds both 127.0.0.1 and [::1]. Still open: does a runtime 127.0.0.1
  redirect match a registered `http://localhost`?

### Servers

| Account | IMAP | SMTP |
|---|---|---|
| Gmail | `imap.gmail.com:993` | `smtp.gmail.com:465` or `:587` |
| Microsoft 365 | `outlook.office365.com:993` | `smtp.office365.com:587` STARTTLS |
| Personal Outlook.com | `outlook.office365.com:993` | `smtp-mail.outlook.com:587` STARTTLS |

The Outlook.com hosts come from <https://support.microsoft.com/office/8361e398-8af4-4e97-b147-6c6c4ac95353>.

XOAUTH2 string: `base64("user=" + email + "\x01auth=Bearer " + token + "\x01\x01")`. The unit test reproduces
Google's worked example byte for byte.

## Windows Credential Manager size limit

**The limit:** `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 5*512 = **2560 bytes**
(<https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>).

**The crate:** `set_password` stores UTF-16, which caps a token at **1280 characters**. `set_secret` stores raw bytes,
which allows **2560**. The store saves tokens as UTF-8 bytes through `set_secret`.

**Measured** (`tests/store.rs`, `credential_manager_size_limit_report`):

| Characters | set_password | set_secret | raw CredWriteW | TokenStore |
|---|---|---|---|---|
| up to 1280 | ok | ok | ok | Credential Manager |
| 1281–2560 | too long | ok | ok | Credential Manager |
| 2561 and up | too long | too long | 0x800706F7 | DPAPI file |

- **Over the limit:** at 2561 bytes `CredWriteW` itself fails with `0x800706F7` (RPC_X_BAD_STUB_DATA).
- **Microsoft token size:** Microsoft does not document refresh-token length. Community reports put it at about
  1,000–2,000 characters (unsourced). The CLI prints the real length.

### Finding: parallel Credential Manager writes can lose deletes

Calls to Credential Manager from several threads at once, each on a *different* entry, sometimes lost a delete.
`CredDeleteW` returned success and an immediate read said not-found, yet the entry came back later. Test entries were
left behind in 2 of 5 parallel runs and 0 of 5 serial runs.

The fix is a process-wide mutex (`store::with_credential_lock`). Since adding it, 25 parallel runs have left nothing
behind. The leftovers from before the fix were deleted.

For `cm-auth`: keep the lock, and consider a named mutex (`Local\clawsmail-rust-credentials`) if two processes could
write at once.

## DPAPI fallback

- **When it is used:** a token over 2560 bytes, or any Credential Manager failure (tested with an account name the
  store cannot address).
- **Encryption:** `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`, bound to the current user, with the entropy
  `clawsmail-rust refresh token v1`.
- **File:** `%LOCALAPPDATA%\clawsmail-rust\tokens\<base64url(sha256(service\0account))[..18]>.dpapi`. The contents
  are the magic `CMRT-DPAPI-1\n` followed by the blob. It is written to a temp file and renamed into place. The hashed
  name keeps email addresses out of file names.
- **Only one copy is live:** a save to Credential Manager deletes the file; a save to the file tries to delete the
  keyring copy; and `load` prefers the file. A stale keyring copy can therefore never shadow a newer token.
- **Tests:** a token moving between backends leaves no stale copy, the file contains no plaintext, and the wrong
  entropy fails to decrypt.
- **Limitations:** an administrator password reset makes the file undecryptable, which forces a new sign-in. Other
  programs running as the same user can decrypt it, which is also true of Credential Manager.
- **Persistence:** credentials use `CRED_PERSIST_LOCAL_MACHINE` (`Local`), not the crate default `Enterprise`, which
  roams with the profile.

## Provider caveats

### Google

- **Testing status:** an app in Testing gets refresh tokens that expire after 7 days
  (<https://developers.google.com/identity/protocols/oauth2#expiration>).
- **Other expiry causes:** the token goes unused for 6 months; the password changes (Gmail scopes); the account
  passes 100 refresh tokens per client ID; or access is revoked.
- **Restricted scope:** `https://mail.google.com/` is restricted
  (<https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification>).
  - Production use needs verification.
  - A CASA security assessment is required "if you store or transmit restricted scope data on servers". Clawsmail
    has no server, so CASA arguably does not apply, but verification still does. Confirm with Google before
    publishing.
  - Exceptions include personal use by a small known group, and development or testing projects.
- **Unverified apps** show a warning screen and are limited to 100 users
  (<https://support.google.com/cloud/answer/7454865>).
- **Practical path:** use Testing-status IDs during development. For public builds, complete verification or let
  users bring their own client ID (the per-account override already supports this).

### Microsoft

- **Personal accounts:** some third-party reports (Mozilla bug 1780083, Microsoft Q&A) describe `invalid_scope`
  errors. Test with a real personal mailbox.
- **SMTP on personal Outlook.com:**
  - It requires OAuth2, and the SMTP host is `smtp-mail.outlook.com`.
  - IMAP may need enabling in Outlook settings.
  - Some reports say new consumer mailboxes refuse SMTP AUTH even with OAuth; there is no official statement.
  - Keep Graph `sendMail` as a fallback. It needs a separate token for `https://graph.microsoft.com/Mail.Send`.
- **SMTP on Microsoft 365:** tenant and mailbox settings (`SmtpClientAuthenticationDisabled`) and security defaults
  can disable SMTP AUTH. Basic-auth SMTP is being retired from the end of December 2026, but OAuth is unaffected.
- **Admin consent:** tenants that block user consent send users into an admin-consent loop. The UI should explain
  this.
- **App registration:** needs "Allow public client flows" and the "Mobile and desktop applications" platform.

## Not verified / open

- Does a runtime `127.0.0.1` redirect match a registered `http://localhost` (Microsoft)?
- Does Google really require `client_secret` for Desktop clients?
- Personal Microsoft accounts: `invalid_scope` and SMTP AUTH.
- Where the delegated IMAP and SMTP permissions appear in the Entra portal. Registering them statically is optional,
  because the scopes are requested at sign-in.

## Notes for `cm-auth`

- Save a rotated refresh token *before* using the new access token.
- Run one refresh at a time per account. Two concurrent rotations would invalidate each other.
- Store only refresh tokens; keep access tokens in memory.
- `invalid_grant` on refresh means "sign in again" (the 7-day Testing expiry, a password change, revocation).
- The email address from the ID token is unvalidated. That is fine for pre-filling the user name.

## Manual test with real IDs (opens the real browser)

```powershell
cd spikes\oauth
$env:CM_GOOGLE_CLIENT_ID = "<id>.apps.googleusercontent.com"; $env:CM_GOOGLE_CLIENT_SECRET = "<secret>"
cargo run --bin oauth-spike -- login --provider google --save
cargo run --bin oauth-spike -- refresh --provider google --account you@gmail.com
cargo run --bin oauth-spike -- login --provider microsoft --client-id <entra-app-id> --save
cargo run --bin oauth-spike -- forget --account you@gmail.com
```

`--print-xoauth2` prints the base64 string for a manual `AUTHENTICATE XOAUTH2` check. Stored entries use the service
name `clawsmail-rust-spike`; the tests use `clawsmail-rust-spike-test` and clean up after themselves.
