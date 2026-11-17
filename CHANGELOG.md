# Changelog

Design decisions, problems and their fixes. Routine changes are in the Git history.

## 2026-11-17_213839_1794947919: M0 spike results

- **IMAP: async-imap 0.12.** Every requirement works natively or through small workarounds in our own layer: SASL-IR
  through the mechanism string, a raw-command path, APPENDUID/COPYUID, and a BODYSTRUCTURE converter. It is the only
  candidate that handles Gmail X-GM-* natively.
  - `imap-client` was rejected: it was archived on 2026-05-17, cannot express X-GM items, and silently drops FETCH
    lines that contain unknown items.
  - Its successor `io-imap` is promising, but it is six months old and has had five breaking releases in six weeks.
  - Problems found in async-imap: typed fetches swallow a tagged NO, and the unsolicited channel (bounded at 100)
    drops the overflow silently, VANISHED included.
  - imap-proto's own BODYSTRUCTURE part numbering is wrong for siblings, so we use our own converter.
- **Windows shell: `windows` 0.62.2 + `webview2-com` 0.39.1 (raw COM); `wry` not needed.** The release exe is
  331 KiB; the WebView2 loader is linked statically.
  - Safety: scripts off, a strict CSP plus a `WebResourceRequested` 403 backstop, `cid:` served from
    `https://cid.invalid/`, every navigation away cancelled, menus and devtools off.
  - WebView2 paints on run_hidden's hidden desktop, so GUI tests can use screenshots.
  - Idle memory: about 6 MB private for the shell and about 163 MB including WebView2's processes.
  - Pitfall: `IsUserInitiated` is true for `<meta refresh>`, so it cannot decide whether to open the system browser.
- **OAuth: hand-written PKCE loopback client on reqwest 0.13 (rustls), instead of `oauth2` 5.0** (which pulls in
  reqwest 0.12 and a second TLS stack).
  - Tokens are stored in Credential Manager through `keyring-core` + `windows-native-keyring-store`, using
    `set_secret`, with a 2560-byte limit. The crate's `set_password` would cap tokens at 1280 characters.
  - Above the limit, or if the keyring fails, tokens go to a DPAPI-encrypted file.
  - Problem: concurrent Credential Manager calls on *different* entries sometimes lost a delete, and the test
    entries came back. Fixed with a process-wide lock; 25 parallel runs since have left nothing behind.
- **Corrections to earlier assumptions:**
  - Outlook.com SMTP is `smtp-mail.outlook.com`.
  - Microsoft no longer documents a 90-day refresh-token lifetime.
  - The Entra portal cannot register an `http://127.0.0.1` redirect, so the redirect is `http://localhost`.

## 2026-11-17_210213_1794945733: project start

- **Licence:** GPL-3.0-or-later, the same as upstream Claws Mail, so its code and logic can be translated.
- **UI:** a shared Rust core with a thin native shell per OS: Win32 via `windows-rs` first, AppKit and GTK4 later.
  This was chosen over a single cross-platform toolkit to keep the look native and the program lean.
- **HTML mail:** rendered in the system webview: WebView2 on Windows (already part of Windows 11, so it adds
  nothing to our binary), WKWebView on macOS, WebKitGTK on Linux.
- **OAuth apps:** registered by the maintainer. Client IDs are passed into builds through environment variables,
  because the repository is public.
- **Cache policy:** in `cm-core` from day one. A folder setting overrides the account setting, which overrides the
  global one, field by field. The default is Remote mode with a 200 MiB body cache. Remote-only storage has to live in
  the storage layer and cannot be added on afterwards.
- **Spikes:** live in `spikes/`, each as a standalone Cargo workspace excluded from the main one, so experiments never
  touch the main `Cargo.lock`.
