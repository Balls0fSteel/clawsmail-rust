# Plan

## Current work

### M0: bootstrap and spikes (2026-11-17_210213_1794945733)

- [x] Repository, workspace, GPL-3.0 licence, toolchain pin, CI, `cm-core` cache policy
- [x] Spike A (`spikes/imap`): **async-imap 0.12** chosen, with our own raw-command layer. See
      `spikes/imap/FINDINGS.md`.
- [x] Spike B (`spikes/webview`): Win32 with `windows` 0.62 plus WebView2 through `webview2-com` 0.39 works. All 7
      safety rules hold; the exe is 331 KiB. See `spikes/webview/FINDINGS.md`.
- [x] Spike C (`spikes/oauth`): hand-written PKCE loopback flow on reqwest 0.13; Credential Manager with a DPAPI
      fallback. See `spikes/oauth/FINDINGS.md` and `docs/oauth-setup.md`.
- [ ] **User step:** register the Google and Entra apps (`docs/oauth-setup.md`), then run `oauth-spike login` for
      both providers to settle the open questions below.

## Next

### M1: headless core

- Crates: `cm-auth`, `cm-imap`, `cm-smtp`, `cm-mime`, `cm-store`, `cm-html`, `cm-engine` and `cm-cli`.
- The CLI can add a password or OAuth account, list folders, sync headers in Full and Remote modes, show a message,
  save one attachment (fetching only that part), send mail and resume after a reconnect.
- Tests: a MIME corpus, cache-policy eviction, and sync against the fake server.
- `cm-imap`: async-imap 0.12, pinned. Move `spikes/imap/fake-imap` into the workspace as test support.
  - Drain the unsolicited channel after every command. It holds only 100 entries and drops the rest silently.
  - Send resync commands (VANISHED) and body-part fetches through the raw path. Typed fetches swallow a tagged NO.
  - Wrap every command in a timeout, and drop the connection when it fires. IDLE gets its own connection.
  - Gmail has no QRESYNC: use the UID-diff resync from the spike's findings, with X-GM-MSGID as a stable key.
  - Plan for async-imap's next breaking release (`Error::No`/`Error::Bad`). Re-evaluate `io-imap` at the end of M1.
- `cm-auth`, from the OAuth spike:
  - Save a rotated refresh token before using the new access token.
  - One refresh at a time per account.
  - A process-wide lock around Credential Manager calls; consider a named mutex across processes.
- Account presets: Outlook.com SMTP is `smtp-mail.outlook.com:587`; Microsoft 365 is `smtp.office365.com:587`.
- `cm-html`: the sanitiser must drop `<meta http-equiv>`. Serve mail over about 2 MB through the request handler
  instead of `NavigateToString`.

### M2: Windows shell for reading

- Three panes: folder tree, virtual message list with sorting and threads, and the message view.
- An attachment strip and an account wizard with provider presets and the global cache mode.
- IDLE notifications. Sound volume defaults to 5–10%.

### M3: actions and compose

- Flags, move/copy/delete and drag and drop.
- Plain-text compose: reply, reply all and forward; signatures and identities.
- Attachments, drafts and an offline outbox.

### M4: everyday completeness

- Search, Claws-style filters, and an address book with autocomplete.
- A UI for per-folder cache settings.
- Preferences, dark mode, shortcuts, `.eml`/mbox import and export, printing.

### Later

- HTML compose, PGP and S/MIME, POP3.
- Importing a Claws Mail profile, CardDAV.
- AppKit and GTK4 shells, an MSI or winget package.

## Architecture

- **UI boundary:** UI shells talk only to `cm-engine`, sending `Command`s and receiving `Event`s. On Windows the UI
  thread is woken by `PostMessage(WM_APP)` and never blocks.
- **Cache policy:** resolved folder → account → global (`cm-core::CachePolicy`). Every read of a body or part goes
  through one `MailStore` interface that fetches on demand.
- **Storage:** configuration in `%APPDATA%\clawsmail-rust`, index and cache in `%LOCALAPPDATA%\clawsmail-rust`;
  `--portable` keeps both next to the executable.
- **HTML safety:** ammonia sanitising, a strict CSP, no scripts, remote content blocked until allowed, links open in
  the system browser, and `cid:` images served from the message's own parts.
- **OAuth:** client IDs go into release builds through `CM_GOOGLE_CLIENT_ID` / `CM_MS_CLIENT_ID` and are never
  committed. Each account can override them.

## Open questions

- Google: refresh tokens expire after 7 days while the Cloud app is in Testing status, and `https://mail.google.com/`
  is a restricted scope, which needs verification before production use. Public builds may need "bring your own
  client ID".
- Google: do Desktop clients really need `client_secret` at the token endpoint?
- Microsoft: does a runtime `127.0.0.1` redirect match a registered `http://localhost`?
- Microsoft: personal accounts may hit `invalid_scope`, or have SMTP AUTH refused. The fallback is Graph `sendMail`,
  which needs a separate token.
- WebView2 at high DPI (`WM_DPICHANGED`) is untested: the hidden desktop runs at 96 DPI.

## Known TODOs

- Release builds: consider `+crt-static` so the exe does not need `VCRUNTIME140.dll`.
- The real app uses `windows_subsystem = "windows"` and logs to a file.
