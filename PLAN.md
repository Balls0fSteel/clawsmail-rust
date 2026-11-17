# Plan

## Current work

### M0: bootstrap and spikes (2026-11-17_210213_1794945733)

- [x] Repository, workspace, GPL-3.0 licence, toolchain pin, CI, `cm-core` cache policy
- [ ] Spike A (`spikes/imap`): choose an IMAP library. Requirements: XOAUTH2 (SASL-IR), IDLE, BODYSTRUCTURE,
      `UID FETCH BODY.PEEK[section]`, CONDSTORE/QRESYNC, UIDPLUS, MOVE and Gmail X-GM extensions.
      Tested against a scripted fake server.
- [ ] Spike B (`spikes/webview`): a Win32 window with a TreeView, a virtual ListView and a WebView2 child.
      It must show `cid:` images, block remote images and keep scripts off.
- [ ] Spike C (`spikes/oauth`): auth code with PKCE and a loopback redirect for Google and Microsoft; tokens in
      Credential Manager, with a DPAPI-encrypted file as fallback; `docs/oauth-setup.md`.

## Next

### M1: headless core

- Crates: `cm-auth`, `cm-imap`, `cm-smtp`, `cm-mime`, `cm-store`, `cm-html`, `cm-engine` and `cm-cli`.
- The CLI can add a password or OAuth account, list folders, sync headers in Full and Remote modes, show a message,
  save one attachment (fetching only that part), send mail and resume after a reconnect.
- Tests: a MIME corpus, cache-policy eviction, and sync against the fake server.

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

- Does WebView2 paint on the hidden desktop that `run_hidden.ps1` uses? If not, capture it with `CapturePreview`.
- Google: refresh tokens expire after 7 days while the Cloud app is in Testing status. Find out what moving the app to
  production needs for the restricted `https://mail.google.com/` scope.
- Microsoft: some new personal Outlook.com mailboxes reportedly refuse SMTP AUTH even with OAuth. A fallback would
  be sending through Graph `sendMail`.

## Known TODOs

- (none yet)
