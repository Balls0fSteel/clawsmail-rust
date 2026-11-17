# clawsmail-rust

A lean desktop mail client in Rust, modelled on [Claws Mail](https://www.claws-mail.org/)
(upstream source: <https://github.com/eworm-de/claws-mail>). Windows comes first; macOS and Linux follow.

Status: early bootstrap. Nothing usable yet.

## Goals

- Native UI on each OS: Win32 on Windows, AppKit on macOS and GTK4 on Linux, all on top of one shared Rust core.
- IMAP and SMTP, with OAuth2 sign-in for Gmail and Microsoft accounts and passwords for other servers.
- Remote-only mode: keep only headers locally and fetch bodies and attachments on demand. It can be set globally, per account or per folder.
- Safe HTML mail rendering in the system webview: no scripts, and remote content stays blocked until you allow it.
- Attachments, threading, filters, an address book and the rest of the usual mail features.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/cm-core` | Domain types and the cache policy |
| `apps/` | Native UI shells (coming) |
| `spikes/` | Throwaway experiments that inform library choices |

See `PLAN.md` for the roadmap and `CHANGELOG.md` for design decisions.

## Building

```
cargo build --workspace
cargo test --workspace
```

The toolchain is pinned in `rust-toolchain.toml`.

## Licence

GPL-3.0-or-later, the same as Claws Mail. See `LICENSE`.
