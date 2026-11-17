# Changelog

Design decisions, problems and their fixes. Routine changes are in the Git history.

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
