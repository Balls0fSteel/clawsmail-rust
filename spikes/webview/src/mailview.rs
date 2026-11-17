//! The WebView2 mail view and its safety rules, through `webview2-com` (raw COM).
//!
//! Everything here runs on the UI thread (an STA). WebView2 calls the handlers back on that
//! thread through the normal message loop, so nothing blocks and nothing needs a lock; state is
//! kept in thread-locals. COM pointers are cloned out of the `RefCell` before calling into
//! WebView2, because WebView2 can re-enter the window procedure (and so this module) from
//! inside a call.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use webview2_com::Microsoft::Web::WebView2::Win32::*;
use webview2_com::*;
use windows::Win32::Foundation::{E_POINTER, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::System::Com::{IStream, STGM_CREATE, STGM_SHARE_EXCLUSIVE, STGM_WRITE};
use windows::Win32::UI::Shell::{SHCreateMemStream, SHCreateStreamOnFileEx};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetClassNameW, PostMessageW, WM_RBUTTONDOWN, WM_RBUTTONUP,
};
use windows::core::{BOOL, HSTRING, Interface, PWSTR, Result};

use crate::mail::{self, CID_ORIGIN, Message};
use crate::{Opts, log};

#[derive(Clone)]
struct Web {
    controller: ICoreWebView2Controller,
    webview: ICoreWebView2,
}

thread_local! {
    static WEB: RefCell<Option<Web>> = const { RefCell::new(None) };
    static MESSAGE: RefCell<Option<Message>> = const { RefCell::new(None) };
    /// Set just before `NavigateToString`; the next `NavigationStarting` is our own content.
    static ALLOW_NEXT_NAVIGATION: Cell<bool> = const { Cell::new(false) };
    /// Navigation id of our own content, so `NavigationCompleted` can tell it apart.
    static CONTENT_NAVIGATION: Cell<u64> = const { Cell::new(u64::MAX) };
    static PENDING_BOUNDS: Cell<Option<RECT>> = const { Cell::new(None) };
    pub static STATS: RefCell<Stats> = RefCell::new(Stats::default());
}

#[derive(Default, Debug)]
pub struct Stats {
    pub blocked: Vec<String>,
    pub cid_served: Vec<String>,
    pub navigations_cancelled: Vec<String>,
    pub new_windows_blocked: Vec<String>,
    pub context_menu_requests: u32,
    pub csp_reports: Vec<String>,
}

fn web() -> Option<Web> {
    WEB.with_borrow(|w| w.clone())
}

/// Folder for WebView2's profile: under %TEMP%, never the default `<exe>.WebView2` next to the exe.
pub fn user_data_folder() -> PathBuf {
    std::env::temp_dir().join("clawsmail-rust-spike").join("webview2")
}

/// Starts creating the environment and the controller. Returns at once; the rest happens in
/// completion handlers on this thread.
pub fn create(parent: HWND, opts: &'static Opts) -> Result<()> {
    let folder = user_data_folder();
    std::fs::create_dir_all(&folder).ok();
    log!("[webview] user data folder: {}", folder.display());

    let options = CoreWebView2EnvironmentOptions::default();
    // Tracking prevention is on by default in the options object; keep it, and keep browser
    // extensions off. Nothing else is needed at environment level.
    let options: ICoreWebView2EnvironmentOptions = options.into();

    let handler = CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(
        move |hr, env| {
            hr?;
            let env = env.ok_or_else(|| windows::core::Error::from(E_POINTER))?;
            on_environment(parent, env, opts)
        },
    ));
    unsafe {
        CreateCoreWebView2EnvironmentWithOptions(
            None,
            &HSTRING::from(folder.as_os_str()),
            &options,
            &handler,
        )
    }
}

fn on_environment(parent: HWND, env: ICoreWebView2Environment, opts: &'static Opts) -> Result<()> {
    let mut version = PWSTR::null();
    unsafe { env.BrowserVersionString(&mut version)? };
    log!("[webview] runtime version: {}", take_pwstr(version));

    let env2 = env.clone();
    let handler = CreateCoreWebView2ControllerCompletedHandler::create(Box::new(
        move |hr, controller| {
            hr?;
            let controller = controller.ok_or_else(|| windows::core::Error::from(E_POINTER))?;
            if let Err(e) = on_controller(env2, controller, opts) {
                log!("[webview] setup failed: {e:?}");
                return Err(e);
            }
            Ok(())
        },
    ));
    unsafe { env.CreateCoreWebView2Controller(parent, &handler) }
}

fn on_controller(
    env: ICoreWebView2Environment,
    controller: ICoreWebView2Controller,
    opts: &'static Opts,
) -> Result<()> {
    let webview = unsafe { controller.CoreWebView2()? };

    // ---- Safety point 1 and 6: settings. They apply from the next navigation on, so they are
    // set before the first NavigateToString.
    unsafe {
        let s = webview.Settings()?;
        s.SetIsScriptEnabled(opts.allow_scripts)?;
        s.SetAreDefaultContextMenusEnabled(opts.allow_menus)?;
        s.SetAreDevToolsEnabled(false)?;
        s.SetIsWebMessageEnabled(false)?;
        s.SetAreDefaultScriptDialogsEnabled(false)?;
        s.SetIsStatusBarEnabled(false)?;
        if let Ok(s3) = s.cast::<ICoreWebView2Settings3>() {
            // Also blocks F12 / Ctrl+Shift+I, reload (F5) and find; the real app maps the
            // keys it wants (print, find) itself.
            s3.SetAreBrowserAcceleratorKeysEnabled(false)?;
        }
        if let Ok(s4) = s.cast::<ICoreWebView2Settings4>() {
            s4.SetIsPasswordAutosaveEnabled(false)?;
            s4.SetIsGeneralAutofillEnabled(false)?;
        }
        if let Ok(s8) = s.cast::<ICoreWebView2Settings8>() {
            // SmartScreen would send visited URLs to Microsoft; we never navigate anyway.
            s8.SetIsReputationCheckingRequired(false)?;
        }

        let (mut script, mut menus, mut devtools) = (BOOL(1), BOOL(1), BOOL(1));
        s.IsScriptEnabled(&mut script)?;
        s.AreDefaultContextMenusEnabled(&mut menus)?;
        s.AreDevToolsEnabled(&mut devtools)?;
        log!(
            "[settings] IsScriptEnabled={} AreDefaultContextMenusEnabled={} AreDevToolsEnabled={}",
            script.as_bool(),
            menus.as_bool(),
            devtools.as_bool()
        );
    }

    // ---- Safety point 2 and 3: every request goes through WebResourceRequested.
    unsafe {
        match webview.cast::<ICoreWebView2_22>() {
            Ok(wv22) => {
                // Covers documents, shared workers and service workers, not only the page.
                wv22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                    &HSTRING::from("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
                )?;
                log!("[webview] request filter: '*' all contexts, all source kinds (ICoreWebView2_22)");
            }
            Err(_) => {
                webview.AddWebResourceRequestedFilter(
                    &HSTRING::from("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                )?;
                log!("[webview] request filter: '*' all contexts (ICoreWebView2)");
            }
        }
        let env_for_responses = env.clone();
        let mut token = 0i64;
        webview.add_WebResourceRequested(
            &WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else { return Ok(()) };
                on_resource_request(&env_for_responses, &args)
            })),
            &mut token,
        )?;
    }

    // ---- Safety point 4: navigation away is cancelled, in the page and in frames;
    // target=_blank and window.open go through NewWindowRequested.
    unsafe {
        let mut token = 0i64;
        webview.add_NavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(|_sender, args| {
                let Some(args) = args else { return Ok(()) };
                let mut uri = PWSTR::null();
                args.Uri(&mut uri)?;
                let uri = take_pwstr(uri);
                let mut id = 0u64;
                args.NavigationId(&mut id)?;
                if ALLOW_NEXT_NAVIGATION.replace(false) {
                    CONTENT_NAVIGATION.set(id);
                    log!("[nav] allowed own content (id {id}): {}", shorten(&uri, 60));
                } else {
                    args.SetCancel(true)?;
                    let mut user = BOOL(0);
                    args.IsUserInitiated(&mut user)?;
                    log!(
                        "[nav] CANCELLED (id {id}, user_initiated={}): {uri} -> would open in the system browser",
                        user.as_bool()
                    );
                    STATS.with_borrow_mut(|s| s.navigations_cancelled.push(uri));
                }
                Ok(())
            })),
            &mut token,
        )?;
        webview.add_FrameNavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(|_sender, args| {
                let Some(args) = args else { return Ok(()) };
                let mut uri = PWSTR::null();
                args.Uri(&mut uri)?;
                let uri = take_pwstr(uri);
                args.SetCancel(true)?;
                log!("[nav] CANCELLED frame navigation: {uri}");
                STATS.with_borrow_mut(|s| s.navigations_cancelled.push(format!("frame:{uri}")));
                Ok(())
            })),
            &mut token,
        )?;
        webview.add_NewWindowRequested(
            &NewWindowRequestedEventHandler::create(Box::new(|_sender, args| {
                let Some(args) = args else { return Ok(()) };
                let mut uri = PWSTR::null();
                args.Uri(&mut uri)?;
                let uri = take_pwstr(uri);
                // Handled without setting NewWindow: no window opens.
                args.SetHandled(true)?;
                log!("[nav] BLOCKED new window: {uri} -> would open in the system browser");
                STATS.with_borrow_mut(|s| s.new_windows_blocked.push(uri));
                Ok(())
            })),
            &mut token,
        )?;
        webview.add_NavigationCompleted(
            &NavigationCompletedEventHandler::create(Box::new(|sender, args| {
                let (Some(sender), Some(args)) = (sender, args) else { return Ok(()) };
                let mut id = 0u64;
                args.NavigationId(&mut id)?;
                let mut ok = BOOL(0);
                args.IsSuccess(&mut ok)?;
                let mut status = COREWEBVIEW2_WEB_ERROR_STATUS::default();
                args.WebErrorStatus(&mut status)?;
                if id == CONTENT_NAVIGATION.get() {
                    let mut title = PWSTR::null();
                    sender.DocumentTitle(&mut title)?;
                    log!(
                        "[nav] content loaded (id {id}, success={}); DocumentTitle read natively = {:?}",
                        ok.as_bool(),
                        take_pwstr(title)
                    );
                    crate::on_content_loaded();
                } else {
                    log!(
                        "[nav] completed (id {id}) success={} status={}",
                        ok.as_bool(),
                        status.0
                    );
                }
                Ok(())
            })),
            &mut token,
        )?;
        if let Ok(wv11) = webview.cast::<ICoreWebView2_11>() {
            wv11.add_ContextMenuRequested(
                &ContextMenuRequestedEventHandler::create(Box::new(|_sender, _args| {
                    STATS.with_borrow_mut(|s| s.context_menu_requests += 1);
                    log!("[menu] ContextMenuRequested fired (the right click reached the page)");
                    Ok(())
                })),
                &mut token,
            )?;
        }
    }

    // Console messages (CSP violations show up here) through the DevTools protocol. This works
    // with the DevTools UI disabled: only the host can call it.
    unsafe {
        let receiver = webview.GetDevToolsProtocolEventReceiver(&HSTRING::from("Log.entryAdded"))?;
        let mut token = 0i64;
        receiver.add_DevToolsProtocolEventReceived(
            &DevToolsProtocolEventReceivedEventHandler::create(Box::new(|_sender, args| {
                let Some(args) = args else { return Ok(()) };
                let mut json = PWSTR::null();
                args.ParameterObjectAsJson(&mut json)?;
                let json = take_pwstr(json);
                log!("[console] {}", shorten(&json, 400));
                if json.contains("Content Security Policy") {
                    STATS.with_borrow_mut(|s| s.csp_reports.push(json));
                }
                Ok(())
            })),
            &mut token,
        )?;
        webview.CallDevToolsProtocolMethod(
            &HSTRING::from("Log.enable"),
            &HSTRING::from("{}"),
            &CallDevToolsProtocolMethodCompletedHandler::create(Box::new(|hr, _json| {
                log!("[console] Log.enable -> {:?}", hr.map(|_| "ok"));
                Ok(())
            })),
        )?;
    }

    unsafe {
        controller.SetIsVisible(true)?;
    }
    WEB.with_borrow_mut(|w| {
        *w = Some(Web {
            controller: controller.clone(),
            webview: webview.clone(),
        })
    });
    if let Some(rect) = PENDING_BOUNDS.take() {
        set_bounds(rect);
    }

    // ---- Safety point 5: content via NavigateToString, with the CSP meta tag first in <head>.
    let msg = mail::sample();
    let policy = mail::csp(opts.allow_scripts);
    let csp = (!opts.no_csp).then_some(policy.as_str());
    match csp {
        Some(p) => log!("[csp] {p}"),
        None => log!("[csp] DISABLED for this run (--no-csp): only the request handler protects"),
    }
    let html = mail::document(&msg, csp);
    MESSAGE.with_borrow_mut(|m| *m = Some(msg));
    ALLOW_NEXT_NAVIGATION.set(true);
    unsafe { webview.NavigateToString(&HSTRING::from(html.as_str())) }
}

fn on_resource_request(
    env: &ICoreWebView2Environment,
    args: &ICoreWebView2WebResourceRequestedEventArgs,
) -> Result<()> {
    unsafe {
        let request = args.Request()?;
        let mut uri = PWSTR::null();
        request.Uri(&mut uri)?;
        let uri = take_pwstr(uri);

        if let Some(id) = uri.strip_prefix(CID_ORIGIN) {
            let id = percent_decode(id);
            let part = MESSAGE.with_borrow(|m| {
                m.as_ref()
                    .and_then(|m| m.part(&id))
                    .map(|p| (p.mime, p.data))
            });
            let response = match part {
                Some((mime, data)) => {
                    let stream: IStream = SHCreateMemStream(Some(data))
                        .ok_or_else(|| windows::core::Error::from(E_POINTER))?;
                    log!("[cid] served {uri} ({mime}, {} bytes) from the message's own parts", data.len());
                    STATS.with_borrow_mut(|s| s.cid_served.push(uri.clone()));
                    let headers = format!("Content-Type: {mime}\r\nCache-Control: no-store");
                    env.CreateWebResourceResponse(&stream, 200, &HSTRING::from("OK"), &HSTRING::from(headers))?
                }
                None => {
                    log!("[cid] not found in message: {uri}");
                    env.CreateWebResourceResponse(None, 404, &HSTRING::from("Not Found"), &HSTRING::new())?
                }
            };
            return args.SetResponse(&response);
        }

        // Everything else (http, https, ws, ...) is blocked: remote content is off by default.
        log!("[blocked] {uri}");
        STATS.with_borrow_mut(|s| s.blocked.push(uri));
        let response =
            env.CreateWebResourceResponse(None, 403, &HSTRING::from("Blocked"), &HSTRING::new())?;
        args.SetResponse(&response)
    }
}

/// Positions the view in client coordinates of the parent window.
pub fn set_bounds(rect: RECT) {
    match web() {
        Some(w) => unsafe {
            let _ = w.controller.SetBounds(rect);
        },
        None => PENDING_BOUNDS.set(Some(rect)),
    }
}

/// The controller's current bounds, read back from WebView2.
pub fn bounds() -> Option<RECT> {
    let w = web()?;
    let mut r = RECT::default();
    unsafe { w.controller.Bounds(&mut r).ok()? };
    Some(r)
}

/// Tells WebView2 the top-level window moved (keeps popups and IME in the right place).
pub fn notify_moved() {
    if let Some(w) = web() {
        unsafe {
            let _ = w.controller.NotifyParentWindowPositionChanged();
        }
    }
}

/// Closes the controller before the parent window goes away.
pub fn close() {
    if let Some(w) = WEB.with_borrow_mut(|w| w.take()) {
        unsafe {
            let _ = w.controller.Close();
        }
    }
}

/// Runs host script (works with IsScriptEnabled = false) and logs what the page looks like.
pub fn probe(label: &'static str) {
    let Some(w) = web() else { return };
    const JS: &str = r#"(() => {
        const im = id => { const e = document.getElementById(id); return e ? e.naturalWidth + "x" + e.naturalHeight : "none"; };
        return "title=" + document.title
            + " | probe=" + document.getElementById("script-probe").textContent
            + " | bodyBg=" + getComputedStyle(document.body).backgroundColor
            + " | cid-img=" + im("cid-img")
            + " | tracker=" + im("tracker")
            + " | location=" + location.href.slice(0, 40);
    })()"#;
    let handler = ExecuteScriptCompletedHandler::create(Box::new(move |hr, json| {
        match hr {
            Ok(()) => {
                let text = json.trim_matches('"').to_string();
                log!("[probe:{label}] {text}");
                let ran = text.contains("SCRIPT RAN");
                let cid_ok = text.contains("cid-img=192x48");
                let tracker_ok = text.contains("tracker=0x0");
                log!(
                    "[probe:{label}] verdict: page script ran = {ran}; cid image rendered = {cid_ok}; tracker loaded = {}",
                    !tracker_ok
                );
            }
            Err(e) => log!("[probe:{label}] ExecuteScript failed: {e:?}"),
        }
        Ok(())
    }));
    unsafe {
        let _ = w.webview.ExecuteScript(&HSTRING::from(JS), &handler);
    }
}

/// Clicks both links from host script, as a user would (nobody can click on the hidden desktop).
pub fn click_links() {
    let Some(w) = web() else { return };
    log!("[nav] host script clicks #away and #blank");
    let js = r#"document.getElementById("away").click(); document.getElementById("blank").click(); "clicked""#;
    let handler = ExecuteScriptCompletedHandler::create(Box::new(|_hr, _json| Ok(())));
    unsafe {
        let _ = w.webview.ExecuteScript(&HSTRING::from(js), &handler);
    }
}

/// Posts a right click to the page's render widget window. Posted (not SendInput), so it only
/// reaches that hidden window and never the user's real mouse.
pub fn right_click(parent: HWND, x: i32, y: i32) {
    struct Found(Vec<(HWND, String)>);
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let found = unsafe { &mut *(lparam.0 as *mut Found) };
        let mut buf = [0u16; 128];
        let n = unsafe { GetClassNameW(hwnd, &mut buf) } as usize;
        found.0.push((hwnd, String::from_utf16_lossy(&buf[..n])));
        BOOL(1)
    }
    let mut found = Found(Vec::new());
    unsafe {
        let _ = EnumChildWindows(Some(parent), Some(each), LPARAM(&mut found as *mut _ as isize));
    }
    let classes: Vec<&str> = found.0.iter().map(|(_, c)| c.as_str()).collect();
    log!("[menu] child windows: {classes:?}");
    let target = found
        .0
        .iter()
        .find(|(_, c)| c == "Chrome_RenderWidgetHostHWND")
        .map(|(h, _)| *h);
    match target {
        Some(h) => unsafe {
            let pos = LPARAM(((y as isize) << 16) | (x as isize & 0xffff));
            let _ = PostMessageW(Some(h), WM_RBUTTONDOWN, WPARAM(0x0002), pos);
            let _ = PostMessageW(Some(h), WM_RBUTTONUP, WPARAM(0), pos);
            log!("[menu] posted a right click at ({x},{y}) to Chrome_RenderWidgetHostHWND");
        },
        None => log!("[menu] no Chrome_RenderWidgetHostHWND child found (visual hosting?)"),
    }
}

/// Writes the rendered view to a PNG with `CapturePreview`. `done` runs when the file is closed.
pub fn capture(path: &Path, done: impl FnOnce(bool) + 'static) -> Result<()> {
    let Some(w) = web() else {
        done(false);
        return Ok(());
    };
    let stream: IStream = unsafe {
        SHCreateStreamOnFileEx(
            &HSTRING::from(path.as_os_str()),
            (STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE).0,
            FILE_ATTRIBUTE_NORMAL.0,
            true,
            None,
        )?
    };
    let path = path.to_path_buf();
    let keep = stream.clone();
    let handler = CapturePreviewCompletedHandler::create(Box::new(move |hr| {
        drop(keep); // closes the file
        match hr {
            Ok(()) => log!("[capture] CapturePreview wrote {}", path.display()),
            Err(ref e) => log!("[capture] CapturePreview failed: {e:?}"),
        }
        done(hr.is_ok());
        Ok(())
    }));
    unsafe {
        w.webview
            .CapturePreview(COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG, &stream, &handler)
    }
}

fn take_pwstr(p: PWSTR) -> String {
    webview2_com::take_pwstr(p)
}

fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        if bytes[i] == b'%'
            && let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decode() {
        assert_eq!(super::percent_decode("logo%40clawsmail"), "logo@clawsmail");
        assert_eq!(super::percent_decode("%é%4"), "%é%4");
    }
}
