//! Spike B: a Claws-Mail-style Win32 window built from native common controls (windows-rs),
//! with a folder TreeView, a virtual ListView of 100,000 rows and a locked-down WebView2 view.
//!
//! Options:
//!   --exit-after <s>   close the window after this many seconds
//!   --capture <png>    write the WebView's rendering with CapturePreview after the probes
//!   --scroll-to <row>  select and show this row of the message list
//!   --rows <n>         number of fake rows (default 100000)
//!   --allow-scripts    positive control: scripts on and allowed by the CSP
//!   --no-csp           leave out the CSP meta tag, so only the request handler blocks
//!   --allow-menus      positive control: default context menus on, to check the right-click probe
//!   --resize <w>x<h>   resize the window (in DIP) 1 s after the mail loaded, then check the layout
//!   --log <file>       also write the stdout lines to this file (run_hidden shares the console)
//!
//! Console subsystem on purpose: the spike reports what it observed on stdout.

mod mail;
mod mailview;
mod rows;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    COLOR_WINDOW, CreateFontIndirectW, DeleteObject, HBRUSH, HFONT, HGDIOBJ, UpdateWindow,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow,
    GetThreadDpiAwarenessContext, SystemParametersInfoForDpi,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, PWSTR, Result, w};

pub struct Opts {
    pub exit_after: Option<f64>,
    pub capture: Option<PathBuf>,
    pub scroll_to: Option<usize>,
    pub rows: usize,
    pub allow_scripts: bool,
    pub no_csp: bool,
    pub allow_menus: bool,
    pub resize: Option<(i32, i32)>,
}

static OPTS: OnceLock<Opts> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

/// Timestamped stdout line.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let line = format!("{:>7.3}s {}", $crate::elapsed(), format_args!($($arg)*));
        $crate::emit(&line);
    }};
}

static LOG_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

pub fn emit(line: &str) {
    use std::io::Write;
    println!("{line}");
    if let Ok(mut f) = LOG_FILE.lock()
        && let Some(f) = f.as_mut()
    {
        let _ = writeln!(f, "{line}");
    }
}

pub fn elapsed() -> f64 {
    START.get().map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0)
}

const ID_TREE: usize = 100;
const ID_LIST: usize = 101;

const TIMER_EXIT: usize = 1;
const TIMER_LIST_BENCH: usize = 2;
const TIMER_CLICK_LINKS: usize = 3;
const TIMER_PROBE_AGAIN: usize = 4;
const TIMER_CAPTURE: usize = 5;
const TIMER_RIGHT_CLICK: usize = 6;
const TIMER_RESIZE: usize = 7;

#[derive(Default)]
struct Ui {
    main: HWND,
    tree: HWND,
    list: HWND,
    font: HFONT,
    dpi: u32,
}

thread_local! {
    static UI: RefCell<Ui> = RefCell::new(Ui::default());
    static DISPINFO_CALLS: Cell<u64> = const { Cell::new(0) };
    static EXIT_REQUESTED: Cell<bool> = const { Cell::new(false) };
    static CAPTURE_PENDING: Cell<bool> = const { Cell::new(false) };
}

/// Copies the handles out, so no borrow is held while messages are sent.
fn ui() -> (HWND, HWND, HWND, u32) {
    UI.with_borrow(|u| (u.main, u.tree, u.list, u.dpi))
}

fn opts() -> &'static Opts {
    OPTS.get().expect("options parsed")
}

fn scale(v: i32, dpi: u32) -> i32 {
    (v as i64 * dpi as i64 / 96) as i32
}

fn parse_args() -> Opts {
    let mut o = Opts {
        exit_after: None,
        capture: None,
        scroll_to: None,
        rows: 100_000,
        allow_scripts: false,
        no_csp: false,
        allow_menus: false,
        resize: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--exit-after" => o.exit_after = args.next().and_then(|v| v.parse().ok()),
            "--capture" => o.capture = args.next().map(PathBuf::from),
            "--scroll-to" => o.scroll_to = args.next().and_then(|v| v.parse().ok()),
            "--rows" => o.rows = args.next().and_then(|v| v.parse().ok()).unwrap_or(o.rows),
            "--allow-scripts" => o.allow_scripts = true,
            "--no-csp" => o.no_csp = true,
            "--allow-menus" => o.allow_menus = true,
            "--resize" => {
                o.resize = args.next().and_then(|v| {
                    let (w, h) = v.split_once('x')?;
                    Some((w.parse().ok()?, h.parse().ok()?))
                })
            }
            "--log" => {
                if let Some(path) = args.next()
                    && let Ok(f) = std::fs::File::create(path)
                    && let Ok(mut slot) = LOG_FILE.lock()
                {
                    *slot = Some(f);
                }
            }
            other => eprintln!("unknown argument: {other}"),
        }
    }
    o
}

fn main() -> Result<()> {
    START.get_or_init(Instant::now);
    OPTS.get_or_init(parse_args);
    let o = opts();

    unsafe {
        // WebView2 requires a single-threaded apartment on the UI thread.
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;

        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);
    }
    report_environment();

    let instance: HINSTANCE = unsafe { GetModuleHandleW(None)?.into() };
    let class = w!("ClawsMailRustSpikeMain");
    unsafe {
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as usize as *mut _),
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("Claws Mail Rust - WebView2 spike"),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1280,
            800,
            None,
            None,
            Some(instance),
            None,
        )?;

        // Size the window for its monitor's DPI (CreateWindow sizes are in physical pixels).
        let dpi = GetDpiForWindow(hwnd);
        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            scale(1280, dpi),
            scale(800, dpi),
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = UpdateWindow(hwnd);
        log!("[dpi] GetDpiForWindow = {dpi} (scale {}%)", dpi * 100 / 96);

        if let Some(s) = o.exit_after {
            SetTimer(Some(hwnd), TIMER_EXIT, (s * 1000.0) as u32, None);
        }
        SetTimer(Some(hwnd), TIMER_LIST_BENCH, 300, None);

        if let Err(e) = mailview::create(hwnd, o) {
            log!("[webview] could not start WebView2: {e:?}");
        }

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    summary();
    Ok(())
}

fn report_environment() {
    unsafe {
        let ctx = GetThreadDpiAwarenessContext();
        let v2 = AreDpiAwarenessContextsEqual(ctx, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
            .as_bool();
        log!("[dpi] thread awareness context is Per-Monitor-V2: {v2} (from the manifest)");

        // Which comctl32 got loaded: the WinSxS v6 copy means the manifest dependency worked.
        if let Ok(m) = GetModuleHandleW(w!("comctl32.dll")) {
            let mut buf = [0u16; 512];
            let n = GetModuleFileNameW(Some(m), &mut buf) as usize;
            let path = String::from_utf16_lossy(&buf[..n]);
            let v6 = path.to_ascii_lowercase().contains("common-controls_6595b64144ccf1df_6.");
            log!("[comctl] {path} (v6 visual styles: {v6})");
        }
    }
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf()));
    if let Some(dir) = exe_dir {
        log!("[webview] default folder next to exe present at start: {}", has_webview2_dir(&dir));
    }
}

fn has_webview2_dir(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".WebView2"))
        })
        .unwrap_or(false)
}

fn summary() {
    mailview::STATS.with_borrow(|s| {
        log!("==== summary ====");
        log!("blocked requests ({}): {:?}", s.blocked.len(), s.blocked);
        log!("cid parts served ({}): {:?}", s.cid_served.len(), s.cid_served);
        log!(
            "navigations cancelled ({}): {:?}",
            s.navigations_cancelled.len(),
            s.navigations_cancelled
        );
        log!(
            "new windows blocked ({}): {:?}",
            s.new_windows_blocked.len(),
            s.new_windows_blocked
        );
        log!("CSP console reports: {}", s.csp_reports.len());
        log!("ContextMenuRequested events: {}", s.context_menu_requests);
    });
    log!("LVN_GETDISPINFO calls in total: {}", DISPINFO_CALLS.get());
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())) {
        log!("default '<exe>.WebView2' folder next to exe present at exit: {}", has_webview2_dir(&dir));
    }
    log!(
        "user data folder exists in temp: {}",
        mailview::user_data_folder().exists()
    );
}

/// Called by the mail view when our own content finished loading.
pub fn on_content_loaded() {
    let (main, ..) = ui();
    mailview::probe("loaded");
    unsafe {
        SetTimer(Some(main), TIMER_RIGHT_CLICK, 1500, None);
        if opts().resize.is_some() {
            SetTimer(Some(main), TIMER_RESIZE, 1000, None);
        }
        // The mail's meta refresh fires at 2 s; the host clicks the links at 3 s.
        SetTimer(Some(main), TIMER_CLICK_LINKS, 3000, None);
        SetTimer(Some(main), TIMER_PROBE_AGAIN, 4000, None);
        if opts().capture.is_some() {
            CAPTURE_PENDING.set(true);
            SetTimer(Some(main), TIMER_CAPTURE, 4500, None);
        }
    }
}

fn message_font(dpi: u32) -> HFONT {
    unsafe {
        let mut ncm = NONCLIENTMETRICSW {
            cbSize: size_of::<NONCLIENTMETRICSW>() as u32,
            ..Default::default()
        };
        let _ = SystemParametersInfoForDpi(
            SPI_GETNONCLIENTMETRICS.0,
            ncm.cbSize,
            Some(&mut ncm as *mut _ as *mut _),
            0,
            dpi,
        );
        CreateFontIndirectW(&ncm.lfMessageFont)
    }
}

fn apply_font(dpi: u32) {
    let font = message_font(dpi);
    let old = UI.with_borrow_mut(|u| {
        u.dpi = dpi;
        std::mem::replace(&mut u.font, font)
    });
    let (_, tree, list, _) = ui();
    unsafe {
        for h in [tree, list] {
            SendMessageW(h, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
        }
        for (i, (_, width)) in rows::COLUMNS.iter().enumerate() {
            SendMessageW(
                list,
                LVM_SETCOLUMNWIDTH,
                Some(WPARAM(i)),
                Some(LPARAM(scale(*width, dpi) as isize)),
            );
        }
        if !old.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(old.0));
        }
    }
}

fn create_children(hwnd: HWND) -> Result<()> {
    let instance: HINSTANCE = unsafe { GetModuleHandleW(None)?.into() };
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    unsafe {
        let tree = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_TREEVIEWW,
            PCWSTR::null(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(
                    TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT,
                ),
            0,
            0,
            0,
            0,
            Some(hwnd),
            Some(HMENU(ID_TREE as *mut _)),
            Some(instance),
            None,
        )?;
        let _ = SetWindowTheme(tree, w!("Explorer"), PCWSTR::null());

        let list = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            PCWSTR::null(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS),
            0,
            0,
            0,
            0,
            Some(hwnd),
            Some(HMENU(ID_LIST as *mut _)),
            Some(instance),
            None,
        )?;
        let _ = SetWindowTheme(list, w!("Explorer"), PCWSTR::null());
        let ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP;
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            Some(WPARAM(ex as usize)),
            Some(LPARAM(ex as isize)),
        );

        UI.with_borrow_mut(|u| {
            u.main = hwnd;
            u.tree = tree;
            u.list = list;
        });

        for (i, (name, width)) in rows::COLUMNS.iter().enumerate() {
            let mut text: Vec<u16> = name.encode_utf16().chain([0]).collect();
            let col = LVCOLUMNW {
                mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
                cx: scale(*width, dpi),
                pszText: PWSTR(text.as_mut_ptr()),
                iSubItem: i as i32,
                ..Default::default()
            };
            SendMessageW(
                list,
                LVM_INSERTCOLUMNW,
                Some(WPARAM(i)),
                Some(LPARAM(&col as *const _ as isize)),
            );
        }

        let rows = opts().rows;
        let t = Instant::now();
        SendMessageW(
            list,
            LVM_SETITEMCOUNT,
            Some(WPARAM(rows)),
            Some(LPARAM(LVSICF_NOINVALIDATEALL as isize)),
        );
        log!(
            "[list] LVM_SETITEMCOUNT({rows}) took {:.3} ms",
            t.elapsed().as_secs_f64() * 1000.0
        );

        fill_tree(tree);
    }
    apply_font(dpi);
    Ok(())
}

fn fill_tree(tree: HWND) {
    let insert = |parent: HTREEITEM, text: &str| -> HTREEITEM {
        let mut buf: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let tvi = TVINSERTSTRUCTW {
            hParent: parent,
            hInsertAfter: TVI_LAST,
            Anonymous: TVINSERTSTRUCTW_0 {
                item: TVITEMW {
                    mask: TVIF_TEXT,
                    pszText: PWSTR(buf.as_mut_ptr()),
                    ..Default::default()
                },
            },
        };
        let r = unsafe {
            SendMessageW(
                tree,
                TVM_INSERTITEMW,
                Some(WPARAM(0)),
                Some(LPARAM(&tvi as *const _ as isize)),
            )
        };
        HTREEITEM(r.0)
    };
    let expand = |item: HTREEITEM| unsafe {
        SendMessageW(
            tree,
            TVM_EXPAND,
            Some(WPARAM(TVE_EXPAND.0 as usize)),
            Some(LPARAM(item.0)),
        );
    };

    let alice = insert(TVI_ROOT, "alice@example.com (IMAP)");
    let inbox = insert(alice, "Inbox (12)");
    for f in ["Drafts", "Sent", "Queue", "Trash (3)", "Junk"] {
        insert(alice, f);
    }
    let lists = insert(alice, "Lists");
    insert(lists, "rust-users (847)");
    insert(lists, "claws-mail-users (5)");
    let work = insert(TVI_ROOT, "work@example.org (Exchange)");
    insert(work, "Inbox (100000)");
    insert(work, "Archive");
    let local = insert(TVI_ROOT, "Local mailbox (MH)");
    insert(local, "inbox");
    expand(alice);
    expand(lists);
    expand(work);
    unsafe {
        SendMessageW(
            tree,
            TVM_SELECTITEM,
            Some(WPARAM(TVGN_CARET as usize)),
            Some(LPARAM(inbox.0)),
        );
    }
}

/// Fixed splits: folder tree 220 DIP wide on the left, message list on the top 40% of the
/// right side, the mail view below it.
fn layout(hwnd: HWND) {
    let (_, tree, list, _) = ui();
    if tree.is_invalid() {
        return;
    }
    let [t, l, v] = compute_layout(hwnd);
    unsafe {
        let _ = MoveWindow(tree, t.left, t.top, t.right - t.left, t.bottom - t.top, true);
        let _ = MoveWindow(list, l.left, l.top, l.right - l.left, l.bottom - l.top, true);
    }
    mailview::set_bounds(v);
}

/// Rectangles of the tree, the list and the mail view in client coordinates.
fn compute_layout(hwnd: HWND) -> [RECT; 3] {
    let dpi = ui().3;
    let mut rc = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut rc);
    }
    let (w, h) = (rc.right, rc.bottom);
    let gap = scale(4, dpi);
    let tree_w = scale(220, dpi).min(w / 2);
    let right_x = tree_w + gap;
    let list_h = h * 2 / 5;
    [
        RECT { left: 0, top: 0, right: tree_w, bottom: h },
        RECT { left: right_x, top: 0, right: w.max(right_x), bottom: list_h },
        RECT { left: right_x, top: list_h + gap, right: w.max(right_x), bottom: h },
    ]
}

/// Resizes the window and checks that the children and the WebView follow.
fn resize_and_check(hwnd: HWND, w: i32, h: i32) {
    let (_, tree, list, dpi) = ui();
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            scale(w, dpi),
            scale(h, dpi),
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
    let child_rect = |child: HWND| -> RECT {
        let mut r = RECT::default();
        unsafe {
            let _ = GetWindowRect(child, &mut r);
            let mut pts = [
                windows::Win32::Foundation::POINT { x: r.left, y: r.top },
                windows::Win32::Foundation::POINT { x: r.right, y: r.bottom },
            ];
            windows::Win32::Graphics::Gdi::MapWindowPoints(None, Some(hwnd), &mut pts);
            RECT { left: pts[0].x, top: pts[0].y, right: pts[1].x, bottom: pts[1].y }
        }
    };
    let [t, l, v] = compute_layout(hwnd);
    let actual = [child_rect(tree), child_rect(list), mailview::bounds().unwrap_or_default()];
    let fmt = |r: &RECT| format!("({},{})-({},{})", r.left, r.top, r.right, r.bottom);
    let mut client = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut client);
    }
    log!("[resize] window set to {w}x{h} DIP; client area now {}x{}", client.right, client.bottom);
    for (name, want, got) in [("tree", t, actual[0]), ("list", l, actual[1]), ("webview", v, actual[2])] {
        log!("[resize] {name}: expected {} actual {} -> {}", fmt(&want), fmt(&got), if want == got { "OK" } else { "MISMATCH" });
    }
}

fn select_row(list: HWND, row: usize) {
    unsafe {
        let item = LVITEMW {
            stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0),
            state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0),
            ..Default::default()
        };
        // Clear the old selection, then select the row.
        let clear = LVITEMW {
            stateMask: LVIS_SELECTED,
            ..Default::default()
        };
        SendMessageW(
            list,
            LVM_SETITEMSTATE,
            Some(WPARAM(usize::MAX)),
            Some(LPARAM(&clear as *const _ as isize)),
        );
        SendMessageW(
            list,
            LVM_SETITEMSTATE,
            Some(WPARAM(row)),
            Some(LPARAM(&item as *const _ as isize)),
        );
        SendMessageW(list, LVM_ENSUREVISIBLE, Some(WPARAM(row)), Some(LPARAM(0)));
    }
}

fn list_bench() {
    let (_, _, list, _) = ui();
    let rows = opts().rows;
    if rows == 0 {
        return;
    }
    let before = DISPINFO_CALLS.get();
    let t = Instant::now();
    unsafe {
        SendMessageW(list, LVM_ENSUREVISIBLE, Some(WPARAM(rows - 1)), Some(LPARAM(0)));
        let _ = UpdateWindow(list);
    }
    let to_end = t.elapsed();
    let t = Instant::now();
    unsafe {
        SendMessageW(list, LVM_ENSUREVISIBLE, Some(WPARAM(rows / 2)), Some(LPARAM(0)));
        let _ = UpdateWindow(list);
    }
    let to_mid = t.elapsed();
    let target = opts().scroll_to.unwrap_or(0).min(rows - 1);
    let t = Instant::now();
    select_row(list, target);
    unsafe {
        let _ = UpdateWindow(list);
    }
    let to_target = t.elapsed();
    log!(
        "[list] jump+repaint: to row {} {:.2} ms, to row {} {:.2} ms, to row {target} {:.2} ms; \
         {} LVN_GETDISPINFO calls for the three repaints",
        rows - 1,
        to_end.as_secs_f64() * 1000.0,
        rows / 2,
        to_mid.as_secs_f64() * 1000.0,
        to_target.as_secs_f64() * 1000.0,
        DISPINFO_CALLS.get() - before
    );
}

fn on_getdispinfo(info: &mut NMLVDISPINFOW) {
    DISPINFO_CALLS.set(DISPINFO_CALLS.get() + 1);
    let item = &mut info.item;
    if item.mask & LVIF_TEXT == LVIF_TEXT && !item.pszText.is_null() && item.cchTextMax > 0 {
        let text = rows::cell(item.iItem as usize, item.iSubItem);
        let max = item.cchTextMax as usize - 1;
        let mut n = 0;
        for (i, u) in text.encode_utf16().take(max).enumerate() {
            unsafe { *item.pszText.0.add(i) = u };
            n = i + 1;
        }
        unsafe { *item.pszText.0.add(n) = 0 };
    }
}

fn request_exit(hwnd: HWND) {
    if CAPTURE_PENDING.get() {
        log!("[exit] waiting for the capture to finish");
        EXIT_REQUESTED.set(true);
        return;
    }
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            if let Err(e) = create_children(hwnd) {
                log!("creating child controls failed: {e:?}");
                return LRESULT(-1);
            }
            LRESULT(0)
        }
        WM_SIZE => {
            layout(hwnd);
            LRESULT(0)
        }
        WM_MOVE | WM_MOVING => {
            mailview::notify_moved();
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_DPICHANGED => {
            let dpi = (wparam.0 & 0xffff) as u32;
            log!("[dpi] WM_DPICHANGED -> {dpi}");
            apply_font(dpi);
            let r = unsafe { &*(lparam.0 as *const RECT) };
            unsafe {
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    r.left,
                    r.top,
                    r.right - r.left,
                    r.bottom - r.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
            layout(hwnd);
            LRESULT(0)
        }
        WM_NOTIFY => {
            let hdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if hdr.idFrom == ID_LIST && hdr.code == LVN_GETDISPINFOW {
                on_getdispinfo(unsafe { &mut *(lparam.0 as *mut NMLVDISPINFOW) });
            }
            LRESULT(0)
        }
        WM_TIMER => {
            let id = wparam.0;
            match id {
                TIMER_EXIT => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    log!("[exit] --exit-after reached");
                    request_exit(hwnd);
                }
                TIMER_LIST_BENCH => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    list_bench();
                }
                TIMER_RIGHT_CLICK => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    let dpi = ui().3;
                    mailview::right_click(hwnd, scale(120, dpi), scale(60, dpi));
                }
                TIMER_RESIZE => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    if let Some((w, h)) = opts().resize {
                        resize_and_check(hwnd, w, h);
                    }
                }
                TIMER_CLICK_LINKS => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    mailview::click_links();
                }
                TIMER_PROBE_AGAIN => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    mailview::probe("after-navigation-attempts");
                }
                TIMER_CAPTURE => {
                    unsafe {
                        let _ = KillTimer(Some(hwnd), id);
                    }
                    if let Some(path) = opts().capture.clone() {
                        let done = move |_ok: bool| {
                            CAPTURE_PENDING.set(false);
                            if EXIT_REQUESTED.get() {
                                request_exit(hwnd);
                            }
                        };
                        if let Err(e) = mailview::capture(&path, done) {
                            log!("[capture] could not start: {e:?}");
                            CAPTURE_PENDING.set(false);
                        }
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            mailview::close();
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
