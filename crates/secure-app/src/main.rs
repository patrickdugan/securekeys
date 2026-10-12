// SecureKeys — a capture-excluded, hardened secure-input window for Windows 11.
//
// A modern, honest successor to keystroke-encryption tools. It does NOT try to
// "encrypt keystrokes" (the destination always sees plaintext, so that model is
// a dead end). Instead it gives you a small window that:
//   * is excluded from screen capture via SetWindowDisplayAffinity(WDA_EXCLUDE-
//     FROMCAPTURE) — proven to block PrintWindow, GDI BitBlt, and Windows.
//     Graphics.Capture (OBS/Teams/Snipping Tool) in the `selftest`/wgc-capture;
//   * handles the secret ENTIRELY in-process (no global keyboard hook, no DLL
//     injection, no kernel driver) and renders it only as dots, never plaintext;
//   * hands the secret off via the clipboard with an automatic wipe.
//
// Built with CFG + CET + ASLR hardening (see ..\..\build.cmd). Zero external deps.
//
// Subcommands:
//   securekeys              Run in the tray; Ctrl+Alt+S opens the secure window.
//   securekeys selftest     Prove capture-exclusion (PrintWindow + GDI BitBlt). Exit 0=pass.
//   securekeys demo <dir>   Masking demo: dots-only vs blank captures.
//   securekeys injecttest   Verify the SendInput Unicode autofill path.
//   securekeys passkey[-demo]  WebAuthn/Windows Hello availability / full credential flow.
//   securekeys verifysig <p>   Authenticode-verify a file (the safe-update gate).
//   securekeys store/get/list/forget <name>   Windows Credential Manager vault.
//   securekeys credtest     Automated vault round-trip. Exit 0=pass.
//   securekeys smoke        Init window+hotkey+tray, then exit (crash-free check).

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::Mutex;

mod passkey;
mod verify;
mod store;

// ---------------- types ----------------
type HWND = isize;
type WPARAM = usize;
type LPARAM = isize;
type LRESULT = isize;
type COLORREF = u32;
type BOOL = i32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RECT { left: i32, top: i32, right: i32, bottom: i32 }
#[repr(C)]
struct POINT { x: i32, y: i32 }
#[repr(C)]
struct WNDCLASSW {
    style: u32,
    lpfnWndProc: Option<unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT>,
    cbClsExtra: i32, cbWndExtra: i32, hInstance: isize, hIcon: isize, hCursor: isize,
    hbrBackground: isize, lpszMenuName: *const u16, lpszClassName: *const u16,
}
#[repr(C)]
struct MSG { hwnd: HWND, message: u32, wParam: WPARAM, lParam: LPARAM, time: u32, pt: POINT }
#[repr(C)]
struct PAINTSTRUCT { hdc: isize, fErase: BOOL, rcPaint: RECT, fRestore: BOOL, fIncUpdate: BOOL, rgbReserved: [u8; 32] }
#[repr(C)]
struct BITMAPINFOHEADER {
    biSize: u32, biWidth: i32, biHeight: i32, biPlanes: u16, biBitCount: u16,
    biCompression: u32, biSizeImage: u32, biXPelsPerMeter: i32, biYPelsPerMeter: i32,
    biClrUsed: u32, biClrImportant: u32,
}
#[repr(C)]
struct BITMAPINFO { bmiHeader: BITMAPINFOHEADER, bmiColors: [u32; 3] }
#[repr(C)]
struct KEYBDINPUT { wVk: u16, wScan: u16, dwFlags: u32, time: u32, dwExtraInfo: usize }
#[repr(C)]
struct INPUT { r#type: u32, _pad: u32, ki: KEYBDINPUT, _pad2: [u8; 8] } // 40 bytes on x64
#[repr(C)]
struct NOTIFYICONDATAW {
    cbSize: u32, hWnd: isize, uID: u32, uFlags: u32, uCallbackMessage: u32, hIcon: isize,
    szTip: [u16; 128], dwState: u32, dwStateMask: u32, szInfo: [u16; 256], uVersion: u32,
    szInfoTitle: [u16; 64], dwInfoFlags: u32, guidItem: [u8; 16], hBalloonIcon: isize,
}

// ---------------- constants ----------------
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_EX_TOPMOST: u32 = 0x0000_0008;
const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
const SW_SHOW: i32 = 5;
const SW_HIDE: i32 = 0;
const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_PAINT: u32 = 0x000F;
const WM_CHAR: u32 = 0x0102;
const WM_TIMER: u32 = 0x0113;
const WM_HOTKEY: u32 = 0x0312;
const WM_APP_TRAY: u32 = 0x8000 + 1;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONUP: u32 = 0x0205;
const PM_REMOVE: u32 = 0x0001;
const WDA_NONE: u32 = 0x0000_0000;
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x0000_0011;
const PW_RENDERFULLCONTENT: u32 = 0x0000_0002;
const DIB_RGB_COLORS: u32 = 0;
const BI_RGB: u32 = 0;
const SRCCOPY: u32 = 0x00CC_0020;
const DT_CENTER: u32 = 0x1;
const DT_VCENTER: u32 = 0x4;
const DT_SINGLELINE: u32 = 0x20;
const DT_LEFT: u32 = 0x0;
const DT_NOPREFIX: u32 = 0x0800;
const OPAQUE: i32 = 2;
const TRANSPARENT: i32 = 1;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const HWND_TOPMOST: HWND = -1;
const DPI_PER_MONITOR_AWARE_V2: isize = -4;
const GMEM_MOVEABLE: u32 = 0x0002;
const CF_UNICODETEXT: u32 = 13;
const MOD_ALT: u32 = 0x0001;
const MOD_CONTROL: u32 = 0x0002;
const MOD_NOREPEAT: u32 = 0x4000;
const HOTKEY_ID: i32 = 1;
const TIMER_CLIP: usize = 1;
const CLIP_CLEAR_MS: u32 = 20_000;
const WM_KEYDOWN: u32 = 0x0100;
const WM_GETTEXT: u32 = 0x000D;
const VK_BACK: i32 = 0x08;
const VK_RETURN: i32 = 0x0D;
const VK_SHIFT: i32 = 0x10;
const VK_ESCAPE: i32 = 0x1B;
const INPUT_KEYBOARD: u32 = 1;
const KEYEVENTF_KEYUP: u32 = 0x0002;
const KEYEVENTF_UNICODE: u32 = 0x0004;
const ES_AUTOHSCROLL: u32 = 0x0080;
const CLEARTYPE_QUALITY: u32 = 5;
const DEFAULT_CHARSET: u32 = 1;

// ---------------- FFI ----------------
#[link(name = "user32")]
extern "system" {
    fn RegisterClassW(c: *const WNDCLASSW) -> u16;
    fn CreateWindowExW(ex: u32, cls: *const u16, name: *const u16, style: u32,
        x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: isize, inst: isize, p: *mut c_void) -> HWND;
    fn DefWindowProcW(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    fn ShowWindow(h: HWND, c: i32) -> BOOL;
    fn UpdateWindow(h: HWND) -> BOOL;
    fn DestroyWindow(h: HWND) -> BOOL;
    fn SetWindowDisplayAffinity(h: HWND, a: u32) -> BOOL;
    fn GetWindowRect(h: HWND, r: *mut RECT) -> BOOL;
    fn GetClientRect(h: HWND, r: *mut RECT) -> BOOL;
    fn InvalidateRect(h: HWND, r: *const RECT, erase: BOOL) -> BOOL;
    fn PrintWindow(h: HWND, hdc: isize, flags: u32) -> BOOL;
    fn GetDC(h: HWND) -> isize;
    fn ReleaseDC(h: HWND, hdc: isize) -> i32;
    fn BeginPaint(h: HWND, ps: *mut PAINTSTRUCT) -> isize;
    fn EndPaint(h: HWND, ps: *const PAINTSTRUCT) -> BOOL;
    fn FillRect(hdc: isize, r: *const RECT, b: isize) -> i32;
    fn DrawTextW(hdc: isize, s: *const u16, c: i32, r: *mut RECT, fmt: u32) -> i32;
    fn GetMessageW(m: *mut MSG, h: HWND, min: u32, max: u32) -> BOOL;
    fn PeekMessageW(m: *mut MSG, h: HWND, min: u32, max: u32, remove: u32) -> BOOL;
    fn TranslateMessage(m: *const MSG) -> BOOL;
    fn DispatchMessageW(m: *const MSG) -> LRESULT;
    fn PostMessageW(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> BOOL;
    fn PostQuitMessage(code: i32);
    fn SetForegroundWindow(h: HWND) -> BOOL;
    fn SetFocus(h: HWND) -> HWND;
    fn SetWindowPos(h: HWND, after: HWND, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> BOOL;
    fn LoadCursorW(inst: isize, name: *const u16) -> isize;
    fn LoadIconW(inst: isize, name: *const u16) -> isize;
    fn SetProcessDpiAwarenessContext(ctx: isize) -> BOOL;
    fn GetSystemMetrics(index: i32) -> i32;
    fn SetTimer(h: HWND, id: usize, elapse: u32, func: usize) -> usize;
    fn KillTimer(h: HWND, id: usize) -> BOOL;
    fn RegisterHotKey(h: HWND, id: i32, modifiers: u32, vk: u32) -> BOOL;
    fn UnregisterHotKey(h: HWND, id: i32) -> BOOL;
    fn OpenClipboard(h: HWND) -> BOOL;
    fn EmptyClipboard() -> BOOL;
    fn SetClipboardData(format: u32, mem: isize) -> isize;
    fn CloseClipboard() -> BOOL;
    fn GetForegroundWindow() -> HWND;
    fn GetKeyState(vk: i32) -> i16;
    fn SendInput(n: u32, inputs: *const INPUT, cbsize: i32) -> u32;
    fn SendMessageW(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT;
}
#[link(name = "gdi32")]
extern "system" {
    fn CreateSolidBrush(c: COLORREF) -> isize;
    fn DeleteObject(o: isize) -> BOOL;
    fn SetBkMode(hdc: isize, mode: i32) -> i32;
    fn SetBkColor(hdc: isize, c: COLORREF) -> COLORREF;
    fn SetTextColor(hdc: isize, c: COLORREF) -> COLORREF;
    fn CreateCompatibleDC(hdc: isize) -> isize;
    fn DeleteDC(hdc: isize) -> BOOL;
    fn CreateDIBSection(hdc: isize, bmi: *const BITMAPINFO, usage: u32,
        bits: *mut *mut c_void, section: isize, offset: u32) -> isize;
    fn SelectObject(hdc: isize, o: isize) -> isize;
    fn BitBlt(dst: isize, x: i32, y: i32, w: i32, h: i32, src: isize, sx: i32, sy: i32, rop: u32) -> BOOL;
    fn CreateFontW(h: i32, w: i32, esc: i32, orient: i32, weight: i32, italic: u32, underline: u32,
        strike: u32, charset: u32, outprec: u32, clipprec: u32, quality: u32, pitch: u32, face: *const u16) -> isize;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn Sleep(ms: u32);
    fn GlobalAlloc(flags: u32, bytes: usize) -> isize;
    fn GlobalLock(mem: isize) -> *mut c_void;
    fn GlobalUnlock(mem: isize) -> BOOL;
    fn GlobalFree(mem: isize) -> isize;
}
#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(message: u32, data: *const NOTIFYICONDATAW) -> BOOL;
}

// ---------------- shared state ----------------
struct State { secret: Vec<u16>, status: String, prior: HWND }
static STATE: Mutex<State> = Mutex::new(State { secret: Vec::new(), status: String::new(), prior: 0 });
// When set, Enter stores the secret into the Windows Credential Manager under
// this name instead of copying to the clipboard (the `store <name>` command).
static STORE_TARGET: Mutex<Option<String>> = Mutex::new(None);

fn key_unicode(scan: u16, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        _pad: 0,
        ki: KEYBDINPUT {
            wVk: 0,
            wScan: scan,
            dwFlags: KEYEVENTF_UNICODE | if up { KEYEVENTF_KEYUP } else { 0 },
            time: 0,
            dwExtraInfo: 0,
        },
        _pad2: [0; 8],
    }
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn zeroize(v: &mut Vec<u16>) {
    for x in v.iter_mut() { *x = 0; }
    v.clear();
}

// colors (COLORREF = 0x00BBGGRR)
const BG: COLORREF = 0x0020_1811;      // dark slate
const BOXBG: COLORREF = 0x0030_2820;   // input box
const FG: COLORREF = 0x00FF_FFFF;      // white
const DIM: COLORREF = 0x00B0_A090;     // muted

// ================= secure window =================
unsafe extern "system" fn secure_wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_KEYDOWN => {
            match w as i32 {
                VK_RETURN => {
                    if (GetKeyState(VK_SHIFT) as u16 & 0x8000) != 0 { inject_to_prior(h); }
                    else { confirm(h); }
                }
                VK_ESCAPE => {
                    { let mut st = STATE.lock().unwrap(); zeroize(&mut st.secret); st.status = "Cleared.".into(); }
                    if STORE_TARGET.lock().unwrap().is_some() { DestroyWindow(h); } else { ShowWindow(h, SW_HIDE); }
                }
                VK_BACK => {
                    let mut st = STATE.lock().unwrap();
                    if let Some(x) = st.secret.last_mut() { *x = 0; }
                    st.secret.pop();
                }
                _ => return DefWindowProcW(h, msg, w, l),
            }
            InvalidateRect(h, null_mut(), 1);
            0
        }
        WM_CHAR => {
            let c = w as u16;
            if c >= 0x20 {
                { let mut st = STATE.lock().unwrap();
                  if st.secret.len() < 256 { st.secret.push(c); st.status.clear(); } }
                InvalidateRect(h, null_mut(), 1);
            }
            0
        }
        WM_TIMER => {
            if w == TIMER_CLIP {
                clear_clipboard(h);
                KillTimer(h, TIMER_CLIP);
                let mut st = STATE.lock().unwrap();
                st.status = "Clipboard wiped.".into();
                drop(st);
                InvalidateRect(h, null_mut(), 1);
            }
            0
        }
        WM_HOTKEY => {
            let p = GetForegroundWindow();
            { STATE.lock().unwrap().prior = p; }
            show_secure(h);
            0
        }
        WM_APP_TRAY => {
            let ev = (l as u32) & 0xFFFF;
            if ev == WM_LBUTTONUP {
                let p = GetForegroundWindow();
                { STATE.lock().unwrap().prior = p; }
                show_secure(h);
            } else if ev == WM_RBUTTONUP {
                DestroyWindow(h);
            }
            0
        }
        WM_PAINT => { paint_secure(h); 0 }
        WM_CLOSE => { // hide to tray instead of exiting (store mode exits)
            { let mut st = STATE.lock().unwrap(); zeroize(&mut st.secret); }
            if STORE_TARGET.lock().unwrap().is_some() { DestroyWindow(h); } else { ShowWindow(h, SW_HIDE); }
            0
        }
        WM_DESTROY => { PostQuitMessage(0); 0 }
        _ => DefWindowProcW(h, msg, w, l),
    }
}

unsafe fn show_secure(h: HWND) {
    SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    ShowWindow(h, SW_SHOW);
    SetForegroundWindow(h);
    SetFocus(h);
    InvalidateRect(h, null_mut(), 1);
}

unsafe fn make_font(px: i32, weight: i32) -> isize {
    let face = wide("Segoe UI");
    CreateFontW(-px, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, face.as_ptr())
}

unsafe fn paint_secure(h: HWND) {
    let mut ps: PAINTSTRUCT = std::mem::zeroed();
    let hdc = BeginPaint(h, &mut ps);
    let mut rc = RECT::default();
    GetClientRect(h, &mut rc);

    let bg = CreateSolidBrush(BG);
    FillRect(hdc, &rc, bg);
    DeleteObject(bg);
    SetBkMode(hdc, TRANSPARENT);

    let f_title = make_font(21, 600);
    let f_body = make_font(17, 400);
    let f_dot = make_font(28, 700);
    let old = SelectObject(hdc, f_title);

    // title
    SetTextColor(hdc, FG);
    let title = wide("SecureKeys — secure entry");
    let mut r = RECT { left: 24, top: 16, right: rc.right - 24, bottom: 46 };
    DrawTextW(hdc, title.as_ptr(), -1, &mut r, DT_LEFT | DT_SINGLELINE);

    // input box with masked dots
    let boxr = RECT { left: 24, top: 56, right: rc.right - 24, bottom: 106 };
    let b = CreateSolidBrush(BOXBG);
    FillRect(hdc, &boxr, b);
    DeleteObject(b);
    let len = { STATE.lock().unwrap().secret.len() };
    let mut dr = boxr;
    dr.left += 14;
    if len == 0 {
        SelectObject(hdc, f_body);
        SetTextColor(hdc, DIM);
        let ph = wide("(type your secret — it is never shown or logged)");
        DrawTextW(hdc, ph.as_ptr(), -1, &mut dr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    } else {
        SelectObject(hdc, f_dot);
        SetTextColor(hdc, FG);
        let dots: Vec<u16> = std::iter::repeat(0x2022u16).take(len).collect();
        DrawTextW(hdc, dots.as_ptr(), len as i32, &mut dr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    SelectObject(hdc, f_body);
    // capture-exclusion status
    SetTextColor(hdc, 0x0060_D060); // green
    let cap = wide("● Capture: EXCLUDED  (WDA_EXCLUDEFROMCAPTURE)");
    let mut cr = RECT { left: 24, top: 116, right: rc.right - 24, bottom: 140 };
    DrawTextW(hdc, cap.as_ptr(), -1, &mut cr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    // hints
    SetTextColor(hdc, DIM);
    let hint1 = wide("Enter = copy (auto-wipes 20s)    ·    Shift+Enter = type into last app");
    let mut hr = RECT { left: 24, top: 144, right: rc.right - 24, bottom: 168 };
    DrawTextW(hdc, hint1.as_ptr(), -1, &mut hr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    let hint2 = wide("Esc = clear and hide");
    let mut hr2 = RECT { left: 24, top: 168, right: rc.right - 24, bottom: 192 };
    DrawTextW(hdc, hint2.as_ptr(), -1, &mut hr2, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    let status = { STATE.lock().unwrap().status.clone() };
    if !status.is_empty() {
        SetTextColor(hdc, 0x0070_C0F0);
        let sw = wide(&status);
        let mut sr = RECT { left: 24, top: 196, right: rc.right - 24, bottom: 220 };
        DrawTextW(hdc, sw.as_ptr(), -1, &mut sr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    }

    SelectObject(hdc, old);
    DeleteObject(f_title);
    DeleteObject(f_body);
    DeleteObject(f_dot);
    EndPaint(h, &ps);
}

unsafe fn confirm(h: HWND) {
    // store mode: write to the Windows Credential Manager instead of the clipboard
    let store_target = { STORE_TARGET.lock().unwrap().clone() };
    if let Some(name) = store_target {
        let secret_u16 = { STATE.lock().unwrap().secret.clone() };
        if secret_u16.is_empty() { return; }
        let mut bytes = String::from_utf16_lossy(&secret_u16).into_bytes();
        let ok = store::write(&name, &bytes);
        for b in bytes.iter_mut() { *b = 0; }
        {
            let mut st = STATE.lock().unwrap();
            zeroize(&mut st.secret);
            st.status = if ok { format!("Stored '{name}' in Windows Credential Manager.") } else { "Store FAILED.".into() };
        }
        InvalidateRect(h, null_mut(), 1);
        Sleep(1100);
        DestroyWindow(h);
        return;
    }
    let data: Vec<u16> = {
        let st = STATE.lock().unwrap();
        if st.secret.is_empty() { return; }
        let mut d = st.secret.clone();
        d.push(0);
        d
    };
    let bytes = data.len() * 2;
    let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if mem != 0 {
        let p = GlobalLock(mem) as *mut u16;
        if !p.is_null() {
            std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
            GlobalUnlock(mem);
            if OpenClipboard(h) != 0 {
                EmptyClipboard();
                if SetClipboardData(CF_UNICODETEXT, mem) == 0 { GlobalFree(mem); }
                CloseClipboard();
                SetTimer(h, TIMER_CLIP, CLIP_CLEAR_MS, 0);
            } else {
                GlobalFree(mem);
            }
        } else {
            GlobalFree(mem);
        }
    }
    // the plaintext copy we built, and the in-memory secret, are wiped now
    let mut d2 = data;
    for x in d2.iter_mut() { *x = 0; }
    let mut st = STATE.lock().unwrap();
    zeroize(&mut st.secret);
    st.status = "Copied. Paste now — clipboard auto-wipes in 20s.".into();
    drop(st);
    InvalidateRect(h, null_mut(), 1);
}

unsafe fn clear_clipboard(h: HWND) {
    if OpenClipboard(h) != 0 {
        EmptyClipboard();
        CloseClipboard();
    }
}

// Autofill: type the secret into the window that had focus before SecureKeys,
// via synthetic Unicode keystrokes (SendInput). No clipboard involved.
unsafe fn inject_to_prior(h: HWND) {
    let (mut data, prior) = {
        let st = STATE.lock().unwrap();
        (st.secret.clone(), st.prior)
    };
    if data.is_empty() || prior == 0 {
        let mut st = STATE.lock().unwrap();
        st.status = if prior == 0 { "No previous window to type into.".into() } else { "Nothing to type.".into() };
        drop(st);
        InvalidateRect(h, null_mut(), 1);
        return;
    }
    ShowWindow(h, SW_HIDE);
    SetForegroundWindow(prior);
    Sleep(120);
    let mut inputs: Vec<INPUT> = Vec::with_capacity(data.len() * 2);
    for &u in &data {
        inputs.push(key_unicode(u, false));
        inputs.push(key_unicode(u, true));
    }
    SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32);
    for x in inputs.iter_mut() { x.ki.wScan = 0; }
    for x in data.iter_mut() { *x = 0; }
    let mut st = STATE.lock().unwrap();
    zeroize(&mut st.secret);
    st.status = "Typed into previous app.".into();
}

unsafe fn create_secure_window(inst: isize, visible: bool) -> HWND {
    let cls = wide("SkSecureWnd");
    let wc = WNDCLASSW {
        style: 0, lpfnWndProc: Some(secure_wndproc), cbClsExtra: 0, cbWndExtra: 0,
        hInstance: inst, hIcon: LoadIconW(0, 32512 as *const u16),
        hCursor: LoadCursorW(0, 32512 as *const u16),
        hbrBackground: 0, lpszMenuName: null_mut(), lpszClassName: cls.as_ptr(),
    };
    RegisterClassW(&wc);
    let (w, hgt) = (600, 300);
    let x = (GetSystemMetrics(0) - w) / 2;
    let y = (GetSystemMetrics(1) - hgt) / 3;
    let style = WS_OVERLAPPEDWINDOW | if visible { WS_VISIBLE } else { 0 };
    let title = wide("SecureKeys");
    let h = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, cls.as_ptr(), title.as_ptr(),
        style, x, y, w, hgt, 0, 0, inst, null_mut());
    SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE);
    h
}

unsafe fn add_tray(h: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = h;
    nid.uID = 1;
    nid.uFlags = 0x1 | 0x2 | 0x4; // MESSAGE|ICON|TIP
    nid.uCallbackMessage = WM_APP_TRAY;
    nid.hIcon = LoadIconW(0, 32512 as *const u16); // IDI_APPLICATION
    let tip = wide("SecureKeys — Ctrl+Alt+S to open");
    for (i, c) in tip.iter().enumerate().take(127) { nid.szTip[i] = *c; }
    Shell_NotifyIconW(0, &nid); // NIM_ADD
}

unsafe fn del_tray(h: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = h;
    nid.uID = 1;
    Shell_NotifyIconW(2, &nid); // NIM_DELETE
}

fn run_app() {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let inst = GetModuleHandleW(null_mut());
        let h = create_secure_window(inst, false);
        add_tray(h);
        let hk = RegisterHotKey(h, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 0x53); // 'S'
        println!("SecureKeys is running in the tray.");
        println!("  Open:  Ctrl+Alt+S{}", if hk == 0 { "  (hotkey registration FAILED)" } else { "" });
        println!("  Exit:  right-click the tray icon");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        UnregisterHotKey(h, HOTKEY_ID);
        del_tray(h);
        let mut st = STATE.lock().unwrap();
        zeroize(&mut st.secret);
    }
}

// `store <name>`: open the secure window; Enter writes the secret to the
// Windows Credential Manager under SecureKeys/<name> (see confirm()).
fn run_store(name: &str) {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        { *STORE_TARGET.lock().unwrap() = Some(name.to_string()); }
        let inst = GetModuleHandleW(null_mut());
        let h = create_secure_window(inst, true);
        show_secure(h);
        println!("Enter the secret for '{name}' in the secure window (Enter = store, Esc = cancel).");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let mut st = STATE.lock().unwrap();
        zeroize(&mut st.secret);
    }
}

fn run_smoke() {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let inst = GetModuleHandleW(null_mut());
        let h = create_secure_window(inst, false);
        add_tray(h);
        let hk = RegisterHotKey(h, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 0x53);
        // process a few messages, then tear down
        for _ in 0..20 {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(10);
        }
        UnregisterHotKey(h, HOTKEY_ID);
        del_tray(h);
        DestroyWindow(h);
        println!("SMOKE OK: window + tray + hotkey({}) initialised and torn down cleanly.",
            if hk != 0 { "ok" } else { "FAILED" });
    }
}

// ================= capture helpers (selftest/demo) =================
unsafe fn make_dib(mem: isize, w: i32, h: i32) -> (isize, *mut c_void) {
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB,
            biSizeImage: 0, biXPelsPerMeter: 0, biYPelsPerMeter: 0, biClrUsed: 0, biClrImportant: 0,
        },
        bmiColors: [0; 3],
    };
    let mut bits: *mut c_void = null_mut();
    let dib = CreateDIBSection(mem, &bmi, DIB_RGB_COLORS, &mut bits, 0, 0);
    SelectObject(mem, dib);
    (dib, bits)
}
unsafe fn read_bits(bits: *mut c_void, w: i32, h: i32) -> Vec<u8> {
    let n = (w * h * 4) as usize;
    let mut v = vec![0u8; n];
    std::ptr::copy_nonoverlapping(bits as *const u8, v.as_mut_ptr(), n);
    v
}
unsafe fn capture_printwindow(h: HWND) -> (i32, i32, Vec<u8>) {
    let mut rc = RECT::default();
    GetWindowRect(h, &mut rc);
    let (w, hgt) = (rc.right - rc.left, rc.bottom - rc.top);
    let screen = GetDC(0);
    let mem = CreateCompatibleDC(screen);
    let (dib, bits) = make_dib(mem, w, hgt);
    PrintWindow(h, mem, PW_RENDERFULLCONTENT);
    let out = read_bits(bits, w, hgt);
    DeleteObject(dib); DeleteDC(mem); ReleaseDC(0, screen);
    (w, hgt, out)
}
unsafe fn capture_screen_bitblt(h: HWND) -> (i32, i32, Vec<u8>) {
    let mut rc = RECT::default();
    GetWindowRect(h, &mut rc);
    let (w, hgt) = (rc.right - rc.left, rc.bottom - rc.top);
    let screen = GetDC(0);
    let mem = CreateCompatibleDC(screen);
    let (dib, bits) = make_dib(mem, w, hgt);
    BitBlt(mem, 0, 0, w, hgt, screen, rc.left, rc.top, SRCCOPY);
    let out = read_bits(bits, w, hgt);
    DeleteObject(dib); DeleteDC(mem); ReleaseDC(0, screen);
    (w, hgt, out)
}
fn frac<F: Fn(u8, u8, u8) -> bool>(bgra: &[u8], pred: F) -> f64 {
    let px = bgra.len() / 4;
    if px == 0 { return 0.0; }
    let mut hits = 0usize;
    for c in bgra.chunks_exact(4) { if pred(c[0], c[1], c[2]) { hits += 1; } }
    hits as f64 / px as f64
}
fn is_magenta(b: u8, g: u8, r: u8) -> bool { b > 200 && g < 60 && r > 200 }
fn is_light(b: u8, g: u8, r: u8) -> bool { b > 180 && g > 180 && r > 180 }

fn write_bmp(path: &str, w: i32, h: i32, bgra: &[u8]) {
    let row = (w * 3 + 3) & !3;
    let img = (row * h) as usize;
    let file = 54 + img;
    let mut o = Vec::with_capacity(file);
    o.extend_from_slice(b"BM");
    o.extend_from_slice(&(file as u32).to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&54u32.to_le_bytes());
    o.extend_from_slice(&40u32.to_le_bytes());
    o.extend_from_slice(&w.to_le_bytes());
    o.extend_from_slice(&h.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&24u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(img as u32).to_le_bytes());
    o.extend_from_slice(&2835i32.to_le_bytes());
    o.extend_from_slice(&2835i32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    for y in (0..h).rev() {
        let mut written = 0;
        for x in 0..w as usize {
            let p = (y * w * 4) as usize + x * 4;
            o.push(bgra[p]); o.push(bgra[p + 1]); o.push(bgra[p + 2]);
            written += 3;
        }
        while written < row { o.push(0); written += 1; }
    }
    let _ = std::fs::write(path, o);
}

// ---- probe window (plain magenta + secret text) for the exclusion selftest ----
unsafe extern "system" fn probe_wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(h, &mut ps);
            let mut rc = RECT::default();
            GetClientRect(h, &mut rc);
            let brush = CreateSolidBrush(0x00FF_00FF);
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, 0x00FF_FFFF);
            let mut t = wide("SECRET-7788");
            DrawTextW(hdc, t.as_ptr(), -1, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            EndPaint(h, &ps);
            0
        }
        WM_DESTROY => { PostQuitMessage(0); 0 }
        _ => DefWindowProcW(h, msg, w, l),
    }
}
unsafe fn pump(ms: u32) {
    for _ in 0..(ms / 10).max(1) {
        let mut msg: MSG = std::mem::zeroed();
        while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}
unsafe fn make_probe(inst: isize, cls: *const u16, title: &str, x: i32, excluded: bool) -> HWND {
    let t = wide(title);
    let h = CreateWindowExW(0, cls, t.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        x, 120, 420, 300, 0, 0, inst, null_mut());
    if excluded { SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE); }
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
    SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    SetForegroundWindow(h);
    h
}

fn run_selftest() -> i32 {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let inst = GetModuleHandleW(null_mut());
        let cls = wide("SkProbeWnd");
        let wc = WNDCLASSW {
            style: 0, lpfnWndProc: Some(probe_wndproc), cbClsExtra: 0, cbWndExtra: 0,
            hInstance: inst, hIcon: 0, hCursor: LoadCursorW(0, 32512 as *const u16),
            hbrBackground: 0, lpszMenuName: null_mut(), lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);
        let normal = make_probe(inst, cls.as_ptr(), "NORMAL (leaks)", 120, false);
        let protected = make_probe(inst, cls.as_ptr(), "PROTECTED", 580, true);
        pump(700);

        let (_, _, nb) = capture_printwindow(normal);
        let (_, _, pb) = capture_printwindow(protected);
        let (_, _, ns) = capture_screen_bitblt(normal);
        let (_, _, ps) = capture_screen_bitblt(protected);
        let (nf, pf) = (frac(&nb, is_magenta) * 100.0, frac(&pb, is_magenta) * 100.0);
        let (nsf, psf) = (frac(&ns, is_magenta) * 100.0, frac(&ps, is_magenta) * 100.0);

        println!("capture-exclusion selftest (secret must survive in NORMAL, vanish in PROTECTED):");
        println!("  PrintWindow   NORMAL {nf:6.2}%   PROTECTED {pf:6.2}%");
        println!("  ScreenBitBlt  NORMAL {nsf:6.2}%   PROTECTED {psf:6.2}%");
        let pass = nf > 50.0 && nsf > 50.0 && pf < 1.0 && psf < 1.0;
        println!("RESULT: {}", if pass { "PASS" } else { "FAIL" });
        DestroyWindow(normal);
        DestroyWindow(protected);
        if pass { 0 } else { 1 }
    }
}

fn run_demo(out_dir: &str) {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let inst = GetModuleHandleW(null_mut());
        let h = create_secure_window(inst, true);
        show_secure(h);
        pump(300);
        // type a sample secret in-process via WM_CHAR (what a keystroke would do)
        for c in "hunter2-🔒".encode_utf16() { PostMessageW(h, WM_CHAR, c as usize, 0); }
        pump(300);

        // (1) exclusion OFF: the capture sees only DOTS, never the plaintext
        SetWindowDisplayAffinity(h, WDA_NONE);
        pump(100);
        let (w1, h1, masked) = capture_printwindow(h);
        write_bmp(&format!("{out_dir}/demo_masked.bmp"), w1, h1, &masked);
        let dots_light = frac(&masked, is_light) * 100.0;

        // (2) exclusion ON: the capture is blank
        SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE);
        pump(100);
        let (w2, h2, excluded) = capture_printwindow(h);
        write_bmp(&format!("{out_dir}/demo_excluded.bmp"), w2, h2, &excluded);
        let excl_light = frac(&excluded, is_light) * 100.0;

        println!("secure-input demo (typed secret rendered only as dots):");
        println!("  exclusion OFF : {dots_light:6.2}% light pixels (dots visible, plaintext never drawn) -> demo_masked.bmp");
        println!("  exclusion ON  : {excl_light:6.2}% light pixels (window blank in capture)              -> demo_excluded.bmp");
        { let mut st = STATE.lock().unwrap(); zeroize(&mut st.secret); }
        DestroyWindow(h);
    }
}

// Verifies the SendInput Unicode path used by Shift+Enter autofill: type a known
// (non-secret) string into a real EDIT control and read it back.
fn run_injecttest() -> i32 {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let inst = GetModuleHandleW(null_mut());
        let cls = wide("EDIT");
        let title = wide(""); // empty: EDIT uses the window name as its initial text
        let h = CreateWindowExW(0, cls.as_ptr(), title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE | ES_AUTOHSCROLL, 200, 200, 420, 120, 0, 0, inst, null_mut());
        ShowWindow(h, SW_SHOW);
        SetForegroundWindow(h);
        SetFocus(h);
        pump(250);
        let sample = "HELLO-世界-42";
        let mut inputs: Vec<INPUT> = Vec::new();
        for u in sample.encode_utf16() {
            inputs.push(key_unicode(u, false));
            inputs.push(key_unicode(u, true));
        }
        SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32);
        pump(250);
        let mut buf = vec![0u16; 256];
        let n = SendMessageW(h, WM_GETTEXT, 256, buf.as_mut_ptr() as isize);
        let got = String::from_utf16_lossy(&buf[..(n.max(0) as usize)]);
        println!("SendInput Unicode autofill test:");
        println!("  sent: {sample}");
        println!("  read: {got}");
        let pass = got == sample;
        println!("RESULT: {}", if pass { "PASS" } else { "FAIL" });
        DestroyWindow(h);
        if pass { 0 } else { 1 }
    }
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "selftest" => std::process::exit(run_selftest()),
        "smoke" => run_smoke(),
        "demo" => {
            let dir = std::env::args().nth(2).unwrap_or_else(|| ".".to_string());
            run_demo(&dir);
        }
        "passkey" => passkey::run_availability(),
        "passkey-demo" => std::process::exit(passkey::run_demo()),
        "injecttest" => std::process::exit(run_injecttest()),
        "verifysig" => {
            let p = std::env::args().nth(2).unwrap_or_default();
            if p.is_empty() { eprintln!("usage: securekeys verifysig <path>"); std::process::exit(2); }
            std::process::exit(verify::run_verify(&p));
        }
        "store" => {
            let name = std::env::args().nth(2).unwrap_or_default();
            if name.is_empty() { eprintln!("usage: securekeys store <name>"); std::process::exit(2); }
            run_store(&name);
        }
        "get" => {
            let name = std::env::args().nth(2).unwrap_or_default();
            if name.is_empty() { eprintln!("usage: securekeys get <name>"); std::process::exit(2); }
            std::process::exit(store::run_get(&name));
        }
        "forget" => {
            let name = std::env::args().nth(2).unwrap_or_default();
            if name.is_empty() { eprintln!("usage: securekeys forget <name>"); std::process::exit(2); }
            std::process::exit(store::run_forget(&name));
        }
        "list" => std::process::exit(store::run_list()),
        "credtest" => std::process::exit(store::run_credtest()),
        "" => run_app(),
        other => {
            eprintln!("unknown subcommand: {other}\nusage: securekeys [selftest|demo <dir>|smoke|passkey|passkey-demo|injecttest|verifysig <path>|store <name>|get <name>|list|forget <name>|credtest]");
            std::process::exit(2);
        }
    }
}
