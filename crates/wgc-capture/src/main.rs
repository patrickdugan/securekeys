// wgc-capture — does WDA_EXCLUDEFROMCAPTURE block Windows.Graphics.Capture?
//
// WGC is the modern capture API behind OBS, Teams/Zoom screen share, Xbox Game
// Bar and the Win11 Snipping Tool. This harness creates two identical secret
// windows (one with WDA_EXCLUDEFROMCAPTURE) and captures each via a real WGC
// per-window session (CreateForWindow -> FramePool -> staging texture -> map),
// then reports how much of the magenta secret survived.
//
// Positive control: the NORMAL window must show magenta (proves WGC works here).
// Claim under test: the PROTECTED window must come back ~0% (proves exclusion).
//
// Window scaffolding is raw FFI (no deps); only D3D11 + WGC use the windows crate.

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr::null_mut;

use windows::core::{Interface, Result};
use windows::Graphics::SizeInt32;
use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::{IDXGIAdapter, IDXGIDevice};
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

// ---------- raw Win32 FFI for the test windows ----------
type RawHwnd = isize;
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
    lpfnWndProc: Option<unsafe extern "system" fn(RawHwnd, u32, WPARAM, LPARAM) -> LRESULT>,
    cbClsExtra: i32, cbWndExtra: i32, hInstance: isize, hIcon: isize, hCursor: isize,
    hbrBackground: isize, lpszMenuName: *const u16, lpszClassName: *const u16,
}
#[repr(C)]
struct MSG { hwnd: RawHwnd, message: u32, wParam: WPARAM, lParam: LPARAM, time: u32, pt: POINT }
#[repr(C)]
struct PAINTSTRUCT { hdc: isize, fErase: BOOL, rcPaint: RECT, fRestore: BOOL, fIncUpdate: BOOL, rgbReserved: [u8; 32] }

const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const SW_SHOW: i32 = 5;
const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const PM_REMOVE: u32 = 0x0001;
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x0000_0011;
const DT_CENTER: u32 = 0x1;
const DT_VCENTER: u32 = 0x4;
const DT_SINGLELINE: u32 = 0x20;
const TRANSPARENT: i32 = 1;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const HWND_TOPMOST: RawHwnd = -1;
const DPI_PER_MONITOR_AWARE_V2: isize = -4;

#[link(name = "user32")]
extern "system" {
    fn RegisterClassW(c: *const WNDCLASSW) -> u16;
    fn CreateWindowExW(ex: u32, cls: *const u16, name: *const u16, style: u32,
        x: i32, y: i32, w: i32, h: i32, parent: RawHwnd, menu: isize, inst: isize, p: *mut c_void) -> RawHwnd;
    fn DefWindowProcW(h: RawHwnd, m: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    fn ShowWindow(h: RawHwnd, c: i32) -> BOOL;
    fn UpdateWindow(h: RawHwnd) -> BOOL;
    fn DestroyWindow(h: RawHwnd) -> BOOL;
    fn SetWindowDisplayAffinity(h: RawHwnd, a: u32) -> BOOL;
    fn GetClientRect(h: RawHwnd, r: *mut RECT) -> BOOL;
    fn BeginPaint(h: RawHwnd, ps: *mut PAINTSTRUCT) -> isize;
    fn EndPaint(h: RawHwnd, ps: *const PAINTSTRUCT) -> BOOL;
    fn FillRect(hdc: isize, r: *const RECT, b: isize) -> i32;
    fn DrawTextW(hdc: isize, s: *const u16, c: i32, r: *mut RECT, fmt: u32) -> i32;
    fn PeekMessageW(m: *mut MSG, h: RawHwnd, min: u32, max: u32, remove: u32) -> BOOL;
    fn TranslateMessage(m: *const MSG) -> BOOL;
    fn DispatchMessageW(m: *const MSG) -> LRESULT;
    fn PostQuitMessage(code: i32);
    fn SetForegroundWindow(h: RawHwnd) -> BOOL;
    fn SetWindowPos(h: RawHwnd, after: RawHwnd, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> BOOL;
    fn LoadCursorW(inst: isize, name: *const u16) -> isize;
    fn SetProcessDpiAwarenessContext(ctx: isize) -> BOOL;
}
#[link(name = "gdi32")]
extern "system" {
    fn CreateSolidBrush(c: COLORREF) -> isize;
    fn DeleteObject(o: isize) -> BOOL;
    fn SetBkMode(hdc: isize, mode: i32) -> i32;
    fn SetTextColor(hdc: isize, c: COLORREF) -> COLORREF;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn Sleep(ms: u32);
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
const SECRET: &str = "SECRET-7788";
const MAGENTA: COLORREF = 0x00FF_00FF;

unsafe extern "system" fn wndproc(h: RawHwnd, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(h, &mut ps);
            let mut rc = RECT::default();
            GetClientRect(h, &mut rc);
            let brush = CreateSolidBrush(MAGENTA);
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, 0x00FF_FFFF);
            let mut t = wide(SECRET);
            DrawTextW(hdc, t.as_mut_ptr(), -1, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
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

unsafe fn make_window(inst: isize, cls: *const u16, title: &str, x: i32, excluded: bool) -> RawHwnd {
    let t = wide(title);
    let h = CreateWindowExW(0, cls, t.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        x, 120, 420, 300, 0, 0, inst, null_mut());
    if excluded {
        let ok = SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE);
        println!("  SetWindowDisplayAffinity -> {}", if ok != 0 { "OK" } else { "FAILED" });
    }
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
    SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    SetForegroundWindow(h);
    h
}

fn magenta_fraction(bgra: &[u8]) -> f64 {
    let px = bgra.len() / 4;
    if px == 0 { return 0.0; }
    let mut hits = 0usize;
    for c in bgra.chunks_exact(4) {
        if c[0] > 200 && c[1] < 60 && c[2] > 200 { hits += 1; }
    }
    hits as f64 / px as f64
}

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

// ---------- D3D11 + WGC ----------
fn make_device() -> Result<(ID3D11Device, ID3D11DeviceContext, IDirect3DDevice)> {
    let adapter: Option<&IDXGIAdapter> = None;
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    unsafe {
        D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_HARDWARE, HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION,
            Some(&mut device), None, Some(&mut context))
        .or_else(|_| D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_WARP, HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION,
            Some(&mut device), None, Some(&mut context)))?;
    }
    let device = device.unwrap();
    let context = context.unwrap();
    let dxgi: IDXGIDevice = device.cast()?;
    let wrt: IDirect3DDevice = unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi)? }.cast()?;
    Ok((device, context, wrt))
}

fn capture_wgc(
    raw: RawHwnd,
    d3d: &ID3D11Device,
    ctx: &ID3D11DeviceContext,
    wrt: &IDirect3DDevice,
) -> Result<(i32, i32, Vec<u8>, u32)> {
    let interop: IGraphicsCaptureItemInterop =
        windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(HWND(raw as *mut c_void))? };
    let size: SizeInt32 = item.Size()?;
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        wrt, DirectXPixelFormat::B8G8R8A8UIntNormalized, 1, size)?;
    let session = pool.CreateCaptureSession(&item)?;
    session.StartCapture()?;

    // Poll ~2s, counting every frame WGC delivers and keeping the last one.
    let mut frames = 0u32;
    let mut frame = None;
    for _ in 0..200 {
        unsafe { pump(10); }
        if let Ok(f) = pool.TryGetNextFrame() {
            frames += 1;
            frame = Some(f);
        }
    }
    let frame = match frame {
        Some(f) => f,
        None => { let _ = session.Close(); let _ = pool.Close(); return Ok((size.Width, size.Height, vec![], 0)); }
    };

    let surface = frame.Surface()?;
    let access: IDirect3DDxgiInterfaceAccess = surface.cast()?;
    let texture: ID3D11Texture2D = unsafe { access.GetInterface()? };

    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    let w = desc.Width as i32;
    let h = desc.Height as i32;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
    desc.MiscFlags = 0;

    let mut staging: Option<ID3D11Texture2D> = None;
    unsafe { d3d.CreateTexture2D(&desc, None, Some(&mut staging))? };
    let staging = staging.unwrap();
    unsafe { ctx.CopyResource(&staging, &texture) };

    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    unsafe { ctx.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))? };
    let mut out = vec![0u8; (w * h * 4) as usize];
    unsafe {
        let src = mapped.pData as *const u8;
        let pitch = mapped.RowPitch as usize;
        for y in 0..h as usize {
            std::ptr::copy_nonoverlapping(
                src.add(y * pitch),
                out.as_mut_ptr().add(y * (w as usize) * 4),
                (w as usize) * 4,
            );
        }
        ctx.Unmap(&staging, 0);
    }

    let _ = frame.Close();
    let _ = session.Close();
    let _ = pool.Close();
    Ok((w, h, out, frames))
}

fn main() -> Result<()> {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    unsafe {
        SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2);
        let _ = RoInitialize(RO_INIT_MULTITHREADED);
    }
    let (d3d, ctx, wrt) = make_device()?;

    let (normal, protected) = unsafe {
        let inst = GetModuleHandleW(null_mut());
        let cls = wide("WgcPocClass");
        let wc = WNDCLASSW {
            style: 0, lpfnWndProc: Some(wndproc), cbClsExtra: 0, cbWndExtra: 0,
            hInstance: inst, hIcon: 0, hCursor: LoadCursorW(0, 32512 as *const u16),
            hbrBackground: 0, lpszMenuName: null_mut(), lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);
        println!("Creating NORMAL window...");
        let n = make_window(inst, cls.as_ptr(), "NORMAL (leaks)", 120, false);
        println!("Creating PROTECTED window (WDA_EXCLUDEFROMCAPTURE)...");
        let p = make_window(inst, cls.as_ptr(), "PROTECTED", 580, true);
        pump(600);
        (n, p)
    };

    let (nw, nh, nbits, nfr) = capture_wgc(normal, &d3d, &ctx, &wrt)?;
    let (pw, ph, pbits, pfr) = capture_wgc(protected, &d3d, &ctx, &wrt)?;

    if !nbits.is_empty() { write_bmp(&format!("{out_dir}/wgc_normal.bmp"), nw, nh, &nbits); }
    if !pbits.is_empty() { write_bmp(&format!("{out_dir}/wgc_protected.bmp"), pw, ph, &pbits); }

    let nf = magenta_fraction(&nbits) * 100.0;
    let pf = magenta_fraction(&pbits) * 100.0;
    println!("\n=== Windows.Graphics.Capture result ===");
    println!("WGC NORMAL   : {nfr:3} frames, {nf:6.2}% magenta  (positive control - WGC must see this)");
    println!("WGC PROTECTED: {pfr:3} frames, {pf:6.2}% magenta  (claim under test - should be ~0)");
    let pass = nf > 50.0 && pf < 1.0;
    println!("\nVERDICT: {}", if pass {
        "PASS - WGC captured the normal window but the protected window was excluded."
    } else if nf <= 50.0 {
        "INCONCLUSIVE - WGC did not capture the control window; harness/compositor issue."
    } else {
        "FAIL - the protected window leaked through WGC."
    });

    unsafe { DestroyWindow(normal); DestroyWindow(protected); pump(50); }
    Ok(())
}
