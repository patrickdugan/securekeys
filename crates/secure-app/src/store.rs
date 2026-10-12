// store.rs — secret storage via the Windows Credential Manager.
//
// This is the "password-manager integration" done the honest way: instead of
// depending on a third-party manager, SecureKeys uses Windows' own built-in,
// DPAPI-protected credential vault (CredWriteW/CredReadW). Secrets are stored
// under the target prefix "SecureKeys/<name>" as CRED_TYPE_GENERIC.
//
//   securekeys store <name>   enter a secret (secure window) -> vault
//   securekeys get <name>     vault -> clipboard
//   securekeys list           list stored SecureKeys secrets
//   securekeys forget <name>  delete one
//   securekeys credtest       automated write/read/delete round-trip (exit 0 = pass)

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
struct FILETIME { low: u32, high: u32 }
#[repr(C)]
struct CREDENTIALW {
    Flags: u32,
    Type: u32,
    TargetName: *mut u16,
    Comment: *mut u16,
    LastWritten: FILETIME,
    CredentialBlobSize: u32,
    CredentialBlob: *mut u8,
    Persist: u32,
    AttributeCount: u32,
    Attributes: *mut c_void,
    TargetAlias: *mut u16,
    UserName: *mut u16,
}

const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
const CF_UNICODETEXT: u32 = 13;
const GMEM_MOVEABLE: u32 = 0x0002;

#[link(name = "advapi32")]
extern "system" {
    fn CredWriteW(cred: *const CREDENTIALW, flags: u32) -> i32;
    fn CredReadW(target: *const u16, typ: u32, flags: u32, cred: *mut *mut CREDENTIALW) -> i32;
    fn CredDeleteW(target: *const u16, typ: u32, flags: u32) -> i32;
    fn CredEnumerateW(filter: *const u16, flags: u32, count: *mut u32, creds: *mut *mut *mut CREDENTIALW) -> i32;
    fn CredFree(buf: *mut c_void);
}
#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(h: isize) -> i32;
    fn EmptyClipboard() -> i32;
    fn SetClipboardData(format: u32, mem: isize) -> isize;
    fn CloseClipboard() -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GlobalAlloc(flags: u32, bytes: usize) -> isize;
    fn GlobalLock(mem: isize) -> *mut c_void;
    fn GlobalUnlock(mem: isize) -> i32;
    fn GlobalFree(mem: isize) -> isize;
    fn GetLastError() -> u32;
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
fn target_of(name: &str) -> String { format!("SecureKeys/{name}") }

/// Write raw secret bytes to the vault under SecureKeys/<name>. Returns success.
pub fn write(name: &str, data: &[u8]) -> bool {
    let mut tn = wide(&target_of(name));
    let mut blob = data.to_vec();
    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: tn.as_mut_ptr(),
        Comment: null_mut(),
        LastWritten: FILETIME { low: 0, high: 0 },
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: null_mut(),
        TargetAlias: null_mut(),
        UserName: null_mut(),
    };
    let ok = unsafe { CredWriteW(&cred, 0) != 0 };
    for b in blob.iter_mut() { *b = 0; } // wipe our copy
    ok
}

/// Read secret bytes from the vault. Returns None if absent.
pub fn read(name: &str) -> Option<Vec<u8>> {
    let tn = wide(&target_of(name));
    let mut p: *mut CREDENTIALW = null_mut();
    unsafe {
        if CredReadW(tn.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) == 0 || p.is_null() {
            return None;
        }
        let c = &*p;
        let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec();
        CredFree(p as *mut c_void);
        Some(bytes)
    }
}

pub fn delete(name: &str) -> bool {
    let tn = wide(&target_of(name));
    unsafe { CredDeleteW(tn.as_ptr(), CRED_TYPE_GENERIC, 0) != 0 }
}

fn copy_to_clipboard(s: &str) -> bool {
    let mut data: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = data.len() * 2;
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if mem == 0 { return false; }
        let p = GlobalLock(mem) as *mut u16;
        if p.is_null() { GlobalFree(mem); return false; }
        std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
        GlobalUnlock(mem);
        let ok = if OpenClipboard(0) != 0 {
            EmptyClipboard();
            let set = SetClipboardData(CF_UNICODETEXT, mem) != 0;
            CloseClipboard();
            if !set { GlobalFree(mem); }
            set
        } else {
            GlobalFree(mem);
            false
        };
        for x in data.iter_mut() { *x = 0; }
        ok
    }
}

pub fn run_get(name: &str) -> i32 {
    match read(name) {
        Some(bytes) => {
            let s = String::from_utf8_lossy(&bytes).to_string();
            let ok = copy_to_clipboard(&s);
            println!("'{name}': {}", if ok {
                "copied to clipboard — paste now (CLI get does not auto-wipe; clear it after use)"
            } else {
                "FAILED to set clipboard"
            });
            if ok { 0 } else { 1 }
        }
        None => { println!("'{name}' not found in the vault."); 1 }
    }
}

pub fn run_forget(name: &str) -> i32 {
    if delete(name) { println!("deleted '{name}'."); 0 }
    else { println!("'{name}' not found."); 1 }
}

pub fn run_list() -> i32 {
    let filter = wide("SecureKeys/*");
    let mut count: u32 = 0;
    let mut arr: *mut *mut CREDENTIALW = null_mut();
    unsafe {
        if CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut arr) == 0 {
            let e = GetLastError();
            if e == 1168 { println!("no SecureKeys secrets stored."); return 0; } // ERROR_NOT_FOUND
            println!("enumerate failed (err {e})");
            return 1;
        }
        println!("stored SecureKeys secrets ({count}):");
        for i in 0..count as isize {
            let c = &**arr.offset(i);
            let mut len = 0;
            while *c.TargetName.add(len) != 0 { len += 1; }
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(c.TargetName, len));
            println!("  {}", name.strip_prefix("SecureKeys/").unwrap_or(&name));
        }
        CredFree(arr as *mut c_void);
    }
    0
}

/// Automated proof: write a test secret, read it back, confirm, then delete.
pub fn run_credtest() -> i32 {
    let name = "__credtest__";
    let secret = "vault-round-trip-世界-7788";
    let wrote = write(name, secret.as_bytes());
    let got = read(name).map(|b| String::from_utf8_lossy(&b).to_string());
    let deleted = delete(name);
    let gone = read(name).is_none();
    println!("Windows Credential Manager round-trip:");
    println!("  write  : {}", if wrote { "ok" } else { "FAILED" });
    println!("  read   : {}", got.as_deref().unwrap_or("(none)"));
    println!("  delete : {} (absent after delete: {})", if deleted { "ok" } else { "FAILED" }, gone);
    let pass = wrote && got.as_deref() == Some(secret) && deleted && gone;
    println!("RESULT: {}", if pass { "PASS" } else { "FAIL" });
    if pass { 0 } else { 1 }
}
