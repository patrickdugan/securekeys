// verify.rs — Authenticode signature verification via WinVerifyTrust.
//
// This is the security-critical half of safe auto-update: before running any
// downloaded update, verify it carries a valid, trusted Authenticode signature.
// The HTTPS download itself can be MITM'd; this check is what makes substitution
// of a malicious binary fail. (The download + an update server are not built —
// see README; this is the part that does not need external infrastructure.)
//
// `securekeys verifysig <path>` -> exit 0 if the file is validly signed & trusted.

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
struct GUID { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }

#[repr(C)]
struct WINTRUST_FILE_INFO {
    cbStruct: u32,
    pcwszFilePath: *const u16,
    hFile: isize,
    pgKnownSubject: *mut GUID,
}
#[repr(C)]
struct WINTRUST_DATA {
    cbStruct: u32,
    pPolicyCallbackData: *mut c_void,
    pSIPClientData: *mut c_void,
    dwUIChoice: u32,
    fdwRevocationChecks: u32,
    dwUnionChoice: u32,
    pFile: *mut WINTRUST_FILE_INFO, // union member (all members are pointers)
    dwStateAction: u32,
    hWVTStateData: isize,
    pwszURLReference: *const u16,
    dwProvFlags: u32,
    dwUIContext: u32,
    pSignatureSettings: *mut c_void,
}

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_SAFER_FLAG: u32 = 0x100;

// WINTRUST_ACTION_GENERIC_VERIFY_V2
const ACTION: GUID = GUID {
    d1: 0x00AAC56B, d2: 0xCD44, d3: 0x11d0,
    d4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: isize, action: *const GUID, data: *mut c_void) -> i32;
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn describe(hr: i32) -> &'static str {
    match hr as u32 {
        0 => "valid, signed and trusted",
        0x800B0100 => "NOT signed (TRUST_E_NOSIGNATURE)",
        0x800B0111 => "untrusted root (CERT_E_UNTRUSTEDROOT)",
        0x800B010C => "certificate revoked (CERT_E_REVOKED)",
        0x800B0101 => "certificate expired (CERT_E_EXPIRED)",
        0x80096010 => "bad digest — file was modified (TRUST_E_BAD_DIGEST)",
        0x800B010A => "no chain to a trusted root (CERT_E_CHAINING)",
        _ => "not trusted",
    }
}

pub fn run_verify(path: &str) -> i32 {
    let wpath = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wpath.as_ptr(),
        hFile: 0,
        pgKnownSubject: null_mut(),
    };
    let mut wtd = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        pFile: &mut file,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: 0,
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_SAFER_FLAG,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };
    unsafe {
        let hr = WinVerifyTrust(0, &ACTION, &mut wtd as *mut _ as *mut c_void);
        println!("Authenticode check: {path}");
        println!("  -> {} (hr=0x{:08X})", describe(hr), hr as u32);
        // release the state data
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(0, &ACTION, &mut wtd as *mut _ as *mut c_void);
        if hr == 0 { 0 } else { 1 }
    }
}
