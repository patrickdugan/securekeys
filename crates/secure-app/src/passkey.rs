// passkey.rs — the "prefer passkeys" path via the native Windows WebAuthn API.
//
// A passkey means there is NO typed secret to steal: the private key lives in the
// TPM / Windows Hello and only a signature leaves the machine. This module:
//   * run_availability(): reports API version + platform-authenticator presence.
//   * run_demo(): the full flow — MakeCredential (enrol a credential, Windows
//     Hello prompt) then GetAssertion (authenticate with it, Hello prompt).
//
// Uses a non-resident (server-side) credential so it does not clutter the user's
// passkey list. Zero external deps — raw FFI to webauthn.dll + advapi32.

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr::null_mut;

type HWND = isize;

#[repr(C)]
struct RpInfo { dwVersion: u32, pwszId: *const u16, pwszName: *const u16, pwszIcon: *const u16 }
#[repr(C)]
struct UserInfo {
    dwVersion: u32, cbId: u32, pbId: *mut u8,
    pwszName: *const u16, pwszIcon: *const u16, pwszDisplayName: *const u16,
}
#[repr(C)]
struct CoseParam { dwVersion: u32, pwszCredentialType: *const u16, lAlg: i32 }
#[repr(C)]
struct CoseParams { cCredentialParameters: u32, pCredentialParameters: *const CoseParam }
#[repr(C)]
struct ClientData { dwVersion: u32, cbClientDataJSON: u32, pbClientDataJSON: *mut u8, pwszHashAlgId: *const u16 }
#[repr(C)]
struct Credential { dwVersion: u32, cbId: u32, pbId: *mut u8, pwszCredentialType: *const u16 }
#[repr(C)]
struct Credentials { cCredentials: u32, pCredentials: *mut Credential }
#[repr(C)]
struct Extensions { cExtensions: u32, pExtensions: *mut c_void }
#[repr(C)]
struct MakeCredOpts {
    dwVersion: u32,
    dwTimeoutMilliseconds: u32,
    CredentialList: Credentials,
    Extensions: Extensions,
    dwAuthenticatorAttachment: u32,
    bRequireResidentKey: i32,
    dwUserVerificationRequirement: u32,
    dwAttestationConveyancePreference: u32,
    dwFlags: u32,
}
#[repr(C)]
struct GetAssertOpts {
    dwVersion: u32,
    dwTimeoutMilliseconds: u32,
    CredentialList: Credentials,
    Extensions: Extensions,
    dwAuthenticatorAttachment: u32,
    dwUserVerificationRequirement: u32,
    dwFlags: u32,
}
// output structs (allocated by the API); we only read fields up to the ones named.
#[repr(C)]
struct CredAttestation {
    dwVersion: u32,
    pwszFormatType: *const u16,
    cbAuthenticatorData: u32,
    pbAuthenticatorData: *mut u8,
    cbAttestation: u32,
    pbAttestation: *mut u8,
    dwAttestationDecodeType: u32,
    pvAttestationDecode: *mut c_void,
    cbAttestationObject: u32,
    pbAttestationObject: *mut u8,
    cbCredentialId: u32,
    pbCredentialId: *mut u8,
}
#[repr(C)]
struct Assertion {
    dwVersion: u32,
    cbAuthenticatorData: u32,
    pbAuthenticatorData: *mut u8,
    cbSignature: u32,
    pbSignature: *mut u8,
}

const WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256: i32 = -7;
const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM: u32 = 1;
const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
const WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE: u32 = 3;

const WS_OVERLAPPED: u32 = 0x0000_0000;
const SW_SHOW: i32 = 5;

#[link(name = "webauthn")]
extern "system" {
    fn WebAuthNGetApiVersionNumber() -> u32;
    fn WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(p: *mut i32) -> i32;
    fn WebAuthNAuthenticatorMakeCredential(hwnd: HWND, rp: *const RpInfo, user: *const UserInfo,
        cose: *const CoseParams, cd: *const ClientData, opts: *const MakeCredOpts,
        out: *mut *mut CredAttestation) -> i32;
    fn WebAuthNAuthenticatorGetAssertion(hwnd: HWND, rpId: *const u16, cd: *const ClientData,
        opts: *const GetAssertOpts, out: *mut *mut Assertion) -> i32;
    fn WebAuthNFreeCredentialAttestation(p: *mut CredAttestation);
    fn WebAuthNFreeAssertion(p: *mut Assertion);
    fn WebAuthNGetErrorName(hr: i32) -> *const u16;
}
#[link(name = "advapi32")]
extern "system" {
    fn SystemFunction036(buf: *mut u8, len: u32) -> u8; // RtlGenRandom
}
#[link(name = "user32")]
extern "system" {
    fn CreateWindowExW(ex: u32, cls: *const u16, name: *const u16, style: u32,
        x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: isize, inst: isize, p: *mut c_void) -> HWND;
    fn ShowWindow(h: HWND, c: i32) -> i32;
    fn SetForegroundWindow(h: HWND) -> i32;
    fn DestroyWindow(h: HWND) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
}

fn w(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    unsafe { SystemFunction036(v.as_mut_ptr(), n as u32); }
    v
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(T[((n >> 6) & 63) as usize] as char); }
        if chunk.len() > 2 { out.push(T[(n & 63) as usize] as char); }
    }
    out
}

fn err_name(hr: i32) -> String {
    unsafe {
        let p = WebAuthNGetErrorName(hr);
        if p.is_null() { return format!("0x{hr:08X}"); }
        let mut len = 0;
        while *p.add(len) != 0 { len += 1; }
        let s = std::slice::from_raw_parts(p, len);
        format!("{} (0x{hr:08X})", String::from_utf16_lossy(s))
    }
}

unsafe fn ui_window() -> HWND {
    let cls = w("STATIC");
    let title = w("SecureKeys passkey");
    let inst = GetModuleHandleW(null_mut());
    let h = CreateWindowExW(0, cls.as_ptr(), title.as_ptr(), WS_OVERLAPPED,
        300, 300, 360, 120, 0, 0, inst, null_mut());
    ShowWindow(h, SW_SHOW);
    SetForegroundWindow(h);
    h
}

pub fn run_availability() {
    unsafe {
        let ver = WebAuthNGetApiVersionNumber();
        let mut avail: i32 = 0;
        let hr = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&mut avail);
        println!("WebAuthn / passkey platform check:");
        println!("  WebAuthn API version          : {ver}");
        println!("  Platform authenticator (Hello): {} (hr=0x{:08X})",
            if avail != 0 { "AVAILABLE" } else { "not available" }, hr);
        println!("A passkey login means no typed secret exists to steal — the preferred path.");
        println!("Run `securekeys passkey-demo` for the full MakeCredential + GetAssertion flow.");
    }
}

pub fn run_demo() -> i32 {
    unsafe {
        let hwnd = ui_window();
        let rp_id = w("securekeys.local");
        let rp_name = w("SecureKeys Demo");
        let user_name = w("demo@securekeys.local");
        let user_display = w("SecureKeys Demo User");
        let cred_type = w("public-key");
        let hash = w("SHA-256");

        let challenge = rand_bytes(32);
        let mut user_id = rand_bytes(16);

        let create_json = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://securekeys.local\",\"crossOrigin\":false}}",
            b64url(&challenge));
        let mut create_bytes = create_json.into_bytes();

        let rp = RpInfo { dwVersion: 1, pwszId: rp_id.as_ptr(), pwszName: rp_name.as_ptr(), pwszIcon: null_mut() };
        let user = UserInfo {
            dwVersion: 1, cbId: user_id.len() as u32, pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_ptr(), pwszIcon: null_mut(), pwszDisplayName: user_display.as_ptr(),
        };
        let cose = CoseParam { dwVersion: 1, pwszCredentialType: cred_type.as_ptr(), lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 };
        let coses = CoseParams { cCredentialParameters: 1, pCredentialParameters: &cose };
        let cd = ClientData {
            dwVersion: 1, cbClientDataJSON: create_bytes.len() as u32,
            pbClientDataJSON: create_bytes.as_mut_ptr(), pwszHashAlgId: hash.as_ptr(),
        };
        let opts = MakeCredOpts {
            dwVersion: 1, dwTimeoutMilliseconds: 60_000,
            CredentialList: Credentials { cCredentials: 0, pCredentials: null_mut() },
            Extensions: Extensions { cExtensions: 0, pExtensions: null_mut() },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            bRequireResidentKey: 0, // non-resident: won't clutter the passkey list
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            dwFlags: 0,
        };

        println!("Passkey full flow (Windows Hello will prompt twice)...");
        println!("  [1/2] MakeCredential — enrol a credential for RP 'securekeys.local'");
        let mut att: *mut CredAttestation = null_mut();
        let hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &coses, &cd, &opts, &mut att);
        if hr != 0 || att.is_null() {
            println!("  MakeCredential FAILED: {}", err_name(hr));
            DestroyWindow(hwnd);
            return 1;
        }
        let cred_id = {
            let a = &*att;
            std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec()
        };
        println!("  credential created: id = {} bytes, prefix {}",
            cred_id.len(),
            cred_id.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>());
        WebAuthNFreeCredentialAttestation(att);

        // [2/2] GetAssertion with that credential
        println!("  [2/2] GetAssertion — authenticate with the new credential");
        let get_challenge = rand_bytes(32);
        let get_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://securekeys.local\",\"crossOrigin\":false}}",
            b64url(&get_challenge));
        let mut get_bytes = get_json.into_bytes();
        let mut cred_id_mut = cred_id.clone();
        let mut allow = Credential {
            dwVersion: 1, cbId: cred_id_mut.len() as u32, pbId: cred_id_mut.as_mut_ptr(),
            pwszCredentialType: cred_type.as_ptr(),
        };
        let gcd = ClientData {
            dwVersion: 1, cbClientDataJSON: get_bytes.len() as u32,
            pbClientDataJSON: get_bytes.as_mut_ptr(), pwszHashAlgId: hash.as_ptr(),
        };
        let gopts = GetAssertOpts {
            dwVersion: 1, dwTimeoutMilliseconds: 60_000,
            CredentialList: Credentials { cCredentials: 1, pCredentials: &mut allow },
            Extensions: Extensions { cExtensions: 0, pExtensions: null_mut() },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: 0,
        };
        let mut asrt: *mut Assertion = null_mut();
        let hr2 = WebAuthNAuthenticatorGetAssertion(hwnd, rp_id.as_ptr(), &gcd, &gopts, &mut asrt);
        let ok = if hr2 == 0 && !asrt.is_null() {
            let sig = (*asrt).cbSignature;
            println!("  assertion OK: signature = {sig} bytes (private key never left the TPM)");
            WebAuthNFreeAssertion(asrt);
            true
        } else {
            println!("  GetAssertion FAILED: {}", err_name(hr2));
            false
        };

        for b in user_id.iter_mut() { *b = 0; }
        DestroyWindow(hwnd);
        println!("\nRESULT: {}", if ok { "PASS — passkey created and used, no typed secret involved." } else { "FAIL" });
        if ok { 0 } else { 1 }
    }
}
