# SecureKeys

A small, honest, modern successor to keystroke-encryption anti-keylogger tools
(e.g. QFX KeyScrambler), for **Windows 11**. Zero external dependencies in the
app; no kernel driver, no DLL injection.

## Why this instead of "keystroke encryption"

Keystroke-encryption tools encrypt key events between the keyboard driver and
the target application, then decrypt them inside that application. That model is
a dead end: **the application must end up with the plaintext**, so any code
running at your privilege level can read it after decryption (UI Automation,
reading the edit control, screen scraping, clipboard, form-grabbers). It also
only defends a short local hop and adds large attack surface — in KeyScrambler's
case a non-mitigated legacy **kernel driver** and a **DLL-side-loading** pattern
abused in the wild.

SecureKeys takes the opposite approach:

- **Capture exclusion.** The secure window sets
  `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`, so it is visible to
  you but omitted from screen capture. Verified (below) to block `PrintWindow`,
  GDI `BitBlt`, and `Windows.Graphics.Capture` (the API behind OBS, Teams/Zoom
  share, the Snipping Tool and Xbox Game Bar).
- **In-process input.** The secret is handled entirely inside the one process
  (`WM_CHAR`), never via a global keyboard hook, injected DLL, or kernel driver.
  It is rendered only as dots — the plaintext is never drawn.
- **Safe hand-off, two ways.** On **Enter** the secret goes to the clipboard and
  is **auto-wiped after 20 seconds**. On **Shift+Enter** it is typed straight
  into the window that had focus before SecureKeys (synthetic Unicode keystrokes
  via `SendInput`) — **no clipboard involved**. Either way the in-memory buffer
  is zeroized immediately.
- **Hardened binary.** Built with Control Flow Guard, CET shadow stack and
  (High-Entropy) ASLR — `DllCharacteristics 0xC160` + CET, versus KeyScrambler's
  kernel driver at `0x0000`.

## What it does NOT protect against (by design — no software can)

- Hardware keyloggers / HDMI capture cards (they sit below the OS).
- A camera pointed at the screen.
- Kernel-mode or DWM-patching malware (runs above the app).
- Anything already executing at your privilege that reads the target app's text
  after you paste it.

The honest value is against commodity user-mode keyloggers, accidental/malicious
screen-share and screen-recorder leaks, and screenshot-grabbing infostealers.
For the typed-secret problem more broadly, prefer **passkeys / WebAuthn /
Windows Hello** (nothing to type) — SecureKeys is for the residual cases where
you must type or paste a secret.

## Verified capture-exclusion (run it yourself: `securekeys selftest`)

Two identical windows paint the same secret; one has the exclusion flag. The
secret must survive in the NORMAL window and vanish in the PROTECTED one.

| Capture method | Used by | NORMAL (control) | PROTECTED |
| --- | --- | --- | --- |
| GDI `PrintWindow` | thumbnailers, some stealers | 76.75% | **0.00%** |
| GDI screen `BitBlt` | legacy screenshot stealers | 76.70% | **0.00%** |
| `Windows.Graphics.Capture` | OBS, Teams/Zoom, Snipping Tool, Game Bar | 1 frame, 82.62% | **0 frames** |

The WGC check lives in the separate `wgc-capture` crate (it needs Direct3D11 +
WinRT via the official `windows` crate; the app itself stays dependency-free).

## Layout

```
securekeys/
  crates/secure-app/     the SecureKeys app (zero deps)        -> securekeys.exe
  crates/wgc-capture/    WGC verification harness (windows crate)
  build.cmd  inspect.cmd
```

## Build (Windows)

Requires: rustup with the `stable-x86_64-pc-windows-msvc` toolchain, and
Visual Studio **Build Tools 2022** (for `link.exe` + CFG/CET). Then:

```bat
build.cmd            :: builds the whole workspace with the hardening flags
inspect.cmd          :: dumps the mitigation flags from securekeys.exe
```

Binaries land in `%LOCALAPPDATA%\securekeys-build\release\` (kept out of OneDrive).

## Run

```bat
securekeys            :: run in the tray; Ctrl+Alt+S opens the secure window
                      ::   Enter = clipboard (auto-wipe)   Shift+Enter = type into last app   Esc = clear
securekeys selftest   :: prove capture exclusion (PrintWindow + BitBlt); exit 0 = pass
securekeys demo <dir> :: masking demo -> demo_masked.bmp (dots only) / demo_excluded.bmp (blank)
securekeys injecttest :: verify the SendInput Unicode autofill path; exit 0 = pass
securekeys passkey    :: report Windows WebAuthn API version + platform-authenticator (Hello) availability
securekeys passkey-demo :: full passkey flow — MakeCredential + GetAssertion via Windows Hello (2 prompts)
securekeys verifysig <path> :: Authenticode-verify a file (the safe-update gate); exit 0 = signed & trusted
securekeys store <name> :: enter a secret in the secure window -> Windows Credential Manager (DPAPI-protected)
securekeys get <name>   :: vault -> clipboard
securekeys list         :: list stored SecureKeys secrets
securekeys forget <name> :: delete a stored secret
securekeys credtest     :: automated vault write/read/delete round-trip; exit 0 = pass
securekeys smoke      :: init window + tray + hotkey, then exit (crash-free check)
```

## Updates, signing, and password managers

- **Authenticode verification** (`verifysig`) is implemented — this is the gate
  that makes auto-update safe: a downloaded update is only run if it carries a
  valid, trusted signature, so a MITM on the download cannot substitute a
  malicious binary. It needs no external infrastructure and is testable today.
- **Code-signing** (`sign.cmd`) is a template around `signtool`. It cannot sign
  without a code-signing certificate you supply — by design.
- **HTTPS update download + an update server** are *not* built: they require a
  server you host and a signing cert. The design is: fetch a signed version
  manifest over HTTPS → download → `verifysig` → run. Only the verify step is
  implemented so far.
- **Password-manager integration** is implemented against Windows' own built-in
  vault — the **Credential Manager** (`store` / `get` / `list` / `forget`).
  Secrets are DPAPI-protected by Windows under `SecureKeys/<name>`; no third-party
  manager required. Verified by `credtest`. Prefer passkeys where the site
  supports them — then there is no secret for a manager to hold at all.

## Status / roadmap

Working: capture-excluded hardened secure window; masked in-process input;
**clipboard hand-off with auto-wipe**; **Shift+Enter autofill into the previous
window via `SendInput`** (verified by `injecttest`); global hotkey; tray icon;
**full passkey flow** — `WebAuthNAuthenticatorMakeCredential` + `GetAssertion`
via Windows Hello (`passkey` / `passkey-demo`); **Authenticode verification**
(`verifysig`); **secret storage in the Windows Credential Manager** (`store` /
`get` / `list` / `forget`, verified by `credtest`); built-in `selftest`; and the
WGC verification harness.

Not built yet: HTTPS update download + an update server; a real code-signing
cert (both need infrastructure/a cert you own).

See [THREAT_MODEL.md](THREAT_MODEL.md).
