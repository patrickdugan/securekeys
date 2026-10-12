# SecureKeys — threat model

## Asset

A short secret the user must enter on a Windows 11 machine (password, seed
phrase, recovery code, API token) in the moment between typing it and handing it
to a legitimate consumer (a login form, a wallet, a terminal).

## Trust assumptions

- The OS kernel, DWM, and the hardware are trusted. If they are compromised, no
  user-mode tool can help; that is out of scope.
- The user's own process runs at medium (or the user's) integrity. Malware
  already running at that integrity or higher is largely out of scope (it can
  read the target app after the secret arrives). SecureKeys reduces, not
  eliminates, exposure in that case.
- The target application that ultimately receives the secret is trusted with it.

## Adversaries and coverage

| Adversary | Mechanism | SecureKeys |
| --- | --- | --- |
| Commodity user-mode keylogger | `SetWindowsHookEx`, `GetAsyncKeyState`, raw input in another process | **Mitigated** — input is handled in-process; there is no global key event carrying the secret. |
| Screen recorder / screen-share leak | `Windows.Graphics.Capture`, Desktop Duplication | **Mitigated** — window excluded from capture (verified: 0 frames via WGC). |
| Screenshot-grabbing infostealer | `PrintWindow`, GDI `BitBlt`, DWM thumbnails | **Mitigated** — verified 0.00% of the secret captured. |
| Clipboard stealer | clipboard polling after paste | **Partially** — the clipboard hand-off auto-wipes after 20s, and **Shift+Enter autofill (`SendInput`) bypasses the clipboard entirely**, closing this channel. A stealer reading the clipboard within the 20s window (if you use Enter) still wins. |
| Memory scraper at same integrity | reading this process's heap | **Partially** — secret buffer is zeroized on use/clear, but a scraper reading between keypress and wipe can still win. No anti-dump guarantees. |
| Hardware keylogger | inline device between keyboard and PC | **Not covered** — below the OS. |
| Camera / shoulder surfing | photograph the screen | **Not covered** — physical. |
| Kernel / DWM-patching malware | patch the compositor or input stack | **Not covered** — above the app's privilege; trusted by assumption. |

## Why not keystroke encryption

The destination application must receive plaintext, so encrypting key events
only protects the driver→app hop and never the plaintext at the destination.
Better crypto cannot close that gap. Worse, the usual implementation ships a
kernel driver and injects a DLL into every protected app — net new attack
surface. SecureKeys therefore does not encrypt keystrokes; it removes the global
key event entirely (in-process input) and hides the window from capture.

## Design choices that follow from the model

- **No kernel driver, no DLL injection, no global hook.** Nothing is added to
  other processes or to the kernel; the whole attack surface is one hardened,
  user-mode process.
- **Exploit mitigations on.** CFG + CET shadow stack + (High-Entropy) ASLR, so a
  memory-safety bug is far harder to turn into code execution. (`0xC160` + CET.)
- **Minimise secret lifetime.** Rendered only as dots; zeroized on copy/clear;
  clipboard auto-wiped after 20s.
- **Prefer eliminating the secret.** The recommended path is passkeys / WebAuthn
  / Windows Hello, where there is no typed secret to steal at all; SecureKeys is
  the fallback for secrets that must still be typed or pasted.

## Known residual risks

- The clipboard hand-off is plaintext for up to 20s (or until overwritten).
- Same-integrity malware can read UI Automation / process memory / the clipboard
  in the brief window the secret exists.
- `WDA_EXCLUDEFROMCAPTURE` depends on DWM enforcing it; a future OS change or a
  capture path we have not tested could differ. The `selftest` and `wgc-capture`
  harnesses exist so this can be re-verified on any build.
