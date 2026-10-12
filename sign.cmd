@echo off
rem Authenticode-sign the SecureKeys binary. REQUIRES your own code-signing
rem certificate. Without a cert this cannot sign -- that is intentional.
rem
rem 1) signtool.exe ships with the Windows SDK, typically under:
rem      C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe
rem
rem 2) Sign the binary (choose ONE):
rem    (A) certificate in the Windows certificate store, auto-selected:
rem        signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 "<exe>"
rem    (B) certificate from a PFX file:
rem        signtool sign /fd SHA256 /f your-cert.pfx /p <password> /tr http://timestamp.digicert.com /td SHA256 "<exe>"
rem
rem 3) Verify the signature:
rem        signtool verify /pa "<exe>"
rem        securekeys verifysig "<exe>"
rem
rem Default target: %LOCALAPPDATA%\securekeys-build\release\securekeys.exe
echo sign.cmd is a template -- open it and run the steps with your own certificate.
