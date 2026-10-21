# Cert-Toolset - project context for Claude Code

PowerShell toolset for certificate management on Windows Server.
Public repo. Owner: Tobias Tillstam / Tillnet. License: MIT.

## Status

- 2026-10-16: four scripts reworked from Tobias's CSR scripts and aligned to
  the house template (see CHANGELOG). Tested in user context on Windows 11
  (PS 5.1 + 7.6, PEM verified with OpenSSL).
- 2026-10-16: elevated test round passed against the Local Machine store with a
  lab CA (root + issuing CA): real certreq -accept, -InstallRootCA, password
  dialog, PFX/PEM verified with OpenSSL. Fixes from it: batch-wide chain
  collection, leaf-only certreq input, WhatIf exports, exit codes, short host
  names. Not yet tested: actual removal by -RemoveStaleRequests; a real
  (non-lab) CA.
- 2026-10-20: documentation/comment review; released publicly as v1.0.0.
- 2026-10-20: v1.1.0 - .NET PFX writer on PowerShell 7 after
  `Export-PfxCertificate` was not found on PS 7.0 / Server 2016. Tested here on
  PS 5.1 + 7.6 (OpenSSL + certutil); not yet run on PS 7.0 itself.
  First PS 7.0 run: the read-back via the Windows PFX loader failed, because
  Server 2016 cannot open AES PFX files. Read-back is now managed .NET
  (Pkcs12Info + C# key check); the Windows loader result is only a warning.
  Confirmed on PS 7.0 / Server 2016 with a real (non-lab) CA certificate:
  AES PFX + PEM exported, full chain, managed check passed, expected warning.
- 2026-10-21: v1.2.0 - export folder = certificate CN (no _yyyyMM); opt-in JKS
  export for a Java 8u161 / Tomcat 7 target. JKS verified with Java 8 keytool
  (list, key recovery via -importkeystore, key matches cert) on PS 5.1 + 7.6
  with a test chain in CurrentUser. Not yet tested: elevated end-to-end run,
  Tomcat loading the JKS.
- 2026-10-21: v1.2.1 - first real run (PS 7.0) failed the JKS read-back:
  PS 7.0 parses `0xFEEDFEEDL` as negative. Fixed (no large hex literals);
  reproduced and verified with a portable PS 7.0.13 + keytool. Rule: never use
  hex literals >= 0x80000000 in these scripts - PS versions disagree on them.

## Design decisions

- Separate, self-contained scripts (no shared module/dot-sourced file). The
  helper functions are duplicated on purpose - keep copies in sync when editing.
- Config: `CertToolset.config.json` next to the scripts (gitignored), example
  tracked. Parameters override config; missing keys use built-in defaults.
- Store: Local Machine only (`$StoreLocation` in each script).
- Export passwords: interactive only (dialog, console fallback). Never add a
  password parameter.
- PEM: native PowerShell, one combined file (cert + chain + encrypted PKCS#8).
- PFX: `Export-PfxCertificate` on PS 5.1, .NET `Pkcs12Builder` on PS 7 (the PKI
  module is Windows PowerShell-only). No OpenSSL dependency.
- JKS: native writer (Sun KeyProtector + "Mighty Aphrodite" digest), no Java
  dependency. Classic JKS on purpose: Java 8 < 8u301 cannot read AES PKCS12.
  Alias = Friendly Name lower-cased (Java looks aliases up in lower case).
  Opt-in only; never part of the default formats.
- Export folder = certificate CN (renewals share it); files = Friendly Name.
- `Test-CertRequest.ps1` has no `#Requires -RunAsAdministrator` on purpose
  (runs on many machines as non-admin).
- Static analysis: `Invoke-ScriptAnalyzer -Path . -Settings .\PSScriptAnalyzerSettings.psd1`.

## Coding conventions (house template)

The scripts follow the Tillnet PowerShell house template (the owner's global
CLAUDE.md); the rules below are the parts that matter in this repo.

- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator`.
- `[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]`.
- Every parameter `[Parameter(Mandatory = $false)]` with a comment above it.
- `.NOTES` block: Author, Webpage, GitHub, Version, Date Created,
  Last Modified, Change Log, Operational notes.
- `# ---...---` section banners; Write-Verbose Starting/Finished bookends.
- Single flat try/catch/finally; catch is `Write-Error $_; throw`.
- Pure ASCII. ShouldProcess only on real state changes.
- Remediation opt-in via named switches, never a catch-all `-Fix`.
- Log/output dirs default to `$PSScriptRoot`, fallback `(Get-Location).Path`.

## Repo hygiene

- `.gitignore` blocks certificate material (*.pfx, *.key, *.pem, *.cer, ...).
  Never commit keys, exported certs or real thumbprints/hostnames from
  client environments.
