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

## Design decisions

- Separate, self-contained scripts (no shared module/dot-sourced file). The
  helper functions are duplicated on purpose - keep copies in sync when editing.
- Config: `CertToolset.config.json` next to the scripts (gitignored), example
  tracked. Parameters override config; missing keys use built-in defaults.
- Store: Local Machine only (`$StoreLocation` in each script).
- Export passwords: interactive only (dialog, console fallback). Never add a
  password parameter.
- PEM: native PowerShell, one combined file (cert + chain + encrypted PKCS#8).
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
