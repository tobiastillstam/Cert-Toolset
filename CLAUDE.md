# Cert-Toolset - project context for Claude Code

PowerShell toolset for certificate management on Windows Server.
Public repo. Owner: Tobias Tillstam / Tillnet. License: MIT.

## File layout

- `New-CertRequest.ps1` - generates a PKCS#10 CSR with certreq.
- `Test-CertRequest.ps1` - decodes CSRs and checks them against the policy.
- `Complete-CertRequest.ps1` - accepts CA responses, optionally exports
  PFX / PEM / JKS.
- `Export-CertBundle.ps1` - exports installed certificates from
  `Cert:\LocalMachine\My` as PFX / PEM / JKS.
- `CertToolset.config.example.json` - tracked example config.
- `PSScriptAnalyzerSettings.psd1` - analyzer settings.
- `README.md`, `CHANGELOG.md`, `LICENSE`, `.gitignore`, `.gitattributes`.
- Working folders (gitignored): `Requests/`, `Responses/`, `Exports/`, `Logs/`.

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
- PFX encryption: AES256_SHA256 by default. Server 2016 and older cannot
  import AES-encrypted PFX files; for those targets set
  `Export.PfxEncryption` to `TripleDES_SHA1`.
- PFX read-back is managed .NET (Pkcs12Info + key check), not the Windows PFX
  loader, which cannot open AES PFX files on older Windows. A loader failure is
  only a warning.
- JKS: native writer (Sun KeyProtector + "Mighty Aphrodite" digest), no Java
  dependency. Classic JKS on purpose: Java 8 < 8u301 cannot read AES PKCS12.
  Alias = Friendly Name lower-cased (Java looks aliases up in lower case).
  Opt-in only; never part of the default formats.
- Export folder = certificate CN (renewals share it); files = Friendly Name.
- `Test-CertRequest.ps1` has no `#Requires -RunAsAdministrator` on purpose
  (runs on many machines as non-admin).
- Never use hex literals >= 0x80000000 in these scripts - PowerShell versions
  disagree on whether they are negative.
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
  live systems.
