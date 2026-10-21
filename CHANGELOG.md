# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-21

### Added
- Java KeyStore (JKS) export, opt-in: `-ExportJks` in `Complete-CertRequest.ps1`
  1.3.0 and `-Format Jks` in `Export-CertBundle.ps1` 1.2.0 (the default formats
  stay PFX and PEM). Classic JKS, as read by Java 8 / Tomcat 7 with
  `keystoreType="JKS"`: private key and full chain under the alias
  `<FriendlyName>` (lower case), one password for keystore and key. Written
  natively (no Java needed) and read back before it is saved (integrity digest,
  chain, private key). Verified with Java 8 `keytool`.

### Changed
- Export folder is now the certificate's CN instead of the Friendly Name, so the
  `_yyyyMM` date is gone from folder names and renewals share a folder
  (`Exports\app01.contoso.local\app01.contoso.local_202610.pfx`). File names
  keep the full Friendly Name. Certificates without a CN use the Friendly Name
  as before. Existing exports in `Exports\<FriendlyName>\` are not moved.
- Password dialog text mentions PFX/PEM/JKS.

## [1.1.0] - 2026-10-20

### Changed
- `Export-CertBundle.ps1` 1.1.0 and `Complete-CertRequest.ps1` 1.2.0: on
  PowerShell 7 the PFX is written with .NET (`Pkcs12Builder`) instead of
  `Export-PfxCertificate`. Same layout and algorithms (AES256-SHA256 or
  TripleDES-SHA1, chain included, Friendly Name kept). Before it is saved, the
  file is checked in .NET (MAC, certificates, private key against the
  certificate), independent of the Windows PFX loader. The log names the PFX
  writer.
- Warning when Windows on the exporting machine cannot open AES-encrypted PFX
  files (Server 2016 and older), with the `TripleDES_SHA1` hint. README:
  troubleshooting entry for "The specified network password is not correct".

### Fixed
- `Export-PfxCertificate` not recognized on PowerShell 7.0 (e.g. Server 2016),
  which does not auto-load the Windows PKI module. The PKI module is now only
  looked up when a PFX is requested, so PEM-only exports never need it.

## [1.0.0] - 2026-10-20

First public release.

### Added
- Repository scaffold: README, CHANGELOG, LICENSE (MIT), `.gitignore`,
  `.gitattributes`, CLAUDE.md.
- `New-CertRequest.ps1` 1.0.0 (from New-Csr.ps1 0.3.0): JSON config, transcript,
  IP SANs and IP as CN, Subject/key-length overrides, no silent overwrites,
  pending-request collision check, `-WhatIf` creates nothing.
- `Test-CertRequest.ps1` 1.0.0 (from Test-Csr.ps1 0.1.0): structured decoding
  via CertEnroll, signature/CN-in-SAN/Key Usage/EKU/Subject checks, files or
  folders, exit code, `-PassThru`. Runs without admin rights.
- `Complete-CertRequest.ps1` 1.0.0 (from Complete_CSR.ps1 0.2.0): responses
  matched by public key, `.crt`/`.pem`/`.p7b`/full-chain input, intermediates
  installed, opt-in PFX/PEM export, password dialog, `-RemoveStaleRequests`,
  chain trust check with operator steps before certreq, `-InstallRootCA`.
- `Export-CertBundle.ps1` 1.0.0: list and re-export installed certificates.
- Native encrypted PEM export (PBES2, PBKDF2-SHA256 + AES-256-CBC).
- `CertToolset.config.example.json`, `PSScriptAnalyzerSettings.psd1`.

### Changed (after the elevated test round, 2026-10-16)
- `Complete-CertRequest.ps1` 1.1.0: CA certificates are collected from all
  response files first, so a leaf-only response no longer fails when its chain
  is in another file of the same run. Only the CAs of the certificate's own
  chain are installed; the log names the file each CA came from.
- `Complete-CertRequest.ps1`: `certreq -accept` always gets the leaf only, so it
  no longer copies the root CA into `Cert:\LocalMachine\CA` from a `.p7b`.
- `Complete-CertRequest.ps1`: `-WhatIf` shows the planned PFX/PEM exports and
  warns about existing export files.
- `Complete-CertRequest.ps1` and `Export-CertBundle.ps1` (1.0.1): exit code 1
  when a response or export failed.
- `Complete-CertRequest.ps1`: clear error for files that are not certificates.
- `New-CertRequest.ps1` 1.1.0: short host names (no domain) allowed as CN and
  `-DnsName`, with a warning.
- README: wildcard example for `Export-CertBundle.ps1 -FriendlyName` fixed
  (`[*].contoso.com*`; the Friendly Name keeps the `*`).
- Documentation and comment review before the public release: README lists
  `.p7c` responses, untested areas and a Development section; parameter and
  helper comments corrected; `.ps1`/`.psd1` checked out with CRLF.

### Fixed (compared to the original scripts)
- Test: the "Key Usage present" check also matched "Enhanced Key Usage".
- Complete: every response was reported as failed under `-WhatIf`.
- New: `-WhatIf` created folders; declining the INF step under `-Confirm`
  still ran certreq against a missing/stale INF.

[Unreleased]: https://github.com/tobiastillstam/Cert-Toolset/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/tobiastillstam/Cert-Toolset/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/tobiastillstam/Cert-Toolset/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tobiastillstam/Cert-Toolset/releases/tag/v1.0.0
