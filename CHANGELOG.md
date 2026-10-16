# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed (compared to the original scripts)
- Test: the "Key Usage present" check also matched "Enhanced Key Usage".
- Complete: every response was reported as failed under `-WhatIf`.
- New: `-WhatIf` created folders; declining the INF step under `-Confirm`
  still ran certreq against a missing/stale INF.
