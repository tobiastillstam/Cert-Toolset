# Cert-Toolset

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Platform](https://img.shields.io/badge/Windows%20Server-certificates-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-0.1.0-blue)

PowerShell toolset for certificate management on Windows Server: create a CSR,
check it, complete it with the CA response, and export the certificate as PFX
and/or PEM for this or other machines and appliances.

Built on Windows tools only (certreq, CertEnroll, .NET). No OpenSSL needed.

---

## Workflow

```text
New-CertRequest.ps1      ->  Requests\<name>.csr          send to the CA
Test-CertRequest.ps1     ->  PASS/FAIL against the policy (optional)
   ... CA signs ...      ->  drop the reply in Responses\
Complete-CertRequest.ps1 ->  installed in LocalMachine\My
                             Exports\<name>\<name>.pfx / .pem  (opt-in)
Export-CertBundle.ps1    ->  re-export an installed certificate later
```

---

## Scripts

| Script | Purpose | Admin |
|---|---|---|
| `New-CertRequest.ps1` | Builds a certreq INF and CSR. CN can be an FQDN, wildcard or IP; extra DNS and IP SANs. Key stays pending in `Cert:\LocalMachine\REQUEST`. | Yes |
| `Test-CertRequest.ps1` | Decodes CSRs (file or folder) and checks key, hash, SANs, CN-in-SAN, Key Usage, EKU, Subject and signature. Exit code 1 on failure. | **No** |
| `Complete-CertRequest.ps1` | Installs CA responses (`.cer` `.crt` `.pem` `.p7b`, full chain OK) with `certreq -accept`, adds missing intermediates, checks the chain is trusted (opt-in `-InstallRootCA`), optional PFX/PEM export, moves responses to `Completed\`. Optional cleanup of stale pending requests. | Yes |
| `Export-CertBundle.ps1` | Lists or exports installed certificates (by thumbprint or Friendly Name) as PFX/PEM. | Yes |

Every script supports `-WhatIf`, `-Confirm` and `-Verbose`, and writes a
transcript to `Logs\`. Run `Get-Help .\<script>.ps1 -Full` for all parameters.

---

## Quick start

```powershell
# One-time: create your config from the example
Copy-Item .\CertToolset.config.example.json .\CertToolset.config.json
notepad .\CertToolset.config.json

# 1. Request (wildcard + apex, plus an IP SAN)
.\New-CertRequest.ps1 -CommonName '*.contoso.com' -DnsName 'contoso.com' -IpAddress '10.0.0.20'

# 2. Check it
.\Test-CertRequest.ps1 -Path .\Requests

# 3. After the CA replies: put the file in .\Responses, then
.\Complete-CertRequest.ps1 -ExportPfx -ExportPem

# Later: export again
.\Export-CertBundle.ps1 -List
.\Export-CertBundle.ps1 -FriendlyName 'wildcard.contoso.com*' -Format Pem
```

---

## Folder layout

All folders are next to the scripts by default (configurable).

```text
Requests\                 INF + CSR files
Responses\                CA replies to process
Responses\Completed\      processed replies
Exports\<FriendlyName>\   .pfx and .pem   (ACL: Administrators, SYSTEM, current user)
Logs\                     one transcript per run
```

---

## Configuration

`CertToolset.config.json` next to the scripts (not committed; start from
`CertToolset.config.example.json`). Every key is optional; missing keys use the
built-in defaults. Parameters override the config.

| Key | Default | Used by |
|---|---|---|
| `Subject.Country` / `State` / `Locality` / `Organization` / `OrganizationalUnit` | empty | New (Subject), Test (checked when set) |
| `KeyLength` | `4096` | New, Test (minimum) |
| `HashAlgorithm` | `SHA512` | New, Test |
| `KeyProvider` | `Microsoft Software Key Storage Provider` | New |
| `KeyExportable` | `true` | New |
| `KeyUsage` | `DigitalSignature`, `KeyEncipherment` | New, Test |
| `EnhancedKeyUsage` | Server + Client Authentication OIDs | New, Test |
| `Folders.Requests` / `Responses` / `Exports` / `Logs` | same names | all |
| `Export.PfxEncryption` | `AES256_SHA256` (`TripleDES_SHA1` for old appliances) | Complete, Export |
| `Export.PemIncludeRoot` | `true` | Complete, Export |
| `Export.PemIterations` | `100000` | Complete, Export |
| `Export.MinPasswordLength` | `12` | Complete, Export |

---

## Exports

- **PFX** - private key + chain, `Export-PfxCertificate`, AES256-SHA256 by default.
- **PEM** - one combined file: certificate, chain, then the private key as
  `ENCRYPTED PRIVATE KEY` (PKCS#8, PBKDF2-SHA256 + AES-256-CBC, the OpenSSL 3
  default). Same layout as `openssl pkcs12 -in x.pfx -out x.pem`. Uses the same
  password as the PFX.
- The password is asked for in a dialog box (masked console prompt in remote
  sessions or without a desktop). It is never a parameter, so it does not end up
  in transcripts, history or process lists.

Unencrypted key for an appliance that needs it (on any machine with OpenSSL):

```bash
openssl pkey -in name.pem -out name.key
```

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows (.NET Framework 4.7.2+).
- An **elevated** session, except `Test-CertRequest.ps1`.
- Tested on Windows 11 (PS 5.1 and 7.6). PEM output verified with OpenSSL.

---

## Troubleshooting

| Message | Cause / fix |
|---|---|
| `No pending request on this machine matches this response` | The CSR was made on another machine, or its pending request was removed. Complete it where it was created. |
| `The CA chain is not trusted on this machine` | Checked before certreq runs; the log lists the steps. Root in the response file: confirm its thumbprint with the CA owner, then run again with `-InstallRootCA`. Otherwise add the root (and intermediates) to the response file, or import them into `Cert:\LocalMachine\Root` / `CA`. |
| `The chain is incomplete` (warning) | An intermediate/root is missing locally; the export holds only what was found. |
| `Export file already exists` | Use `-Force`, or export again with `Export-CertBundle.ps1`. |

---

## License

MIT - see [LICENSE](LICENSE).

Author: Tobias Tillstam, [Tillnet](https://tillnet.se) -
[GitHub](https://github.com/tobiastillstam)
