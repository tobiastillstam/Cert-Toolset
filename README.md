# Cert-Toolset

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Platform](https://img.shields.io/badge/Windows%20Server-certificates-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-1.1.0-blue)

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
| `New-CertRequest.ps1` | Builds a certreq INF and CSR. CN can be an FQDN, short host name (warning), wildcard or IP; extra DNS and IP SANs. Key stays pending in `Cert:\LocalMachine\REQUEST`. | Yes |
| `Test-CertRequest.ps1` | Decodes CSRs (file or folder) and checks key, hash, SANs, CN-in-SAN, Key Usage, EKU, Subject and signature. Exit code 1 on failure. | **No** |
| `Complete-CertRequest.ps1` | Installs CA responses (`.cer` `.crt` `.pem` `.p7b` `.p7c`, full chain OK) with `certreq -accept`, adds missing intermediates, checks the chain is trusted (opt-in `-InstallRootCA`), optional PFX/PEM export, moves responses to `Completed\`. A leaf-only response can use the chain from another response file in the same run. Optional cleanup of stale pending requests. Exit code 1 on failure. | Yes |
| `Export-CertBundle.ps1` | Lists or exports installed certificates (by thumbprint or Friendly Name) as PFX/PEM. Exit code 1 on failure. | Yes |

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

# Later: export again. A wildcard's Friendly Name starts with '*' (only the file
# names use 'wildcard.'), so match the literal '*' with [*].
.\Export-CertBundle.ps1 -List
.\Export-CertBundle.ps1 -FriendlyName '[*].contoso.com*' -Format Pem
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

- **PFX** - private key + chain, AES256-SHA256 by default. Windows PowerShell
  5.1 uses `Export-PfxCertificate` (TripleDES only on Server 2016 and older);
  PowerShell 7 uses the .NET PFX writer (`Pkcs12Builder`) and checks the file
  in .NET (MAC, certificate, private key) before saving it. The log names the
  writer.
- **Server 2016 and older cannot import AES-encrypted PFX files.** For a PFX
  that goes to such a machine, set `Export.PfxEncryption` to `TripleDES_SHA1`.
  When the exporting machine itself is one of them, the log warns about it.
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
- Tested elevated on Windows 11 (PS 5.1 and 7.6) against the Local Machine
  store with a lab CA (root + issuing CA). PFX and PEM output verified with
  OpenSSL.
- Not yet tested: actual removal by `-RemoveStaleRequests` (only `-WhatIf`),
  and responses from a public CA.

---

## Development

Static analysis (PSScriptAnalyzer):

```powershell
Invoke-ScriptAnalyzer -Path . -Settings .\PSScriptAnalyzerSettings.psd1
```

The scripts are self-contained on purpose: shared helper functions are
duplicated in each script, so keep the copies in sync when editing one.

---

## Troubleshooting

| Message | Cause / fix |
|---|---|
| `No pending request on this machine matches this response` | The CSR was made on another machine, or its pending request was removed. Complete it where it was created. |
| `The CA chain is not trusted on this machine` | Checked before certreq runs; the log lists the steps. Root in the response file: confirm its thumbprint with the CA owner, then run again with `-InstallRootCA`. Otherwise add the root (and intermediates) to the response file, or import them into `Cert:\LocalMachine\Root` / `CA`. |
| `The chain is incomplete` (warning) | An intermediate/root is missing locally; the export holds only what was found. |
| `Export file already exists` | Use `-Force`, or export again with `Export-CertBundle.ps1`. |
| `The term 'Export-PfxCertificate' is not recognized` | Toolset 1.0.0 on PowerShell 7.0, which does not load the Windows PKI module. Update to 1.1.0 (PowerShell 7 has its own PFX writer), or run the script in Windows PowerShell 5.1. |
| `The specified network password is not correct` (importing a PFX) | Usually not the password: Server 2016 and older cannot open AES-encrypted PFX files. Export again with `Export.PfxEncryption` = `TripleDES_SHA1`. |
| `Not a readable certificate file` | The response is not DER, Base64/PEM or PKCS#7 (e.g. an HTML page or a text mail saved as `.cer`). Get the certificate file again from the CA. |
| Retiring a root CA | Remove it from `Cert:\LocalMachine\Root` **and** check `Cert:\LocalMachine\CA`: a `.p7b` imported by hand (or with an older toolset version) can leave a copy there. |

---

## License

MIT - see [LICENSE](LICENSE).

Author: Tobias Tillstam, [Tillnet](https://tillnet.se) -
[GitHub](https://github.com/tobiastillstam)
