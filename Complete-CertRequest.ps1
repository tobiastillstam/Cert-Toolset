#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Completes pending certificate requests with the CA responses and optionally
    exports each certificate as PFX and/or PEM.

.DESCRIPTION
    For every CA response in the Responses folder (.cer, .crt, .pem, .p7b, .p7c):
      1. Reads all certificates in the file (DER, Base64/PEM, PKCS#7, full-chain
         PEM) and finds the one whose public key matches a pending request in
         Cert:\LocalMachine\REQUEST (created by New-CertRequest.ps1).
      2. With -InstallRootCA: adds a root CA certificate from the response file to
         Cert:\LocalMachine\Root if it is not trusted yet. Then installs
         intermediate CA certificates from the file into Cert:\LocalMachine\CA
         when they are missing.
      3. Checks that the chain ends in a trusted root. If not, stops for that
         file and shows what to do (instead of a bare certreq error).
      4. Installs it with "certreq -accept -machine", which binds it to the pending
         private key and carries over the Friendly Name, and confirms the
         certificate is in Cert:\LocalMachine\My with a private key.
      5. With -ExportPfx / -ExportPem: asks for a password (dialog box, console
         fallback) and writes Exports\<FriendlyName>\<FriendlyName>.pfx and/or .pem.
         The .pem holds the certificate, the chain and the private key encrypted
         with the same password (PKCS#8, PBKDF2-SHA256 + AES-256-CBC), the same
         layout as "openssl pkcs12 -in x.pfx -out x.pem".
      6. Moves the response file to Responses\Completed.

    A response that is already installed (same thumbprint with a private key in
    LocalMachine\My) is not installed again; it is exported if asked and moved to
    Completed. A response that matches no pending request is reported as failed
    and left in place. Each file is handled separately; one failure does not stop
    the batch.

    With -RemoveStaleRequests, pending requests older than -StaleDays are removed
    together with their private keys.

    A transcript of every run is written to the Logs folder.

    Supports -WhatIf and -Confirm.

.PARAMETER ResponsePath
    Folder with CA response files. Default: the Responses folder from the config,
    relative to the script folder.

.PARAMETER ExportPath
    Root folder for exports. Default: the Exports folder from the config,
    relative to the script folder.

.PARAMETER ExportPfx
    Export each completed certificate as a password-protected .pfx (private key
    and chain).

.PARAMETER ExportPem
    Export each completed certificate as a combined .pem (certificate, chain and
    encrypted private key).

.PARAMETER InstallRootCA
    Trust a root CA certificate that is included in the response file by adding
    it to Cert:\LocalMachine\Root. Confirm its thumbprint with the CA owner first.
    Without this switch, roots are never trusted automatically.

.PARAMETER RemoveStaleRequests
    Remove pending requests (and their private keys) older than -StaleDays from
    Cert:\LocalMachine\REQUEST.

.PARAMETER StaleDays
    Age in days for -RemoveStaleRequests. Default: 30.

.PARAMETER Force
    Overwrite existing export files.

.PARAMETER ConfigPath
    JSON config file. Default: <script folder>\CertToolset.config.json

.PARAMETER LogPath
    Folder for the transcript. Default: the Logs folder from the config, relative
    to the script folder.

.EXAMPLE
    .\Complete-CertRequest.ps1 -WhatIf
    Shows which responses would be installed, without changing anything.

.EXAMPLE
    .\Complete-CertRequest.ps1 -ExportPfx -ExportPem
    Installs all responses and exports each certificate as PFX and PEM.

.EXAMPLE
    .\Complete-CertRequest.ps1 -InstallRootCA -WhatIf
    Shows which root CA from the response files would be trusted.

.EXAMPLE
    .\Complete-CertRequest.ps1 -RemoveStaleRequests -StaleDays 60 -WhatIf
    Lists pending requests older than 60 days that would be removed.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.0.0
    Date Created  : 2026-09-04
    Last Modified : 2026-10-16

    Change Log
    ----------
    1.0.0 (2026-10-16) - Renamed from Complete_CSR.ps1 and reworked for Cert-Toolset:
                          JSON config, transcript logging, no password parameter
                          (dialog/console prompt per certificate), exports are
                          opt-in (-ExportPfx, -ExportPem), native encrypted PEM,
                          AES256-SHA256 PFX, Exports folder with restricted ACL,
                          .crt/.pem/.p7b/full-chain responses, response matched to
                          the pending request by public key, already-installed
                          responses skipped, intermediates installed, no silent
                          overwrites (-Force), -WhatIf no longer reports false
                          failures, -RemoveStaleRequests, trust check with
                          operator steps before certreq, -InstallRootCA.
    0.2.0 (2026-09-04) - Renamed to Complete_CSR.ps1, optional CerPath/PfxPath.
    0.1.0 (2026-09-04) - Initial release.

    Operational notes:
    - Requires local Administrator rights (Local Machine store).
    - The password is never a parameter, so it does not end up in the transcript,
      command history or process list. Each certificate gets its own prompt. In a
      remote session (Enter-PSSession) or without a desktop, a masked console
      prompt is used instead of the dialog.
    - The Exports root folder is created with an ACL limited to Administrators,
      SYSTEM and the account running the script. If it already exists with a
      broader ACL, a warning is shown (the ACL is not changed).
    - Root CAs are only trusted with -InstallRootCA, and only when the root
      certificate is in the response file. The added root is logged with its
      thumbprint. Under -WhatIf the trust check assumes the planned root is added.
    - The chain in PFX/PEM is built from the local stores plus the certificates
      in the response file. If an intermediate is missing, the export still
      happens and a warning is shown.
    - Export options are in the config: Export.PfxEncryption (AES256_SHA256 or
      TripleDES_SHA1 for old appliances), Export.PemIncludeRoot,
      Export.PemIterations and Export.MinPasswordLength.
    - The transcript is written even under -WhatIf (for accountability).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Folder with CA response files. Default: Responses folder from the config.
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$ResponsePath,

    # Root folder for exports. Default: Exports folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    # Export each completed certificate as PFX.
    [Parameter(Mandatory = $false)]
    [switch]$ExportPfx,

    # Export each completed certificate as combined PEM (encrypted key).
    [Parameter(Mandatory = $false)]
    [switch]$ExportPem,

    # Trust a root CA included in the response file (adds it to LocalMachine\Root).
    [Parameter(Mandatory = $false)]
    [switch]$InstallRootCA,

    # Remove pending requests older than -StaleDays (with their private keys).
    [Parameter(Mandatory = $false)]
    [switch]$RemoveStaleRequests,

    # Age in days for -RemoveStaleRequests.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 30,

    # Overwrite existing export files.
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    # JSON config file. Default: <script folder>\CertToolset.config.json
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    # Folder for the transcript. Default: Logs folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

# -------------------------------------------------------------------------
# Helper functions - general
# -------------------------------------------------------------------------

function Write-Log {
    # Timestamped, ASCII-only log line to the host (captured by the transcript).
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
        [string]$Level = 'INFO'
    )
    Write-Host ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message)
}

function Get-BaseDirectory {
    # Script folder, falling back to the current location.
    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Get-Location).Path
}

function Resolve-ToolsetPath {
    # Absolute path; relative paths are resolved against the script folder.
    param([string]$Path, [string]$BaseDirectory)
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path -Path $BaseDirectory -ChildPath $Path))
}

function Get-DefaultConfig {
    # Built-in defaults; the JSON config overrides any key it contains.
    return @{
        Subject          = @{ Country = ''; State = ''; Locality = ''; Organization = ''; OrganizationalUnit = '' }
        KeyLength        = 4096
        HashAlgorithm    = 'SHA512'
        KeyProvider      = 'Microsoft Software Key Storage Provider'
        KeyExportable    = $true
        KeyUsage         = @('DigitalSignature', 'KeyEncipherment')
        EnhancedKeyUsage = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        Folders          = @{ Requests = 'Requests'; Responses = 'Responses'; Exports = 'Exports'; Logs = 'Logs' }
        Export           = @{ PfxEncryption = 'AES256_SHA256'; PemIncludeRoot = $true; PemIterations = 100000; MinPasswordLength = 12 }
    }
}

function Merge-Config {
    # Copies JSON values over the defaults, recursing into nested sections.
    param([hashtable]$Default, [object]$Json, [string]$Prefix = '')
    foreach ($Prop in $Json.PSObject.Properties) {
        $Name = $Prop.Name
        if (-not $Default.ContainsKey($Name)) {
            Write-Log "Config: unknown setting '$Prefix$Name' ignored." 'WARN'
            continue
        }
        if ($null -eq $Prop.Value) { continue }
        if ($Default[$Name] -is [hashtable]) {
            Merge-Config -Default $Default[$Name] -Json $Prop.Value -Prefix "$Prefix$Name."
        }
        elseif ($Default[$Name] -is [array]) {
            $Default[$Name] = @($Prop.Value)
        }
        else {
            $Default[$Name] = $Prop.Value
        }
    }
}

function Read-ToolsetConfig {
    # Defaults merged with the JSON file. A missing default-path file is not an error.
    param([string]$Path, [bool]$Explicit)
    $Config = Get-DefaultConfig
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $Json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        Merge-Config -Default $Config -Json $Json
        Write-Log "Config: $Path"
    }
    elseif ($Explicit) {
        throw "Config file not found: $Path"
    }
    else {
        Write-Log "No config file at $Path - using built-in defaults." 'WARN'
    }
    return $Config
}

function Stop-ToolsetTranscript {
    # PS 7 Stop-Transcript honours -WhatIf (PS 5.1 has no such parameter).
    $StopParams = @{}
    if ((Get-Command Stop-Transcript).Parameters.ContainsKey('WhatIf')) { $StopParams['WhatIf'] = $false }
    Stop-Transcript @StopParams | Out-Null
}

function Invoke-NativeCommand {
    # Runs an exe, capturing output and exit code. stderr must not trip
    # ErrorActionPreference = Stop in Windows PowerShell 5.1.
    param([string]$FilePath, [string[]]$ArgumentList)
    $OldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $Output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $OldPreference
    }
    return [pscustomobject]@{ ExitCode = $ExitCode; Output = $Output }
}

function ConvertTo-SafeFileName {
    # '*.' -> 'wildcard.' and invalid file name characters -> '_'.
    param([string]$Name)
    $Safe = $Name -replace '^\*\.', 'wildcard.'
    foreach ($Char in [IO.Path]::GetInvalidFileNameChars()) {
        $Safe = $Safe.Replace([string]$Char, '_')
    }
    return $Safe
}

# -------------------------------------------------------------------------
# Helper functions - certificates
# -------------------------------------------------------------------------

function Read-CertificateFile {
    # All certificates in a file: PEM (one or many), Base64, DER or PKCS#7.
    param([string]$File)
    $Text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($File))
    $Blocks = [regex]::Matches($Text, '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----')
    $Certs = @()
    if ($Blocks.Count -gt 0) {
        foreach ($Block in $Blocks) {
            $Der = [Convert]::FromBase64String(($Block.Groups[1].Value -replace '\s', ''))
            $Certs += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Der)
        }
    }
    else {
        $Collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $Collection.Import($File)
        $Certs = @($Collection)
    }
    if ($Certs.Count -eq 0) { throw 'No certificates found in the file.' }
    return , $Certs
}

function Test-IsCaCertificate {
    # True when Basic Constraints says CA=true.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($Extension in $Certificate.Extensions) {
        if ($Extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            return [bool]$Extension.CertificateAuthority
        }
    }
    return $false
}

function Get-PublicKeyId {
    # Base64 of the encoded public key, used to match responses to requests.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return [Convert]::ToBase64String($Certificate.PublicKey.EncodedKeyValue.RawData)
}

function Get-CertificateChain {
    # Issuer chain above the certificate (leaf excluded), plus whether it is complete.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$ExtraCertificates = @(),
        [bool]$IncludeRoot
    )
    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $Chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    foreach ($Extra in $ExtraCertificates) { [void]$Chain.ChainPolicy.ExtraStore.Add($Extra) }
    [void]$Chain.Build($Certificate)

    $Issuers = @()
    $Elements = @($Chain.ChainElements | ForEach-Object { $_.Certificate })
    for ($i = 1; $i -lt $Elements.Count; $i++) {
        $IsRoot = ($Elements[$i].Subject -eq $Elements[$i].Issuer)
        if ($IsRoot -and -not $IncludeRoot) { continue }
        $Issuers += $Elements[$i]
    }
    $Last = $Elements[$Elements.Count - 1]
    $Partial = @($Chain.ChainStatus | Where-Object { $_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain })
    $Complete = ($Partial.Count -eq 0) -and ($Last.Subject -eq $Last.Issuer)
    $Chain.Dispose()
    return [pscustomobject]@{ Issuers = $Issuers; Complete = $Complete }
}

function Test-ChainTrust {
    # Builds the chain as Windows will (local stores + file certs) and reports
    # whether it ends in a trusted root. Revocation is not checked here.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$ExtraCertificates = @()
    )
    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    foreach ($Extra in $ExtraCertificates) { [void]$Chain.ChainPolicy.ExtraStore.Add($Extra) }
    [void]$Chain.Build($Certificate)
    $Flags = 0
    foreach ($Status in $Chain.ChainStatus) { $Flags = $Flags -bor [int]$Status.Status }
    $Elements = @($Chain.ChainElements | ForEach-Object { $_.Certificate })
    $Chain.Dispose()
    $Untrusted = [bool]($Flags -band [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot)
    $Partial = [bool]($Flags -band [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain)
    return [pscustomobject]@{
        Trusted = -not ($Untrusted -or $Partial)
        Partial = $Partial
        Top     = $Elements[$Elements.Count - 1]
    }
}

function Get-TrustHelp {
    # Operator instructions for an untrusted or incomplete CA chain.
    param([object]$Trust, [bool]$RootInFile)
    $Top = $Trust.Top
    $Lines = @()
    if ($Trust.Partial) {
        $Lines += "The chain stops at '$($Top.Issuer)': that CA certificate was not found on this machine or in the response file."
        $Lines += 'What to do:'
        $Lines += '  1. Get the missing CA certificate(s) - intermediate and root - from the CA owner.'
        $Lines += '  2. Either put the full chain in the response file (append to the .pem, or use a .p7b) and run'
        $Lines += '     again with -InstallRootCA, or import them yourself:'
        $Lines += '       Import-Certificate -FilePath .\intermediate.cer -CertStoreLocation Cert:\LocalMachine\CA'
        $Lines += '       Import-Certificate -FilePath .\root.cer -CertStoreLocation Cert:\LocalMachine\Root'
        $Lines += '  3. Run Complete-CertRequest.ps1 again.'
    }
    elseif ($RootInFile) {
        $Lines += "The chain ends in root CA '$($Top.Subject)' (thumbprint $($Top.Thumbprint)), which is not trusted on this machine."
        $Lines += 'The root CA certificate is included in the response file. What to do:'
        $Lines += '  1. Confirm the thumbprint above with the CA owner (never trust an unknown root).'
        $Lines += '  2. Run again with -InstallRootCA to add it to Cert:\LocalMachine\Root.'
    }
    else {
        $Lines += "The chain ends in root CA '$($Top.Subject)' (thumbprint $($Top.Thumbprint)), which is not trusted on this machine."
        $Lines += 'What to do:'
        $Lines += '  1. Get the root CA certificate from the CA owner and confirm its thumbprint.'
        $Lines += '  2. Either append it to the response file (or use a .p7b with the full chain) and run again'
        $Lines += '     with -InstallRootCA, or import it yourself:'
        $Lines += '       Import-Certificate -FilePath .\root.cer -CertStoreLocation Cert:\LocalMachine\Root'
        $Lines += '  3. Run Complete-CertRequest.ps1 again.'
    }
    return $Lines
}

# -------------------------------------------------------------------------
# Helper functions - export (PFX, encrypted PEM, password prompt, ACL)
# -------------------------------------------------------------------------

function ConvertTo-DerLength {
    # DER length octets.
    param([int]$Length)
    if ($Length -lt 0x80) { return , [byte[]]@($Length) }
    $Bytes = New-Object 'System.Collections.Generic.List[byte]'
    $Value = $Length
    while ($Value -gt 0) { $Bytes.Insert(0, [byte]($Value -band 0xFF)); $Value = $Value -shr 8 }
    $Bytes.Insert(0, [byte](0x80 -bor $Bytes.Count))
    return , $Bytes.ToArray()
}

function New-DerElement {
    # Tag + length + value. Value may be several byte arrays (concatenated).
    param([byte]$Tag, [object[]]$Content = @())
    $Body = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($Part in $Content) { if ($null -ne $Part) { $Body.AddRange([byte[]]$Part) } }
    $Out = New-Object 'System.Collections.Generic.List[byte]'
    $Out.Add($Tag)
    $Out.AddRange((ConvertTo-DerLength -Length $Body.Count))
    $Out.AddRange($Body)
    return , $Out.ToArray()
}

function New-DerInteger {
    # INTEGER from unsigned big-endian bytes, or from an int.
    param([object]$Value)
    if ($Value -is [int]) {
        $Bytes = [BitConverter]::GetBytes([int]$Value)
        [Array]::Reverse($Bytes)
    }
    else {
        $Bytes = [byte[]]$Value
    }
    $Start = 0
    while ($Start -lt $Bytes.Length - 1 -and $Bytes[$Start] -eq 0) { $Start++ }
    $Trimmed = [byte[]]$Bytes[$Start..($Bytes.Length - 1)]
    if ($Trimmed[0] -band 0x80) { $Trimmed = [byte[]](@([byte]0) + $Trimmed) }
    return New-DerElement -Tag 0x02 -Content @(, $Trimmed)
}

function New-DerOid {
    # OBJECT IDENTIFIER from dotted notation.
    param([string]$Oid)
    $Parts = $Oid.Split('.') | ForEach-Object { [long]$_ }
    $Bytes = New-Object 'System.Collections.Generic.List[byte]'
    $Bytes.Add([byte]($Parts[0] * 40 + $Parts[1]))
    for ($i = 2; $i -lt $Parts.Count; $i++) {
        $Value = $Parts[$i]
        $Chunk = New-Object 'System.Collections.Generic.List[byte]'
        $Chunk.Add([byte]($Value -band 0x7F))
        $Value = $Value -shr 7
        while ($Value -gt 0) { $Chunk.Insert(0, [byte](0x80 -bor ($Value -band 0x7F))); $Value = $Value -shr 7 }
        $Bytes.AddRange($Chunk)
    }
    return New-DerElement -Tag 0x06 -Content @(, $Bytes.ToArray())
}

function Read-DerElement {
    # Reads one TLV at Offset. Returns Tag, ValueOffset, Length, Next.
    param([byte[]]$Data, [int]$Offset)
    $Tag = $Data[$Offset]
    $Length = [int]$Data[$Offset + 1]
    $Pos = $Offset + 2
    if ($Length -band 0x80) {
        $Count = $Length -band 0x7F
        $Length = 0
        for ($i = 0; $i -lt $Count; $i++) { $Length = ($Length -shl 8) -bor $Data[$Pos + $i] }
        $Pos += $Count
    }
    return [pscustomobject]@{ Tag = $Tag; ValueOffset = $Pos; Length = $Length; Next = $Pos + $Length }
}

function Get-DerValue {
    # Copy of an element's value bytes.
    param([byte[]]$Data, [object]$Element)
    $Value = New-Object byte[] $Element.Length
    [Array]::Copy($Data, $Element.ValueOffset, $Value, 0, $Element.Length)
    return , $Value
}

function Get-Pkcs12DerivedKey {
    # RFC 7292 appendix B.2 KDF with SHA-1 (used to undo the Windows 3DES export).
    param([byte[]]$PasswordBmp, [byte[]]$Salt, [int]$Iterations, [byte]$Id, [int]$Count)
    $u = 20; $v = 64
    $D = [byte[]](@($Id) * $v)
    $SLen = $v * [Math]::Ceiling($Salt.Length / $v)
    $PLen = $v * [Math]::Ceiling($PasswordBmp.Length / $v)
    $I = New-Object byte[] ($SLen + $PLen)
    for ($k = 0; $k -lt $SLen; $k++) { $I[$k] = $Salt[$k % $Salt.Length] }
    for ($k = 0; $k -lt $PLen; $k++) { $I[$SLen + $k] = $PasswordBmp[$k % $PasswordBmp.Length] }
    $Sha1 = [System.Security.Cryptography.SHA1]::Create()
    $Result = New-Object 'System.Collections.Generic.List[byte]'
    while ($Result.Count -lt $Count) {
        $A = $Sha1.ComputeHash([byte[]]($D + $I))
        for ($r = 1; $r -lt $Iterations; $r++) { $A = $Sha1.ComputeHash($A) }
        $Result.AddRange($A)
        if ($Result.Count -ge $Count) { break }
        $B = New-Object byte[] $v
        for ($k = 0; $k -lt $v; $k++) { $B[$k] = $A[$k % $u] }
        for ($j = 0; $j -lt $I.Length; $j += $v) {
            $Carry = 1
            for ($k = $v - 1; $k -ge 0; $k--) {
                $Sum = $I[$j + $k] + $B[$k] + $Carry
                $I[$j + $k] = [byte]($Sum -band 0xFF)
                $Carry = $Sum -shr 8
            }
        }
    }
    $Sha1.Dispose()
    return , [byte[]]$Result.GetRange(0, $Count).ToArray()
}

function Initialize-NCryptExport {
    # P/Invoke wrapper for NCryptExportKey with PKCS#8 encryption parameters.
    if ('CertToolset.NCryptExport' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace CertToolset {
    public static class NCryptExport {
        [StructLayout(LayoutKind.Sequential)]
        struct NCryptBuffer { public int cbBuffer; public int BufferType; public IntPtr pvBuffer; }
        [StructLayout(LayoutKind.Sequential)]
        struct NCryptBufferDesc { public int ulVersion; public int cBuffers; public IntPtr pBuffers; }
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType,
            ref NCryptBufferDesc pParameterList, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        public static byte[] ExportEncryptedPkcs8(IntPtr hKey, string password, byte[] pbeParams) {
            byte[] secret = Encoding.Unicode.GetBytes(password + "\0");
            byte[] oid = Encoding.ASCII.GetBytes("1.2.840.113549.1.12.1.3\0");
            byte[][] parts = { secret, oid, pbeParams };
            int[] types = { 46, 41, 42 };
            IntPtr[] mem = new IntPtr[3];
            int size = Marshal.SizeOf(typeof(NCryptBuffer));
            IntPtr buffers = Marshal.AllocHGlobal(size * 3);
            try {
                for (int i = 0; i < 3; i++) {
                    mem[i] = Marshal.AllocHGlobal(parts[i].Length);
                    Marshal.Copy(parts[i], 0, mem[i], parts[i].Length);
                    NCryptBuffer b = new NCryptBuffer { cbBuffer = parts[i].Length, BufferType = types[i], pvBuffer = mem[i] };
                    Marshal.StructureToPtr(b, new IntPtr(buffers.ToInt64() + i * size), false);
                }
                NCryptBufferDesc desc = new NCryptBufferDesc { ulVersion = 0, cBuffers = 3, pBuffers = buffers };
                int needed;
                int rc = NCryptExportKey(hKey, IntPtr.Zero, "PKCS8_PRIVATEKEY", ref desc, null, 0, out needed, 0x40);
                if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
                byte[] output = new byte[needed];
                rc = NCryptExportKey(hKey, IntPtr.Zero, "PKCS8_PRIVATEKEY", ref desc, output, output.Length, out needed, 0x40);
                if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
                if (needed != output.Length) Array.Resize(ref output, needed);
                return output;
            }
            finally {
                for (int i = 0; i < 3; i++) {
                    if (mem[i] != IntPtr.Zero) {
                        Marshal.Copy(new byte[parts[i].Length], 0, mem[i], parts[i].Length);
                        Marshal.FreeHGlobal(mem[i]);
                    }
                }
                Marshal.FreeHGlobal(buffers);
            }
        }
    }
}
'@
}

function Get-Pkcs8PrivateKey {
    # Unencrypted PKCS#8 PrivateKeyInfo (RSA) for a certificate's private key.
    # Kept in memory only; the caller encrypts it before anything is written.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $Rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $Rsa) { throw 'The certificate has no RSA private key.' }

    $Parameters = $null
    try { $Parameters = $Rsa.ExportParameters($true) } catch { $Parameters = $null }

    if ($Parameters) {
        # CAPI keys and CNG keys that allow plaintext export (certreq Exportable = TRUE).
        $RsaPrivateKey = New-DerElement -Tag 0x30 -Content @(
            (New-DerInteger 0), (New-DerInteger $Parameters.Modulus), (New-DerInteger $Parameters.Exponent),
            (New-DerInteger $Parameters.D), (New-DerInteger $Parameters.P), (New-DerInteger $Parameters.Q),
            (New-DerInteger $Parameters.DP), (New-DerInteger $Parameters.DQ), (New-DerInteger $Parameters.InverseQ)
        )
        foreach ($Field in 'D', 'P', 'Q', 'DP', 'DQ', 'InverseQ') {
            if ($Parameters.$Field) { [Array]::Clear($Parameters.$Field, 0, $Parameters.$Field.Length) }
        }
        $Algorithm = New-DerElement -Tag 0x30 -Content @((New-DerOid '1.2.840.113549.1.1.1'), [byte[]](0x05, 0x00))
        $Pkcs8 = New-DerElement -Tag 0x30 -Content @((New-DerInteger 0), $Algorithm, (New-DerElement -Tag 0x04 -Content @(, $RsaPrivateKey)))
        [Array]::Clear($RsaPrivateKey, 0, $RsaPrivateKey.Length)
        return , $Pkcs8
    }

    if (-not ($Rsa -is [System.Security.Cryptography.RSACng])) {
        throw 'The private key is not exportable.'
    }
    $Policy = $Rsa.Key.ExportPolicy
    if (-not ($Policy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport)) {
        throw "The private key is not exportable (export policy: $Policy)."
    }

    # CNG key that only allows encrypted export (e.g. imported from a PFX): let
    # Windows export it with PBE-SHA1-3DES under a random one-time password, then
    # decrypt it in memory. Windows PowerShell 5.1 needs this; PS 7 handles it in
    # ExportParameters above.
    Initialize-NCryptExport
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Salt = New-Object byte[] 8; $Random.GetBytes($Salt)
    $PwdBytes = New-Object byte[] 24; $Random.GetBytes($PwdBytes)
    $Random.Dispose()
    $OneTime = [Convert]::ToBase64String($PwdBytes)

    # Native PBE_PARAMS: int iIterations, int cbSalt, byte rgbSalt[8]
    $PbeParams = [byte[]]([BitConverter]::GetBytes([int]2048) + [BitConverter]::GetBytes([int]8) + $Salt)

    $Handle = $Rsa.Key.Handle
    try {
        $Encrypted = [CertToolset.NCryptExport]::ExportEncryptedPkcs8($Handle.DangerousGetHandle(), $OneTime, $PbeParams)
    }
    finally {
        $Handle.Dispose()
    }

    # EncryptedPrivateKeyInfo: SEQ { SEQ { OID, SEQ { OCTET salt, INT iterations } }, OCTET cipher }
    # Salt and iterations are read back from the blob rather than assumed.
    $Outer = Read-DerElement -Data $Encrypted -Offset 0
    $AlgId = Read-DerElement -Data $Encrypted -Offset $Outer.ValueOffset
    $AlgOid = Read-DerElement -Data $Encrypted -Offset $AlgId.ValueOffset
    $ParamSeq = Read-DerElement -Data $Encrypted -Offset $AlgOid.Next
    $SaltElement = Read-DerElement -Data $Encrypted -Offset $ParamSeq.ValueOffset
    $Salt = Get-DerValue -Data $Encrypted -Element $SaltElement
    $IterElement = Read-DerElement -Data $Encrypted -Offset $SaltElement.Next
    $Iterations = 0
    foreach ($Byte in (Get-DerValue -Data $Encrypted -Element $IterElement)) { $Iterations = ($Iterations -shl 8) -bor $Byte }
    $Cipher = Get-DerValue -Data $Encrypted -Element (Read-DerElement -Data $Encrypted -Offset $AlgId.Next)

    $PasswordBmp = [Text.Encoding]::BigEndianUnicode.GetBytes($OneTime + [char]0)
    $Key = Get-Pkcs12DerivedKey -PasswordBmp $PasswordBmp -Salt $Salt -Iterations $Iterations -Id 1 -Count 24
    $Iv = Get-Pkcs12DerivedKey -PasswordBmp $PasswordBmp -Salt $Salt -Iterations $Iterations -Id 2 -Count 8
    $Des = [System.Security.Cryptography.TripleDES]::Create()
    $Des.Mode = 'CBC'; $Des.Padding = 'PKCS7'
    $Decryptor = $Des.CreateDecryptor($Key, $Iv)
    $Plain = $Decryptor.TransformFinalBlock($Cipher, 0, $Cipher.Length)
    $Decryptor.Dispose(); $Des.Dispose()
    [Array]::Clear($Key, 0, $Key.Length)
    return , $Plain
}

function Protect-Pkcs8PrivateKey {
    # PKCS#8 EncryptedPrivateKeyInfo with PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC
    # (the OpenSSL 3 default). Password bytes are UTF-8, as OpenSSL uses them.
    param([byte[]]$Pkcs8, [System.Security.SecureString]$Password, [int]$Iterations)

    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Salt = New-Object byte[] 16; $Random.GetBytes($Salt)
    $Iv = New-Object byte[] 16; $Random.GetBytes($Iv)
    $Random.Dispose()

    $PasswordBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureStringPlain $Password))
    $Kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $Key = $Kdf.GetBytes(32)
    $Kdf.Dispose()
    [Array]::Clear($PasswordBytes, 0, $PasswordBytes.Length)

    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Mode = 'CBC'; $Aes.Padding = 'PKCS7'; $Aes.KeySize = 256
    $Encryptor = $Aes.CreateEncryptor($Key, $Iv)
    $Cipher = $Encryptor.TransformFinalBlock($Pkcs8, 0, $Pkcs8.Length)
    $Encryptor.Dispose(); $Aes.Dispose()
    [Array]::Clear($Key, 0, $Key.Length)

    $Prf = New-DerElement -Tag 0x30 -Content @((New-DerOid '1.2.840.113549.2.9'), [byte[]](0x05, 0x00))   # hmacWithSHA256
    $Pbkdf2 = New-DerElement -Tag 0x30 -Content @(
        (New-DerOid '1.2.840.113549.1.5.12'),
        (New-DerElement -Tag 0x30 -Content @((New-DerElement -Tag 0x04 -Content @(, $Salt)), (New-DerInteger $Iterations), $Prf))
    )
    $Scheme = New-DerElement -Tag 0x30 -Content @((New-DerOid '2.16.840.1.101.3.4.1.42'), (New-DerElement -Tag 0x04 -Content @(, $Iv)))   # aes256-CBC
    $Pbes2 = New-DerElement -Tag 0x30 -Content @((New-DerOid '1.2.840.113549.1.5.13'), (New-DerElement -Tag 0x30 -Content @($Pbkdf2, $Scheme)))
    return New-DerElement -Tag 0x30 -Content @($Pbes2, (New-DerElement -Tag 0x04 -Content @(, $Cipher)))
}

function ConvertTo-Pem {
    # PEM block with 64-character Base64 lines.
    param([byte[]]$Data, [string]$Label)
    $B64 = [Convert]::ToBase64String($Data)
    $Lines = for ($i = 0; $i -lt $B64.Length; $i += 64) { $B64.Substring($i, [Math]::Min(64, $B64.Length - $i)) }
    return "-----BEGIN $Label-----`n" + ($Lines -join "`n") + "`n-----END $Label-----`n"
}

function ConvertFrom-SecureStringPlain {
    # Plain text of a SecureString (needed for the PEM key encryption).
    param([System.Security.SecureString]$SecureString)
    $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
}

function Read-PasswordConsole {
    # Masked console prompt with confirmation. Returns $null when left empty.
    param([string]$Target, [int]$MinLength)
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        $First = Read-Host -AsSecureString "Export password for $Target (empty = skip)"
        if ($First.Length -eq 0) { return $null }
        $Second = Read-Host -AsSecureString 'Confirm password'
        $A = ConvertFrom-SecureStringPlain $First
        $B = ConvertFrom-SecureStringPlain $Second
        if ($A -cne $B) { Write-Host 'Passwords do not match.'; continue }
        if ($A.Length -lt $MinLength) { Write-Host "Password must be at least $MinLength characters."; continue }
        return $First
    }
    throw 'No valid password after 3 attempts.'
}

function Read-PasswordDialog {
    # Dialog box with password + confirm fields. Returns a SecureString, or $null
    # when cancelled. Throws if no GUI is available (caller falls back to console).
    param([string]$Target, [int]$MinLength)

    Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop

    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = 'Cert-Toolset - export password'
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.StartPosition = 'CenterScreen'
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Form.TopMost = $true
    $Form.ClientSize = New-Object System.Drawing.Size(420, 205)
    $Form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $Info = New-Object System.Windows.Forms.Label
    $Info.Text = "Password for the exported PFX/PEM of:`r`n$Target"
    $Info.Location = New-Object System.Drawing.Point(12, 10)
    $Info.Size = New-Object System.Drawing.Size(396, 36)
    $Info.AutoEllipsis = $true

    $Label1 = New-Object System.Windows.Forms.Label
    $Label1.Text = 'Password:'
    $Label1.Location = New-Object System.Drawing.Point(12, 57)
    $Label1.Size = New-Object System.Drawing.Size(110, 20)
    $Box1 = New-Object System.Windows.Forms.TextBox
    $Box1.UseSystemPasswordChar = $true
    $Box1.Location = New-Object System.Drawing.Point(125, 54)
    $Box1.Size = New-Object System.Drawing.Size(283, 23)

    $Label2 = New-Object System.Windows.Forms.Label
    $Label2.Text = 'Confirm:'
    $Label2.Location = New-Object System.Drawing.Point(12, 89)
    $Label2.Size = New-Object System.Drawing.Size(110, 20)
    $Box2 = New-Object System.Windows.Forms.TextBox
    $Box2.UseSystemPasswordChar = $true
    $Box2.Location = New-Object System.Drawing.Point(125, 86)
    $Box2.Size = New-Object System.Drawing.Size(283, 23)

    $ErrorLabel = New-Object System.Windows.Forms.Label
    $ErrorLabel.Text = "At least $MinLength characters."
    $ErrorLabel.Location = New-Object System.Drawing.Point(125, 116)
    $ErrorLabel.Size = New-Object System.Drawing.Size(283, 36)

    $Ok = New-Object System.Windows.Forms.Button
    $Ok.Text = 'OK'
    $Ok.Location = New-Object System.Drawing.Point(242, 165)
    $Ok.Size = New-Object System.Drawing.Size(80, 28)
    $Cancel = New-Object System.Windows.Forms.Button
    $Cancel.Text = 'Cancel'
    $Cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Cancel.Location = New-Object System.Drawing.Point(328, 165)
    $Cancel.Size = New-Object System.Drawing.Size(80, 28)

    $Ok.Add_Click({
        if ($Box1.Text -cne $Box2.Text) {
            $ErrorLabel.Text = 'Passwords do not match.'
        }
        elseif ($Box1.Text.Length -lt $MinLength) {
            $ErrorLabel.Text = "Password must be at least $MinLength characters."
        }
        else {
            $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $Form.Close()
        }
    })
    $Form.Add_Shown({ $Form.Activate(); $Box1.Focus() })
    $Form.AcceptButton = $Ok
    $Form.CancelButton = $Cancel
    $Form.Controls.AddRange(@($Info, $Label1, $Box1, $Label2, $Box2, $ErrorLabel, $Ok, $Cancel))

    try {
        $Result = $Form.ShowDialog()
        if ($Result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
        $Secure = New-Object System.Security.SecureString
        foreach ($Char in $Box1.Text.ToCharArray()) { $Secure.AppendChar($Char) }
        $Secure.MakeReadOnly()
        return $Secure
    }
    finally {
        $Box1.Text = ''; $Box2.Text = ''
        $Form.Dispose()
    }
}

function Read-ExportPassword {
    # Dialog box when a desktop is available, masked console prompt otherwise.
    param([string]$Target, [int]$MinLength)
    $UseConsole = ($Host.Name -eq 'ServerRemoteHost') -or (-not [Environment]::UserInteractive)
    if (-not $UseConsole) {
        try {
            return Read-PasswordDialog -Target $Target -MinLength $MinLength
        }
        catch {
            Write-Log "Password dialog not available ($($_.Exception.Message)); using the console." 'WARN'
        }
    }
    return Read-PasswordConsole -Target $Target -MinLength $MinLength
}

function Initialize-ExportRoot {
    # Creates the export root with an ACL limited to Administrators, SYSTEM and the
    # current account. An existing folder is only checked, never changed.
    param([string]$Path)
    $Allowed = @(
        'S-1-5-32-544',                                                   # BUILTIN\Administrators
        'S-1-5-18',                                                       # NT AUTHORITY\SYSTEM
        ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        $Acl = Get-Acl -LiteralPath $Path
        $Acl.SetAccessRuleProtection($true, $false)
        foreach ($Rule in @($Acl.Access)) { [void]$Acl.RemoveAccessRule($Rule) }
        foreach ($Sid in $Allowed) {
            $Identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $Acl
        Write-Log "Created export folder with restricted ACL (Administrators, SYSTEM, current user): $Path"
        return
    }
    $Acl = Get-Acl -LiteralPath $Path
    $Others = @()
    foreach ($Rule in $Acl.Access) {
        if ($Rule.AccessControlType -ne 'Allow') { continue }
        try { $Sid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $Sid = [string]$Rule.IdentityReference }
        if ($Allowed -notcontains $Sid -and $Sid -ne 'S-1-3-0') { $Others += [string]$Rule.IdentityReference }   # S-1-3-0 = CREATOR OWNER
    }
    if ($Others.Count -gt 0) {
        Write-Log "Export folder $Path also grants access to: $(($Others | Select-Object -Unique) -join ', '). It will hold private keys." 'WARN'
    }
}

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$TranscriptStarted = $false

try {
    $ErrorActionPreference = 'Stop'

    # --- Fixed settings -----------------------------------------------------
    # The toolset works on the Local Machine store only.
    $StoreLocation = 'LocalMachine'
    $CertReqStoreFlag = $(if ($StoreLocation -eq 'LocalMachine') { '-machine' } else { '-user' })
    $ResponseExtensions = @('.cer', '.crt', '.pem', '.p7b', '.p7c')

    # --- Config and logging -------------------------------------------------
    $BaseDirectory = Get-BaseDirectory
    $ConfigExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
    if (-not $ConfigPath) { $ConfigPath = Join-Path -Path $BaseDirectory -ChildPath 'CertToolset.config.json' }
    $ConfigPath = Resolve-ToolsetPath -Path $ConfigPath -BaseDirectory $BaseDirectory

    if (-not $LogPath) {
        # The config is read after the transcript starts, so peek at Folders.Logs here.
        $LogFolder = (Get-DefaultConfig).Folders.Logs
        if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
            $Peek = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($Peek.Folders -and $Peek.Folders.Logs) { $LogFolder = $Peek.Folders.Logs }
        }
        $LogPath = $LogFolder
    }
    $LogPath = Resolve-ToolsetPath -Path $LogPath -BaseDirectory $BaseDirectory
    if (-not (Test-Path -LiteralPath $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $ScriptBaseName = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $TranscriptFile = Join-Path -Path $LogPath -ChildPath ('{0}-{1}.log' -f $ScriptBaseName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Start-Transcript -LiteralPath $TranscriptFile -WhatIf:$false -Confirm:$false | Out-Null
    $TranscriptStarted = $true

    Write-Log "=== $ScriptBaseName start ==="
    if ($WhatIfPreference) { Write-Log 'Mode: WhatIf (nothing is changed)' }
    $Config = Read-ToolsetConfig -Path $ConfigPath -Explicit $ConfigExplicit

    # --- Input validation ---------------------------------------------------
    if (-not $ResponsePath) { $ResponsePath = $Config.Folders.Responses }
    $ResponsePath = Resolve-ToolsetPath -Path $ResponsePath -BaseDirectory $BaseDirectory
    if (-not $ExportPath) { $ExportPath = $Config.Folders.Exports }
    $ExportPath = Resolve-ToolsetPath -Path $ExportPath -BaseDirectory $BaseDirectory
    $CompletedPath = Join-Path -Path $ResponsePath -ChildPath 'Completed'

    $PfxEncryption = [string]$Config.Export.PfxEncryption
    if ($PfxEncryption -notin 'AES256_SHA256', 'TripleDES_SHA1') {
        throw "Export.PfxEncryption '$PfxEncryption' is not supported (AES256_SHA256, TripleDES_SHA1)."
    }
    $PemIncludeRoot = [bool]$Config.Export.PemIncludeRoot
    $PemIterations = [int]$Config.Export.PemIterations
    if ($PemIterations -lt 10000) { throw "Export.PemIterations $PemIterations is too low (minimum 10000)." }
    $MinPasswordLength = [int]$Config.Export.MinPasswordLength
    if ($MinPasswordLength -lt 1) { $MinPasswordLength = 1 }

    $PfxParams = @{ ChainOption = 'BuildChain' }
    if ((Get-Command Export-PfxCertificate).Parameters.ContainsKey('CryptoAlgorithmOption')) {
        $PfxParams['CryptoAlgorithmOption'] = $PfxEncryption
    }
    elseif ($ExportPfx -and $PfxEncryption -ne 'TripleDES_SHA1') {
        Write-Log 'This Windows version cannot write AES PFX files; the PFX uses TripleDES-SHA1.' 'WARN'
    }

    Write-Log "Responses : $ResponsePath"
    Write-Log "Exports   : $ExportPath (PFX: $([bool]$ExportPfx), PEM: $([bool]$ExportPem))"

    $Files = @()
    if (Test-Path -LiteralPath $ResponsePath -PathType Container) {
        $Files = @(Get-ChildItem -LiteralPath $ResponsePath -File | Where-Object { $ResponseExtensions -contains $_.Extension.ToLowerInvariant() } | Sort-Object Name)
    }
    elseif ($PSCmdlet.ShouldProcess($ResponsePath, 'Create Responses folder')) {
        New-Item -Path $ResponsePath -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $ResponsePath"
    }
    if ($Files.Count -eq 0) { Write-Log "No response files ($($ResponseExtensions -join ', ')) in $ResponsePath" 'WARN' }

    # --- Main logic ---------------------------------------------------------
    $Counts = [ordered]@{ Completed = 0; AlreadyInstalled = 0; WhatIf = 0; Failed = 0; ExportFailed = 0 }

    foreach ($File in $Files) {
        Write-Log ''
        Write-Log "----- $($File.Name) -----"

        try {
            $FileCerts = Read-CertificateFile -File $File.FullName

            # Find the end-entity certificate: already installed with a key, or
            # matching a pending request by public key.
            $Pending = @{}
            foreach ($Request in @(Get-ChildItem -Path "Cert:\$StoreLocation\REQUEST")) {
                $Pending[(Get-PublicKeyId $Request)] = $Request
            }
            $Leaf = $null
            $Installed = $null
            $PendingMatch = $null
            foreach ($Cert in $FileCerts) {
                $InStore = Get-Item -Path "Cert:\$StoreLocation\My\$($Cert.Thumbprint)" -ErrorAction SilentlyContinue
                if ($InStore -and $InStore.HasPrivateKey) { $Leaf = $Cert; $Installed = $InStore; break }
                $Match = $Pending[(Get-PublicKeyId $Cert)]
                if ($Match) { $Leaf = $Cert; $PendingMatch = $Match; break }
            }
            if (-not $Leaf) {
                $Names = ($FileCerts | ForEach-Object { $_.Subject }) -join '; '
                throw "No pending request on this machine matches this response ($Names). Was the CSR created on another machine, or the pending request removed?"
            }

            $Extras = @($FileCerts | Where-Object { $_.Thumbprint -ne $Leaf.Thumbprint })
            Write-Log "Certificate : $($Leaf.Subject)"
            Write-Log "Issuer      : $($Leaf.Issuer)"
            Write-Log "Thumbprint  : $($Leaf.Thumbprint)"
            Write-Log ("Valid       : {0:yyyy-MM-dd} - {1:yyyy-MM-dd}" -f $Leaf.NotBefore, $Leaf.NotAfter)
            if ($Extras.Count) { Write-Log "Chain certs in file: $($Extras.Count)" }
            if ($Leaf.NotAfter -lt (Get-Date)) { Write-Log 'The certificate has already expired.' 'WARN' }

            # CA certificates from the response file, in chain order: root first
            # (only with -InstallRootCA), then intermediates, so certreq and the
            # exports can build the chain.
            $FileRoots = @($Extras | Where-Object { (Test-IsCaCertificate $_) -and $_.Subject -eq $_.Issuer })
            $RootPlanned = $false
            foreach ($Root in $FileRoots) {
                if (Get-Item -Path "Cert:\$StoreLocation\Root\$($Root.Thumbprint)" -ErrorAction SilentlyContinue) { continue }
                if (-not $InstallRootCA) {
                    Write-Log "Root CA '$($Root.Subject)' from the file is not trusted on this machine." 'WARN'
                    continue
                }
                $RootPlanned = $true
                $RootLabel = "{0} (thumbprint {1}, valid to {2:yyyy-MM-dd})" -f $Root.Subject, $Root.Thumbprint, $Root.NotAfter
                if ($PSCmdlet.ShouldProcess($RootLabel, "Trust root CA: add to Cert:\$StoreLocation\Root")) {
                    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $StoreLocation)
                    $Store.Open('ReadWrite')
                    $Store.Add($Root)
                    $Store.Close()
                    Write-Log "Root CA added to the trusted root store (-InstallRootCA): $RootLabel" 'WARN'
                }
            }

            foreach ($Extra in $Extras) {
                if (-not (Test-IsCaCertificate $Extra)) { continue }
                if ($Extra.Subject -eq $Extra.Issuer) { continue }
                if (Get-Item -Path "Cert:\$StoreLocation\CA\$($Extra.Thumbprint)" -ErrorAction SilentlyContinue) { continue }
                if ($PSCmdlet.ShouldProcess($Extra.Subject, "Add intermediate CA to Cert:\$StoreLocation\CA")) {
                    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store('CA', $StoreLocation)
                    $Store.Open('ReadWrite')
                    $Store.Add($Extra)
                    $Store.Close()
                    Write-Log "Added intermediate CA: $($Extra.Subject)"
                }
            }

            if ($Installed) {
                Write-Log "Already installed in Cert:\$StoreLocation\My with a private key - not installing again."
                $Counts.AlreadyInstalled++
            }
            else {
                Write-Log "Pending request: '$($PendingMatch.FriendlyName)' (created $('{0:yyyy-MM-dd}' -f $PendingMatch.NotBefore))"

                # certreq -accept refuses certificates whose chain is not trusted;
                # check first so the operator gets clear steps instead.
                $Trust = Test-ChainTrust -Certificate $Leaf -ExtraCertificates $Extras
                if (-not $Trust.Trusted -and -not ($WhatIfPreference -and $RootPlanned)) {
                    foreach ($Line in (Get-TrustHelp -Trust $Trust -RootInFile ($FileRoots.Count -gt 0))) { Write-Log $Line 'WARN' }
                    throw 'The CA chain is not trusted on this machine - see the steps above.'
                }

                if (-not $PSCmdlet.ShouldProcess($File.FullName, "Install certificate via certreq -accept $CertReqStoreFlag")) {
                    $Counts.WhatIf++
                    continue
                }

                # A multi-certificate PEM is handed to certreq as the leaf only.
                $AcceptFile = $File.FullName
                $TempFile = $null
                if ($FileCerts.Count -gt 1 -and $File.Extension -in '.pem', '.cer', '.crt') {
                    $TempFile = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("CertToolset-{0}.cer" -f $Leaf.Thumbprint)
                    [IO.File]::WriteAllBytes($TempFile, $Leaf.RawData)
                    $AcceptFile = $TempFile
                }
                try {
                    $Result = Invoke-NativeCommand -FilePath 'certreq.exe' -ArgumentList @('-accept', $CertReqStoreFlag, '-q', $AcceptFile)
                }
                finally {
                    if ($TempFile) { Remove-Item -LiteralPath $TempFile -Force -ErrorAction SilentlyContinue }
                }
                $Result.Output | Where-Object { $_.Trim() } | ForEach-Object { Write-Log "certreq: $($_.Trim())" }
                if ($Result.ExitCode -ne 0) {
                    $Code = '0x{0:X8}' -f $Result.ExitCode
                    if ($Code -in '0x800B010A', '0x800B0109') {
                        $Trust = Test-ChainTrust -Certificate $Leaf -ExtraCertificates $Extras
                        foreach ($Line in (Get-TrustHelp -Trust $Trust -RootInFile ($FileRoots.Count -gt 0))) { Write-Log $Line 'WARN' }
                        throw "certreq -accept failed ($Code): the CA chain is not trusted on this machine - see the steps above."
                    }
                    throw "certreq -accept failed ($Code). See the certreq lines above."
                }

                # Confirm the key really is bound (not just a clean exit code).
                $Installed = Get-Item -Path "Cert:\$StoreLocation\My\$($Leaf.Thumbprint)" -ErrorAction SilentlyContinue
                if (-not $Installed) { throw "Certificate $($Leaf.Thumbprint) not found in Cert:\$StoreLocation\My after certreq -accept." }
                if (-not $Installed.HasPrivateKey) { throw "Certificate $($Leaf.Thumbprint) has no private key after certreq -accept." }
                Write-Log "Installed in Cert:\$StoreLocation\My with private key, Friendly Name '$($Installed.FriendlyName)'." 'OK'
                $Counts.Completed++
            }

            # --- Export -----------------------------------------------------
            if ($ExportPfx -or $ExportPem) {
                $FriendlyName = $Installed.FriendlyName
                if ([string]::IsNullOrWhiteSpace($FriendlyName)) {
                    $FriendlyName = $Installed.Thumbprint
                    Write-Log 'No Friendly Name; using the thumbprint for file names.' 'WARN'
                }
                $SafeName = ConvertTo-SafeFileName -Name $FriendlyName
                $TargetFolder = Join-Path -Path $ExportPath -ChildPath $SafeName
                $PfxFile = Join-Path -Path $TargetFolder -ChildPath "$SafeName.pfx"
                $PemFile = Join-Path -Path $TargetFolder -ChildPath "$SafeName.pem"

                try {
                    foreach ($Target in @($(if ($ExportPfx) { $PfxFile }), $(if ($ExportPem) { $PemFile })) | Where-Object { $_ }) {
                        if ((Test-Path -LiteralPath $Target) -and -not $Force) {
                            throw "Export file already exists: $Target (use -Force to overwrite, or Export-CertBundle.ps1)."
                        }
                    }
                    $DoPfx = $ExportPfx -and $PSCmdlet.ShouldProcess($PfxFile, 'Export PFX (private key + chain)')
                    $DoPem = $ExportPem -and $PSCmdlet.ShouldProcess($PemFile, 'Export PEM (certificate + chain + encrypted key)')

                    if ($DoPfx -or $DoPem) {
                        $Chain = Get-CertificateChain -Certificate $Installed -ExtraCertificates $Extras -IncludeRoot $PemIncludeRoot
                        if (-not $Chain.Complete) {
                            Write-Log 'The chain is incomplete (an intermediate or root is missing); exports hold only what was found.' 'WARN'
                        }

                        $Password = Read-ExportPassword -Target $FriendlyName -MinLength $MinPasswordLength
                        if (-not $Password) { throw 'Password prompt cancelled - nothing exported.' }

                        Initialize-ExportRoot -Path $ExportPath
                        if (-not (Test-Path -LiteralPath $TargetFolder)) { New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null }

                        if ($DoPfx) {
                            if (Test-Path -LiteralPath $PfxFile) { Remove-Item -LiteralPath $PfxFile -Force }
                            Export-PfxCertificate -Cert $Installed -FilePath $PfxFile -Password $Password @PfxParams | Out-Null
                            Write-Log "PFX exported: $PfxFile" 'OK'
                        }
                        if ($DoPem) {
                            $Pkcs8 = Get-Pkcs8PrivateKey -Certificate $Installed
                            try {
                                $Encrypted = Protect-Pkcs8PrivateKey -Pkcs8 $Pkcs8 -Password $Password -Iterations $PemIterations
                            }
                            finally {
                                [Array]::Clear($Pkcs8, 0, $Pkcs8.Length)
                            }
                            $Pem = (ConvertTo-Pem -Data $Installed.RawData -Label 'CERTIFICATE')
                            foreach ($Issuer in $Chain.Issuers) { $Pem += (ConvertTo-Pem -Data $Issuer.RawData -Label 'CERTIFICATE') }
                            $Pem += (ConvertTo-Pem -Data $Encrypted -Label 'ENCRYPTED PRIVATE KEY')
                            [IO.File]::WriteAllText($PemFile, $Pem, [Text.Encoding]::ASCII)
                            Write-Log "PEM exported: $PemFile (certificate + $($Chain.Issuers.Count) chain cert(s) + encrypted key)" 'OK'
                        }
                        $Password.Dispose()
                    }
                }
                catch {
                    Write-Log "Export failed: $($_.Exception.Message)" 'ERROR'
                    $Counts.ExportFailed++
                }
            }

            # --- Archive the response ---------------------------------------
            if ($PSCmdlet.ShouldProcess($File.FullName, "Move to $CompletedPath")) {
                if (-not (Test-Path -LiteralPath $CompletedPath)) { New-Item -Path $CompletedPath -ItemType Directory -Force | Out-Null }
                $Destination = Join-Path -Path $CompletedPath -ChildPath $File.Name
                if (Test-Path -LiteralPath $Destination) {
                    $Destination = Join-Path -Path $CompletedPath -ChildPath ('{0}-{1}{2}' -f $File.BaseName, (Get-Date -Format 'yyyyMMdd-HHmmss'), $File.Extension)
                }
                Move-Item -LiteralPath $File.FullName -Destination $Destination
                Write-Log "Moved to $Destination"
            }
        }
        catch {
            Write-Log "FAILED: $($_.Exception.Message)" 'ERROR'
            Write-Log 'The response file was left in place for a retry.'
            $Counts.Failed++
        }
    }

    # --- Stale pending requests --------------------------------------------
    if ($RemoveStaleRequests) {
        Write-Log ''
        Write-Log "----- Pending requests older than $StaleDays days -----"
        $Cutoff = (Get-Date).AddDays(-$StaleDays)
        $Stale = @(Get-ChildItem -Path "Cert:\$StoreLocation\REQUEST" | Where-Object { $_.NotBefore -lt $Cutoff })
        if ($Stale.Count -eq 0) { Write-Log 'None found.' }
        foreach ($Request in $Stale) {
            $Label = "'{0}' {1} (created {2:yyyy-MM-dd})" -f $Request.FriendlyName, $Request.Thumbprint, $Request.NotBefore
            if ($PSCmdlet.ShouldProcess($Label, 'Remove pending request and its private key')) {
                Remove-Item -Path "Cert:\$StoreLocation\REQUEST\$($Request.Thumbprint)" -DeleteKey
                Write-Log "Removed pending request $Label"
            }
        }
    }

    Write-Log ''
    Write-Log ('----- Summary: {0} completed, {1} already installed, {2} failed, {3} export(s) failed{4} -----' -f
        $Counts.Completed, $Counts.AlreadyInstalled, $Counts.Failed, $Counts.ExportFailed,
        $(if ($Counts.WhatIf) { ", $($Counts.WhatIf) skipped (WhatIf)" } else { '' }))
    if ($Counts.Failed -gt 0) { Write-Log "Failed responses were left in $ResponsePath for a retry." 'WARN' }

    Write-Log "=== $ScriptBaseName end ==="
}
catch {
    Write-Error $_
    throw
}
finally {
    if ($TranscriptStarted) { Stop-ToolsetTranscript }
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
}
