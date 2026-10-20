#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exports installed certificates from Cert:\LocalMachine\My as PFX and/or PEM.

.DESCRIPTION
    Re-exports certificates that are already installed on this machine, e.g. for
    another server or an appliance long after Complete-CertRequest.ps1 ran.
    Select certificates by -Thumbprint or -FriendlyName (wildcards allowed), or
    use -List to see the certificates that have a private key.

    For each certificate, asks for a password (dialog box, console fallback) and
    writes to Exports\<FriendlyName>\:
      <FriendlyName>.pfx   private key + chain, password protected
      <FriendlyName>.pem   certificate + chain + private key encrypted with the
                           same password (PKCS#8, PBKDF2-SHA256 + AES-256-CBC),
                           the same layout as "openssl pkcs12 -in x.pfx -out x.pem"

    A transcript of every run is written to the Logs folder.

    Exit code: 0 when every selected certificate was exported, 1 when any failed.

    Supports -WhatIf and -Confirm.

.PARAMETER Thumbprint
    Thumbprint(s) of the certificate(s) to export. Spaces and hidden characters
    copied from the certificate dialog are removed.

.PARAMETER FriendlyName
    Friendly Name of the certificate(s) to export. Wildcards allowed, e.g.
    'app01*'. Every match is exported (one password prompt each).

.PARAMETER Format
    Pfx, Pem or both. Default: both.

.PARAMETER List
    List the certificates in Cert:\LocalMachine\My that have a private key, with
    expiry and export status, and exit.

.PARAMETER ExportPath
    Root folder for exports. Default: the Exports folder from the config,
    relative to the script folder.

.PARAMETER Force
    Overwrite existing export files.

.PARAMETER ConfigPath
    JSON config file. Default: <script folder>\CertToolset.config.json

.PARAMETER LogPath
    Folder for the transcript. Default: the Logs folder from the config, relative
    to the script folder.

.EXAMPLE
    .\Export-CertBundle.ps1 -List
    Shows the certificates that can be exported.

.EXAMPLE
    .\Export-CertBundle.ps1 -FriendlyName 'app01.contoso.local_202610'
    Exports PFX and PEM for one certificate.

.EXAMPLE
    .\Export-CertBundle.ps1 -Thumbprint 'A1B2...' -Format Pem -Force
    Re-exports only the PEM and overwrites an existing file.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.1.0
    Date Created  : 2026-10-16
    Last Modified : 2026-10-20

    Change Log
    ----------
    1.1.0 (2026-10-20) - PowerShell 7 writes the PFX with .NET (Pkcs12Builder)
                          instead of Export-PfxCertificate, which PS 7.0 cannot
                          load; -Format Pem no longer needs the PKI module.
    1.0.1 (2026-10-16) - Exit code 1 when any export failed.
    1.0.0 (2026-10-16) - Initial release.

    Operational notes:
    - Requires local Administrator rights (Local Machine store).
    - The password is never a parameter, so it does not end up in the transcript,
      command history or process list. In a remote session (Enter-PSSession) or
      without a desktop, a masked console prompt is used instead of the dialog.
    - The private key must be exportable. Keys created by New-CertRequest.ps1 are;
      keys imported from a PFX without "Mark this key as exportable" are not.
    - The Exports root folder is created with an ACL limited to Administrators,
      SYSTEM and the account running the script. If it already exists with a
      broader ACL, a warning is shown (the ACL is not changed).
    - The chain is built from the local certificate stores. If an intermediate is
      missing, the export still happens and a warning is shown.
    - Export options are in the config: Export.PfxEncryption (AES256_SHA256 or
      TripleDES_SHA1 for old appliances), Export.PemIncludeRoot,
      Export.PemIterations and Export.MinPasswordLength.
    - PFX writer: Windows PowerShell 5.1 uses Export-PfxCertificate (TripleDES
      only on Server 2016 and older); PowerShell 7 uses .NET Pkcs12Builder (AES
      on every Windows version) and reads the file back before writing it. The
      log names the writer used.
    - Only RSA keys can be exported to PEM.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Thumbprint(s) of the certificate(s) to export.
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$Thumbprint,

    # Friendly Name of the certificate(s) to export; wildcards allowed.
    [Parameter(Mandatory = $false)]
    [string]$FriendlyName,

    # Export formats: Pfx, Pem or both.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Pfx', 'Pem')]
    [string[]]$Format = @('Pfx', 'Pem'),

    # List exportable certificates and exit.
    [Parameter(Mandatory = $false)]
    [switch]$List,

    # Root folder for exports. Default: Exports folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

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

function Get-PfxExportPlan {
    # How the PFX is written. PowerShell 7: .NET Pkcs12Builder, because the PKI
    # module is Windows PowerShell-only there (PS 7.0 does not auto-load it, later
    # versions run it in a compatibility session with deserialized objects).
    # Windows PowerShell 5.1: Export-PfxCertificate.
    param([string]$Encryption)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
        catch { throw "The .NET PFX writer (System.Security.Cryptography.Pkcs) is not available in PowerShell $($PSVersionTable.PSVersion): $($_.Exception.Message)" }
        return [pscustomobject]@{ Method = 'DotNet'; Encryption = $Encryption; CmdletParams = @{} }
    }
    $Command = Get-Command Export-PfxCertificate -ErrorAction SilentlyContinue
    if (-not $Command) {
        throw 'Export-PfxCertificate (PKI module) is not available in Windows PowerShell on this machine. Run the script in PowerShell 7 (it has its own PFX writer) or export PEM only.'
    }
    $CmdletParams = @{ ChainOption = 'BuildChain' }
    $Effective = $Encryption
    if ($Command.Parameters.ContainsKey('CryptoAlgorithmOption')) { $CmdletParams['CryptoAlgorithmOption'] = $Encryption }
    else { $Effective = 'TripleDES_SHA1' }   # Server 2016 and older: no AES option
    return [pscustomobject]@{ Method = 'Cmdlet'; Encryption = $Effective; CmdletParams = $CmdletParams }
}

function Export-PfxFile {
    # Password-protected PFX with the certificate, its chain (root included) and
    # the private key, written as planned by Get-PfxExportPlan.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$ExtraCertificates = @(),
        [System.Security.SecureString]$Password,
        [object]$Plan,
        [string]$FilePath
    )
    if ($Plan.Method -eq 'Cmdlet') {
        $CmdletParams = $Plan.CmdletParams
        Export-PfxCertificate -Cert $Certificate -FilePath $FilePath -Password $Password @CmdletParams | Out-Null
        return
    }

    # .NET: certificates in a password-encrypted safe, the key in a shrouded key
    # bag, linked by localKeyId and labelled with the Friendly Name, sealed with a
    # MAC. Same algorithms as the Windows export: PBES2 AES-256-CBC + PBKDF2-SHA256
    # with a SHA-256 MAC, or PBE-SHA1-3DES with a SHA-1 MAC for old appliances.
    if ($Plan.Encryption -eq 'AES256_SHA256') {
        $Pbe = New-Object System.Security.Cryptography.PbeParameters(
            [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [System.Security.Cryptography.HashAlgorithmName]::SHA256, 2048)
        $MacHash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    }
    else {
        $Pbe = New-Object System.Security.Cryptography.PbeParameters(
            [System.Security.Cryptography.PbeEncryptionAlgorithm]::TripleDes3KeyPkcs12, [System.Security.Cryptography.HashAlgorithmName]::SHA1, 2048)
        $MacHash = [System.Security.Cryptography.HashAlgorithmName]::SHA1
    }

    $Key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $Key) { $Key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate) }
    if (-not $Key) { throw 'The certificate has no RSA or ECDSA private key.' }

    $Chain = Get-CertificateChain -Certificate $Certificate -ExtraCertificates $ExtraCertificates -IncludeRoot $true
    $Attributes = @([System.Security.Cryptography.Pkcs.Pkcs9LocalKeyId]::new([byte[]]$Certificate.GetCertHash()))
    if ($Certificate.FriendlyName) {
        $Bmp = New-DerElement -Tag 0x1E -Content @(, [Text.Encoding]::BigEndianUnicode.GetBytes($Certificate.FriendlyName))   # BMPString
        $Attributes += New-Object System.Security.Cryptography.AsnEncodedData('1.2.840.113549.1.9.20', $Bmp)                  # friendlyName
    }

    $Plain = ConvertFrom-SecureStringPlain $Password
    try {
        $CertContents = New-Object System.Security.Cryptography.Pkcs.Pkcs12SafeContents
        $LeafBag = $CertContents.AddCertificate($Certificate)
        foreach ($Attribute in $Attributes) { [void]$LeafBag.Attributes.Add($Attribute) }
        foreach ($Issuer in $Chain.Issuers) { [void]$CertContents.AddCertificate($Issuer) }

        $KeyContents = New-Object System.Security.Cryptography.Pkcs.Pkcs12SafeContents
        $KeyBag = $KeyContents.AddShroudedKey($Key, [string]$Plain, $Pbe)
        foreach ($Attribute in $Attributes) { [void]$KeyBag.Attributes.Add($Attribute) }

        $Builder = New-Object System.Security.Cryptography.Pkcs.Pkcs12Builder
        $Builder.AddSafeContentsEncrypted($CertContents, [string]$Plain, $Pbe)
        $Builder.AddSafeContentsUnencrypted($KeyContents)
        $Builder.SealWithMac([string]$Plain, $MacHash, 2048)
        $Bytes = $Builder.Encode()

        # Read it back before writing: the password must open it and give the key.
        $Check = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $Check.Import($Bytes, [string]$Plain, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        $Leaf = @($Check | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint })
        $Readable = ($Leaf.Count -eq 1 -and $Leaf[0].HasPrivateKey)
        foreach ($Cert in $Check) { $Cert.Dispose() }
        if (-not $Readable) { throw 'The PFX written by the .NET writer could not be read back with its private key.' }
    }
    finally {
        $Plain = $null
        $Key.Dispose()
    }
    [IO.File]::WriteAllBytes($FilePath, $Bytes)
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
# Helper functions - selection
# -------------------------------------------------------------------------

function Get-KeyExportStatus {
    # 'Exportable', 'Not exportable', 'Not RSA' or 'Unknown' for a certificate's private key.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    try {
        $Rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if (-not $Rsa) { return 'Not RSA' }
        if ($Rsa -is [System.Security.Cryptography.RSACng]) {
            $Exportable = [System.Security.Cryptography.CngExportPolicies]::AllowExport -bor [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
            if ($Rsa.Key.ExportPolicy -band $Exportable) { return 'Exportable' }
            return 'Not exportable'
        }
        if ($Rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            if ($Rsa.CspKeyContainerInfo.Exportable) { return 'Exportable' }
            return 'Not exportable'
        }
    }
    catch {
        return 'Unknown'
    }
    return 'Unknown'
}

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$TranscriptStarted = $false
$ExitCode = 0

try {
    $ErrorActionPreference = 'Stop'

    # --- Fixed settings -----------------------------------------------------
    # The toolset works on the Local Machine store only.
    $StoreLocation = 'LocalMachine'

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

    # --- List mode ----------------------------------------------------------
    if ($List) {
        $Available = @(Get-ChildItem -Path "Cert:\$StoreLocation\My" | Where-Object { $_.HasPrivateKey } | Sort-Object NotAfter)
        Write-Log "Certificates with a private key in Cert:\$StoreLocation\My: $($Available.Count)"
        Write-Log ('{0,-40}  {1,-10}  {2,-14}  {3}' -f 'Thumbprint', 'Expires', 'Key', 'Friendly Name / Subject')
        foreach ($Cert in $Available) {
            $Name = $(if ($Cert.FriendlyName) { $Cert.FriendlyName } else { '(no Friendly Name)' })
            Write-Log ('{0,-40}  {1:yyyy-MM-dd}  {2,-14}  {3} / {4}' -f $Cert.Thumbprint, $Cert.NotAfter, (Get-KeyExportStatus $Cert), $Name, $Cert.Subject)
        }
        Write-Log "=== $ScriptBaseName end ==="
        return
    }

    # --- Input validation ---------------------------------------------------
    if (-not $Thumbprint -and -not $FriendlyName) {
        throw 'Specify -Thumbprint or -FriendlyName (use -List to see the certificates).'
    }
    if (-not $ExportPath) { $ExportPath = $Config.Folders.Exports }
    $ExportPath = Resolve-ToolsetPath -Path $ExportPath -BaseDirectory $BaseDirectory

    $PfxEncryption = [string]$Config.Export.PfxEncryption
    if ($PfxEncryption -notin 'AES256_SHA256', 'TripleDES_SHA1') {
        throw "Export.PfxEncryption '$PfxEncryption' is not supported (AES256_SHA256, TripleDES_SHA1)."
    }
    $PemIncludeRoot = [bool]$Config.Export.PemIncludeRoot
    $PemIterations = [int]$Config.Export.PemIterations
    if ($PemIterations -lt 10000) { throw "Export.PemIterations $PemIterations is too low (minimum 10000)." }
    $MinPasswordLength = [int]$Config.Export.MinPasswordLength
    if ($MinPasswordLength -lt 1) { $MinPasswordLength = 1 }

    $ExportPfx = $Format -contains 'Pfx'
    $ExportPem = $Format -contains 'Pem'
    $PfxPlan = $null
    if ($ExportPfx) {
        $PfxPlan = Get-PfxExportPlan -Encryption $PfxEncryption
        if ($PfxPlan.Encryption -ne $PfxEncryption) {
            Write-Log 'Export-PfxCertificate on this Windows version cannot write AES PFX files; the PFX uses TripleDES-SHA1.' 'WARN'
        }
        Write-Log "PFX writer: $(if ($PfxPlan.Method -eq 'DotNet') { ".NET Pkcs12Builder (PowerShell $($PSVersionTable.PSVersion))" } else { 'Export-PfxCertificate' }), $($PfxPlan.Encryption)"
    }

    # Selection by thumbprint and/or Friendly Name.
    $Selected = [ordered]@{}
    foreach ($Value in $Thumbprint) {
        $Clean = ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($Clean.Length -ne 40) { throw "Thumbprint '$Value' is not 40 hex characters." }
        $Cert = Get-Item -Path "Cert:\$StoreLocation\My\$Clean" -ErrorAction SilentlyContinue
        if (-not $Cert) { throw "No certificate with thumbprint $Clean in Cert:\$StoreLocation\My." }
        $Selected[$Cert.Thumbprint] = $Cert
    }
    if ($FriendlyName) {
        $NameMatches = @(Get-ChildItem -Path "Cert:\$StoreLocation\My" | Where-Object { $_.FriendlyName -like $FriendlyName })
        if ($NameMatches.Count -eq 0) { throw "No certificate with Friendly Name like '$FriendlyName' in Cert:\$StoreLocation\My (use -List)." }
        foreach ($Cert in $NameMatches) { $Selected[$Cert.Thumbprint] = $Cert }
    }

    Write-Log "Exports : $ExportPath (PFX: $ExportPfx, PEM: $ExportPem)"
    Write-Log "Selected: $($Selected.Count) certificate(s)"

    # --- Main logic ---------------------------------------------------------
    $Counts = [ordered]@{ Exported = 0; Skipped = 0; Failed = 0 }

    foreach ($Cert in $Selected.Values) {
        Write-Log ''
        Write-Log "----- $(if ($Cert.FriendlyName) { $Cert.FriendlyName } else { $Cert.Thumbprint }) -----"
        Write-Log "Certificate : $($Cert.Subject)"
        Write-Log "Thumbprint  : $($Cert.Thumbprint)"
        Write-Log ("Valid       : {0:yyyy-MM-dd} - {1:yyyy-MM-dd}" -f $Cert.NotBefore, $Cert.NotAfter)

        try {
            if (-not $Cert.HasPrivateKey) { throw 'The certificate has no private key on this machine.' }
            $KeyStatus = Get-KeyExportStatus $Cert
            if ($KeyStatus -eq 'Not exportable') { throw 'The private key is marked as not exportable.' }
            if ($ExportPem -and $KeyStatus -eq 'Not RSA') { throw 'PEM export supports RSA keys only.' }
            if ($Cert.NotAfter -lt (Get-Date)) { Write-Log 'The certificate has expired.' 'WARN' }

            $Name = $Cert.FriendlyName
            if ([string]::IsNullOrWhiteSpace($Name)) {
                $Name = $Cert.Thumbprint
                Write-Log 'No Friendly Name; using the thumbprint for file names.' 'WARN'
            }
            $SafeName = ConvertTo-SafeFileName -Name $Name
            $TargetFolder = Join-Path -Path $ExportPath -ChildPath $SafeName
            $PfxFile = Join-Path -Path $TargetFolder -ChildPath "$SafeName.pfx"
            $PemFile = Join-Path -Path $TargetFolder -ChildPath "$SafeName.pem"

            foreach ($Target in @($(if ($ExportPfx) { $PfxFile }), $(if ($ExportPem) { $PemFile })) | Where-Object { $_ }) {
                if ((Test-Path -LiteralPath $Target) -and -not $Force) {
                    throw "Export file already exists: $Target (use -Force to overwrite)."
                }
            }
            $DoPfx = $ExportPfx -and $PSCmdlet.ShouldProcess($PfxFile, 'Export PFX (private key + chain)')
            $DoPem = $ExportPem -and $PSCmdlet.ShouldProcess($PemFile, 'Export PEM (certificate + chain + encrypted key)')
            if (-not ($DoPfx -or $DoPem)) {
                $Counts.Skipped++
                continue
            }

            $Chain = Get-CertificateChain -Certificate $Cert -IncludeRoot $PemIncludeRoot
            if (-not $Chain.Complete) {
                Write-Log 'The chain is incomplete (an intermediate or root is missing); exports hold only what was found.' 'WARN'
            }

            $Password = Read-ExportPassword -Target $Name -MinLength $MinPasswordLength
            if (-not $Password) { throw 'Password prompt cancelled - nothing exported.' }

            Initialize-ExportRoot -Path $ExportPath
            if (-not (Test-Path -LiteralPath $TargetFolder)) { New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null }

            if ($DoPfx) {
                if (Test-Path -LiteralPath $PfxFile) { Remove-Item -LiteralPath $PfxFile -Force }
                Export-PfxFile -Certificate $Cert -Password $Password -Plan $PfxPlan -FilePath $PfxFile
                Write-Log "PFX exported: $PfxFile" 'OK'
            }
            if ($DoPem) {
                $Pkcs8 = Get-Pkcs8PrivateKey -Certificate $Cert
                try {
                    $Encrypted = Protect-Pkcs8PrivateKey -Pkcs8 $Pkcs8 -Password $Password -Iterations $PemIterations
                }
                finally {
                    [Array]::Clear($Pkcs8, 0, $Pkcs8.Length)
                }
                $Pem = (ConvertTo-Pem -Data $Cert.RawData -Label 'CERTIFICATE')
                foreach ($Issuer in $Chain.Issuers) { $Pem += (ConvertTo-Pem -Data $Issuer.RawData -Label 'CERTIFICATE') }
                $Pem += (ConvertTo-Pem -Data $Encrypted -Label 'ENCRYPTED PRIVATE KEY')
                [IO.File]::WriteAllText($PemFile, $Pem, [Text.Encoding]::ASCII)
                Write-Log "PEM exported: $PemFile (certificate + $($Chain.Issuers.Count) chain cert(s) + encrypted key)" 'OK'
            }
            $Password.Dispose()
            $Counts.Exported++
        }
        catch {
            Write-Log "FAILED: $($_.Exception.Message)" 'ERROR'
            $Counts.Failed++
        }
    }

    Write-Log ''
    Write-Log ('----- Summary: {0} exported, {1} failed{2} -----' -f $Counts.Exported, $Counts.Failed,
        $(if ($Counts.Skipped) { ", $($Counts.Skipped) skipped (WhatIf)" } else { '' }))
    if ($Counts.Failed -gt 0) { $ExitCode = 1 }

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

exit $ExitCode
