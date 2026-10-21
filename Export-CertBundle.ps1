#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exports installed certificates from Cert:\LocalMachine\My as PFX, PEM and/or
    Java KeyStore (JKS).

.DESCRIPTION
    Re-exports certificates that are already installed on this machine, e.g. for
    another server or an appliance long after Complete-CertRequest.ps1 ran.
    Select certificates by -Thumbprint or -FriendlyName (wildcards allowed), or
    use -List to see the certificates that have a private key.

    For each certificate, asks for a password (dialog box, console fallback) and
    writes to Exports\<CN>\ (the certificate's CN without the date, so renewals
    land next to the previous files):
      <FriendlyName>.pfx   private key + chain, password protected
      <FriendlyName>.pem   certificate + chain + private key encrypted with the
                           same password (PKCS#8, PBKDF2-SHA256 + AES-256-CBC),
                           the same layout as "openssl pkcs12 -in x.pfx -out x.pem"
      <FriendlyName>.jks   only with -Format Jks: private key + full chain under
                           the alias <FriendlyName> (lower case); keystore and
                           key use the same password

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
    Pfx, Pem and/or Jks. Default: Pfx and Pem. Jks (Java KeyStore, e.g. for
    Tomcat on Java 8) is opt-in.

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

.EXAMPLE
    .\Export-CertBundle.ps1 -FriendlyName 'app01.contoso.local_202610' -Format Jks
    Exports a JKS keystore for Tomcat (alias 'app01.contoso.local_202610').

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.2.1
    Date Created  : 2026-10-16
    Last Modified : 2026-10-21

    Change Log
    ----------
    1.2.1 (2026-10-21) - JKS export failed on PowerShell 7.0 ("unexpected
                          header"): the JKS magic no longer uses a hex literal,
                          which 7.0 parses as a negative number.
    1.2.0 (2026-10-21) - Export folder is the certificate's CN (no _yyyyMM), so
                          renewals share it; file names keep the Friendly Name.
                          New opt-in -Format Jks: native JKS keystore, read
                          back before it is written.
    1.1.0 (2026-10-20) - PowerShell 7 writes the PFX with .NET (Pkcs12Builder)
                          instead of Export-PfxCertificate, which PS 7.0 cannot
                          load; -Format Pem no longer needs the PKI module.
                          The PFX is checked in .NET before it is written;
                          warning when Windows here cannot open AES PFX files.
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
      only on Server 2016 and older); PowerShell 7 uses .NET Pkcs12Builder and
      checks the file in .NET (MAC, certificate, private key) before writing it.
      The log names the writer used.
    - Server 2016 and older cannot import AES-encrypted PFX files. When the
      exporting machine is one of them, a warning is logged; set
      Export.PfxEncryption to TripleDES_SHA1 for PFX files meant for such
      machines.
    - JKS: written natively (no Java needed) in the classic JKS format, which
      Java 8 and Tomcat 7 read as keystoreType JKS. Java 8 before 8u301 cannot
      read AES-encrypted PFX files; use the JKS (or a TripleDES_SHA1 PFX) there.
      The JKS key protection is the format's own SHA-1 scheme and weaker than
      the PFX/PEM encryption; keytool shows a "migrate to PKCS12" note.
    - Exports from toolset 1.1.0 and older are in Exports\<FriendlyName>\; they
      are not moved.
    - Only RSA keys can be exported to PEM and JKS.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Thumbprint(s) of the certificate(s) to export.
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$Thumbprint,

    # Friendly Name of the certificate(s) to export; wildcards allowed.
    [Parameter(Mandatory = $false)]
    [string]$FriendlyName,

    # Export formats: Pfx, Pem, Jks (any combination). Default: Pfx and Pem.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Pfx', 'Pem', 'Jks')]
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

function ConvertTo-BigEndian {
    # Unsigned big-endian integer of Size bytes (JKS fields).
    param([long]$Value, [int]$Size)
    $Bytes = New-Object byte[] $Size
    for ($i = $Size - 1; $i -ge 0; $i--) { $Bytes[$i] = [byte]($Value -band 0xFF); $Value = $Value -shr 8 }
    return , $Bytes
}

function ConvertFrom-BigEndian {
    # Unsigned big-endian integer of Size bytes at Offset (JKS fields).
    param([byte[]]$Data, [int]$Offset, [int]$Size)
    $Value = [long]0
    for ($i = 0; $i -lt $Size; $i++) { $Value = ($Value -shl 8) -bor $Data[$Offset + $i] }
    return $Value
}

function Get-JksKeyStream {
    # Sun JKS KeyProtector keystream: SHA-1 chained over password + salt/digest.
    param([byte[]]$PasswordBytes, [byte[]]$Salt, [int]$Length)
    $Sha1 = [System.Security.Cryptography.SHA1]::Create()
    $Stream = New-Object byte[] $Length
    $Digest = $Salt
    for ($Pos = 0; $Pos -lt $Length; $Pos += 20) {
        $Digest = $Sha1.ComputeHash([byte[]]($PasswordBytes + $Digest))
        [Array]::Copy($Digest, 0, $Stream, $Pos, [Math]::Min(20, $Length - $Pos))
    }
    $Sha1.Dispose()
    return , $Stream
}

function Get-JksDigest {
    # JKS integrity digest: SHA-1 over password + "Mighty Aphrodite" + keystore body.
    param([byte[]]$PasswordBytes, [byte[]]$Data, [int]$Length)
    $Magic = [Text.Encoding]::UTF8.GetBytes('Mighty Aphrodite')
    $Sha1 = [System.Security.Cryptography.SHA1]::Create()
    [void]$Sha1.TransformBlock($PasswordBytes, 0, $PasswordBytes.Length, $null, 0)
    [void]$Sha1.TransformBlock($Magic, 0, $Magic.Length, $null, 0)
    [void]$Sha1.TransformFinalBlock($Data, 0, $Length)
    $Hash = $Sha1.Hash
    $Sha1.Dispose()
    return , $Hash
}

function New-JksKeystore {
    # JKS keystore (version 2) with one private key entry. The key is protected
    # with the Sun KeyProtector (OID 1.3.6.1.4.1.42.2.17.1.1): PKCS#8 XORed with
    # a SHA-1 keystream, then a SHA-1 check value. This is the JKS format's own
    # (weak) scheme; it is what Java 8 / Tomcat 7 read as keystoreType JKS.
    param(
        [string]$Alias,
        [byte[]]$Pkcs8,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Chain,
        [byte[]]$PasswordBytes
    )
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Salt = New-Object byte[] 20; $Random.GetBytes($Salt)
    $Random.Dispose()

    $Stream = Get-JksKeyStream -PasswordBytes $PasswordBytes -Salt $Salt -Length $Pkcs8.Length
    $Protected = New-Object byte[] (20 + $Pkcs8.Length + 20)
    [Array]::Copy($Salt, 0, $Protected, 0, 20)
    for ($i = 0; $i -lt $Pkcs8.Length; $i++) { $Protected[20 + $i] = $Pkcs8[$i] -bxor $Stream[$i] }
    [Array]::Clear($Stream, 0, $Stream.Length)
    $Sha1 = [System.Security.Cryptography.SHA1]::Create()
    $Check = $Sha1.ComputeHash([byte[]]($PasswordBytes + $Pkcs8))
    $Sha1.Dispose()
    [Array]::Copy($Check, 0, $Protected, 20 + $Pkcs8.Length, 20)
    $AlgId = New-DerElement -Tag 0x30 -Content @((New-DerOid '1.3.6.1.4.1.42.2.17.1.1'), [byte[]](0x05, 0x00))
    $KeyInfo = New-DerElement -Tag 0x30 -Content @($AlgId, (New-DerElement -Tag 0x04 -Content @(, $Protected)))

    # Java readUTF/writeUTF strings: 2-byte length + UTF-8 (ASCII here).
    $AliasBytes = [Text.Encoding]::UTF8.GetBytes($Alias)
    $TypeBytes = [Text.Encoding]::ASCII.GetBytes('X.509')
    $Epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
    $Now = [long]([DateTime]::UtcNow - $Epoch).TotalMilliseconds

    $Out = New-Object 'System.Collections.Generic.List[byte]'
    $Out.AddRange([byte[]](254, 237, 254, 237))              # magic FE ED FE ED
    $Out.AddRange((ConvertTo-BigEndian -Value 2 -Size 4))            # version
    $Out.AddRange((ConvertTo-BigEndian -Value 1 -Size 4))            # entry count
    $Out.AddRange((ConvertTo-BigEndian -Value 1 -Size 4))            # tag: private key entry
    $Out.AddRange((ConvertTo-BigEndian -Value $AliasBytes.Length -Size 2)); $Out.AddRange($AliasBytes)
    $Out.AddRange((ConvertTo-BigEndian -Value $Now -Size 8))
    $Out.AddRange((ConvertTo-BigEndian -Value $KeyInfo.Length -Size 4)); $Out.AddRange($KeyInfo)
    $Out.AddRange((ConvertTo-BigEndian -Value $Chain.Count -Size 4))
    foreach ($Cert in $Chain) {
        $Out.AddRange((ConvertTo-BigEndian -Value $TypeBytes.Length -Size 2)); $Out.AddRange($TypeBytes)
        $Out.AddRange((ConvertTo-BigEndian -Value $Cert.RawData.Length -Size 4)); $Out.AddRange($Cert.RawData)
    }
    $Body = $Out.ToArray()
    $Out.AddRange((Get-JksDigest -PasswordBytes $PasswordBytes -Data $Body -Length $Body.Length))
    return , $Out.ToArray()
}

function Test-JksKeystore {
    # Reads a JKS keystore back: structure, integrity digest, chain count, and
    # the private key unprotected with the password and compared with the
    # original PKCS#8. Throws on any mismatch.
    param([byte[]]$Data, [byte[]]$PasswordBytes, [byte[]]$Pkcs8, [int]$ChainCount)
    $Body = $Data.Length - 20
    $Digest = Get-JksDigest -PasswordBytes $PasswordBytes -Data $Data -Length $Body
    for ($i = 0; $i -lt 20; $i++) {
        if ($Digest[$i] -ne $Data[$Body + $i]) { throw 'JKS check failed: the integrity digest does not verify with the password.' }
    }
    # Magic FEEDFEED as decimal: hex literals of this size parse differently
    # across PowerShell versions (negative Int32/Int64 in some).
    $Header = @(0, 4, 8, 12 | ForEach-Object { ConvertFrom-BigEndian -Data $Data -Offset $_ -Size 4 })
    if ($Header[0] -ne 4277010157 -or $Header[1] -ne 2 -or $Header[2] -ne 1 -or $Header[3] -ne 1) {
        throw ('JKS check failed: unexpected header (magic 0x{0:X8}, version {1}, entries {2}, entry type {3}).' -f $Header[0], $Header[1], $Header[2], $Header[3])
    }
    $Pos = 16
    $Pos += 2 + (ConvertFrom-BigEndian -Data $Data -Offset $Pos -Size 2) + 8            # alias, date
    $KeyLength = [int](ConvertFrom-BigEndian -Data $Data -Offset $Pos -Size 4); $Pos += 4
    $KeyInfo = New-Object byte[] $KeyLength
    [Array]::Copy($Data, $Pos, $KeyInfo, 0, $KeyLength); $Pos += $KeyLength
    $Count = [int](ConvertFrom-BigEndian -Data $Data -Offset $Pos -Size 4); $Pos += 4
    for ($c = 0; $c -lt $Count; $c++) {
        $Pos += 2 + (ConvertFrom-BigEndian -Data $Data -Offset $Pos -Size 2)
        $Pos += 4 + (ConvertFrom-BigEndian -Data $Data -Offset $Pos -Size 4)
    }
    if ($Count -ne $ChainCount -or $Pos -ne $Body) { throw 'JKS check failed: certificate chain or length mismatch.' }

    $Outer = Read-DerElement -Data $KeyInfo -Offset 0
    $AlgId = Read-DerElement -Data $KeyInfo -Offset $Outer.ValueOffset
    $Protected = Get-DerValue -Data $KeyInfo -Element (Read-DerElement -Data $KeyInfo -Offset $AlgId.Next)
    $PlainLength = $Protected.Length - 40
    $Salt = New-Object byte[] 20
    [Array]::Copy($Protected, 0, $Salt, 0, 20)
    $Stream = Get-JksKeyStream -PasswordBytes $PasswordBytes -Salt $Salt -Length $PlainLength
    $Same = ($PlainLength -eq $Pkcs8.Length)
    for ($i = 0; $Same -and $i -lt $PlainLength; $i++) {
        if (($Protected[20 + $i] -bxor $Stream[$i]) -ne $Pkcs8[$i]) { $Same = $false }
    }
    [Array]::Clear($Stream, 0, $Stream.Length)
    if (-not $Same) { throw 'JKS check failed: the private key could not be read back with the password.' }
}

function Export-JksFile {
    # Java KeyStore (JKS) with the private key and its chain under one alias.
    # Keystore and key share the password (Tomcat expects them to be equal).
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Issuers = @(),
        [string]$Alias,
        [System.Security.SecureString]$Password,
        [string]$FilePath
    )
    $Chain = @($Certificate) + @($Issuers)
    # Java hashes passwords as char[] in big-endian UTF-16.
    $PasswordBytes = [Text.Encoding]::BigEndianUnicode.GetBytes((ConvertFrom-SecureStringPlain $Password))
    $Pkcs8 = Get-Pkcs8PrivateKey -Certificate $Certificate
    try {
        $Bytes = New-JksKeystore -Alias $Alias -Pkcs8 $Pkcs8 -Chain $Chain -PasswordBytes $PasswordBytes
        Test-JksKeystore -Data $Bytes -PasswordBytes $PasswordBytes -Pkcs8 $Pkcs8 -ChainCount $Chain.Count
    }
    finally {
        [Array]::Clear($Pkcs8, 0, $Pkcs8.Length)
        [Array]::Clear($PasswordBytes, 0, $PasswordBytes.Length)
    }
    Write-Log 'JKS check: integrity digest, chain and private key verified with the password.'
    [IO.File]::WriteAllBytes($FilePath, $Bytes)
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
    $Info.Text = "Password for the exported PFX/PEM/JKS of:`r`n$Target"
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

function Get-ExportTarget {
    # Export folder and file names. The folder is the certificate's CN (no
    # date), so renewals share it; the files keep the Friendly Name (thumbprint
    # if it is empty). Without a CN, the folder uses the file name.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$FriendlyName,
        [string]$ExportPath
    )
    $Name = $FriendlyName
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = $Certificate.Thumbprint }
    $SafeName = ConvertTo-SafeFileName -Name $Name
    $FolderName = $SafeName
    if ($Certificate.Subject -match '(^|,\s*)CN=') {
        $CommonName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (-not [string]::IsNullOrWhiteSpace($CommonName)) { $FolderName = ConvertTo-SafeFileName -Name $CommonName }
    }
    $Folder = Join-Path -Path $ExportPath -ChildPath $FolderName
    return [pscustomobject]@{
        Name    = $Name
        Alias   = $Name.ToLowerInvariant()   # Java stores JKS aliases in lower case
        Folder  = $Folder
        PfxFile = Join-Path -Path $Folder -ChildPath "$SafeName.pfx"
        PemFile = Join-Path -Path $Folder -ChildPath "$SafeName.pem"
        JksFile = Join-Path -Path $Folder -ChildPath "$SafeName.jks"
    }
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

function Initialize-PfxKeyCheck {
    # Managed check of a PFX key bag (PowerShell 7 only): decrypts it without the
    # Windows PFX loader and compares the key with the certificate's public key.
    if ('CertToolset.PfxKeyCheck' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace CertToolset {
    public static class PfxKeyCheck {
        public static bool KeyMatches(byte[] encryptedPkcs8, string password, X509Certificate2 certificate) {
            int read;
            using (RSA certRsa = certificate.GetRSAPublicKey()) {
                if (certRsa != null) {
                    using (RSA key = RSA.Create()) {
                        key.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out read);
                        return CryptographicOperations.FixedTimeEquals(key.ExportParameters(false).Modulus, certRsa.ExportParameters(false).Modulus);
                    }
                }
            }
            using (ECDsa certEc = certificate.GetECDsaPublicKey()) {
                if (certEc != null) {
                    using (ECDsa key = ECDsa.Create()) {
                        key.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out read);
                        ECPoint a = key.ExportParameters(false).Q, b = certEc.ExportParameters(false).Q;
                        return CryptographicOperations.FixedTimeEquals(a.X, b.X) && CryptographicOperations.FixedTimeEquals(a.Y, b.Y);
                    }
                }
            }
            return false;
        }
    }
}
'@
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

        # Read it back before writing, in .NET only (the Windows PFX loader cannot
        # open AES files on older Windows): MAC, certificate and private key must
        # all open with the password.
        Initialize-PfxKeyCheck
        $Consumed = 0
        $Info = [System.Security.Cryptography.Pkcs.Pkcs12Info]::Decode([System.ReadOnlyMemory[byte]]$Bytes, [ref]$Consumed, $false)
        if (-not $Info.VerifyMac([string]$Plain)) { throw 'PFX check failed: the MAC does not verify with the password.' }
        $CertCount = 0; $LeafFound = $false; $KeyMatches = $false
        foreach ($Safe in $Info.AuthenticatedSafe) {
            if ($Safe.ConfidentialityMode -eq [System.Security.Cryptography.Pkcs.Pkcs12ConfidentialityMode]::Password) { $Safe.Decrypt([string]$Plain) }
            foreach ($Bag in $Safe.GetBags()) {
                if ($Bag -is [System.Security.Cryptography.Pkcs.Pkcs12CertBag]) {
                    $CertCount++
                    $BagCert = $Bag.GetCertificate()
                    if ($BagCert.Thumbprint -eq $Certificate.Thumbprint) { $LeafFound = $true }
                    $BagCert.Dispose()
                }
                elseif ($Bag -is [System.Security.Cryptography.Pkcs.Pkcs12ShroudedKeyBag]) {
                    $KeyMatches = [CertToolset.PfxKeyCheck]::KeyMatches($Bag.EncryptedPkcs8PrivateKey.ToArray(), [string]$Plain, $Certificate)
                }
            }
        }
        if (-not ($LeafFound -and $KeyMatches)) { throw 'PFX check failed: the certificate or its private key could not be read back with the password.' }

        # Windows' own PFX loader on this machine (informational only).
        $WindowsError = $null
        try {
            $Check = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $Check.Import($Bytes, [string]$Plain, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
            foreach ($Cert in $Check) { $Cert.Dispose() }
        }
        catch {
            $WindowsError = $_.Exception.GetBaseException().Message
        }
    }
    finally {
        $Plain = $null
        $Key.Dispose()
    }
    [IO.File]::WriteAllBytes($FilePath, $Bytes)
    Write-Log "PFX check: MAC, $CertCount certificate(s) and the private key verified with the password."
    if ($WindowsError -and $Plan.Encryption -eq 'AES256_SHA256') {
        Write-Log "Windows on this machine cannot open AES-encrypted PFX files ($WindowsError), as on Server 2016 and older. The file is valid for newer Windows, OpenSSL and appliances; set Export.PfxEncryption to TripleDES_SHA1 if the PFX must be imported on a machine like this one." 'WARN'
    }
    elseif ($WindowsError) {
        Write-Log "Windows on this machine could not open the PFX ($WindowsError), although the .NET check passed." 'WARN'
    }
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
    $ExportJks = $Format -contains 'Jks'
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

    Write-Log "Exports : $ExportPath (PFX: $ExportPfx, PEM: $ExportPem, JKS: $ExportJks)"
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
            if (($ExportPem -or $ExportJks) -and $KeyStatus -eq 'Not RSA') { throw 'PEM and JKS export support RSA keys only.' }
            if ($Cert.NotAfter -lt (Get-Date)) { Write-Log 'The certificate has expired.' 'WARN' }

            if ([string]::IsNullOrWhiteSpace($Cert.FriendlyName)) {
                Write-Log 'No Friendly Name; using the thumbprint for file names.' 'WARN'
            }
            $ExportTarget = Get-ExportTarget -Certificate $Cert -FriendlyName $Cert.FriendlyName -ExportPath $ExportPath
            $Name = $ExportTarget.Name
            $TargetFolder = $ExportTarget.Folder
            $PfxFile = $ExportTarget.PfxFile
            $PemFile = $ExportTarget.PemFile
            $JksFile = $ExportTarget.JksFile

            foreach ($Target in @($(if ($ExportPfx) { $PfxFile }), $(if ($ExportPem) { $PemFile }), $(if ($ExportJks) { $JksFile })) | Where-Object { $_ }) {
                if ((Test-Path -LiteralPath $Target) -and -not $Force) {
                    throw "Export file already exists: $Target (use -Force to overwrite)."
                }
            }
            $DoPfx = $ExportPfx -and $PSCmdlet.ShouldProcess($PfxFile, 'Export PFX (private key + chain)')
            $DoPem = $ExportPem -and $PSCmdlet.ShouldProcess($PemFile, 'Export PEM (certificate + chain + encrypted key)')
            $DoJks = $ExportJks -and $PSCmdlet.ShouldProcess($JksFile, "Export JKS (private key + chain, alias '$($ExportTarget.Alias)')")
            if (-not ($DoPfx -or $DoPem -or $DoJks)) {
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
            if ($DoJks) {
                # Full chain, root included, as in the PFX.
                $JksChain = Get-CertificateChain -Certificate $Cert -IncludeRoot $true
                if (Test-Path -LiteralPath $JksFile) { Remove-Item -LiteralPath $JksFile -Force }
                Export-JksFile -Certificate $Cert -Issuers $JksChain.Issuers -Alias $ExportTarget.Alias -Password $Password -FilePath $JksFile
                Write-Log "JKS exported: $JksFile (alias '$($ExportTarget.Alias)', certificate + $($JksChain.Issuers.Count) chain cert(s) + key)" 'OK'
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
