#Requires -Version 5.1

<#
.SYNOPSIS
    Decodes certificate signing requests (CSRs) and checks them against the
    Cert-Toolset certificate policy.

.DESCRIPTION
    Decodes each PKCS#10 request with the built-in CertEnroll COM objects (no
    OpenSSL needed), shows its contents, and runs PASS/FAIL checks:

      - Signature is valid (the request was not altered)
      - Key algorithm is RSA, key length is at least the policy length
      - Signature hash matches the policy hash algorithm
      - Subject has a CN, and the CN is also listed as a SAN
      - At least one DNS or IP SAN
      - Key Usage present, critical, and contains the policy usages
      - Every policy EKU is present
      - Subject C/S/L/O/OU match the policy (only fields that have a value in
        the config are checked)

    The policy comes from CertToolset.config.json next to the script. Without a
    config file, built-in defaults are used (RSA 4096, SHA512, Digital Signature +
    Key Encipherment, Server + Client Authentication) and Subject fields are not
    checked.

    Read-only. Does not need administrator rights, so it can be copied to and run
    on any machine. Accepts files or folders (every *.csr and *.req in a folder).

    Exit code: 0 when every request passes, 1 when any check fails.

.PARAMETER Path
    One or more CSR files or folders. Required.

.PARAMETER KeyLength
    Minimum RSA key length to accept. Overrides the config (default 4096).

.PARAMETER ShowRawDump
    Also show the full "certutil -dump" output for each request.

.PARAMETER PassThru
    Write one result object per request to the pipeline.

.PARAMETER ConfigPath
    JSON config file. Default: <script folder>\CertToolset.config.json

.PARAMETER LogPath
    Folder for the transcript. Default: the Logs folder from the config, relative
    to the script folder; falls back to the current folder if that is not writable.

.EXAMPLE
    .\Test-CertRequest.ps1 -Path .\Requests\app01.contoso.local_202610.csr
    Checks one request.

.EXAMPLE
    .\Test-CertRequest.ps1 -Path .\Requests -KeyLength 2048
    Checks every request in the folder and accepts 2048-bit keys.

.EXAMPLE
    $r = .\Test-CertRequest.ps1 -Path D:\Incoming -PassThru; $r | Where-Object { -not $_.Passed }
    Collects results and lists the requests that failed.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.0.0
    Date Created  : 2026-08-28
    Last Modified : 2026-10-16

    Change Log
    ----------
    1.0.0 (2026-10-16) - Renamed from Test-Csr.ps1 and reworked for Cert-Toolset:
                          structured decoding via CertEnroll instead of text matching
                          on certutil output (the old 'Key Usage' check also matched
                          'Enhanced Key Usage'), signature check, CN-in-SAN check, IP
                          SANs, Key Usage critical/flags, Subject checks from the JSON
                          config, files or folders, exit code, -PassThru, transcript.
    0.1.0 (2026-08-28) - Initial release.

    Operational notes:
    - Deliberately has no "#Requires -RunAsAdministrator" (exception to the house
      template): it is read-only and meant to run on many machines, often without
      admin rights.
    - Only PKCS#10 requests are supported (certreq RequestType = PKCS10, OpenSSL
      "req"). CMC/PKCS#7-wrapped requests are reported as not decodable.
    - The transcript goes to the Logs folder next to the script. If that is not
      writable, the current folder's Logs is tried; if neither works the run
      continues without a transcript (with a warning).
    - A request that cannot be decoded is reported as FAIL and the remaining
      requests are still checked (per-request error handling).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # One or more CSR files or folders. Required.
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$Path,

    # Minimum RSA key length; overrides the config.
    [Parameter(Mandatory = $false)]
    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength,

    # Also show the full certutil -dump output.
    [Parameter(Mandatory = $false)]
    [switch]$ShowRawDump,

    # Write one result object per request to the pipeline.
    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    # JSON config file. Default: <script folder>\CertToolset.config.json
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    # Folder for the transcript. Default: Logs folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

# -------------------------------------------------------------------------
# Helper functions
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

function Start-ToolsetTranscript {
    # Tries each folder in turn; returns the transcript file, or $null if none
    # was writable (this script must also run without admin rights).
    param([string[]]$Folders, [string]$BaseName)
    $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    foreach ($Folder in $Folders) {
        try {
            if (-not (Test-Path -LiteralPath $Folder)) {
                New-Item -Path $Folder -ItemType Directory -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
            }
            $File = Join-Path -Path $Folder -ChildPath ('{0}-{1}.log' -f $BaseName, $Stamp)
            Start-Transcript -LiteralPath $File -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
            return $File
        }
        catch {
            Write-Warning "Cannot write transcript to ${Folder}: $($_.Exception.Message)"
        }
    }
    return $null
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

function Get-RdnValue {
    # Value of one RDN (e.g. 'CN') from a distinguished name, or ''.
    param([string]$DistinguishedName, [string]$Rdn)
    $Match = [regex]::Match($DistinguishedName, "(?:^|,\s*)$Rdn=(`"[^`"]*`"|[^,]*)")
    if ($Match.Success) { return $Match.Groups[1].Value.Trim('"', ' ') }
    return ''
}

function Read-CertRequest {
    # Decodes a PKCS#10 file (PEM/Base64 or DER) into a plain object.
    param([string]$File)

    $Bytes = [IO.File]::ReadAllBytes($File)
    $Request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    if ($Bytes.Length -gt 0 -and $Bytes[0] -eq 0x30) {
        # DER: XCN_CRYPT_STRING_BASE64 = 1
        $Request.InitializeDecode([Convert]::ToBase64String($Bytes), 1)
    }
    else {
        # PEM or bare Base64: XCN_CRYPT_STRING_BASE64_ANY = 6
        $Request.InitializeDecode([Text.Encoding]::ASCII.GetString($Bytes), 6)
    }

    $SignatureValid = $true
    try { $Request.CheckSignature(1) } catch { $SignatureValid = $false }   # AllowedSignatureTypeKeySignature

    $Result = [ordered]@{
        Subject          = [string]$Request.Subject.Name
        KeyAlgorithm     = [string]$Request.PublicKey.Algorithm.FriendlyName
        KeyLength        = [int]$Request.PublicKey.Length
        HashAlgorithm    = ([string]$Request.HashAlgorithm.FriendlyName).ToUpperInvariant()
        SignatureValid   = $SignatureValid
        DnsNames         = @()
        IpAddresses      = @()
        OtherSans        = @()
        KeyUsagePresent  = $false
        KeyUsageCritical = $false
        KeyUsageValue    = 0
        Ekus             = @()
    }

    foreach ($Extension in $Request.X509Extensions) {
        $Raw = $Extension.RawData(1)
        switch ($Extension.ObjectId.Value) {
            '2.5.29.17' {
                $San = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                $San.InitializeDecode(1, $Raw)
                foreach ($Entry in $San.AlternativeNames) {
                    switch ([int]$Entry.Type) {
                        3 { $Result.DnsNames += [string]$Entry.strValue }                                   # XCN_CERT_ALT_NAME_DNS_NAME
                        8 { $Result.IpAddresses += ([System.Net.IPAddress]([Convert]::FromBase64String($Entry.RawData(1)))).ToString() }   # XCN_CERT_ALT_NAME_IP_ADDRESS
                        default { $Result.OtherSans += "type$($Entry.Type)=$($Entry.strValue)" }
                    }
                }
            }
            '2.5.29.15' {
                $Ku = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
                $Ku.InitializeDecode(1, $Raw)
                $Result.KeyUsagePresent = $true
                $Result.KeyUsageCritical = [bool]$Extension.Critical
                $Result.KeyUsageValue = [int]$Ku.KeyUsage
            }
            '2.5.29.37' {
                $Eku = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
                $Eku.InitializeDecode(1, $Raw)
                foreach ($Oid in $Eku.EnhancedKeyUsage) { $Result.Ekus += [string]$Oid.Value }
            }
        }
    }
    return [pscustomobject]$Result
}

function Get-OidLabel {
    # "1.3.6.1.5.5.7.3.1 (Server Authentication)" where the name is known.
    param([string]$Oid)
    $Name = ([System.Security.Cryptography.Oid]$Oid).FriendlyName
    if ($Name) { return "$Oid ($Name)" }
    return $Oid
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
    $KeyUsageFlags = [ordered]@{
        DigitalSignature = 0x80
        NonRepudiation   = 0x40
        KeyEncipherment  = 0x20
        DataEncipherment = 0x10
        KeyAgreement     = 0x08
    }

    # --- Config and logging -------------------------------------------------
    $BaseDirectory = Get-BaseDirectory
    $ConfigExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
    if (-not $ConfigPath) { $ConfigPath = Join-Path -Path $BaseDirectory -ChildPath 'CertToolset.config.json' }
    $ConfigPath = Resolve-ToolsetPath -Path $ConfigPath -BaseDirectory $BaseDirectory

    if ($LogPath) {
        $LogCandidates = @(Resolve-ToolsetPath -Path $LogPath -BaseDirectory $BaseDirectory)
    }
    else {
        # The config is read after the transcript starts, so peek at Folders.Logs here.
        $LogFolder = (Get-DefaultConfig).Folders.Logs
        if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
            $Peek = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($Peek.Folders -and $Peek.Folders.Logs) { $LogFolder = $Peek.Folders.Logs }
        }
        $LogCandidates = @(
            (Resolve-ToolsetPath -Path $LogFolder -BaseDirectory $BaseDirectory),
            (Resolve-ToolsetPath -Path $LogFolder -BaseDirectory (Get-Location).Path)
        ) | Select-Object -Unique
    }
    $ScriptBaseName = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $TranscriptFile = Start-ToolsetTranscript -Folders $LogCandidates -BaseName $ScriptBaseName
    $TranscriptStarted = [bool]$TranscriptFile
    if (-not $TranscriptStarted) { Write-Warning 'No transcript for this run (no writable log folder).' }

    Write-Log "=== $ScriptBaseName start ==="
    $Config = Read-ToolsetConfig -Path $ConfigPath -Explicit $ConfigExplicit

    # --- Input validation ---------------------------------------------------
    if (-not $Path -or $Path.Count -eq 0) {
        throw 'Path is required, e.g. -Path .\Requests\app01.contoso.local_202610.csr'
    }

    $Files = @()
    foreach ($Item in $Path) {
        if (Test-Path -LiteralPath $Item -PathType Container) {
            $Found = @(Get-ChildItem -LiteralPath $Item -File | Where-Object { $_.Extension -in '.csr', '.req' })
            if ($Found.Count -eq 0) { Write-Log "No .csr/.req files in $Item" 'WARN' }
            $Files += $Found | ForEach-Object { $_.FullName }
        }
        elseif (Test-Path -LiteralPath $Item -PathType Leaf) {
            $Files += (Resolve-Path -LiteralPath $Item).ProviderPath
        }
        else {
            throw "Path not found: $Item"
        }
    }
    if ($Files.Count -eq 0) { throw 'No requests to check.' }

    # Policy: parameters override the config.
    $MinKeyLength = [int]$Config.KeyLength
    if ($PSBoundParameters.ContainsKey('KeyLength')) { $MinKeyLength = $KeyLength }
    $PolicyHash = ([string]$Config.HashAlgorithm).ToUpperInvariant()

    $PolicyKeyUsage = 0
    foreach ($Usage in $Config.KeyUsage) {
        if (-not $KeyUsageFlags.Contains([string]$Usage)) {
            throw "Unknown KeyUsage '$Usage' in config. Valid: $($KeyUsageFlags.Keys -join ', ')"
        }
        $PolicyKeyUsage = $PolicyKeyUsage -bor $KeyUsageFlags[[string]$Usage]
    }
    $PolicyEkus = @($Config.EnhancedKeyUsage | ForEach-Object { [string]$_ })

    $SubjectRdns = [ordered]@{ Country = 'C'; State = 'S'; Locality = 'L'; Organization = 'O'; OrganizationalUnit = 'OU' }

    Write-Log ("Policy: RSA >= {0}, {1}, Key Usage {2}, EKU {3}" -f $MinKeyLength, $PolicyHash, ($Config.KeyUsage -join '+'), ($PolicyEkus -join ', '))

    # --- Main logic ---------------------------------------------------------
    $FailedRequests = 0

    foreach ($File in $Files) {
        Write-Log ''
        Write-Log "----- $File -----"
        $Checks = New-Object 'System.Collections.Generic.List[object]'
        $Decoded = $null

        try {
            $Decoded = Read-CertRequest -File $File
        }
        catch {
            Write-Log "Cannot decode as PKCS#10: $($_.Exception.Message)" 'ERROR'
            $Checks.Add([pscustomobject]@{ Name = 'Request can be decoded (PKCS#10)'; Passed = $false })
        }

        if ($Decoded) {
            $CommonName = Get-RdnValue -DistinguishedName $Decoded.Subject -Rdn 'CN'
            $KuNames = @($KeyUsageFlags.Keys | Where-Object { $Decoded.KeyUsageValue -band $KeyUsageFlags[$_] })

            Write-Log "Subject        : $($Decoded.Subject)"
            Write-Log "DNS SANs       : $(if ($Decoded.DnsNames.Count) { $Decoded.DnsNames -join ', ' } else { '(none)' })"
            Write-Log "IP SANs        : $(if ($Decoded.IpAddresses.Count) { $Decoded.IpAddresses -join ', ' } else { '(none)' })"
            if ($Decoded.OtherSans.Count) { Write-Log "Other SANs     : $($Decoded.OtherSans -join ', ')" }
            Write-Log "Key            : $($Decoded.KeyAlgorithm) $($Decoded.KeyLength)"
            Write-Log "Hash           : $($Decoded.HashAlgorithm)"
            if ($Decoded.KeyUsagePresent) {
                Write-Log ("Key Usage      : {0} (0x{1:X2}, critical={2})" -f ($KuNames -join ', '), $Decoded.KeyUsageValue, $Decoded.KeyUsageCritical)
            }
            else {
                Write-Log 'Key Usage      : (none)'
            }
            Write-Log "EKU            : $(if ($Decoded.Ekus.Count) { ($Decoded.Ekus | ForEach-Object { Get-OidLabel $_ }) -join ', ' } else { '(none)' })"

            $AllSans = @($Decoded.DnsNames) + @($Decoded.IpAddresses)
            $CnInSan = $false
            if ($CommonName) {
                $CnIp = $null
                if ([System.Net.IPAddress]::TryParse($CommonName, [ref]$CnIp) -and $CommonName -match '[.:]') {
                    $CnInSan = @($Decoded.IpAddresses) -contains $CnIp.ToString()
                }
                else {
                    $CnInSan = @($Decoded.DnsNames) -contains $CommonName
                }
            }

            $Checks.Add([pscustomobject]@{ Name = 'Signature is valid'; Passed = $Decoded.SignatureValid })
            $Checks.Add([pscustomobject]@{ Name = 'Key algorithm is RSA'; Passed = ($Decoded.KeyAlgorithm -eq 'RSA') })
            $Checks.Add([pscustomobject]@{ Name = "Key length >= $MinKeyLength"; Passed = ($Decoded.KeyLength -ge $MinKeyLength) })
            $Checks.Add([pscustomobject]@{ Name = "Hash algorithm is $PolicyHash"; Passed = ($Decoded.HashAlgorithm -eq $PolicyHash) })
            $Checks.Add([pscustomobject]@{ Name = 'Subject has a CN'; Passed = [bool]$CommonName })
            $Checks.Add([pscustomobject]@{ Name = 'At least one DNS or IP SAN'; Passed = ($AllSans.Count -gt 0) })
            $Checks.Add([pscustomobject]@{ Name = 'CN is listed as a SAN'; Passed = $CnInSan })
            $Checks.Add([pscustomobject]@{ Name = 'Key Usage present and critical'; Passed = ($Decoded.KeyUsagePresent -and $Decoded.KeyUsageCritical) })
            $Checks.Add([pscustomobject]@{
                Name   = "Key Usage includes $($Config.KeyUsage -join ' + ')"
                Passed = ($Decoded.KeyUsagePresent -and (($Decoded.KeyUsageValue -band $PolicyKeyUsage) -eq $PolicyKeyUsage))
            })
            foreach ($Oid in $PolicyEkus) {
                $Checks.Add([pscustomobject]@{ Name = "EKU $(Get-OidLabel $Oid)"; Passed = ($Decoded.Ekus -contains $Oid) })
            }
            foreach ($Field in $SubjectRdns.Keys) {
                $Expected = ([string]$Config.Subject[$Field]).Trim()
                if (-not $Expected) { continue }
                $Actual = Get-RdnValue -DistinguishedName $Decoded.Subject -Rdn $SubjectRdns[$Field]
                $Checks.Add([pscustomobject]@{ Name = "Subject $($SubjectRdns[$Field])=$Expected"; Passed = ($Actual -eq $Expected) })
            }

            if ($ShowRawDump) {
                $Dump = Invoke-NativeCommand -FilePath 'certutil.exe' -ArgumentList @('-dump', $File)
                Write-Log '----- certutil -dump -----'
                $Dump.Output | ForEach-Object { Write-Log $_ }
            }
        }

        $Failed = @($Checks | Where-Object { -not $_.Passed })
        foreach ($Check in $Checks) {
            Write-Log ('[{0}] {1}' -f $(if ($Check.Passed) { 'PASS' } else { 'FAIL' }), $Check.Name)
        }
        if ($Failed.Count -eq 0) {
            Write-Log 'Result: all checks passed.' 'OK'
        }
        else {
            Write-Log "Result: $($Failed.Count) check(s) failed." 'WARN'
            $FailedRequests++
        }

        if ($PassThru) {
            [pscustomobject]@{
                File             = $File
                Subject          = $(if ($Decoded) { $Decoded.Subject } else { $null })
                DnsNames         = $(if ($Decoded) { $Decoded.DnsNames } else { @() })
                IpAddresses      = $(if ($Decoded) { $Decoded.IpAddresses } else { @() })
                KeyAlgorithm     = $(if ($Decoded) { $Decoded.KeyAlgorithm } else { $null })
                KeyLength        = $(if ($Decoded) { $Decoded.KeyLength } else { $null })
                HashAlgorithm    = $(if ($Decoded) { $Decoded.HashAlgorithm } else { $null })
                EnhancedKeyUsage = $(if ($Decoded) { $Decoded.Ekus } else { @() })
                Passed           = ($Failed.Count -eq 0)
                FailedChecks     = @($Failed | ForEach-Object { $_.Name })
            }
        }
    }

    Write-Log ''
    Write-Log "----- Summary: $($Files.Count) request(s), $($Files.Count - $FailedRequests) passed, $FailedRequests failed -----"
    if ($FailedRequests -gt 0) { $ExitCode = 1 }

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
