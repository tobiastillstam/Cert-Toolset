#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Generates a PKCS#10 certificate signing request (CSR) with certreq, replacing the
    manual Certificate Manager "Create Custom Request" workflow.

.DESCRIPTION
    Builds a certreq INF file and runs "certreq -new" to produce a Base64 CSR. The
    private key is created in the Local Machine store and stays there as a pending
    request until Complete-CertRequest.ps1 accepts the CA response.

    The Common Name (CN) is used as the Subject CN and as the first Subject
    Alternative Name (SAN). The CN can be an FQDN, a short host name, a wildcard
    ("*.domain.tld") or an IP address. Extra SANs are added with -DnsName and
    -IpAddress. Short host names (no domain, e.g. "app01") give a warning: internal
    CAs may accept them, public CAs reject them.

    Subject fields (C, S, L, O, OU), key length, hash algorithm, key provider, Key
    Usage and Extended Key Usage come from CertToolset.config.json next to the
    script. Parameters override the config. Without a config file, built-in defaults
    are used and the Subject holds the CN only.

    Output (default <script folder>\Requests):
      <FriendlyName>.inf   certreq input
      <FriendlyName>.csr   the request to send to the CA

    The Friendly Name defaults to "<CN>_yyyyMM". A '*' in a wildcard CN becomes
    "wildcard." in file names only; the request content is unaffected.

    A transcript of every run is written to the Logs folder.

    Supports -WhatIf and -Confirm.

.PARAMETER CommonName
    FQDN, short host name, wildcard ("*.domain.tld") or IP address for the Subject
    CN. Also added as the first DNS or IP SAN. Required.

.PARAMETER DnsName
    Extra DNS SAN entries (FQDN, short host name or wildcard). Duplicates are
    removed.

.PARAMETER IpAddress
    IP SAN entries, IPv4 or IPv6. Duplicates are removed.

.PARAMETER Country
    Subject C (two letters). Overrides the config.

.PARAMETER State
    Subject S (state or province). Overrides the config.

.PARAMETER Locality
    Subject L (city). Overrides the config.

.PARAMETER Organization
    Subject O. Overrides the config.

.PARAMETER OrganizationalUnit
    Subject OU. Overrides the config.

.PARAMETER KeyLength
    RSA key length: 2048, 3072 or 4096. Overrides the config (default 4096).

.PARAMETER FriendlyName
    Friendly Name for the certificate and base name for the files.
    Default: "<CN>_yyyyMM".

.PARAMETER RequestPath
    Folder for the INF and CSR files. Default: the Requests folder from the config,
    relative to the script folder.

.PARAMETER ConfigPath
    JSON config file. Default: <script folder>\CertToolset.config.json

.PARAMETER LogPath
    Folder for the transcript. Default: the Logs folder from the config, relative
    to the script folder.

.PARAMETER Force
    Overwrite an existing INF/CSR with the same name and allow a new request even if
    a pending request with the same Friendly Name exists.

.EXAMPLE
    .\New-CertRequest.ps1 -CommonName 'app01.contoso.local' -WhatIf
    Shows the request that would be created without writing anything.

.EXAMPLE
    .\New-CertRequest.ps1 -CommonName '*.contoso.com' -DnsName 'contoso.com'
    Wildcard request with the apex domain as an extra SAN. Files are named
    wildcard.contoso.com_<yyyyMM>.inf / .csr.

.EXAMPLE
    .\New-CertRequest.ps1 -CommonName 'nas01.contoso.local' -IpAddress '10.0.0.20' -KeyLength 2048
    Request for an appliance that needs a 2048-bit key and an IP SAN.

.EXAMPLE
    .\New-CertRequest.ps1 -CommonName 'app01.contoso.local' -DnsName 'app01'
    Internal-CA request with the short host name as an extra SAN (gives a warning).

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.1.0
    Date Created  : 2026-08-28
    Last Modified : 2026-10-16

    Change Log
    ----------
    1.1.0 (2026-10-16) - Short host names (no domain) allowed as CN and -DnsName,
                          with a warning.
    1.0.0 (2026-10-16) - Renamed from New-Csr.ps1 and reworked for Cert-Toolset:
                          JSON config, transcript logging, IP SANs (-IpAddress, IP as
                          CN), -DnsName replaces -AdditionalDnsNames, Subject/key
                          overrides, Requests folder, no silent overwrites (-Force),
                          pending-request collision check, -WhatIf creates nothing,
                          INF and CSR gated as one step.
    0.3.0 (2026-09-04) - INF and CSR named after the Friendly Name.
    0.2.0 (2026-08-28) - Additional DNS SANs, wildcard CN support.
    0.1.0 (2026-08-28) - Initial release.

    Operational notes:
    - Requires local Administrator rights: the key is created in the Local Machine
      store (MachineKeySet = TRUE).
    - The pending request lives in Cert:\LocalMachine\REQUEST until it is completed
      with Complete-CertRequest.ps1 (certreq -accept). Do not delete it, or the CA
      response cannot be matched to a private key.
    - -Force does not remove an older pending request with the same Friendly Name;
      it stays in the REQUEST store. Clean those up with
      Complete-CertRequest.ps1 -RemoveStaleRequests.
    - The transcript is written even under -WhatIf (for accountability).
    - Subject values may not contain , + = " \ < > ; or # (no escaping is done).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # FQDN, wildcard or IP address for the Subject CN; also the first SAN. Required.
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$CommonName,

    # Extra DNS SAN entries (FQDN or wildcard).
    [Parameter(Mandatory = $false)]
    [string[]]$DnsName = @(),

    # IP SAN entries (IPv4 or IPv6).
    [Parameter(Mandatory = $false)]
    [string[]]$IpAddress = @(),

    # Subject C (two letters); overrides the config.
    [Parameter(Mandatory = $false)]
    [string]$Country,

    # Subject S (state/province); overrides the config.
    [Parameter(Mandatory = $false)]
    [string]$State,

    # Subject L (city); overrides the config.
    [Parameter(Mandatory = $false)]
    [string]$Locality,

    # Subject O; overrides the config.
    [Parameter(Mandatory = $false)]
    [string]$Organization,

    # Subject OU; overrides the config.
    [Parameter(Mandatory = $false)]
    [string]$OrganizationalUnit,

    # RSA key length; overrides the config.
    [Parameter(Mandatory = $false)]
    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength,

    # Friendly Name and file base name. Default: "<CN>_yyyyMM".
    [Parameter(Mandatory = $false)]
    [string]$FriendlyName,

    # Folder for the INF and CSR. Default: Requests folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$RequestPath,

    # JSON config file. Default: <script folder>\CertToolset.config.json
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    # Folder for the transcript. Default: Logs folder from the config.
    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    # Overwrite existing INF/CSR and ignore a pending request with the same name.
    [Parameter(Mandatory = $false)]
    [switch]$Force
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

function Test-ShortHostName {
    # Single-label host name such as "app01": no dot, at least one letter.
    param([string]$Name)
    return ($Name -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$' -and $Name -match '[a-zA-Z]')
}

function Test-HostName {
    # FQDN, wildcard FQDN (at least one dot after "*.") or short host name,
    # max 253 characters.
    param([string]$Name)
    $Pattern = '^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    if ($Name.Length -gt 253) { return $false }
    return ($Name -match $Pattern -or (Test-ShortHostName -Name $Name))
}

function ConvertTo-IpAddress {
    # Normalized IPv4/IPv6 string, or $null. Rejects short forms like "10.1"
    # that IPAddress.TryParse would accept, and IPv6 scope ids.
    param([string]$Value)
    $Parsed = $null
    if ($Value -match '^\d{1,3}(\.\d{1,3}){3}$') {
        if ([System.Net.IPAddress]::TryParse($Value, [ref]$Parsed)) { return $Parsed.ToString() }
    }
    elseif ($Value -match ':' -and $Value -notmatch '%') {
        if ([System.Net.IPAddress]::TryParse($Value, [ref]$Parsed) -and
            $Parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return $Parsed.ToString()
        }
    }
    return $null
}

function Get-UniqueList {
    # Case-insensitive de-duplication that keeps the first spelling and order.
    param([string[]]$Items)
    $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $Result = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Item in $Items) {
        if ($Item -and $Seen.Add($Item)) { $Result.Add($Item) }
    }
    return , $Result.ToArray()
}

function Assert-SubjectValue {
    # Rejects characters that would need X.500 escaping inside the INF Subject.
    param([string]$Name, [string]$Value)
    if ($Value -match '[,+="\\<>;#]') {
        throw "Subject $Name '$Value' contains a character that is not allowed: , + = `" \ < > ; #"
    }
    if ($Value -ne $Value.Trim()) {
        throw "Subject $Name '$Value' has leading or trailing spaces."
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
    $KeyUsageFlags = [ordered]@{
        DigitalSignature = 0x80
        NonRepudiation   = 0x40
        KeyEncipherment  = 0x20
        DataEncipherment = 0x10
        KeyAgreement     = 0x08
    }
    $KnownEkuNames = @{
        '1.3.6.1.5.5.7.3.1' = 'Server Authentication'
        '1.3.6.1.5.5.7.3.2' = 'Client Authentication'
        '1.3.6.1.5.5.7.3.3' = 'Code Signing'
        '1.3.6.1.5.5.7.3.4' = 'Secure Email'
    }

    # --- Config and logging -------------------------------------------------
    $BaseDirectory = Get-BaseDirectory
    $ConfigExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
    if (-not $ConfigPath) { $ConfigPath = Join-Path -Path $BaseDirectory -ChildPath 'CertToolset.config.json' }
    $ConfigPath = Resolve-ToolsetPath -Path $ConfigPath -BaseDirectory $BaseDirectory

    $DefaultFolders = (Get-DefaultConfig).Folders
    if (-not $LogPath) {
        # The config is read after the transcript starts, so peek at Folders.Logs here.
        $LogFolder = $DefaultFolders.Logs
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
    if ([string]::IsNullOrWhiteSpace($CommonName)) {
        throw 'CommonName is required, e.g. -CommonName app01.contoso.local'
    }
    $CommonName = $CommonName.Trim()

    $CommonNameIp = ConvertTo-IpAddress -Value $CommonName
    if (-not $CommonNameIp -and -not (Test-HostName -Name $CommonName)) {
        throw "CommonName '$CommonName' is not a valid FQDN, short host name, wildcard (*.domain.tld) or IP address."
    }
    if ($CommonName.Length -gt 64) {
        Write-Log "CommonName is $($CommonName.Length) characters; RFC 5280 limits CN to 64. Many CAs will reject it." 'WARN'
    }

    foreach ($Name in $DnsName) {
        if (-not (Test-HostName -Name $Name)) { throw "DnsName '$Name' is not a valid FQDN, short host name or wildcard." }
    }

    # Short names are allowed for internal CAs; public CAs reject them.
    foreach ($Name in @($(if (-not $CommonNameIp) { $CommonName })) + $DnsName) {
        if ($Name -and (Test-ShortHostName -Name $Name)) {
            Write-Log "'$Name' is a short host name (no domain). Internal CAs may accept it; public CAs reject it." 'WARN'
        }
    }

    $IpList = @()
    foreach ($Ip in $IpAddress) {
        $Normalized = ConvertTo-IpAddress -Value $Ip.Trim()
        if (-not $Normalized) { throw "IpAddress '$Ip' is not a valid IPv4 or IPv6 address." }
        $IpList += $Normalized
    }

    if ($CommonNameIp) {
        $AllDnsNames = Get-UniqueList -Items $DnsName
        $AllIpAddresses = Get-UniqueList -Items (@($CommonNameIp) + $IpList)
    }
    else {
        $AllDnsNames = Get-UniqueList -Items (@($CommonName) + $DnsName)
        $AllIpAddresses = Get-UniqueList -Items $IpList
    }

    # Subject: parameters override the config.
    $Subject = @{}
    foreach ($Field in 'Country', 'State', 'Locality', 'Organization', 'OrganizationalUnit') {
        $Value = [string]$Config.Subject[$Field]
        if ($PSBoundParameters.ContainsKey($Field)) { $Value = [string]$PSBoundParameters[$Field] }
        $Value = $Value.Trim()
        if ($Value) { Assert-SubjectValue -Name $Field -Value $Value }
        $Subject[$Field] = $Value
    }
    if ($Subject.Country) {
        if ($Subject.Country -notmatch '^[A-Za-z]{2}$') { throw "Country '$($Subject.Country)' must be a two-letter code, e.g. SE." }
        $Subject.Country = $Subject.Country.ToUpperInvariant()
    }

    $SubjectParts = @("CN=$CommonName")
    if ($Subject.OrganizationalUnit) { $SubjectParts += "OU=$($Subject.OrganizationalUnit)" }
    if ($Subject.Organization)       { $SubjectParts += "O=$($Subject.Organization)" }
    if ($Subject.Locality)           { $SubjectParts += "L=$($Subject.Locality)" }
    if ($Subject.State)              { $SubjectParts += "S=$($Subject.State)" }
    if ($Subject.Country)            { $SubjectParts += "C=$($Subject.Country)" }
    $SubjectString = $SubjectParts -join ', '
    if (-not $Subject.Organization) {
        Write-Log 'No Organization set (config or -Organization); the Subject holds fewer fields.' 'WARN'
    }

    # Key and algorithm settings.
    $EffectiveKeyLength = [int]$Config.KeyLength
    if ($PSBoundParameters.ContainsKey('KeyLength')) { $EffectiveKeyLength = $KeyLength }
    if ($EffectiveKeyLength -notin 2048, 3072, 4096) { throw "KeyLength $EffectiveKeyLength is not supported (2048, 3072, 4096)." }

    $HashAlgorithm = ([string]$Config.HashAlgorithm).ToUpperInvariant()
    if ($HashAlgorithm -notin 'SHA256', 'SHA384', 'SHA512') { throw "HashAlgorithm '$HashAlgorithm' is not supported (SHA256, SHA384, SHA512)." }

    $KeyProvider = [string]$Config.KeyProvider
    if ($KeyProvider -match '"') { throw "KeyProvider '$KeyProvider' may not contain quotes." }

    $Exportable = [bool]$Config.KeyExportable
    if (-not $Exportable) {
        Write-Log 'KeyExportable is false: the key cannot be exported to PFX/PEM later.' 'WARN'
    }

    $KeyUsageValue = 0
    foreach ($Usage in $Config.KeyUsage) {
        if (-not $KeyUsageFlags.Contains([string]$Usage)) {
            throw "Unknown KeyUsage '$Usage'. Valid: $($KeyUsageFlags.Keys -join ', ')"
        }
        $KeyUsageValue = $KeyUsageValue -bor $KeyUsageFlags[[string]$Usage]
    }

    $EkuLines = @()
    foreach ($Oid in $Config.EnhancedKeyUsage) {
        if ([string]$Oid -notmatch '^\d+(\.\d+)+$') { throw "EnhancedKeyUsage '$Oid' is not an OID." }
        $Label = $KnownEkuNames[[string]$Oid]
        if ($Label) { $EkuLines += "OID = $Oid ; $Label" } else { $EkuLines += "OID = $Oid" }
    }

    # Names and paths.
    if (-not $FriendlyName) { $FriendlyName = '{0}_{1}' -f $CommonName, (Get-Date -Format 'yyyyMM') }
    if ($FriendlyName -match '"') { throw "FriendlyName '$FriendlyName' may not contain quotes." }
    $SafeName = ConvertTo-SafeFileName -Name $FriendlyName

    if (-not $RequestPath) { $RequestPath = $Config.Folders.Requests }
    $RequestPath = Resolve-ToolsetPath -Path $RequestPath -BaseDirectory $BaseDirectory
    $InfFile = Join-Path -Path $RequestPath -ChildPath "$SafeName.inf"
    $CsrFile = Join-Path -Path $RequestPath -ChildPath "$SafeName.csr"

    Write-Log "Subject       : $SubjectString"
    Write-Log "DNS SANs      : $(if ($AllDnsNames.Count) { $AllDnsNames -join ', ' } else { '(none)' })"
    Write-Log "IP SANs       : $(if ($AllIpAddresses.Count) { $AllIpAddresses -join ', ' } else { '(none)' })"
    Write-Log "Key           : RSA $EffectiveKeyLength, $KeyProvider, exportable=$Exportable"
    Write-Log "Hash          : $HashAlgorithm"
    Write-Log ("Key Usage     : {0} (0x{1:X2}, critical)" -f ($Config.KeyUsage -join ', '), $KeyUsageValue)
    Write-Log "EKU           : $(($Config.EnhancedKeyUsage) -join ', ')"
    Write-Log "Friendly Name : $FriendlyName"
    Write-Log "INF file      : $InfFile"
    Write-Log "CSR file      : $CsrFile"

    # Collisions: existing files and pending requests with the same Friendly Name.
    $Existing = @($InfFile, $CsrFile | Where-Object { Test-Path -LiteralPath $_ })
    if ($Existing.Count -gt 0) {
        if (-not $Force) {
            throw "Request files already exist: $($Existing -join ', '). Use -Force to overwrite or -FriendlyName for a new name."
        }
        Write-Log "Existing files will be overwritten (-Force): $($Existing -join ', ')" 'WARN'
    }

    $Pending = @(Get-ChildItem -Path "Cert:\$StoreLocation\REQUEST" -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -eq $FriendlyName })
    if ($Pending.Count -gt 0) {
        $PendingInfo = ($Pending | ForEach-Object { '{0} (created {1:yyyy-MM-dd})' -f $_.Thumbprint, $_.NotBefore }) -join ', '
        if (-not $Force) {
            throw "A pending request with Friendly Name '$FriendlyName' already exists: $PendingInfo. Complete it first, or use -Force / -FriendlyName."
        }
        Write-Log "Pending request(s) with the same Friendly Name stay in the REQUEST store: $PendingInfo" 'WARN'
    }

    # --- Build INF ----------------------------------------------------------
    $SanLines = @('2.5.29.17 = "{text}"')
    foreach ($Name in $AllDnsNames)    { $SanLines += "_continue_ = `"dns=$Name&`"" }
    foreach ($Ip in $AllIpAddresses)   { $SanLines += "_continue_ = `"ipaddress=$Ip&`"" }

    # certreq marks the NewRequest KeyUsage extension as critical by default.
    $InfLines = @(
        '[Version]'
        'Signature="$Windows NT$"'
        ''
        '[NewRequest]'
        "Subject = `"$SubjectString`""
        "Exportable = $(if ($Exportable) { 'TRUE' } else { 'FALSE' })"
        'KeyAlgorithm = RSA'
        "KeyLength = $EffectiveKeyLength"
        ('KeyUsage = 0x{0:X2}' -f $KeyUsageValue)
        "MachineKeySet = $(if ($StoreLocation -eq 'LocalMachine') { 'TRUE' } else { 'FALSE' })"
        "ProviderName = `"$KeyProvider`""
        "HashAlgorithm = $HashAlgorithm"
        'RequestType = PKCS10'
        "FriendlyName = `"$FriendlyName`""
        'SMIME = FALSE'
        ''
    )
    if ($EkuLines.Count -gt 0) {
        $InfLines += '[EnhancedKeyUsageExtension]'
        $InfLines += $EkuLines
        $InfLines += ''
    }
    $InfLines += '[Extensions]'
    $InfLines += $SanLines
    $InfContent = ($InfLines -join "`r`n") + "`r`n"

    Write-Verbose "INF content:`r`n$InfContent"

    # --- Main logic ---------------------------------------------------------
    if ($PSCmdlet.ShouldProcess($CsrFile, 'Write INF and generate CSR via certreq -new')) {
        if (-not (Test-Path -LiteralPath $RequestPath)) {
            New-Item -Path $RequestPath -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $RequestPath"
        }
        if (Test-Path -LiteralPath $CsrFile) { Remove-Item -LiteralPath $CsrFile -Force }

        [IO.File]::WriteAllText($InfFile, $InfContent, [Text.Encoding]::ASCII)
        Write-Log "INF written: $InfFile"

        $Result = Invoke-NativeCommand -FilePath 'certreq.exe' -ArgumentList @('-new', '-q', $InfFile, $CsrFile)
        $Result.Output | Where-Object { $_ } | ForEach-Object { Write-Log "certreq: $_" }
        if ($Result.ExitCode -ne 0) {
            throw "certreq -new failed with exit code $($Result.ExitCode): $($Result.Output -join ' | ')"
        }
        if (-not (Test-Path -LiteralPath $CsrFile)) {
            throw "certreq reported success but the CSR was not found: $CsrFile"
        }

        Write-Log "CSR generated: $CsrFile" 'OK'
        Write-Log "Pending request stored in Cert:\$StoreLocation\REQUEST as '$FriendlyName'."
        Write-Log 'Next: check it with Test-CertRequest.ps1, send the CSR to the CA, put the response in the'
        Write-Log 'Responses folder and run Complete-CertRequest.ps1.'
    }

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
