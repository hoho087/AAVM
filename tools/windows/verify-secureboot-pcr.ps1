#requires -Version 5.1
<#
.SYNOPSIS
Validates Secure Boot, TPM 2.0, live SHA-256 PCRs, and TCG measured-boot replay.

.DESCRIPTION
Run in Windows PowerShell as Administrator. The script is read-only: it collects
UEFI variables and Windows TPM/event-log evidence, calls the built-in tpmtool,
and writes SUMMARY.txt plus a ZIP archive under C:\Users\Public by default.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify-secureboot-pcr.ps1

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify-secureboot-pcr.ps1 -OutputDirectory C:\PCR-Report -NoArchive
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$NoArchive,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CompareStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][int]$ExitCode
    )

    if ($Text -match '(?i)no mismatches?|all\s+.*PCR.*match|TCG\s+log.*PCR.*match') {
        return 'PASS'
    }
    if ($Text -match '(?i)there is a mismatch|mismatch between|do not match|PCR.*mismatch') {
        return 'FAIL'
    }
    if ($ExitCode -ne 0) {
        return 'FAIL'
    }
    return 'WARN'
}

function Get-Sha256PcrMap {
    param([Parameter(Mandatory = $true)][string]$Text)

    $map = @{}
    $matches = [regex]::Matches(
        $Text,
        '(?im)PCR\[\s*(\d{1,2})\s*\]\s*:\s*([0-9a-f]{64})(?![0-9a-f])'
    )
    foreach ($match in $matches) {
        $map[[int]$match.Groups[1].Value] = $match.Groups[2].Value.ToLowerInvariant()
    }
    return $map
}

if ($SelfTest) {
    $zero = '0' * 64
    $one = '1' * 64
    $sample = "PCR[00]: $one`nPCR[07]: $zero"
    $map = Get-Sha256PcrMap -Text $sample
    if ($map.Count -ne 2 -or $map[0] -ne $one -or $map[7] -ne $zero) {
        throw 'SELFTEST PCR parser failed.'
    }
    if ((Get-CompareStatus -Text 'There is a mismatch between the TCG log and hardware PCRs' -ExitCode 0) -ne 'FAIL') {
        throw 'SELFTEST mismatch parser failed.'
    }
    if ((Get-CompareStatus -Text 'The TCG log and hardware PCRs match' -ExitCode 0) -ne 'PASS') {
        throw 'SELFTEST match parser failed.'
    }
    Write-Host 'SELFTEST PASS'
    exit 0
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from Windows PowerShell as Administrator.'
    exit 3
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDirectory = Join-Path $env:PUBLIC "KVM-AAVM-PCR-$stamp"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$utf8NoBom = New-Object Text.UTF8Encoding($false)
$checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'WARN', 'INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail
    )
    [void]$checks.Add([pscustomobject]@{
        Check  = $Name
        Status = $Status
        Detail = $Detail
    })
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(ValueFromPipeline = $true)][AllowEmptyString()][string]$Text
    )
    process {
        [IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        $text = ($raw | Out-String).TrimEnd()
    }
    catch {
        $exitCode = -1
        $text = $_ | Out-String
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    Write-Utf8File -Path $OutputPath -Text ($text + [Environment]::NewLine)
    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Text     = [string]$text
    }
}

Write-Host "Collecting Secure Boot and TPM evidence in: $OutputDirectory"

# Secure Boot status and authenticated UEFI variables.
try {
    $secureBoot = [bool](Confirm-SecureBootUEFI)
    if ($secureBoot) {
        Add-Check 'SecureBoot.Enabled' 'PASS' 'Confirm-SecureBootUEFI returned True.'
    }
    else {
        Add-Check 'SecureBoot.Enabled' 'FAIL' 'Confirm-SecureBootUEFI returned False.'
    }
}
catch {
    Add-Check 'SecureBoot.Enabled' 'FAIL' $_.Exception.Message
}

$secureBootVariables = New-Object System.Collections.Generic.List[object]
foreach ($name in @('PK', 'KEK', 'db', 'dbx', 'SetupMode', 'SecureBoot')) {
    try {
        $variable = Get-SecureBootUEFI -Name $name
        $bytes = [byte[]]$variable.Bytes
        $file = Join-Path $OutputDirectory "UEFI-$name.bin"
        [IO.File]::WriteAllBytes($file, $bytes)
        $hash = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLowerInvariant()
        [void]$secureBootVariables.Add([pscustomobject]@{
            Name       = $name
            Length     = $bytes.Length
            Sha256     = $hash
            Attributes = [string]$variable.Attributes
        })

        if ($name -in @('PK', 'KEK', 'db', 'dbx')) {
            if ($bytes.Length -gt 0) {
                Add-Check "SecureBoot.Variable.$name" 'PASS' "Present; $($bytes.Length) bytes; SHA256=$hash"
            }
            else {
                Add-Check "SecureBoot.Variable.$name" 'FAIL' 'Variable is empty.'
            }
        }
        elseif ($name -eq 'SetupMode') {
            if ($bytes.Length -gt 0 -and $bytes[0] -eq 0) {
                Add-Check 'SecureBoot.SetupMode' 'PASS' 'SetupMode=0 (User Mode).'
            }
            else {
                Add-Check 'SecureBoot.SetupMode' 'FAIL' 'SetupMode is not 0.'
            }
        }
        elseif ($name -eq 'SecureBoot') {
            if ($bytes.Length -gt 0 -and $bytes[0] -eq 1) {
                Add-Check 'SecureBoot.VariableState' 'PASS' 'SecureBoot UEFI variable=1.'
            }
            else {
                Add-Check 'SecureBoot.VariableState' 'FAIL' 'SecureBoot UEFI variable is not 1.'
            }
        }
    }
    catch {
        Add-Check "SecureBoot.Variable.$name" 'FAIL' $_.Exception.Message
    }
}
$secureBootVariables | ConvertTo-Json -Depth 4 | Write-Utf8File -Path (Join-Path $OutputDirectory 'secureboot-variables.json')

# Windows TPM state and endorsement key metadata.
try {
    $tpm = Get-Tpm
    $tpm | ConvertTo-Json -Depth 6 | Write-Utf8File -Path (Join-Path $OutputDirectory 'get-tpm.json')
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Add-Check 'TPM.PresentReady' 'PASS' 'TPM is present and ready.'
    }
    else {
        Add-Check 'TPM.PresentReady' 'FAIL' "TpmPresent=$($tpm.TpmPresent); TpmReady=$($tpm.TpmReady)"
    }
    if ($tpm.LockedOut) {
        Add-Check 'TPM.Lockout' 'FAIL' 'TPM reports LockedOut=True.'
    }
    else {
        Add-Check 'TPM.Lockout' 'PASS' 'TPM is not locked out.'
    }
}
catch {
    Add-Check 'TPM.PresentReady' 'FAIL' $_.Exception.Message
}

try {
    $wmiTpm = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' -ClassName Win32_Tpm
    $wmiTpm | Select-Object ManufacturerId, ManufacturerIdTxt, ManufacturerVersion, ManufacturerVersionFull20, PhysicalPresenceVersionInfo, SpecVersion |
        ConvertTo-Json -Depth 4 | Write-Utf8File -Path (Join-Path $OutputDirectory 'win32-tpm.json')
    if ([string]$wmiTpm.SpecVersion -match '2\.0') {
        Add-Check 'TPM.Version' 'PASS' "SpecVersion=$($wmiTpm.SpecVersion)"
    }
    else {
        Add-Check 'TPM.Version' 'FAIL' "SpecVersion=$($wmiTpm.SpecVersion)"
    }
}
catch {
    Add-Check 'TPM.Version' 'FAIL' $_.Exception.Message
}

try {
    $ek = Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256
    $ekSummary = [pscustomobject]@{
        IsPresent                    = [bool]$ek.IsPresent
        PublicKeyHash                = [string]$ek.PublicKeyHash
        ManufacturerCertificateCount = @($ek.ManufacturerCertificates).Count
        AdditionalCertificateCount   = @($ek.AdditionalCertificates).Count
    }
    $ekSummary | ConvertTo-Json -Depth 4 | Write-Utf8File -Path (Join-Path $OutputDirectory 'endorsement-key.json')
    if ($ek.IsPresent -and -not [string]::IsNullOrWhiteSpace([string]$ek.PublicKeyHash)) {
        Add-Check 'TPM.EndorsementKey' 'PASS' "EK public key present; SHA256=$($ek.PublicKeyHash)"
    }
    else {
        Add-Check 'TPM.EndorsementKey' 'FAIL' 'Endorsement public key is unavailable.'
    }
    if (@($ek.ManufacturerCertificates).Count -gt 0) {
        Add-Check 'TPM.ManufacturerEKCertificate' 'PASS' "CertificateCount=$(@($ek.ManufacturerCertificates).Count)"
    }
    else {
        Add-Check 'TPM.ManufacturerEKCertificate' 'WARN' 'No manufacturer EK certificate was returned.'
    }
}
catch {
    Add-Check 'TPM.EndorsementKey' 'WARN' $_.Exception.Message
}

$tpmTool = Join-Path $env:SystemRoot 'System32\tpmtool.exe'
if (-not (Test-Path -LiteralPath $tpmTool)) {
    Add-Check 'TPMTool.Available' 'FAIL' "$tpmTool was not found."
}
else {
    Add-Check 'TPMTool.Available' 'PASS' $tpmTool

    $deviceInfo = Invoke-NativeCapture -FilePath $tpmTool -Arguments @('getdeviceinformation') -OutputPath (Join-Path $OutputDirectory 'tpmtool-device-information.txt')
    if ($deviceInfo.ExitCode -eq 0) {
        Add-Check 'TPMTool.DeviceInformation' 'PASS' 'tpmtool getdeviceinformation exited 0.'
    }
    else {
        Add-Check 'TPMTool.DeviceInformation' 'FAIL' "ExitCode=$($deviceInfo.ExitCode)"
    }

    $tpmLogs = Join-Path $OutputDirectory 'tpmtool-logs'
    $gather = Invoke-NativeCapture -FilePath $tpmTool -Arguments @('gatherlogs', $tpmLogs) -OutputPath (Join-Path $OutputDirectory 'tpmtool-gatherlogs.txt')
    if ($gather.ExitCode -eq 0) {
        Add-Check 'MeasuredBoot.GatherLogs' 'PASS' 'tpmtool gatherlogs exited 0.'
    }
    else {
        Add-Check 'MeasuredBoot.GatherLogs' 'FAIL' "ExitCode=$($gather.ExitCode)"
    }

    $srtmBoot = Join-Path $tpmLogs 'SRTMBoot.dat'
    if (Test-Path -LiteralPath $srtmBoot) {
        $srtmLength = (Get-Item -LiteralPath $srtmBoot).Length
        $srtmHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $srtmBoot).Hash.ToLowerInvariant()
        if ($srtmLength -gt 1024) {
            Add-Check 'MeasuredBoot.SRTMLog' 'PASS' "SRTMBoot.dat=$srtmLength bytes; SHA256=$srtmHash"
        }
        else {
            Add-Check 'MeasuredBoot.SRTMLog' 'FAIL' "SRTMBoot.dat is only $srtmLength bytes."
        }
    }
    else {
        Add-Check 'MeasuredBoot.SRTMLog' 'FAIL' 'SRTMBoot.dat was not produced.'
    }

    $printPcr = Invoke-NativeCapture -FilePath $tpmTool -Arguments @('printpcr', 'sha256') -OutputPath (Join-Path $OutputDirectory 'pcr-sha256-live.txt')
    $pcrMap = Get-Sha256PcrMap -Text $printPcr.Text
    if ($printPcr.ExitCode -eq 0 -and $pcrMap.Count -ge 8) {
        Add-Check 'PCR.LiveRead.SHA256' 'PASS' "Read $($pcrMap.Count) SHA-256 PCR values."
    }
    else {
        Add-Check 'PCR.LiveRead.SHA256' 'WARN' "ExitCode=$($printPcr.ExitCode); parsed=$($pcrMap.Count). See pcr-sha256-live.txt."
    }
    $allZero = '0' * 64
    foreach ($index in @(0, 7)) {
        if ($pcrMap.ContainsKey($index)) {
            if ($pcrMap[$index] -eq $allZero) {
                Add-Check "PCR.$index.NonZero" 'FAIL' "PCR[$('{0:D2}' -f $index)] is all zero."
            }
            else {
                Add-Check "PCR.$index.NonZero" 'PASS' "PCR[$('{0:D2}' -f $index)]=$($pcrMap[$index])"
            }
        }
        else {
            Add-Check "PCR.$index.NonZero" 'WARN' 'PCR value was not parsed from tpmtool output.'
        }
    }

    $comparePcr = Invoke-NativeCapture -FilePath $tpmTool -Arguments @('comparepcr', 'sha256') -OutputPath (Join-Path $OutputDirectory 'pcr-sha256-replay-compare.txt')
    $compareStatus = Get-CompareStatus -Text $comparePcr.Text -ExitCode $comparePcr.ExitCode
    if ($compareStatus -eq 'PASS') {
        Add-Check 'PCR.Replay.SHA256' 'PASS' 'TCG log replay matches live TPM PCRs.'
    }
    elseif ($compareStatus -eq 'FAIL') {
        Add-Check 'PCR.Replay.SHA256' 'FAIL' 'TCG log replay does not match live TPM PCRs; inspect pcr-sha256-replay-compare.txt.'
    }
    else {
        Add-Check 'PCR.Replay.SHA256' 'WARN' "No explicit match/mismatch marker was recognized; ExitCode=$($comparePcr.ExitCode)."
    }
}

# Preserve useful Windows boot and TPM event channels without changing their state.
foreach ($logName in @(
    'Microsoft-Windows-Kernel-Boot/Operational',
    'Microsoft-Windows-TPM-WMI/Operational',
    'Microsoft-Windows-DeviceGuard/Operational'
)) {
    $safeName = $logName -replace '[^A-Za-z0-9.-]', '_'
    try {
        $events = @(Get-WinEvent -LogName $logName -MaxEvents 200 -ErrorAction Stop)
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            ConvertTo-Json -Depth 5 | Write-Utf8File -Path (Join-Path $OutputDirectory "$safeName.json")
        Add-Check "EventLog.$logName" 'INFO' "Collected $($events.Count) events."
    }
    catch {
        Add-Check "EventLog.$logName" 'WARN' $_.Exception.Message
    }
}

$checks | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDirectory 'summary.csv')
$checks | ConvertTo-Json -Depth 5 | Write-Utf8File -Path (Join-Path $OutputDirectory 'summary.json')

$failCount = @($checks | Where-Object Status -eq 'FAIL').Count
$warnCount = @($checks | Where-Object Status -eq 'WARN').Count
$passCount = @($checks | Where-Object Status -eq 'PASS').Count
$overall = 'PASS'
if ($failCount -gt 0) {
    $overall = 'FAIL'
}
$summaryLines = New-Object System.Collections.Generic.List[string]
[void]$summaryLines.Add("OVERALL=$overall")
[void]$summaryLines.Add("PASS=$passCount FAIL=$failCount WARN=$warnCount")
[void]$summaryLines.Add('')
foreach ($check in $checks) {
    [void]$summaryLines.Add("[$($check.Status)] $($check.Check): $($check.Detail)")
}
Write-Utf8File -Path (Join-Path $OutputDirectory 'SUMMARY.txt') -Text (($summaryLines -join [Environment]::NewLine) + [Environment]::NewLine)

$archivePath = $null
if (-not $NoArchive) {
    $archivePath = "$OutputDirectory.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $archivePath -CompressionLevel Optimal
}

Write-Host ''
Write-Host "OVERALL=$overall  PASS=$passCount  FAIL=$failCount  WARN=$warnCount"
Write-Host "Summary: $(Join-Path $OutputDirectory 'SUMMARY.txt')"
if ($archivePath) {
    Write-Host "Archive: $archivePath"
}
Write-Host ''
$checks | Format-Table -AutoSize

if ($failCount -gt 0) {
    exit 2
}
exit 0
