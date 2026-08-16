@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "HW_SELF=%~f0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:HW_SELF,[Text.Encoding]::UTF8);$m='###'+' POWERSHELL '+'###';Invoke-Expression $s.Substring($s.IndexOf($m)+$m.Length)"
set "exitCode=%ERRORLEVEL%"

endlocal & exit /b %exitCode%

### POWERSHELL ###
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$savedPath = Join-Path (Split-Path -Parent $env:HW_SELF) 'hardware_snapshot_saved.txt'
$currentPath = [IO.Path]::GetTempFileName()
$wideLine = '=' * 80
$thinLine = '-' * 80

function Get-DisplayText {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return 'N/A'
    }

    return ([string]$Value).Trim()
}

function Write-HardwareSnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $lines = New-Object 'System.Collections.Generic.List[string]'

    function Add-Line {
        param([AllowEmptyString()][string]$Text = '')
        [void]$lines.Add($Text)
    }

    function Add-Section {
        param([string]$Title)
        Add-Line
        Add-Line $thinLine
        Add-Line "[$Title]"
    }

    function Get-CimData {
        param(
            [Parameter(Mandatory)][string]$ClassName,
            [string]$Filter
        )

        try {
            if ($Filter) {
                return @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop)
            }
            return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        } catch {
            Add-Line ("查詢失敗：{0}" -f $_.Exception.Message)
            return @()
        }
    }

    Add-Line $wideLine
    Add-Line '                             系統與硬體資訊'
    Add-Line $wideLine
    Add-Line ("查詢時間：{0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date))

    Add-Section '系統版本'
    $os = Get-CimData 'Win32_OperatingSystem' | Select-Object -First 1
    if ($os) {
        Add-Line ("系統：{0}" -f (Get-DisplayText $os.Caption))
        Add-Line ("版本：{0}" -f (Get-DisplayText $os.Version))
        Add-Line ("Build：{0}" -f (Get-DisplayText $os.BuildNumber))
        Add-Line ("架構：{0}" -f (Get-DisplayText $os.OSArchitecture))
    }

    Add-Section '電腦型號'
    $systemProduct = Get-CimData 'Win32_ComputerSystemProduct' | Select-Object -First 1
    if ($systemProduct) {
        Add-Line ("廠商：{0}" -f (Get-DisplayText $systemProduct.Vendor))
        Add-Line ("型號：{0}" -f (Get-DisplayText $systemProduct.Name))
        Add-Line ("識別版本：{0}" -f (Get-DisplayText $systemProduct.Version))
    }

    Add-Section '硬碟資訊'
    foreach ($disk in (Get-CimData 'Win32_DiskDrive' | Sort-Object Index, Model)) {
        $size = if ($null -eq $disk.Size) { 'N/A' } else { '{0:N2} GB' -f ([double]$disk.Size / 1GB) }
        Add-Line ("型號：{0}" -f (Get-DisplayText $disk.Model))
        Add-Line ("序號：{0}" -f (Get-DisplayText $disk.SerialNumber))
        Add-Line ("介面：{0}" -f (Get-DisplayText $disk.InterfaceType))
        Add-Line ("容量：{0}" -f $size)
        Add-Line
    }

    Add-Section '記憶體資訊'
    foreach ($memory in (Get-CimData 'Win32_PhysicalMemory' | Sort-Object DeviceLocator, BankLabel)) {
        $capacity = if ($null -eq $memory.Capacity) { 'N/A' } else { '{0:N0} MB' -f ([double]$memory.Capacity / 1MB) }
        Add-Line ("插槽：{0}" -f (Get-DisplayText $memory.DeviceLocator))
        Add-Line ("容量：{0}" -f $capacity)
        Add-Line ("速度：{0} MHz" -f (Get-DisplayText $memory.Speed))
        Add-Line ("料號：{0}" -f (Get-DisplayText $memory.PartNumber))
        Add-Line ("序號：{0}" -f (Get-DisplayText $memory.SerialNumber))
        Add-Line
    }

    Add-Section 'CPU 資訊'
    foreach ($cpu in (Get-CimData 'Win32_Processor' | Sort-Object DeviceID)) {
        Add-Line ("名稱：{0}" -f (Get-DisplayText $cpu.Name))
        Add-Line ("Processor ID：{0}" -f (Get-DisplayText $cpu.ProcessorId))
        Add-Line ("核心數：{0}" -f (Get-DisplayText $cpu.NumberOfCores))
        Add-Line ("執行緒數：{0}" -f (Get-DisplayText $cpu.NumberOfLogicalProcessors))
        Add-Line
    }

    Add-Section 'BIOS 資訊'
    $bios = Get-CimData 'Win32_BIOS' | Select-Object -First 1
    if ($bios) {
        Add-Line ("廠商：{0}" -f (Get-DisplayText $bios.Manufacturer))
        Add-Line ("版本：{0}" -f (Get-DisplayText $bios.SMBIOSBIOSVersion))
        Add-Line ("序號：{0}" -f (Get-DisplayText $bios.SerialNumber))
    }

    Add-Section '主機板資訊'
    $baseBoard = Get-CimData 'Win32_BaseBoard' | Select-Object -First 1
    if ($baseBoard) {
        Add-Line ("廠商：{0}" -f (Get-DisplayText $baseBoard.Manufacturer))
        Add-Line ("型號：{0}" -f (Get-DisplayText $baseBoard.Product))
        Add-Line ("版本：{0}" -f (Get-DisplayText $baseBoard.Version))
        Add-Line ("序號：{0}" -f (Get-DisplayText $baseBoard.SerialNumber))
    }

    Add-Section '系統 UUID'
    if ($systemProduct) {
        Add-Line ("UUID：{0}" -f (Get-DisplayText $systemProduct.UUID))
    }

    Add-Section '網路卡與 MAC 位址'
    $networkAdapters = Get-CimData 'Win32_NetworkAdapterConfiguration' 'IPEnabled=True' |
        Sort-Object Description, MACAddress
    foreach ($adapter in $networkAdapters) {
        $ipAddresses = @($adapter.IPAddress | Where-Object { $_ } | Sort-Object) -join ', '
        Add-Line ("介面：{0}" -f (Get-DisplayText $adapter.Description))
        Add-Line ("MAC：{0}" -f (Get-DisplayText $adapter.MACAddress))
        Add-Line ("IP：{0}" -f (Get-DisplayText $ipAddresses))
        Add-Line ("DHCP：{0}" -f (Get-DisplayText $adapter.DHCPEnabled))
        Add-Line
    }

    Add-Section 'GETMAC 原始資訊'
    try {
        & (Join-Path $env:SystemRoot 'System32\getmac.exe') /v /fo table 2>&1 |
            ForEach-Object { Add-Line ([string]$_) }
    } catch {
        Add-Line ("查詢失敗：{0}" -f $_.Exception.Message)
    }

    Add-Section '完整網路資訊'
    try {
        & (Join-Path $env:SystemRoot 'System32\ipconfig.exe') /all 2>&1 |
            ForEach-Object { Add-Line ([string]$_) }
    } catch {
        Add-Line ("查詢失敗：{0}" -f $_.Exception.Message)
    }

    Add-Line
    Add-Line $wideLine
    [IO.File]::WriteAllLines($Path, $lines, [Text.UTF8Encoding]::new($true))
}

function Get-ComparisonRecords {
    param([Parameter(Mandatory)][string]$Path)

    $section = ''
    $ignoredSections = @('GETMAC 原始資訊', '完整網路資訊')
    $occurrences = @{}

    foreach ($line in [IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)) {
        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1]
            continue
        }
        if (-not $section -or
            $section -in $ignoredSections -or
            $line -match '^查詢時間：' -or
            $line -match '^[=-]+$' -or
            [string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $separator = $line.IndexOf('：')
        if ($separator -lt 0) {
            $field = '資料'
            $value = $line.Trim()
        } else {
            $field = $line.Substring(0, $separator).Trim()
            $value = $line.Substring($separator + 1).Trim()
        }
        if ($section -eq '網路卡與 MAC 位址' -and $field -in @('IP', 'DHCP')) {
            continue
        }

        $baseKey = "$section::$field"
        $occurrences[$baseKey] = 1 + [int]$occurrences[$baseKey]
        $index = $occurrences[$baseKey]
        [pscustomobject]@{
            Key = "$baseKey::$index"
            Name = if ($index -eq 1) { "[$section] $field" } else { "[$section] $field #$index" }
            Value = $value
        }
    }
}

function Show-Snapshot {
    Clear-Host
    [IO.File]::ReadAllLines($currentPath, [Text.Encoding]::UTF8) | Write-Host
}

function Show-Status {
    param([string]$Message)
    Clear-Host
    Write-Host $Message
    Write-Host
}

function Wait-ForKey {
    Write-Host '按任意鍵繼續 . . .' -NoNewline
    try {
        [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } catch {
        [void](Read-Host)
    }
}

function Show-Comparison {
    Clear-Host
    Write-Host $wideLine
    Write-Host '                             硬體資訊對比'
    Write-Host $wideLine
    Write-Host
    Write-Host "基準檔案：$savedPath"
    Write-Host '查詢時間與容易變動的詳細網路資料不列入對比。'
    Write-Host

    $oldByKey = @{}
    $newByKey = @{}
    Get-ComparisonRecords $savedPath | ForEach-Object { $oldByKey[$_.Key] = $_ }
    Get-ComparisonRecords $currentPath | ForEach-Object { $newByKey[$_.Key] = $_ }
    $keys = @((@($oldByKey.Keys) + @($newByKey.Keys)) | Sort-Object -Unique)
    $changed = [Collections.Generic.List[object]]::new()
    $unchanged = [Collections.Generic.List[object]]::new()

    foreach ($key in $keys) {
        $oldExists = $oldByKey.ContainsKey($key)
        $newExists = $newByKey.ContainsKey($key)
        $oldItem = if ($oldExists) { $oldByKey[$key] } else { $null }
        $newItem = if ($newExists) { $newByKey[$key] } else { $null }
        $item = if ($newExists) { $newItem } else { $oldItem }

        if ($oldExists -and $newExists -and $oldItem.Value -eq $newItem.Value) {
            [void]$unchanged.Add($item)
        } else {
            [void]$changed.Add([pscustomobject]@{
                Name = $item.Name
                OldValue = if ($oldExists) { $oldItem.Value } else { '(不存在)' }
                NewValue = if ($newExists) { $newItem.Value } else { '(不存在)' }
            })
        }
    }

    $summaryColor = if ($changed.Count -eq 0) { 'Green' } else { 'Yellow' }
    Write-Host ("差異：{0}/{1}" -f $changed.Count, $keys.Count) -ForegroundColor $summaryColor
    Write-Host

    if ($changed.Count -eq 0) {
        Write-Host '沒有發現差異。' -ForegroundColor Green
    } else {
        Write-Host '變更項目' -ForegroundColor Yellow
        for ($i = 0; $i -lt $changed.Count; $i++) {
            $item = $changed[$i]
            Write-Host ("[差異 {0}/{1}] {2}" -f ($i + 1), $changed.Count, $item.Name) -ForegroundColor Yellow
            Write-Host ("  先前：{0}" -f $item.OldValue) -ForegroundColor Red
            Write-Host ("  目前：{0}" -f $item.NewValue) -ForegroundColor Green
        }
    }

    Write-Host
    Write-Host ("未變更項目：{0}" -f $unchanged.Count) -ForegroundColor Cyan
    for ($i = 0; $i -lt $unchanged.Count; $i++) {
        $item = $unchanged[$i]
        Write-Host ("[未變 {0}/{1}] {2}：{3}" -f ($i + 1), $unchanged.Count, $item.Name, $item.Value)
    }
    Write-Host
    Write-Host $wideLine
}

$exitCode = 0
try {
    try { $Host.UI.RawUI.WindowTitle = '系統與硬體資訊查詢' } catch {}
    Show-Status '正在查詢系統與硬體資訊……'
    Write-HardwareSnapshot $currentPath

    :menu while ($true) {
        Show-Snapshot
        Write-Host
        Write-Host $wideLine
        Write-Host '[R] 重新查詢'
        Write-Host '[S] 儲存目前結果'
        Write-Host '[D] 與上次儲存結果對比'
        Write-Host '[Q] 結束'
        Write-Host $wideLine

        & (Join-Path $env:SystemRoot 'System32\choice.exe') /C RSDQ /N /M '請選擇操作：'
        switch ($LASTEXITCODE) {
            1 {
                Show-Status '正在重新查詢……'
                Write-HardwareSnapshot $currentPath
            }
            2 {
                Show-Status '正在重新查詢並儲存目前資料……'
                Write-HardwareSnapshot $currentPath
                try {
                    Copy-Item -LiteralPath $currentPath -Destination $savedPath -Force -ErrorAction Stop
                    Write-Host '儲存成功。' -ForegroundColor Green
                    Write-Host "儲存位置：$savedPath"
                } catch {
                    Write-Host '儲存失敗。' -ForegroundColor Red
                    Write-Host $_.Exception.Message
                }
                Write-Host
                Wait-ForKey
            }
            3 {
                if (-not (Test-Path -LiteralPath $savedPath -PathType Leaf)) {
                    Show-Status '找不到之前儲存的結果。'
                    Write-Host '請先按 S 儲存一次硬體資訊。'
                    Write-Host "預期檔案位置：$savedPath"
                    Write-Host
                    Wait-ForKey
                    continue
                }

                Show-Status '正在重新查詢目前資料……'
                Write-HardwareSnapshot $currentPath
                Show-Comparison
                Wait-ForKey
            }
            4 { break menu }
            default { break menu }
        }
    }
} catch {
    $exitCode = 1
    Write-Host
    Write-Host ("執行失敗：{0}" -f $_.Exception.Message) -ForegroundColor Red
} finally {
    Remove-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
}

exit $exitCode
