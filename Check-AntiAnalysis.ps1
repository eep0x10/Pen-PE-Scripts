#Requires -Version 5.0
<#
.SYNOPSIS
    Detecta técnicas anti-análise, anti-debug e anti-VM em binários PE.
.DESCRIPTION
    Analisa estaticamente o binário em busca de:
    - APIs de detecção de debugger (IsDebuggerPresent, NtQueryInformationProcess)
    - Técnicas de timing-based detection (GetTickCount, RDTSC via imports)
    - Artefatos de VM/Hypervisor em strings (VMware, VirtualBox, QEMU, Hyper-V)
    - Indicadores de sandbox e análise automatizada
    - Enumeração de processos para detectar ferramentas de análise
    - Seções de código com alta entropia (obfuscação de strings/código)
    Essencial para planejar bypass antes de análise dinâmica.
.PARAMETER ExePath
    Caminho do arquivo PE.
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Check-AntiAnalysis.ps1 -ExePath "C:\malware\sample.exe"
    .\Check-AntiAnalysis.ps1 -ExePath "C:\App\app.exe" -JsonOutput "C:\report\antidebug.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [string]$JsonOutput = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param([string]$Prefix, [string]$Message)
    $color = switch ($Prefix) {
        '[+]'{'Green'} '[-]'{'Red'} '[!]'{'Yellow'} '[*]'{'Cyan'} default{'White'}
    }
    Write-Host "$Prefix $Message" -ForegroundColor $color
}

function Get-Entropy {
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -eq 0) { return 0.0 }
    $freq = @{}
    foreach ($b in $Data) { $freq[$b] = ($freq[$b] ?? 0) + 1 }
    $e = 0.0
    foreach ($cnt in $freq.Values) {
        $p = $cnt / $Data.Length
        $e -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($e, 3)
}

function Get-PEImportFunctions {
    param([byte[]]$Bytes)
    $funcs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $funcs }
        $peOff   = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $magic   = [System.BitConverter]::ToUInt16($Bytes, $peOff + 24)
        $is64    = ($magic -eq 0x020B)
        $numSec  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $optOff  = $peOff + 24
        $secBase = $optOff + $optSize
        $ddBase  = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        $rva2off = { param([uint32]$r)
            for ($s=0;$s -lt $numSec;$s++){
                $b=[int]($secBase+$s*40); $vsz=[System.BitConverter]::ToUInt32($Bytes,$b+8)
                $va=[System.BitConverter]::ToUInt32($Bytes,$b+12); $raw=[System.BitConverter]::ToUInt32($Bytes,$b+20)
                if($r -ge $va -and $r -lt ($va+$vsz)){return [int]($raw+($r-$va))}}; return 0 }
        $readStr = { param([int]$o)
            $sb=[System.Text.StringBuilder]::new()
            while($o -lt $Bytes.Length -and $Bytes[$o] -ne 0){[void]$sb.Append([char]$Bytes[$o++])}; return $sb.ToString() }

        $idRVA = [System.BitConverter]::ToUInt32($Bytes, $ddBase + 8)
        if ($idRVA -eq 0) { return $funcs }
        $desc = & $rva2off $idRVA
        while (($desc + 20) -lt $Bytes.Length) {
            $nameRVA = [System.BitConverter]::ToUInt32($Bytes, $desc + 12)
            $thunkRVA= [System.BitConverter]::ToUInt32($Bytes, $desc + 16)
            if ($nameRVA -eq 0 -and $thunkRVA -eq 0) { break }
            if ($nameRVA -gt 0) {
                $nOff = & $rva2off $nameRVA
                if ($nOff -gt 0) {
                    $thunkOff = & $rva2off $thunkRVA
                    $thunkSz  = if ($is64) { 8 } else { 4 }
                    $highBit  = if ($is64) { [uint64]0x8000000000000000 } else { [uint32]0x80000000 }
                    while ($thunkOff -gt 0 -and ($thunkOff+$thunkSz) -lt $Bytes.Length) {
                        $tv = if($is64){[System.BitConverter]::ToUInt64($Bytes,$thunkOff)}else{[System.BitConverter]::ToUInt32($Bytes,$thunkOff)}
                        if ($tv -eq 0) { break }
                        if (($tv -band $highBit) -eq 0) {
                            $hOff = & $rva2off ([uint32]($tv -band 0x7FFFFFFF))
                            if ($hOff -gt 0) { $fn = & $readStr ($hOff+2); if($fn){[void]$funcs.Add($fn)} }
                        }
                        $thunkOff += $thunkSz
                    }
                }
            }
            $desc += 20
        }
    } catch {}
    return $funcs
}

function Get-PEStrings {
    param([byte[]]$Bytes, [int]$MinLen = 5)
    $r = [System.Collections.Generic.List[string]]::new()
    $sb = [System.Text.StringBuilder]::new()
    foreach ($b in $Bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) { [void]$sb.Append([char]$b) }
        else { if ($sb.Length -ge $MinLen) { $r.Add($sb.ToString()) }; [void]$sb.Clear() }
    }
    if ($sb.Length -ge $MinLen) { $r.Add($sb.ToString()) }
    [void]$sb.Clear()
    $i = 0
    while ($i -lt $Bytes.Length - 1) {
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i+1] -eq 0x00) {
            [void]$sb.Append([char]$Bytes[$i]); $i += 2
        } else { if ($sb.Length -ge $MinLen) { $r.Add($sb.ToString()) }; [void]$sb.Clear(); $i++ }
    }
    if ($sb.Length -ge $MinLen) { $r.Add($sb.ToString()) }
    return $r | Select-Object -Unique
}

function Get-PESections {
    param([byte[]]$Bytes)
    $secs = @()
    try {
        $peOff   = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $numSec  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $secBase = $peOff + 24 + $optSize
        for ($i = 0; $i -lt $numSec; $i++) {
            $b       = $secBase + ($i * 40)
            $nameB   = $Bytes[$b..($b+7)]
            $secName = [System.Text.Encoding]::ASCII.GetString($nameB).TrimEnd("`0")
            $vsz     = [System.BitConverter]::ToUInt32($Bytes, $b + 8)
            $rawOff  = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
            $rawSz   = [System.BitConverter]::ToUInt32($Bytes, $b + 16)
            $chars   = [System.BitConverter]::ToUInt32($Bytes, $b + 36)
            $isExec  = [bool]($chars -band 0x20000000)
            if ($rawOff -gt 0 -and $rawSz -gt 0 -and ($rawOff + $rawSz) -le $Bytes.Length) {
                $secData = $Bytes[$rawOff..([int]($rawOff+$rawSz)-1)]
                $entropy = Get-Entropy -Data $secData
                $secs += [PSCustomObject]@{ Name=$secName; Entropy=$entropy; IsExecutable=$isExec; Size=$rawSz; RawOffset=$rawOff }
            }
        }
    } catch {}
    return $secs
}

# ── Detection rule sets ───────────────────────────────────────────────────────

$antiDebugAPIs = @(
    'IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess',
    'DebugBreak','DebugBreakProcess','DbgBreakPoint','DbgUiRemoteBreakin',
    'OutputDebugStringA','OutputDebugStringW','NtSetInformationThread',
    'ZwSetInformationThread','BlockInput'
)
$timingAPIs = @(
    'GetTickCount','GetTickCount64','QueryPerformanceCounter','QueryPerformanceFrequency',
    'NtQuerySystemTime','timeGetTime','timeBeginPeriod'
)
$enumAPIs = @(
    'CreateToolhelp32Snapshot','Process32FirstW','Process32NextW','Process32First','Process32Next',
    'EnumProcesses','NtQuerySystemInformation','EnumWindows','FindWindowA','FindWindowW',
    'FindWindowExA','FindWindowExW','GetWindowTextA','GetWindowTextW'
)

$vmStrings = @(
    # VMware
    'VMwareHgfs','vmtoolsd','vmwaretray','vmwareuser','vmacthlp','vmhgfs',
    'VMWARE','Virtual machine','vmci.sys','vmmemctl',
    # VirtualBox
    'VBoxGuest','VBoxMouse','VBoxVideo','vboxhook','vboxsf',
    'VBOX_VERSION','VIRTUALBOX','innotek GmbH',
    # QEMU/KVM
    'QEMU','qemu-ga','kvm','virtio',
    # Hyper-V
    'Hyper-V','VMBFS','vmicheartbeat','vmicshutdown',
    # Parallels
    'prl_tools','Parallels',
    # Generic
    'hypervisor','sandbox'
)

$sandboxStrings = @(
    # Known sandbox usernames/hostnames
    'SANDBOX','VIRUS','MALWARE','ANALYSIS','CUCKOO','ANUBIS','THREATTRACK',
    'JOEBOX','GFI-SANDBOX','THREATEXPERT','SUNBELT','COMODO','CWSANDBOX',
    # Analysis tool processes
    'wireshark.exe','procmon.exe','procexp.exe','ollydbg.exe','x32dbg.exe','x64dbg.exe',
    'idaq.exe','idaq64.exe','idaw.exe','windbg.exe','immunity debugger',
    'fiddler.exe','tcpview.exe','autoruns.exe','processhacker.exe',
    # Fake environment indicators
    'currentuser','test','sample','malware'
)

$antiDumpStrings = @(
    'PE-kill','ErasePE','anti-dump','SizeOfImage'
)

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "Not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== ANTI-ANALYSIS DETECTION ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

$bytes    = [System.IO.File]::ReadAllBytes($ExePath)
$imports  = Get-PEImportFunctions -Bytes $bytes
$strings  = Get-PEStrings -Bytes $bytes
$sections = Get-PESections -Bytes $bytes

$findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
$overallRisk = 'NONE'
$riskOrder   = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Detail, [string[]]$Evidence)
    $findings.Add([PSCustomObject]@{ Severity=$Severity; Category=$Category; Detail=$Detail; Evidence=$Evidence })
    if ($riskOrder[$Severity] -gt $riskOrder[$overallRisk]) { Set-Variable -Name overallRisk -Value $Severity -Scope 1 }
}

# ── Anti-debug imports ────────────────────────────────────────────────────────
$foundAD = @($antiDebugAPIs | Where-Object { $imports.Contains($_) })
if ($foundAD.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Category 'Anti-Debug (imports)' `
        -Detail "Detected $($foundAD.Count) anti-debug API(s)" -Evidence $foundAD
    Write-Status '[-]' "[HIGH] Anti-Debug APIs: $($foundAD -join ', ')"
}

# ── Timing detection ──────────────────────────────────────────────────────────
$foundTiming = @($timingAPIs | Where-Object { $imports.Contains($_) })
if ($foundTiming.Count -ge 2) {
    Add-Finding -Severity 'MEDIUM' -Category 'Timing Detection' `
        -Detail "Multiple timing APIs — likely timing-based debugger detection" -Evidence $foundTiming
    Write-Status '[!]' "[MEDIUM] Timing APIs: $($foundTiming -join ', ')"
}

# ── Process enumeration ───────────────────────────────────────────────────────
$foundEnum = @($enumAPIs | Where-Object { $imports.Contains($_) })
if ($foundEnum.Count -gt 0) {
    Add-Finding -Severity 'MEDIUM' -Category 'Process Enumeration' `
        -Detail "Enumerates processes/windows — likely checking for analysis tools" -Evidence $foundEnum
    Write-Status '[!]' "[MEDIUM] Process/Window enumeration: $($foundEnum -join ', ')"
}

# ── VM artifact strings ───────────────────────────────────────────────────────
$foundVM = @($vmStrings | Where-Object { $s = $_; $strings | Where-Object { $_ -match [regex]::Escape($s) } })
if ($foundVM.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Category 'Anti-VM (strings)' `
        -Detail "VM artifact strings detected — will alter behavior in VMs" -Evidence $foundVM
    Write-Status '[-]' "[HIGH] VM artifacts: $($foundVM -join ', ')"
}

# ── Sandbox strings ───────────────────────────────────────────────────────────
$foundSB = @($sandboxStrings | Where-Object { $s = $_; $strings | Where-Object { $_ -imatch [regex]::Escape($s) } })
if ($foundSB.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Category 'Anti-Sandbox (strings)' `
        -Detail "Known sandbox/analysis tool names in strings" -Evidence $foundSB
    Write-Status '[-]' "[HIGH] Sandbox indicators: $($foundSB -join ', ')"
}

# ── High entropy executable sections ─────────────────────────────────────────
$highEntropySecs = @($sections | Where-Object { $_.IsExecutable -and $_.Entropy -gt 6.5 })
if ($highEntropySecs.Count -gt 0) {
    $ev = @($highEntropySecs | ForEach-Object { "$($_.Name): $($_.Entropy)" })
    Add-Finding -Severity 'HIGH' -Category 'Code Obfuscation (entropy)' `
        -Detail "Executable sections with high entropy (>6.5) — strings/code may be encoded" -Evidence $ev
    Write-Status '[-]' "[HIGH] High-entropy executable sections:"
    foreach ($s in $highEntropySecs) {
        Write-Host ("      $($s.Name.PadRight(10)) entropy=$($s.Entropy)  size={0:N0} bytes" -f $s.Size) -ForegroundColor Red
    }
}

# ── Sections with no readable strings ────────────────────────────────────────
$dataSecs = @($sections | Where-Object { -not $_.IsExecutable -and $_.Entropy -gt 7.2 })
if ($dataSecs.Count -gt 0) {
    $ev = @($dataSecs | ForEach-Object { "$($_.Name): $($_.Entropy)" })
    Add-Finding -Severity 'MEDIUM' -Category 'Encrypted Data Sections' `
        -Detail "Non-executable sections with very high entropy (>7.2) — encrypted config/payload" -Evidence $ev
    Write-Status '[!]' "[MEDIUM] Encrypted data sections: $($ev -join ', ')"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Status '[*]' '=== BYPASS RECOMMENDATIONS ==='
if ($foundAD.Count -gt 0) {
    Write-Host '  >> Patch IsDebuggerPresent return value (xor eax,eax + ret) or use ScyllaHide' -ForegroundColor Yellow
    if ($foundAD -contains 'NtQueryInformationProcess') {
        Write-Host '  >> NtQueryInformationProcess(ProcessDebugPort): hook and return 0' -ForegroundColor Yellow
    }
}
if ($foundTiming.Count -ge 2) {
    Write-Host '  >> Use a time-patching plugin (ScyllaHide timer acceleration) or step-over timing checks' -ForegroundColor Yellow
}
if ($foundVM.Count -gt 0) {
    Write-Host '  >> Remove VMware/VBox artifacts from registry/drivers or use bare-metal analysis' -ForegroundColor Yellow
}
if ($highEntropySecs.Count -gt 0) {
    Write-Host '  >> Dump process memory after unpacking (use OEP detection + Scylla dump)' -ForegroundColor Yellow
}
Write-Host ''
Write-Status '[*]' "Overall Anti-Analysis level: $overallRisk"
Write-Host ''

if ($JsonOutput -ne '') {
    $json = [PSCustomObject]@{
        Script        = 'Check-AntiAnalysis'
        Target        = $ExePath
        Timestamp     = (Get-Date -Format 'o')
        RiskLevel     = $overallRisk
        AntiDebugAPIs = $foundAD
        TimingAPIs    = $foundTiming
        EnumAPIs      = $foundEnum
        VMStrings     = $foundVM
        SandboxStrings= $foundSB
        HighEntropySections = @($highEntropySecs | ForEach-Object { [PSCustomObject]@{Name=$_.Name;Entropy=$_.Entropy;Size=$_.Size} })
        Findings      = @($findings | ForEach-Object { [PSCustomObject]@{Severity=$_.Severity;Category=$_.Category;Detail=$_.Detail;Evidence=$_.Evidence} })
    }
    $json | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}
