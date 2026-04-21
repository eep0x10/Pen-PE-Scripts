#Requires -Version 5.0
<#
.SYNOPSIS
    Detecta criação de arquivos em caminhos previsíveis sujeitos a TOCTOU / symlink attacks.
.DESCRIPTION
    Monitora o diretório TEMP e outros caminhos previsíveis durante a execução do alvo,
    classificando arquivos criados por predictabilidade do nome:
    - Nome fixo (sem componente aleatório) → CRITICAL (TOCTOU race condition)
    - Baseado em PID (previsível) → HIGH (race window pequena mas real)
    - Baseado em tempo → MEDIUM (race window dependente de precisão)
    - UUID/random → LOW/NONE (seguro)
    Combina análise estática (strings com padrões de GetTempPath + nome fixo)
    com monitoramento runtime via FileSystemWatcher.
.PARAMETER ExePath
    Caminho do executável alvo.
.PARAMETER ScanSeconds
    Duração do monitoramento em segundos (padrão: 20).
.PARAMETER ExtraWatchDirs
    Diretórios adicionais para monitorar além de %TEMP%.
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Check-TempRace.ps1 -ExePath "C:\App\installer.exe"
    .\Check-TempRace.ps1 -ExePath "C:\App\app.exe" -ScanSeconds 30 -JsonOutput "C:\report\race.json"
    .\Check-TempRace.ps1 -ExePath "C:\App\app.exe" -ExtraWatchDirs @("C:\ProgramData","C:\Windows\Temp")
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [int]$ScanSeconds = 20,
    [string[]]$ExtraWatchDirs = @(),
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

# Classify name predictability
function Get-NamePredictability {
    param([string]$Name)

    # UUID v4 pattern = very unpredictable
    if ($Name -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
        return @{ Risk='NONE'; Label='UUID-based (secure)'; Color='Green' }
    }

    # Long random hex (≥12 hex chars) = unpredictable
    if ($Name -match '[0-9a-fA-F]{12,}') {
        return @{ Risk='LOW'; Label='Long hex component (likely random)'; Color='DarkYellow' }
    }

    # PID-based: contains a realistic PID number (4-6 digits) surrounded by non-alpha
    if ($Name -match '(^|[^0-9])[1-9][0-9]{3,5}([^0-9]|$)') {
        return @{ Risk='HIGH'; Label='PID-based (predictable, small race window)'; Color='Yellow' }
    }

    # Timestamp-based: contains numbers that look like timestamps
    if ($Name -match '\d{8,}') {
        return @{ Risk='MEDIUM'; Label='Timestamp-based (predictable with timing)'; Color='Yellow' }
    }

    # Short random component (1-4 hex chars) = not enough entropy
    if ($Name -match '[0-9a-fA-F]{4,7}') {
        return @{ Risk='MEDIUM'; Label='Short random component (insufficient entropy)'; Color='Yellow' }
    }

    # Purely alphabetic + known extensions = fixed name
    if ($Name -match '^[a-zA-Z0-9_\-\.]{1,20}\.(tmp|exe|dll|bat|ps1|log|cfg|ini|dat)$') {
        return @{ Risk='CRITICAL'; Label='Fixed name (TOCTOU vulnerable)'; Color='Red' }
    }

    return @{ Risk='MEDIUM'; Label='Possibly predictable (manual review)'; Color='Yellow' }
}

# Check if temp file is created with exclusive access (TOCTOU-resistant)
function Test-ExclusiveAccess {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $false }
    try {
        $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        $fs.Close()
        return $false  # we could open it = NOT exclusive
    } catch { return $true }  # locked = exclusive access active
}

# Static analysis: look for fixed temp file patterns in strings
function Find-StaticTempPatterns {
    param([byte[]]$Bytes)
    $patterns = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sb = [System.Text.StringBuilder]::new()

    # Extract strings
    $strings = [System.Collections.Generic.List[string]]::new()
    foreach ($b in $Bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) { [void]$sb.Append([char]$b) }
        else { if ($sb.Length -ge 5) { $strings.Add($sb.ToString()) }; [void]$sb.Clear() }
    }
    $i = 0
    while ($i -lt $Bytes.Length - 1) {
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i+1] -eq 0x00) {
            [void]$sb.Append([char]$Bytes[$i]); $i += 2
        } else { if ($sb.Length -ge 5) { $strings.Add($sb.ToString()) }; [void]$sb.Clear(); $i++ }
    }
    $strings = $strings | Select-Object -Unique

    # Patterns indicating fixed temp file usage
    $fixedPatterns = @(
        @{ Pattern='(?i)%TEMP%\\[a-zA-Z][a-zA-Z0-9_\-]{0,15}\.(tmp|exe|dll|bat|log)$'; Label='Fixed %TEMP% path' }
        @{ Pattern='(?i)GetTempPath.*?(CreateFile|fopen|open)'; Label='GetTempPath + hardcoded name' }
        @{ Pattern='(?i)\\Temp\\[a-zA-Z][a-zA-Z0-9_\-]{0,15}\.(tmp|exe|dll|bat|log)$'; Label='Hardcoded temp path' }
        @{ Pattern='(?i)C:\\Windows\\Temp\\[a-zA-Z]'; Label='C:\Windows\Temp with likely fixed name' }
        @{ Pattern='(?i)C:\\ProgramData\\[a-zA-Z]{3,}\.(tmp|lock|pid)$'; Label='ProgramData fixed file' }
    )

    foreach ($str in $strings) {
        foreach ($fp in $fixedPatterns) {
            if ($str -match $fp.Pattern) {
                $pred = Get-NamePredictability -Name ([System.IO.Path]::GetFileName($str))
                $patterns.Add([PSCustomObject]@{
                    String    = $str
                    PatternLabel = $fp.Label
                    Risk      = $pred.Risk
                    PredLabel = $pred.Label
                })
            }
        }
    }
    return $patterns
}

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "Not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== TEMP FILE RACE CONDITION ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# ── Step 1: Static analysis ───────────────────────────────────────────────────
Write-Status '[*]' 'Static: scanning strings for fixed temp file patterns...'
$staticFindings = Find-StaticTempPatterns -Bytes $bytes
if ($staticFindings.Count -gt 0) {
    Write-Status '[!]' "Static patterns found: $($staticFindings.Count)"
    foreach ($sf in $staticFindings) {
        $col = switch($sf.Risk){'CRITICAL'{'Red'}'HIGH'{'Red'}'MEDIUM'{'Yellow'}default{'DarkGray'}}
        Write-Host ("  [$($sf.Risk)] $($sf.String)") -ForegroundColor $col
        Write-Host ("         Pattern : $($sf.PatternLabel)") -ForegroundColor DarkGray
    }
    Write-Host ''
} else {
    Write-Status '[+]' 'No static fixed-name temp patterns found'
    Write-Host ''
}

# ── Step 2: Setup watchers ────────────────────────────────────────────────────
$watchDirs   = @($env:TEMP, $env:WINDIR + '\Temp', $env:ProgramData) + $ExtraWatchDirs
$watchDirs   = @($watchDirs | Where-Object { $_ -and (Test-Path $_ -PathType Container) } | Select-Object -Unique)
$watchers    = @()
$createdFiles= [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

Write-Status '[*]' "Runtime: monitoring $($watchDirs.Count) directories for ${ScanSeconds}s..."
foreach ($dir in $watchDirs) { Write-Host "      $dir" -ForegroundColor DarkGray }
Write-Host ''

foreach ($dir in $watchDirs) {
    try {
        $w = [System.IO.FileSystemWatcher]::new($dir)
        $w.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName'
        $w.IncludeSubdirectories = $false
        $w.EnableRaisingEvents   = $true
        $captureDir = $dir
        Register-ObjectEvent -InputObject $w -EventName 'Created' -Action {
            $createdFiles.Add([PSCustomObject]@{
                FullPath  = $Event.SourceEventArgs.FullPath
                Name      = $Event.SourceEventArgs.Name
                Directory = $captureDir
                Time      = [datetime]::Now
            })
        } | Out-Null
        $watchers += $w
    } catch { Write-Status '[!]' "Could not watch: $dir" }
}

# Launch process
$proc = $null
try { $proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction Stop } catch {
    Write-Status '[-]' "Launch failed: $($_.Exception.Message)"
    foreach ($w in $watchers) { $w.Dispose() }
    exit 1
}
Write-Status '[*]' "PID: $($proc.Id)"
Write-Host ''

# Monitor progress
$deadline = [datetime]::Now.AddSeconds($ScanSeconds)
while ([datetime]::Now -lt $deadline) {
    Start-Sleep -Seconds 2
    $remaining = [int](($deadline - [datetime]::Now).TotalSeconds)
    Write-Host ("  [${remaining}s remaining] Files captured: $($createdFiles.Count)") -ForegroundColor DarkGray
}

if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch {} }
foreach ($w in $watchers) { $w.Dispose() }

Write-Host ''
Write-Status '[*]' "Total files created: $($createdFiles.Count)"
Write-Host ''

# ── Step 3: Analyze captured files ────────────────────────────────────────────
$findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
$riskOrder   = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }
$overallRisk = if ($staticFindings | Where-Object { $_.Risk -eq 'CRITICAL' }) { 'HIGH' } else { 'NONE' }

if ($createdFiles.Count -gt 0) {
    Write-Status '[*]' '=== RUNTIME FILE CREATION ANALYSIS ==='
    Write-Host ''

    $byName = $createdFiles | Sort-Object Name | Get-Unique -AsString
    foreach ($file in $byName) {
        $pred      = Get-NamePredictability -Name $file.Name
        $exclusive = Test-ExclusiveAccess -FilePath $file.FullPath
        $col       = $pred.Color
        $toctou    = ($pred.Risk -in @('CRITICAL','HIGH')) -and (-not $exclusive)

        Write-Host ("  [$($pred.Risk)] $($file.Name)") -ForegroundColor $col
        Write-Host ("         Path      : $($file.FullPath)") -ForegroundColor White
        Write-Host ("         Label     : $($pred.Label)") -ForegroundColor $col
        Write-Host ("         Exclusive : $exclusive  |  TOCTOU: $toctou") -ForegroundColor DarkGray
        if ($toctou) {
            Write-Host "         >> Replace with symlink targeting a privileged file before process reopens" -ForegroundColor Red
        }
        Write-Host ''

        if ($riskOrder[$pred.Risk] -gt $riskOrder[$overallRisk]) { $overallRisk = $pred.Risk }
        $findings.Add([PSCustomObject]@{
            FileName   = $file.Name
            FullPath   = $file.FullPath
            Directory  = $file.Directory
            Risk       = $pred.Risk
            Label      = $pred.Label
            Exclusive  = $exclusive
            TOCTOURisk = $toctou
        })
    }
} else {
    Write-Status '[+]' 'No files created in monitored directories during scan window'
    Write-Status '[!]' 'Try increasing -ScanSeconds or adding -ExtraWatchDirs'
}

Write-Host ''
Write-Status '[*]' "Overall Risk: $overallRisk"

if ($JsonOutput -ne '') {
    $json = [PSCustomObject]@{
        Script         = 'Check-TempRace'
        Target         = $ExePath
        Timestamp      = (Get-Date -Format 'o')
        RiskLevel      = $overallRisk
        StaticFindings = @($staticFindings)
        RuntimeFindings= @($findings)
        WatchedDirs    = $watchDirs
    }
    $json | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}
