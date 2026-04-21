#Requires -Version 5.0
<#
.SYNOPSIS
    Orquestrador completo de análise de binários PE — executa todos os scripts e gera relatório consolidado.
.DESCRIPTION
    Executa em sequência (e onde possível em paralelo) todos os scripts do toolkit:

    FASE ESTÁTICA (sem execução do binário):
      1. Audit-PEMitigations    — flags ASLR/DEP/CFG/SafeSEH/Authenticode
      2. Check-PEEntropy        — detecção de packer e seções criptografadas
      3. Check-ManifestPrivileges — UAC/autoElevate/uiAccess
      4. Find-DangerousImports  — mapeamento de primitivas de exploração
      5. Check-AntiAnalysis     — anti-debug, anti-VM, obfuscação
      6. Find-HardcodedSecrets  — credenciais e tokens hardcoded
      7. Check-DllHijacking     — DLL hijacking (4 vetores)
      8. Check-DllSideloading   — sideloading de binários assinados
      9. Check-COMHijacking     — COM object hijacking via HKCU
     10. Check-PEPlanting       — binary planting via PATH relativo

    FASE RUNTIME (executa o binário):
     11. Check-NamedPipes       — named pipes com ACL fraca
     12. Check-TempRace         — arquivos temporários previsíveis (TOCTOU)

    Gera:
    - Sumário colorido no console
    - Relatório HTML completo em -OutputDir
.PARAMETER ExePath
    Caminho do executável a analisar.
.PARAMETER OutputDir
    Diretório para salvar o relatório HTML e JSONs individuais (padrão: .\reports\<nome_binário>_<timestamp>).
.PARAMETER SkipRuntime
    Pula os testes que executam o binário (fases 11-12).
.PARAMETER SkipDllPoC
    Não gera PoC de DLL (passa -GeneratePoC=false para os scripts de DLL/COM).
.PARAMETER ScanSeconds
    Duração dos scans runtime em segundos (padrão: 15).
.PARAMETER ScriptsDir
    Diretório dos scripts do toolkit (padrão: mesmo diretório deste script).
.EXAMPLE
    .\Invoke-PEAudit.ps1 -ExePath "C:\Program Files\App\app.exe"
    .\Invoke-PEAudit.ps1 -ExePath "C:\App\app.exe" -OutputDir "C:\reports" -SkipRuntime
    .\Invoke-PEAudit.ps1 -ExePath "C:\App\app.exe" -ScanSeconds 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [string]$OutputDir    = '',
    [switch]$SkipRuntime,
    [switch]$SkipDllPoC,
    [int]$ScanSeconds    = 15,
    [string]$ScriptsDir  = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Bootstrap ─────────────────────────────────────────────────────────────────
$startTime = Get-Date
if ($ScriptsDir -eq '') { $ScriptsDir = $PSScriptRoot }
if (-not (Test-Path $ExePath)) {
    Write-Host '[-] File not found: ' -NoNewline -ForegroundColor Red
    Write-Host $ExePath; exit 1
}

$exeName = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
$ts      = $startTime.ToString('yyyyMMdd_HHmmss')

if ($OutputDir -eq '') { $OutputDir = Join-Path $PSScriptRoot "reports\${exeName}_${ts}" }
[void](New-Item -ItemType Directory -Path $OutputDir -Force)

function Write-Status {
    param([string]$Prefix, [string]$Message)
    $color = switch ($Prefix) {
        '[+]'{'Green'} '[-]'{'Red'} '[!]'{'Yellow'} '[*]'{'Cyan'} '[~]'{'DarkCyan'} default{'White'}
    }
    Write-Host "$Prefix $Message" -ForegroundColor $color
}

function Write-Phase {
    param([string]$Title)
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function Invoke-Script {
    param([string]$Name, [string]$ScriptPath, [hashtable]$Params, [string]$JsonPath)
    Write-Status '[~]' "Running: $Name"
    if (-not (Test-Path $ScriptPath)) {
        Write-Status '[!]' "Script not found: $ScriptPath"
        return [PSCustomObject]@{ Script=$Name; RiskLevel='ERROR'; Error='Script not found'; Findings=@() }
    }
    try {
        # Run in child process to isolate Add-Type conflicts and capture output
        $argList = @('-NonInteractive','-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptPath)
        foreach ($k in $Params.Keys) {
            $v = $Params[$k]
            if ($v -is [bool]) { if ($v) { $argList += "-$k" } }
            else { $argList += "-$k"; $argList += "$v" }
        }
        if ($JsonPath -ne '') { $argList += '-JsonOutput'; $argList += $JsonPath }

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = 'powershell.exe'
        $psi.Arguments = $argList -join ' '
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow  = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        # Print captured output (stripped of ANSI)
        if ($stdout) {
            $stdout -split "`n" | ForEach-Object {
                if ($_ -match '\[-\]') { Write-Host "    $_" -ForegroundColor Red }
                elseif ($_ -match '\[!\]') { Write-Host "    $_" -ForegroundColor Yellow }
                elseif ($_ -match '\[\+\]') { Write-Host "    $_" -ForegroundColor Green }
                elseif ($_ -match '\[\*\]') { Write-Host "    $_" -ForegroundColor Cyan }
                else { Write-Host "    $_" -ForegroundColor Gray }
            }
        }

        # Load JSON result
        if ($JsonPath -ne '' -and (Test-Path $JsonPath)) {
            $json = Get-Content $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            return $json
        }

        # Parse text output for risk if no JSON
        $risk = 'NONE'
        if ($stdout -match 'CRITICAL') { $risk = 'CRITICAL' }
        elseif ($stdout -match '\[-\]') { $risk = 'HIGH' }
        elseif ($stdout -match '\[!\]') { $risk = 'MEDIUM' }
        return [PSCustomObject]@{ Script=$Name; RiskLevel=$risk; Findings=@(); RawOutput=$stdout }

    } catch {
        Write-Status '[!]' "Error in $Name`: $($_.Exception.Message)"
        return [PSCustomObject]@{ Script=$Name; RiskLevel='ERROR'; Error=$_.Exception.Message; Findings=@() }
    }
}

# ── Script registry ───────────────────────────────────────────────────────────
$scripts = [ordered]@{
    'Audit-PEMitigations'     = @{ File='Audit-PEMitigations.ps1';      HasJson=$true;  Runtime=$false }
    'Check-PEEntropy'         = @{ File='Check-PEEntropy.ps1';          HasJson=$true;  Runtime=$false }
    'Check-ManifestPrivileges'= @{ File='Check-ManifestPrivileges.ps1'; HasJson=$true;  Runtime=$false }
    'Find-DangerousImports'   = @{ File='Find-DangerousImports.ps1';    HasJson=$true;  Runtime=$false }
    'Check-AntiAnalysis'      = @{ File='Check-AntiAnalysis.ps1';       HasJson=$true;  Runtime=$false }
    'Find-HardcodedSecrets'   = @{ File='Find-HardcodedSecrets.ps1';    HasJson=$true;  Runtime=$false }
    'Check-DllHijacking'      = @{ File='Check-DllHijacking.ps1';       HasJson=$false; Runtime=$false }
    'Check-DllSideloading'    = @{ File='Check-DllSideloading.ps1';     HasJson=$false; Runtime=$false }
    'Check-COMHijacking'      = @{ File='Check-COMHijacking.ps1';       HasJson=$false; Runtime=$false }
    'Check-PEPlanting'        = @{ File='Check-PEPlanting.ps1';         HasJson=$false; Runtime=$false }
    'Check-NamedPipes'        = @{ File='Check-NamedPipes.ps1';         HasJson=$true;  Runtime=$true  }
    'Check-TempRace'          = @{ File='Check-TempRace.ps1';           HasJson=$true;  Runtime=$true  }
}

$results = [ordered]@{}

# ── Header ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║              PE AUDIT ORCHESTRATOR — Pen-PE-Scripts             ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host ''
Write-Status '[*]' "Target   : $ExePath"
Write-Status '[*]' "Output   : $OutputDir"
Write-Status '[*]' "Runtime  : $(if ($SkipRuntime) { 'DISABLED' } else { "ENABLED (${ScanSeconds}s)" })"
Write-Status '[*]' "DLL PoC  : $(if ($SkipDllPoC) { 'DISABLED' } else { 'ENABLED' })"
Write-Host ''

# ── PHASE 1: Static analysis ──────────────────────────────────────────────────
Write-Phase 'PHASE 1 — STATIC ANALYSIS (no execution)'

foreach ($name in $scripts.Keys) {
    $cfg = $scripts[$name]
    if ($cfg.Runtime) { continue }

    $scriptPath = Join-Path $ScriptsDir $cfg.File
    $jsonPath   = if ($cfg.HasJson) { Join-Path $OutputDir "$name.json" } else { '' }
    $params     = @{ ExePath = $ExePath }

    # Script-specific params
    switch ($name) {
        'Find-HardcodedSecrets' { $params['OutputFile'] = (Join-Path $OutputDir 'hardcoded_secrets.json') }
        'Check-DllHijacking'    { if ($SkipDllPoC) {} }
        'Check-DllSideloading'  { if ($SkipDllPoC) {} }
        'Check-COMHijacking'    { if ($SkipDllPoC) {} }
    }

    $results[$name] = Invoke-Script -Name $name -ScriptPath $scriptPath -Params $params -JsonPath $jsonPath
    Write-Host ''
}

# ── PHASE 2: Runtime analysis ─────────────────────────────────────────────────
if (-not $SkipRuntime) {
    Write-Phase 'PHASE 2 — RUNTIME ANALYSIS (executes target)'
    Write-Status '[!]' "Target will be launched up to $($scripts.Values.Where({$_.Runtime}).Count) time(s)"
    Write-Host ''

    foreach ($name in $scripts.Keys) {
        $cfg = $scripts[$name]
        if (-not $cfg.Runtime) { continue }

        $scriptPath = Join-Path $ScriptsDir $cfg.File
        $jsonPath   = Join-Path $OutputDir "$name.json"
        $params     = @{ ExePath=$ExePath; ScanSeconds=$ScanSeconds }

        $results[$name] = Invoke-Script -Name $name -ScriptPath $scriptPath -Params $params -JsonPath $jsonPath
        Write-Host ''
    }
} else {
    Write-Status '[!]' 'Runtime phase skipped (-SkipRuntime). Tests: Check-NamedPipes, Check-TempRace'
    foreach ($name in ($scripts.Keys | Where-Object { $scripts[$_].Runtime })) {
        $results[$name] = [PSCustomObject]@{ Script=$name; RiskLevel='SKIPPED'; Findings=@() }
    }
}

# ── Risk aggregation ──────────────────────────────────────────────────────────
$riskOrder = @{ CRITICAL=5; HIGH=4; MEDIUM=3; LOW=2; NONE=1; SKIPPED=0; ERROR=0 }
$riskColor = @{ CRITICAL='Red'; HIGH='Red'; MEDIUM='Yellow'; LOW='DarkYellow'; NONE='Green'; SKIPPED='DarkGray'; ERROR='Red' }
$riskCounts = @{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; NONE=0 }

foreach ($name in $results.Keys) {
    $r = $results[$name].RiskLevel
    if ($r -and $riskCounts.ContainsKey($r)) { $riskCounts[$r]++ }
}

$overallRisk = 'NONE'
foreach ($level in @('CRITICAL','HIGH','MEDIUM','LOW')) {
    if ($riskCounts[$level] -gt 0) { $overallRisk = $level; break }
}

# ── Console summary table ─────────────────────────────────────────────────────
Write-Phase 'AUDIT SUMMARY'

$hdr = "{0,-30} {1,-10} {2}" -f 'Script','Risk','Key Finding'
Write-Host $hdr -ForegroundColor DarkGray
Write-Host ('-' * 85) -ForegroundColor DarkGray

foreach ($name in $results.Keys) {
    $r       = $results[$name]
    $risk    = $r.RiskLevel ?? 'ERROR'
    $col     = $riskColor[$risk] ?? 'White'
    $keyFind = ''

    # Extract key finding summary from JSON data
    if ($r.PSObject.Properties.Name -contains 'Findings' -and $r.Findings) {
        $top = @($r.Findings | Where-Object { $_.Severity -in @('CRITICAL','HIGH') }) | Select-Object -First 1
        if ($top) { $keyFind = $top.Category ?? $top.Detail ?? '' }
    }
    if (-not $keyFind -and $r.PSObject.Properties.Name -contains 'Packers' -and $r.Packers) {
        $keyFind = "Packer: $($r.Packers[0])"
    }
    if (-not $keyFind -and $r.PSObject.Properties.Name -contains 'AutoElevate' -and $r.AutoElevate) {
        $keyFind = 'autoElevate=true (UAC bypass candidate)'
    }
    if (-not $keyFind -and $r.PSObject.Properties.Name -contains 'InjectionCombo' -and $r.InjectionCombo) {
        $keyFind = 'Injection trinity: VAllocEx+WPM+CRT'
    }

    $line = "{0,-30} {1,-10} {2}" -f $name, $risk, $keyFind
    Write-Host $line -ForegroundColor $col
}

Write-Host ''
Write-Host ('─' * 85) -ForegroundColor DarkGray
Write-Host "  OVERALL RISK: " -NoNewline
Write-Host $overallRisk -ForegroundColor $riskColor[$overallRisk]
Write-Host ''
Write-Host "  CRITICAL: $($riskCounts.CRITICAL)  HIGH: $($riskCounts.HIGH)  MEDIUM: $($riskCounts.MEDIUM)  LOW: $($riskCounts.LOW)" -ForegroundColor White

$elapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host "  Completed in: ${elapsed}s" -ForegroundColor DarkGray
Write-Host ''

# ── HTML Report generation ────────────────────────────────────────────────────
function Build-HTMLReport {
    param([ordered]$Results, [string]$Target, [string]$OverallRisk, [hashtable]$RiskCounts, [datetime]$StartTime)

    $rBadge = @{ CRITICAL='#dc2626'; HIGH='#ea580c'; MEDIUM='#d97706'; LOW='#65a30d'; NONE='#16a34a'; SKIPPED='#6b7280'; ERROR='#dc2626' }

    $scriptRows = ''
    foreach ($name in $Results.Keys) {
        $r      = $Results[$name]
        $risk   = $r.RiskLevel ?? 'ERROR'
        $badge  = $rBadge[$risk] ?? '#6b7280'
        $findingsHtml = ''

        if ($r.PSObject.Properties.Name -contains 'Findings' -and $r.Findings) {
            foreach ($f in $r.Findings) {
                $sev    = $f.Severity ?? $f.Risk ?? 'INFO'
                $cat    = $f.Category ?? $f.Type ?? $f.PipeName ?? 'Finding'
                $detail = $f.Detail ?? $f.Reason ?? $f.Desc ?? ''
                $ev     = ''
                if ($f.PSObject.Properties.Name -contains 'Evidence' -and $f.Evidence) {
                    $ev = "<br><small style='color:#9ca3af'>$(($f.Evidence | Select-Object -First 8) -join ' · ')</small>"
                }
                if ($f.PSObject.Properties.Name -contains 'Functions' -and $f.Functions) {
                    $ev = "<br><small style='color:#9ca3af'>$(($f.Functions | Select-Object -First 8) -join ' · ')</small>"
                }
                $sevColor = @{ CRITICAL='#dc2626'; HIGH='#ea580c'; MEDIUM='#d97706'; LOW='#65a30d' }[$sev] ?? '#6b7280'
                $findingsHtml += "<div class='finding'><span class='badge' style='background:$sevColor'>$sev</span> <strong>$cat</strong> — $detail$ev</div>"
            }
        }

        # Extra data pills for specific scripts
        $extraHtml = ''
        if ($r.PSObject.Properties.Name -contains 'Packers' -and $r.Packers.Count -gt 0) {
            $extraHtml += "<div class='finding'><span class='badge' style='background:#7c3aed'>PACKER</span> $($r.Packers -join ', ')</div>"
        }
        if ($r.PSObject.Properties.Name -contains 'AutoElevate' -and $r.AutoElevate) {
            $extraHtml += "<div class='finding'><span class='badge' style='background:#dc2626'>UAC BYPASS</span> autoElevate=true + $($r.ExecutionLevel)</div>"
        }
        if ($r.PSObject.Properties.Name -contains 'InjectionCombo' -and $r.InjectionCombo) {
            $extraHtml += "<div class='finding'><span class='badge' style='background:#dc2626'>INJECTION</span> VirtualAllocEx + WriteProcessMemory + CreateRemoteThread detected</div>"
        }
        if ($r.PSObject.Properties.Name -contains 'ImportCount') {
            $ic = $r.ImportCount
            $icColor = if ($ic -le 2) { '#dc2626' } elseif ($ic -le 5) { '#d97706' } else { '#16a34a' }
            $extraHtml += "<div class='finding'><span class='badge' style='background:$icColor'>IMPORTS</span> $ic DLL(s) in import table</div>"
        }
        if ($r.PSObject.Properties.Name -contains 'AntiDebugAPIs' -and $r.AntiDebugAPIs.Count -gt 0) {
            $extraHtml += "<div class='finding'><span class='badge' style='background:#ea580c'>ANTI-DEBUG</span> $($r.AntiDebugAPIs -join ', ')</div>"
        }
        if ($r.PSObject.Properties.Name -contains 'VMStrings' -and $r.VMStrings.Count -gt 0) {
            $extraHtml += "<div class='finding'><span class='badge' style='background:#ea580c'>ANTI-VM</span> $($r.VMStrings | Select-Object -First 4 | ForEach-Object { $_ } -join ', ')</div>"
        }

        $allContent = $findingsHtml + $extraHtml
        if (-not $allContent) { $allContent = '<div class="finding" style="color:#6b7280">No findings</div>' }

        $scriptRows += @"
<tr>
  <td class="script-name">$name</td>
  <td><span class="badge" style="background:$badge">$risk</span></td>
  <td>$allContent</td>
</tr>
"@
    }

    $ovColor  = $rBadge[$OverallRisk] ?? '#6b7280'
    $duration = [Math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PE Audit — $([System.IO.Path]::GetFileName($Target))</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f0f; color: #e5e7eb; line-height: 1.5; }
  .header { background: linear-gradient(135deg, #1e1e2e 0%, #0f0f1a 100%); padding: 2rem; border-bottom: 1px solid #374151; }
  .header h1 { font-size: 1.4rem; color: #60a5fa; margin-bottom: .25rem; }
  .header .meta { color: #6b7280; font-size: .85rem; font-family: monospace; }
  .risk-banner { padding: 1rem 2rem; border-left: 4px solid $ovColor; margin: 1.5rem 2rem; background: #1a1a1a; border-radius: 0 8px 8px 0; }
  .risk-banner h2 { font-size: 1.1rem; }
  .risk-banner .overall { font-size: 2rem; font-weight: 800; color: $ovColor; }
  .counters { display: flex; gap: 1rem; margin: 1rem 2rem; flex-wrap: wrap; }
  .counter { background: #1a1a1a; border: 1px solid #374151; border-radius: 8px; padding: .75rem 1.25rem; text-align: center; min-width: 80px; }
  .counter .n { font-size: 1.6rem; font-weight: 700; }
  .counter .l { font-size: .7rem; color: #6b7280; text-transform: uppercase; }
  .section { margin: 1.5rem 2rem; }
  table { width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; }
  th { background: #1f2937; padding: .75rem 1rem; text-align: left; font-size: .8rem; text-transform: uppercase; color: #9ca3af; letter-spacing: .05em; }
  td { padding: .75rem 1rem; border-bottom: 1px solid #1f2937; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1a2033; }
  .script-name { font-family: monospace; font-size: .85rem; color: #a5b4fc; white-space: nowrap; }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .7rem; font-weight: 700; color: white; letter-spacing: .05em; }
  .finding { margin: .25rem 0; font-size: .82rem; }
  .finding strong { color: #f3f4f6; }
  .footer { margin: 2rem; color: #4b5563; font-size: .75rem; border-top: 1px solid #1f2937; padding-top: 1rem; }
</style>
</head>
<body>
<div class="header">
  <h1>PE Security Audit Report</h1>
  <div class="meta">
    Target: $Target<br>
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  Duration: ${duration}s  |  Scripts: $($Results.Count)
  </div>
</div>

<div class="risk-banner">
  <h2>Overall Risk</h2>
  <div class="overall">$OverallRisk</div>
</div>

<div class="counters">
  <div class="counter"><div class="n" style="color:#dc2626">$($RiskCounts.CRITICAL)</div><div class="l">Critical</div></div>
  <div class="counter"><div class="n" style="color:#ea580c">$($RiskCounts.HIGH)</div><div class="l">High</div></div>
  <div class="counter"><div class="n" style="color:#d97706">$($RiskCounts.MEDIUM)</div><div class="l">Medium</div></div>
  <div class="counter"><div class="n" style="color:#65a30d">$($RiskCounts.LOW)</div><div class="l">Low</div></div>
  <div class="counter"><div class="n" style="color:#16a34a">$($RiskCounts.NONE)</div><div class="l">Clean</div></div>
</div>

<div class="section">
  <table>
    <thead>
      <tr><th>Script</th><th style="width:100px">Risk</th><th>Findings</th></tr>
    </thead>
    <tbody>
      $scriptRows
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by Pen-PE-Scripts / Invoke-PEAudit.ps1 &nbsp;|&nbsp; For authorized use only
</div>
</body>
</html>
"@
}

$html      = Build-HTMLReport -Results $results -Target $ExePath -OverallRisk $overallRisk -RiskCounts $riskCounts -StartTime $startTime
$htmlPath  = Join-Path $OutputDir "report_${exeName}.html"
[System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)

Write-Status '[+]' "HTML report : $htmlPath"
Write-Status '[+]' "JSON files  : $OutputDir"
Write-Host ''

# Try to open report in browser
try { Start-Process $htmlPath } catch {}

Write-Status '[*]' "Audit complete. Overall risk: $overallRisk"
Write-Host ''
