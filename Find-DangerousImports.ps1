#Requires -Version 5.0
<#
.SYNOPSIS
    Categoriza imports de um PE por classe de risco para mapeamento rápido de superfície de ataque.
.DESCRIPTION
    Extrai toda a import table (estática + delay-load) e classifica cada função em categorias:
    Buffer Overflow, Process Injection, Privilege Escalation, Dynamic API Resolution,
    Anti-Analysis, Crypto, IPC/Network e Code Execution. Gera mapa de primitivas disponíveis
    para exploração antes de qualquer análise dinâmica.
.PARAMETER ExePath
    Caminho do arquivo PE (.exe ou .dll).
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Find-DangerousImports.ps1 -ExePath "C:\App\app.exe"
    .\Find-DangerousImports.ps1 -ExePath "C:\App\app.exe" -JsonOutput "C:\report\imports.json"
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

# ── Import table extraction ───────────────────────────────────────────────────
function Get-ImportTable {
    param([byte[]]$Bytes)
    $imports = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $imports }
        $peOff   = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $magic   = [System.BitConverter]::ToUInt16($Bytes, $peOff + 24)
        $is64    = ($magic -eq 0x020B)
        $numSec  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $optOff  = $peOff + 24
        $secBase = $optOff + $optSize
        $ddBase  = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        $rva2off = {
            param([uint32]$rva)
            for ($s = 0; $s -lt $numSec; $s++) {
                $b   = $secBase + ($s * 40)
                $vsz = [System.BitConverter]::ToUInt32($Bytes, $b + 8)
                $va  = [System.BitConverter]::ToUInt32($Bytes, $b + 12)
                $raw = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
                if ($rva -ge $va -and $rva -lt ($va + $vsz)) { return [int]($raw + ($rva - $va)) }
            }; return 0
        }
        $readStr = {
            param([int]$off)
            $sb = [System.Text.StringBuilder]::new()
            while ($off -lt $Bytes.Length -and $Bytes[$off] -ne 0) { [void]$sb.Append([char]$Bytes[$off++]) }
            return $sb.ToString()
        }

        # Process both normal (index 1) and delay-load (index 13) import directories
        foreach ($dirIdx in @(1, 13)) {
            $idRVA = [System.BitConverter]::ToUInt32($Bytes, $ddBase + ($dirIdx * 8))
            if ($idRVA -eq 0) { continue }
            $idOff = & $rva2off $idRVA
            if ($idOff -eq 0) { continue }
            $entrySize = if ($dirIdx -eq 13) { 32 } else { 20 }  # delay descriptor is 32 bytes
            $nameField = if ($dirIdx -eq 13) { 4 } else { 12 }
            $thunkField= if ($dirIdx -eq 13) { 16 } else { 16 }
            $desc = $idOff
            while (($desc + $entrySize) -lt $Bytes.Length) {
                $nameRVA  = [System.BitConverter]::ToUInt32($Bytes, $desc + $nameField)
                $thunkRVA = [System.BitConverter]::ToUInt32($Bytes, $desc + $thunkField)
                if ($nameRVA -eq 0 -and $thunkRVA -eq 0) { break }
                if ($nameRVA -gt 0) {
                    $nameOff = & $rva2off $nameRVA
                    if ($nameOff -gt 0) {
                        $dllName = & $readStr $nameOff
                        if ($dllName) {
                            $thunkOff = & $rva2off $thunkRVA
                            $thunkSz  = if ($is64) { 8 } else { 4 }
                            $highBit  = if ($is64) { [uint64]0x8000000000000000 } else { [uint32]0x80000000 }
                            while ($thunkOff -gt 0 -and ($thunkOff + $thunkSz) -lt $Bytes.Length) {
                                $tv = if ($is64) { [System.BitConverter]::ToUInt64($Bytes,$thunkOff) } else { [System.BitConverter]::ToUInt32($Bytes,$thunkOff) }
                                if ($tv -eq 0) { break }
                                if (($tv -band $highBit) -eq 0) {
                                    $hOff = & $rva2off ([uint32]($tv -band 0x7FFFFFFF))
                                    if ($hOff -gt 0 -and ($hOff + 2) -lt $Bytes.Length) {
                                        $fn = & $readStr ($hOff + 2)
                                        if ($fn) { $imports.Add([PSCustomObject]@{ DLL=$dllName; Function=$fn; Delay=($dirIdx -eq 13) }) }
                                    }
                                } else {
                                    $imports.Add([PSCustomObject]@{ DLL=$dllName; Function="Ordinal_$($tv -band 0xFFFF)"; Delay=($dirIdx -eq 13) })
                                }
                                $thunkOff += $thunkSz
                            }
                        }
                    }
                }
                $desc += $entrySize
            }
        }
    } catch {}
    return $imports
}

# ── Risk classification rules ─────────────────────────────────────────────────
function Get-RiskCategories {
    return [ordered]@{
        'Buffer Overflow' = @{
            Severity = 'CRITICAL'
            Desc     = 'Funções inseguras de string/memória sem bounds checking'
            Color    = 'Red'
            Funcs    = @('strcpy','strcat','sprintf','gets','scanf','vsprintf','lstrcpy',
                         'lstrcat','wsprintf','_mbscpy','wcscat','wcscpy','_tcscpy',
                         'lstrcpyA','lstrcpyW','lstrcatA','lstrcatW')
        }
        'Process Injection' = @{
            Severity = 'CRITICAL'
            Desc     = 'Primitivas para injeção de código em outros processos'
            Color    = 'Red'
            Funcs    = @('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
                         'CreateRemoteThreadEx','NtCreateThreadEx','RtlCreateUserThread',
                         'QueueUserAPC','NtQueueApcThread','SetThreadContext','GetThreadContext',
                         'NtWriteVirtualMemory','NtAllocateVirtualMemory','ZwAllocateVirtualMemory')
        }
        'Privilege Escalation' = @{
            Severity = 'HIGH'
            Desc     = 'APIs de manipulação de tokens e impersonation'
            Color    = 'Red'
            Funcs    = @('OpenProcessToken','AdjustTokenPrivileges','ImpersonateNamedPipeClient',
                         'DuplicateToken','DuplicateTokenEx','SetThreadToken','CreateProcessAsUserA',
                         'CreateProcessAsUserW','CreateProcessWithTokenW','LookupPrivilegeValueA',
                         'LookupPrivilegeValueW','NtSetInformationThread','RtlAdjustPrivilege')
        }
        'Memory Manipulation' = @{
            Severity = 'HIGH'
            Desc     = 'Alocação e modificação direta de memória de processo'
            Color    = 'Red'
            Funcs    = @('VirtualAlloc','VirtualProtect','VirtualProtectEx','NtProtectVirtualMemory',
                         'HeapCreate','mmap','MapViewOfFile','MapViewOfFileEx','NtMapViewOfSection',
                         'ZwMapViewOfSection','NtCreateSection','ZwCreateSection')
        }
        'Dynamic API Resolution' = @{
            Severity = 'HIGH'
            Desc     = 'Resolução manual de API — pode ocultar imports perigosos'
            Color    = 'Yellow'
            Funcs    = @('GetProcAddress','LdrGetProcedureAddress','LoadLibraryA','LoadLibraryW',
                         'LoadLibraryExA','LoadLibraryExW','LdrLoadDll','LdrGetDllHandle')
        }
        'Anti-Analysis' = @{
            Severity = 'MEDIUM'
            Desc     = 'Detecção de debugger, VM ou sandbox'
            Color    = 'Yellow'
            Funcs    = @('IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess',
                         'OutputDebugStringA','OutputDebugStringW','DebugBreak','DebugBreakProcess',
                         'SetUnhandledExceptionFilter','AddVectoredExceptionHandler',
                         'CreateToolhelp32Snapshot','Process32FirstW','Process32NextW',
                         'EnumProcesses','GetTickCount','QueryPerformanceCounter')
        }
        'UAC / Elevation' = @{
            Severity = 'HIGH'
            Desc     = 'Criação de processos com contexto de segurança diferente'
            Color    = 'Yellow'
            Funcs    = @('ShellExecuteA','ShellExecuteW','ShellExecuteExA','ShellExecuteExW',
                         'CreateProcessElevated','CoCreateInstanceAsAdmin',
                         'IShellDispatch2','SHGetDesktopFolder')
        }
        'Crypto (Weak Risk)' = @{
            Severity = 'MEDIUM'
            Desc     = 'APIs criptográficas — verificar se usam algoritmos fracos'
            Color    = 'DarkYellow'
            Funcs    = @('CryptCreateHash','CryptEncrypt','CryptDecrypt','CryptDeriveKey',
                         'CryptGenKey','BCryptOpenAlgorithmProvider','BCryptCreateHash',
                         'NCryptEncrypt','NCryptDecrypt')
        }
        'IPC / Named Pipes' = @{
            Severity = 'MEDIUM'
            Desc     = 'Criação de canais IPC que podem ser explorados via impersonation'
            Color    = 'DarkYellow'
            Funcs    = @('CreateNamedPipeA','CreateNamedPipeW','ConnectNamedPipe',
                         'ImpersonateNamedPipeClient','RevertToSelf','CreatePipe',
                         'CallNamedPipeA','CallNamedPipeW')
        }
        'Network Exposure' = @{
            Severity = 'LOW'
            Desc     = 'Binding de sockets — pode expor serviços sem autenticação'
            Color    = 'DarkYellow'
            Funcs    = @('bind','listen','accept','WSAStartup','socket','WSASocket',
                         'WSAAccept','getaddrinfo','gethostbyname')
        }
        'Dangerous File Ops' = @{
            Severity = 'LOW'
            Desc     = 'Operações de arquivo que podem levar a path traversal ou race conditions'
            Color    = 'Gray'
            Funcs    = @('CreateFileA','CreateFileW','MoveFileA','MoveFileW',
                         'CopyFileA','CopyFileW','DeleteFileA','DeleteFileW',
                         'SetFileAttributesA','SetFileAttributesW')
        }
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "File not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== DANGEROUS IMPORTS ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

$bytes   = [System.IO.File]::ReadAllBytes($ExePath)
$imports = Get-ImportTable -Bytes $bytes
Write-Status '[*]' "Total imports found: $($imports.Count)"
Write-Host ''

$categories = Get-RiskCategories
$results    = [System.Collections.Generic.List[PSCustomObject]]::new()
$overallRisk = 'NONE'
$riskOrder = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }

foreach ($catName in $categories.Keys) {
    $cat      = $categories[$catName]
    $matched  = @($imports | Where-Object { $cat.Funcs -contains $_.Function })
    if ($matched.Count -eq 0) { continue }

    $r = [PSCustomObject]@{
        Category = $catName
        Severity = $cat.Severity
        Count    = $matched.Count
        Desc     = $cat.Desc
        Imports  = ($matched | Select-Object -ExpandProperty Function | Sort-Object -Unique)
        DLLs     = ($matched | Select-Object -ExpandProperty DLL | Sort-Object -Unique)
        HasDelay = ($matched | Where-Object { $_.Delay } | Measure-Object).Count -gt 0
    }
    $results.Add($r)

    if ($riskOrder[$cat.Severity] -gt $riskOrder[$overallRisk]) { $overallRisk = $cat.Severity }

    $col  = $cat.Color
    $delay = if ($r.HasDelay) { ' (delay-load)' } else { '' }
    Write-Host ("  [$($cat.Severity)] $catName$delay") -ForegroundColor $col
    Write-Host ("      $($cat.Desc)") -ForegroundColor DarkGray
    Write-Host ("      Functions : $($r.Imports -join ', ')") -ForegroundColor White
    Write-Host ''
}

# Check for injection combo: all 3 primitives present
$hasVAEx  = ($imports | Where-Object { $_.Function -eq 'VirtualAllocEx' })
$hasWPM   = ($imports | Where-Object { $_.Function -eq 'WriteProcessMemory' })
$hasCRT   = ($imports | Where-Object { $_.Function -in @('CreateRemoteThread','CreateRemoteThreadEx','NtCreateThreadEx') })
if ($hasVAEx -and $hasWPM -and $hasCRT) {
    Write-Status '[-]' '[CRITICAL] Classic injection trinity detected: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread'
    Write-Host ''
}

# Dynamic resolution indicator
$dynRes = @($imports | Where-Object { $_.Function -in @('GetProcAddress','LdrGetProcedureAddress') })
if ($dynRes.Count -gt 0) {
    $hiddenCount = [Math]::Max(0, $results.Count)
    Write-Status '[!]' "Dynamic API resolution present — $hiddenCount additional dangerous imports may be hidden"
    Write-Host ''
}

# Summary
Write-Status '[*]' '=== SUMMARY ==='
Write-Host ("  Overall Risk   : $overallRisk") -ForegroundColor $(switch($overallRisk){'CRITICAL'{'Red'}'HIGH'{'Red'}'MEDIUM'{'Yellow'}'LOW'{'DarkYellow'}default{'Green'}})
Write-Host ("  Total imports  : $($imports.Count)")
Write-Host ("  Risk categories: $($results.Count)")
Write-Host ''

# JSON output for orchestrator
if ($JsonOutput -ne '') {
    $json = [PSCustomObject]@{
        Script      = 'Find-DangerousImports'
        Target      = $ExePath
        Timestamp   = (Get-Date -Format 'o')
        RiskLevel   = $overallRisk
        TotalImports= $imports.Count
        InjectionCombo = ($hasVAEx -and $hasWPM -and $hasCRT)
        DynamicResolution = ($dynRes.Count -gt 0)
        Findings    = @($results | ForEach-Object {
            [PSCustomObject]@{ Severity=$_.Severity; Category=$_.Category; Desc=$_.Desc; Functions=$_.Imports; DLLs=$_.DLLs }
        })
    }
    $json | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}
