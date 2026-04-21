#Requires -Version 5.0
<#
.SYNOPSIS
    Detecta vulnerabilidades de Binary Planting (execução por caminho relativo) em PEs Windows.
.DESCRIPTION
    Analisa estaticamente um executável em busca de imports relacionados a criação de processos
    (CreateProcess*, ShellExecute*, WinExec) e extrai referências a executáveis sem caminho absoluto.
    Para cada referência encontrada, verifica se algum diretório no PATH do sistema é gravável,
    indicando oportunidade de binary planting.
    Com -RuntimeScan usa WMI para capturar processos filhos em tempo real e identificar
    quais foram iniciados via caminho relativo.
.PARAMETER ExePath
    Caminho do executável alvo.
.PARAMETER RuntimeScan
    Executa o alvo e monitora processos filhos via WMI (não requer admin).
.PARAMETER ScanSeconds
    Duração do monitoramento runtime em segundos (padrão: 20).
.PARAMETER DeepPathScan
    Escaneia todos os diretórios do PATH do alvo, não apenas os do sistema.
.EXAMPLE
    .\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe"
    .\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan
    .\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -ScanSeconds 60 -DeepPathScan
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [switch]$RuntimeScan,
    [int]$ScanSeconds = 20,
    [switch]$DeepPathScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param([string]$Prefix, [string]$Message)
    $color = switch ($Prefix) {
        '[+]' { 'Green'  } '[-]' { 'Red'    }
        '[!]' { 'Yellow' } '[*]' { 'Cyan'   }
        default { 'White' }
    }
    Write-Host "$Prefix $Message" -ForegroundColor $color
}

# Check if a directory exists and is writable by the current user
function Test-Writable {
    param([string]$Dir)
    if (-not (Test-Path $Dir -PathType Container)) { return $false }
    $testFile = Join-Path $Dir "__pen_write_test_$PID"
    try {
        [System.IO.File]::WriteAllText($testFile, 'x')
        Remove-Item $testFile -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

# P/Invoke helper to test directory write permission without creating files
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DirWriteCheck2 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint GENERIC_WRITE      = 0x40000000;
    const uint FILE_SHARE_READ    = 0x00000001;
    const uint OPEN_EXISTING      = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    public static bool CanWrite(string path) {
        IntPtr h = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID_HANDLE) return false;
        CloseHandle(h);
        return true;
    }
}
'@ -ErrorAction SilentlyContinue

# Extract import table DLL/function names from PE bytes
function Get-PEImports {
    param([byte[]]$Bytes)
    $imports = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $imports }
        $peOff    = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $magic    = [System.BitConverter]::ToUInt16($Bytes, $peOff + 24)
        $is64     = ($magic -eq 0x020B)
        $numSec   = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $optOff   = $peOff + 24
        $secBase  = $optOff + $optSize
        $ddBase   = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        # Convert RVA to file offset
        $rva2off = {
            param([uint32]$rva)
            for ($s = 0; $s -lt $numSec; $s++) {
                $b   = $secBase + ($s * 40)
                $vsz = [System.BitConverter]::ToUInt32($Bytes, $b + 8)
                $va  = [System.BitConverter]::ToUInt32($Bytes, $b + 12)
                $raw = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
                if ($rva -ge $va -and $rva -lt ($va + $vsz)) { return [int]($raw + ($rva - $va)) }
            }
            return 0
        }

        # Read null-terminated ASCII string
        $readStr = {
            param([int]$off)
            $sb = [System.Text.StringBuilder]::new()
            while ($off -lt $Bytes.Length -and $Bytes[$off] -ne 0) {
                [void]$sb.Append([char]$Bytes[$off++])
            }
            return $sb.ToString()
        }

        # Import Directory = DataDirectory[1]
        $idOff = $ddBase + (1 * 8)
        $idRVA = [System.BitConverter]::ToUInt32($Bytes, $idOff)
        $idSz  = [System.BitConverter]::ToUInt32($Bytes, $idOff + 4)
        if ($idRVA -eq 0) { return $imports }

        $idFileOff = & $rva2off $idRVA
        if ($idFileOff -eq 0) { return $imports }

        # Walk IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, ends with all-zero entry)
        $desc = $idFileOff
        while (($desc + 20) -lt $Bytes.Length) {
            $nameRVA = [System.BitConverter]::ToUInt32($Bytes, $desc + 12)
            $firstThunkRVA = [System.BitConverter]::ToUInt32($Bytes, $desc + 16)
            if ($nameRVA -eq 0 -and $firstThunkRVA -eq 0) { break }

            if ($nameRVA -gt 0) {
                $nameOff = & $rva2off $nameRVA
                if ($nameOff -gt 0) {
                    $dllName = & $readStr $nameOff
                    # Walk thunk array for function names
                    if ($dllName) {
                        $thunkRVA = if ($firstThunkRVA -ne 0) { $firstThunkRVA } else {
                            [System.BitConverter]::ToUInt32($Bytes, $desc)
                        }
                        $thunkOff = & $rva2off $thunkRVA
                        $thunkSz  = if ($is64) { 8 } else { 4 }
                        while ($thunkOff -gt 0 -and ($thunkOff + $thunkSz) -lt $Bytes.Length) {
                            $thunkVal = if ($is64) {
                                [System.BitConverter]::ToUInt64($Bytes, $thunkOff)
                            } else {
                                [System.BitConverter]::ToUInt32($Bytes, $thunkOff)
                            }
                            if ($thunkVal -eq 0) { break }
                            # High bit set = ordinal import, skip
                            $highBit = if ($is64) { [uint64]0x8000000000000000 } else { [uint32]0x80000000 }
                            if (($thunkVal -band $highBit) -eq 0) {
                                $hintRVA = [uint32]($thunkVal -band 0x7FFFFFFF)
                                $hintOff = & $rva2off $hintRVA
                                if ($hintOff -gt 0 -and ($hintOff + 2) -lt $Bytes.Length) {
                                    $funcName = & $readStr ($hintOff + 2)
                                    if ($funcName) { [void]$imports.Add("$dllName!$funcName") }
                                }
                            }
                            $thunkOff += $thunkSz
                        }
                    }
                }
            }
            $desc += 20
        }
    } catch {}
    return $imports
}

# Extract strings from PE bytes (ASCII + Unicode)
function Get-PEStrings {
    param([byte[]]$Bytes, [int]$MinLen = 6)
    $results = [System.Collections.Generic.List[string]]::new()
    $sb = [System.Text.StringBuilder]::new()

    foreach ($b in $Bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) {
            [void]$sb.Append([char]$b)
        } else {
            if ($sb.Length -ge $MinLen) { $results.Add($sb.ToString()) }
            [void]$sb.Clear()
        }
    }
    if ($sb.Length -ge $MinLen) { $results.Add($sb.ToString()) }
    [void]$sb.Clear()

    $i = 0
    while ($i -lt $Bytes.Length - 1) {
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i+1] -eq 0x00) {
            [void]$sb.Append([char]$Bytes[$i])
            $i += 2
        } else {
            if ($sb.Length -ge $MinLen) { $results.Add($sb.ToString()) }
            [void]$sb.Clear()
            $i++
        }
    }
    if ($sb.Length -ge $MinLen) { $results.Add($sb.ToString()) }

    return $results | Select-Object -Unique
}

# Determine if a string looks like a relative executable reference
function Test-RelativeExecRef {
    param([string]$s)
    # Must end with executable extension
    if ($s -notmatch '\.(exe|bat|cmd|ps1|vbs|js|msi|com)$') { return $false }
    # Must NOT contain path separator (absolute reference)
    if ($s -match '[/\\]') { return $false }
    # Must be reasonable length (not too short like "a.exe")
    if ($s.Length -lt 5) { return $false }
    # Skip known Windows built-ins
    $builtins = @('cmd.exe','powershell.exe','msiexec.exe','rundll32.exe','regsvr32.exe',
                  'svchost.exe','conhost.exe','tasklist.exe','net.exe','ping.exe')
    if ($builtins -contains $s.ToLower()) { return $false }
    return $true
}

# Get effective PATH directories for the target binary's context
function Get-EffectivePATH {
    param([string]$ExeDir)
    $dirs = [System.Collections.Generic.List[string]]::new()
    $dirs.Add($ExeDir)
    foreach ($d in ($env:PATH -split ';')) {
        $d = $d.Trim().TrimEnd('\')
        if ($d -and $d -ne '' -and -not $dirs.Contains($d)) { $dirs.Add($d) }
    }
    return $dirs
}

# Runtime: WMI child process monitor
function Start-RuntimeScan {
    param([string]$ParentExe, [int]$Seconds)

    $spawnedProcs = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Status '[*]' "Runtime: monitoring child processes for ${Seconds}s via WMI..."

    $query   = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    $watcher = $null
    $proc    = $null

    try {
        $watcher = New-Object System.Management.ManagementEventWatcher($query)
        $watcher.Start()

        $proc = Start-Process -FilePath $ParentExe -PassThru -ErrorAction SilentlyContinue
        Write-Status '[*]' "Target PID: $($proc.Id)"

        $deadline = [System.DateTime]::UtcNow.AddSeconds($Seconds)
        while ([System.DateTime]::UtcNow -lt $deadline) {
            try {
                $evt = $watcher.WaitForNextEvent((New-Object System.TimeSpan(0,0,1)))
                if ($evt) {
                    $wi = $evt.TargetInstance
                    # Filter to processes spawned by our target
                    if ($wi.ParentProcessId -eq $proc.Id) {
                        $spawnedProcs.Add([PSCustomObject]@{
                            Name        = $wi.Name
                            CommandLine = $wi.CommandLine
                            ExePath     = $wi.ExecutablePath
                            ParentPID   = $wi.ParentProcessId
                        })
                    }
                }
            } catch [System.Management.ManagementException] {}
              catch { break }
        }
    } finally {
        if ($watcher) { $watcher.Stop(); $watcher.Dispose() }
        if ($proc -and -not $proc.HasExited) { $proc.Kill() }
    }

    return $spawnedProcs
}

# ── Main ──────────────────────────────────────────────────────────────────────

if (-not (Test-Path $ExePath)) {
    Write-Status '[-]' "File not found: $ExePath"; exit 1
}

$exeDir = [System.IO.Path]::GetDirectoryName($ExePath)
Write-Status '[*]' '=== BINARY PLANTING ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

# ── Step 1: Import table — identify process creation APIs ─────────────────────
Write-Status '[*]' 'Parsing import table...'
$bytes   = [System.IO.File]::ReadAllBytes($ExePath)
$imports = Get-PEImports -Bytes $bytes

$creationAPIs = @(
    'CreateProcessA','CreateProcessW','CreateProcessAsUserA','CreateProcessAsUserW',
    'ShellExecuteA','ShellExecuteW','ShellExecuteExA','ShellExecuteExW',
    'WinExec','_wsystem','system','_spawnl','_spawnle','_spawnlp','_spawnv',
    'CreateProcessWithLogonW','CreateProcessWithTokenW'
)

$foundAPIs = $imports | Where-Object {
    $funcPart = $_.Split('!')[1]
    $creationAPIs -contains $funcPart
}

if ($foundAPIs) {
    Write-Status '[!]' "Process creation APIs found in import table:"
    foreach ($api in $foundAPIs) { Write-Host "      $api" -ForegroundColor Yellow }
} else {
    Write-Status '[+]' "No direct process creation APIs in import table"
    Write-Status '[!]' "(may use dynamic resolution via LoadLibrary/GetProcAddress)"
}
Write-Host ''

# ── Step 2: Extract relative executable references from strings ───────────────
Write-Status '[*]' 'Scanning strings for relative executable references...'
$strings     = Get-PEStrings -Bytes $bytes
$relativeRefs = $strings | Where-Object { Test-RelativeExecRef -s $_ } | Select-Object -Unique

Write-Status '[*]' "Relative executable references found: $($relativeRefs.Count)"
Write-Host ''

# ── Step 3: Check PATH for planting opportunities ─────────────────────────────
$pathDirs   = Get-EffectivePATH -ExeDir $exeDir
$plantable  = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Status '[*]' "Checking $($pathDirs.Count) PATH directories for planting opportunities..."
Write-Host ''

if ($relativeRefs.Count -gt 0) {
    foreach ($ref in $relativeRefs) {
        foreach ($dir in $pathDirs) {
            $fullPath = Join-Path $dir $ref
            # Skip if the file already exists legitimately in this dir
            $alreadyExists = Test-Path $fullPath

            # Check writability
            $writable = $false
            try { $writable = [DirWriteCheck2]::CanWrite($dir) } catch { $writable = Test-Writable -Dir $dir }

            if ($writable) {
                $risk = if (-not $alreadyExists) { 'HIGH' } else { 'MEDIUM' }
                $plantable.Add([PSCustomObject]@{
                    Executable  = $ref
                    PlantDir    = $dir
                    FileExists  = $alreadyExists
                    Writable    = $true
                    Risk        = $risk
                    Note        = if (-not $alreadyExists) { 'File absent — plant directly' } else { 'File exists — replace or shadow' }
                })
                break  # first writable dir wins (search order)
            }
        }
    }
}

# ── Step 4: Deep PATH scan (check ALL writable dirs, not just first match) ────
$writableDirs = @()
if ($DeepPathScan) {
    Write-Status '[*]' 'Deep PATH scan: checking all directories for writability...'
    $writableDirs = $pathDirs | Where-Object {
        $w = $false
        try { $w = [DirWriteCheck2]::CanWrite($_) } catch { $w = Test-Writable -Dir $_ }
        $w
    }
    if ($writableDirs.Count -gt 0) {
        Write-Status '[!]' "Writable PATH directories ($($writableDirs.Count)):"
        foreach ($d in $writableDirs) {
            Write-Host "      $d" -ForegroundColor Yellow
        }
    } else {
        Write-Status '[+]' 'No writable PATH directories found'
    }
    Write-Host ''
}

# ── Step 5: Runtime scan ──────────────────────────────────────────────────────
$runtimeFindings = @()
if ($RuntimeScan) {
    Write-Host ''
    $spawnedProcs = Start-RuntimeScan -ParentExe $ExePath -Seconds $ScanSeconds
    Write-Status '[*]' "Spawned child processes captured: $($spawnedProcs.Count)"
    Write-Host ''

    foreach ($sp in $spawnedProcs) {
        # Check if the process was started with a relative path (no \ in path portion of cmdline)
        $cmdLine = $sp.CommandLine ?? ''
        $exeFullPath = $sp.ExePath ?? ''
        $isRelative = $false

        # If command line starts with just a filename (no path) or the resolved path
        # is in a dir that isn't the app dir (meaning system PATH was searched)
        if ($cmdLine -match '^"?([^"\\/:]+\.(?:exe|bat|cmd))"?' -or
            ($exeFullPath -and $exeFullPath -notlike "$exeDir\*")) {
            $isRelative = $true
        }

        $runtimeFindings += [PSCustomObject]@{
            Name        = $sp.Name
            CommandLine = $cmdLine
            ResolvedTo  = $exeFullPath
            IsRelative  = $isRelative
        }

        $col = if ($isRelative) { 'Yellow' } else { 'Gray' }
        $rel = if ($isRelative) { '[RELATIVE]' } else { '' }
        Write-Host ("  $rel $($sp.Name)" + $(if ($exeFullPath) { " -> $exeFullPath" })) -ForegroundColor $col
    }
    Write-Host ''
}

# ── Step 6: Report ────────────────────────────────────────────────────────────
Write-Status '[*]' '=== FINDINGS ==='
Write-Host ''

if ($plantable.Count -eq 0 -and $writableDirs.Count -eq 0) {
    Write-Status '[+]' 'No binary planting opportunities detected'
} else {
    if ($plantable.Count -gt 0) {
        Write-Status '[-]' "Binary planting vectors: $($plantable.Count)"
        Write-Host ''
        foreach ($p in ($plantable | Sort-Object Risk)) {
            $col = if ($p.Risk -eq 'HIGH') { 'Red' } else { 'Yellow' }
            Write-Host ("  [$($p.Risk)] $($p.Executable)") -ForegroundColor $col
            Write-Host ("         Plant in : $($p.PlantDir)") -ForegroundColor White
            Write-Host ("         Note     : $($p.Note)") -ForegroundColor Gray
            Write-Host ''
        }
    }

    if ($DeepPathScan -and $writableDirs.Count -gt 0 -and $relativeRefs.Count -eq 0) {
        Write-Status '[!]' 'Writable PATH dirs found but no static relative references detected'
        Write-Status '[!]' 'Use -RuntimeScan to capture dynamic process creation at runtime'
    }
}

if ($RuntimeScan -and $runtimeFindings.Count -gt 0) {
    $relativeProcs = @($runtimeFindings | Where-Object { $_.IsRelative })
    if ($relativeProcs.Count -gt 0) {
        Write-Status '[-]' "Runtime: $($relativeProcs.Count) process(es) started via relative path"
        foreach ($rp in $relativeProcs) {
            Write-Host ("  [-] $($rp.Name)") -ForegroundColor Red
            Write-Host ("      CommandLine: $($rp.CommandLine)") -ForegroundColor Gray
            Write-Host ("      Resolved to: $($rp.ResolvedTo)") -ForegroundColor Gray
            Write-Host ''
        }
    } else {
        Write-Status '[+]' 'Runtime: all child processes started with absolute paths'
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Status '[*]' '=== SUMMARY ==='
Write-Host ("  Process creation APIs : {0}" -f $(if ($foundAPIs) { ($foundAPIs | Measure-Object).Count } else { 0 }))
Write-Host ("  Relative exe refs     : {0}" -f $relativeRefs.Count)
Write-Host ("  Plantable vectors     : {0}" -f $plantable.Count)   -ForegroundColor $(if ($plantable.Count -gt 0) {'Red'} else {'Green'})
if ($DeepPathScan) {
    Write-Host ("  Writable PATH dirs    : {0}" -f $writableDirs.Count) -ForegroundColor $(if ($writableDirs.Count -gt 0) {'Yellow'} else {'Green'})
}
if ($RuntimeScan) {
    $relCnt = @($runtimeFindings | Where-Object { $_.IsRelative }).Count
    Write-Host ("  Relative at runtime   : {0}" -f $relCnt) -ForegroundColor $(if ($relCnt -gt 0) {'Red'} else {'Green'})
}
Write-Host ''
