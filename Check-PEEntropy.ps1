#Requires -Version 5.0
<#
.SYNOPSIS
    Analisa entropia por seção de um PE para detectar packers, protectors e código ofuscado.
.DESCRIPTION
    Calcula a entropia de Shannon para cada seção PE e identifica padrões indicativos de:
    - Packers: UPX, MPRESS, ASPack, PECompact, Petite
    - Protectors: Themida, VMProtect, Enigma, Obsidium (por heurística)
    - Import stripping (sinal de packer genérico)
    - Seções com dados comprimidos ou criptografados
    Sem saber que o binário está packed, você analisa o stub — não o código real.
.PARAMETER ExePath
    Caminho do arquivo PE.
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Check-PEEntropy.ps1 -ExePath "C:\App\app.exe"
    .\Check-PEEntropy.ps1 -ExePath "C:\sample.exe" -JsonOutput "C:\report\entropy.json"
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
    foreach ($cnt in $freq.Values) { $p = $cnt/$Data.Length; $e -= $p*[Math]::Log($p,2) }
    return [Math]::Round($e, 4)
}

# Entropy classification
function Get-EntropyLabel {
    param([double]$E)
    if ($E -ge 7.5)  { return @{ Label='ENCRYPTED/PACKED';   Color='Red';       Risk='CRITICAL' } }
    if ($E -ge 7.0)  { return @{ Label='HIGHLY COMPRESSED';  Color='Red';       Risk='HIGH'     } }
    if ($E -ge 6.5)  { return @{ Label='COMPRESSED/OBFUSC';  Color='Yellow';    Risk='MEDIUM'   } }
    if ($E -ge 6.0)  { return @{ Label='SUSPICIOUS';         Color='DarkYellow';Risk='LOW'      } }
    if ($E -ge 3.5)  { return @{ Label='NORMAL CODE/DATA';   Color='Green';     Risk='NONE'     } }
    return              @{ Label='PLAIN DATA/STRINGS';        Color='DarkGray';  Risk='NONE'     }
}

# Render an ASCII entropy bar
function Format-EntropyBar {
    param([double]$E, [int]$Width = 40)
    $filled = [int]([Math]::Round($E / 8.0 * $Width))
    $bar    = ('█' * $filled).PadRight($Width)
    return "[$bar] $E"
}

function Get-PESections {
    param([byte[]]$Bytes)
    $secs = @()
    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $secs }
        $peOff   = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $numSec  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $secBase = $peOff + 24 + $optSize
        for ($i = 0; $i -lt $numSec; $i++) {
            $b      = $secBase + ($i * 40)
            $nameB  = $Bytes[$b..($b+7)]
            $name   = [System.Text.Encoding]::ASCII.GetString($nameB).TrimEnd("`0")
            $vSize  = [System.BitConverter]::ToUInt32($Bytes, $b + 8)
            $vAddr  = [System.BitConverter]::ToUInt32($Bytes, $b + 12)
            $rawSz  = [System.BitConverter]::ToUInt32($Bytes, $b + 16)
            $rawOff = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
            $chars  = [System.BitConverter]::ToUInt32($Bytes, $b + 36)
            if ($rawOff -gt 0 -and $rawSz -gt 0 -and ($rawOff + $rawSz) -le $Bytes.Length) {
                $data = $Bytes[$rawOff..([int]($rawOff+$rawSz)-1)]
                $secs += [PSCustomObject]@{
                    Name        = if ($name) { $name } else { "(unnamed)" }
                    VirtualAddr = $vAddr
                    VirtualSize = $vSize
                    RawOffset   = $rawOff
                    RawSize     = $rawSz
                    Entropy     = Get-Entropy -Data $data
                    IsExec      = [bool]($chars -band 0x20000000)
                    IsWritable  = [bool]($chars -band 0x80000000)
                    IsReadable  = [bool]($chars -band 0x40000000)
                    FirstBytes  = ($data | Select-Object -First 16 | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
                }
            }
        }
    } catch {}
    return $secs
}

function Get-ImportCount {
    param([byte[]]$Bytes)
    $count = 0
    try {
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

        $idRVA = [System.BitConverter]::ToUInt32($Bytes, $ddBase + 8)
        if ($idRVA -eq 0) { return 0 }
        $desc = & $rva2off $idRVA
        while (($desc + 20) -lt $Bytes.Length) {
            $nameRVA = [System.BitConverter]::ToUInt32($Bytes, $desc + 12)
            $thunkRVA= [System.BitConverter]::ToUInt32($Bytes, $desc + 16)
            if ($nameRVA -eq 0 -and $thunkRVA -eq 0) { break }
            $count++; $desc += 20
        }
    } catch {}
    return $count
}

# Packer detection by section names and byte signatures
function Get-PackerSignature {
    param([PSCustomObject[]]$Sections, [byte[]]$FullBytes)
    $packers = @()

    $names = $Sections | Select-Object -ExpandProperty Name
    if ($names -contains 'UPX0' -or $names -contains 'UPX1' -or $names -contains 'UPX2') {
        $packers += 'UPX'
    }
    if ($names -contains '.MPRESS1' -or $names -contains '.MPRESS2') { $packers += 'MPRESS' }
    if ($names -contains '.aspack')  { $packers += 'ASPack' }
    if ($names -contains '.packed')  { $packers += 'PECompact' }
    if ($names -contains '.petite')  { $packers += 'Petite' }
    if ($names -contains '.nsp0' -or $names -contains '.nsp1') { $packers += 'NsPack' }

    # Check first bytes of first section for UPX signature
    $first = $Sections | Select-Object -First 1
    if ($first -and $first.FirstBytes -match '^60 BE') { $packers += 'UPX (runtime check)' }

    # Themida / WinLicense / VMProtect heuristic:
    # - Very few imports (1-3 DLLs) + very high entropy .text = protector
    $importCount = Get-ImportCount -Bytes $FullBytes
    $execSecs    = @($Sections | Where-Object { $_.IsExec -and $_.Entropy -gt 7.0 })
    if ($importCount -le 2 -and $execSecs.Count -gt 0 -and $packers.Count -eq 0) {
        $packers += 'Unknown protector (stripped imports + high entropy exec section)'
    }

    # Overlay (data after last section)
    if ($Sections.Count -gt 0) {
        $lastSec = $Sections | Sort-Object { $_.RawOffset + $_.RawSize } | Select-Object -Last 1
        $endOfSections = $lastSec.RawOffset + $lastSec.RawSize
        if ($endOfSections -lt $FullBytes.Length - 16) {
            $overlaySize = $FullBytes.Length - $endOfSections
            $overlayData = $FullBytes[$endOfSections..($FullBytes.Length-1)]
            $overlayEntropy = Get-Entropy -Data $overlayData
            $packers += "Overlay detected: $([Math]::Round($overlaySize/1KB,1)) KB, entropy=$overlayEntropy"
        }
    }

    return $packers
}

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "Not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== PE ENTROPY ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath ($([Math]::Round((Get-Item $ExePath).Length/1KB,1)) KB)"
Write-Host ''

$bytes    = [System.IO.File]::ReadAllBytes($ExePath)
$sections = Get-PESections -Bytes $bytes
$packers  = Get-PackerSignature -Sections $sections -FullBytes $bytes
$importCount = Get-ImportCount -Bytes $bytes

$riskOrder = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }
$overallRisk = 'NONE'
$highEntropySecs = @()

# ── Section entropy table ─────────────────────────────────────────────────────
$hdr = "{0,-12} {1,-6} {2,-6} {3,-8} {4,-24} {5}" -f 'Section','Exec','Write','Size(KB)','Classification','Entropy Bar'
Write-Host $hdr -ForegroundColor DarkGray
Write-Host ('-' * 95) -ForegroundColor DarkGray

foreach ($sec in $sections) {
    $lbl  = Get-EntropyLabel -E $sec.Entropy
    $bar  = Format-EntropyBar -E $sec.Entropy -Width 25
    $sz   = [Math]::Round($sec.RawSize / 1KB, 1)
    $exec = if ($sec.IsExec)     { 'YES' } else { 'NO ' }
    $wrt  = if ($sec.IsWritable) { 'YES' } else { 'NO ' }
    $name = $sec.Name.PadRight(12)

    $line = "{0} {1,-6} {2,-6} {3,-8} {4,-24} {5}" -f $name,$exec,$wrt,$sz,$lbl.Label,$bar
    Write-Host $line -ForegroundColor $lbl.Color

    if ($riskOrder[$lbl.Risk] -gt $riskOrder[$overallRisk]) { $overallRisk = $lbl.Risk }
    if ($lbl.Risk -in @('HIGH','CRITICAL')) { $highEntropySecs += $sec }
}

Write-Host ''

# ── Packer detection ──────────────────────────────────────────────────────────
if ($packers.Count -gt 0) {
    Write-Status '[-]' "Packer/Protector signatures detected:"
    foreach ($p in $packers) { Write-Host "      $p" -ForegroundColor Red }
    Write-Host ''
    Write-Status '[!]' 'Static analysis may only reveal the unpacking stub — dump process memory after OEP'
    Write-Status '[!]' 'Recommended: run with x64dbg + OEP detection, then dump + fix imports with Scylla'
    if ($overallRisk -eq 'NONE') { $overallRisk = 'HIGH' }
} else {
    Write-Status '[+]' 'No known packer signatures detected'
}

Write-Host ''

# ── Import count heuristic ────────────────────────────────────────────────────
Write-Host ("  Import DLL count : {0}" -f $importCount) -ForegroundColor $(if($importCount -le 2){'Red'} elseif($importCount -le 5){'Yellow'} else{'Green'})
if ($importCount -eq 0) {
    Write-Status '[-]' '[HIGH] Zero imports — binary likely resolves all APIs dynamically (manual GetProcAddress)'
    if ($riskOrder[$overallRisk] -lt 3) { $overallRisk = 'HIGH' }
} elseif ($importCount -le 2) {
    Write-Status '[!]' '[MEDIUM] Very few imports — possible stripped import table (packer/protector)'
}

Write-Host ''
Write-Status '[*]' "Overall Risk: $overallRisk"

if ($JsonOutput -ne '') {
    $json = [PSCustomObject]@{
        Script       = 'Check-PEEntropy'
        Target       = $ExePath
        Timestamp    = (Get-Date -Format 'o')
        RiskLevel    = $overallRisk
        ImportCount  = $importCount
        Packers      = $packers
        Sections     = @($sections | ForEach-Object {
            [PSCustomObject]@{ Name=$_.Name; Entropy=$_.Entropy; RawSize=$_.RawSize; IsExec=$_.IsExec; Label=(Get-EntropyLabel -E $_.Entropy).Label }
        })
        HighEntropySections = @($highEntropySecs | ForEach-Object {
            [PSCustomObject]@{ Name=$_.Name; Entropy=$_.Entropy; IsExec=$_.IsExec }
        })
    }
    $json | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}
