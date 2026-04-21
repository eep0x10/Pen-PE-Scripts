#Requires -Version 5.0
<#
.SYNOPSIS
    Audita flags de mitigação em binários PE do Windows.
.DESCRIPTION
    Analisa um ou mais executáveis (.exe / .dll) e reporta status de:
    ASLR, High Entropy VA, DEP/NX, Force Integrity, CFG, SafeSEH e Authenticode.
    Ideal para triage rápido de attack surface antes de aprofundar o pentest.
.PARAMETER Path
    Caminho para arquivo PE ou diretório.
.PARAMETER Recurse
    Escaneia subdiretórios recursivamente (apenas com -Path de diretório).
.PARAMETER CsvOutput
    Exporta resultados para arquivo CSV.
.PARAMETER ShowVulnOnly
    Exibe apenas binários com ao menos uma mitigação ausente.
.EXAMPLE
    .\Audit-PEMitigations.ps1 -Path "C:\Program Files\App"
    .\Audit-PEMitigations.ps1 -Path "C:\Windows\System32" -Recurse -ShowVulnOnly
    .\Audit-PEMitigations.ps1 -Path "C:\Program Files" -Recurse -CsvOutput "C:\results.csv"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$Recurse,
    [string]$CsvOutput,
    [switch]$ShowVulnOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── DllCharacteristics bit masks ──────────────────────────────────────────────
$DC_HIGH_ENTROPY_VA  = 0x0020  # 64-bit ASLR high entropy
$DC_DYNAMIC_BASE     = 0x0040  # ASLR (/DYNAMICBASE)
$DC_FORCE_INTEGRITY  = 0x0080  # Mandatory code signing check
$DC_NX_COMPAT        = 0x0100  # DEP (/NXCOMPAT)
$DC_NO_SEH           = 0x0400  # No structured exception handling
$DC_GUARD_CF         = 0x4000  # Control Flow Guard (/guard:cf)

function Write-Status {
    param([string]$Prefix, [string]$Message)
    $color = switch ($Prefix) {
        '[+]' { 'Green'  }
        '[-]' { 'Red'    }
        '[!]' { 'Yellow' }
        '[*]' { 'Cyan'   }
        default { 'White' }
    }
    Write-Host "$Prefix $Message" -ForegroundColor $color
}

# Converts a PE RVA to a raw file offset using the section table
function Convert-RVAToOffset {
    param([byte[]]$Bytes, [uint32]$RVA, [int]$SectionTableOffset, [int]$NumSections)
    for ($i = 0; $i -lt $NumSections; $i++) {
        $base    = $SectionTableOffset + ($i * 40)
        if (($base + 40) -ge $Bytes.Length) { break }
        $vSize   = [System.BitConverter]::ToUInt32($Bytes, $base + 8)
        $vAddr   = [System.BitConverter]::ToUInt32($Bytes, $base + 12)
        $rawOff  = [System.BitConverter]::ToUInt32($Bytes, $base + 20)
        if ($RVA -ge $vAddr -and $RVA -lt ($vAddr + $vSize)) {
            return [int]($rawOff + ($RVA - $vAddr))
        }
    }
    return 0
}

function Get-PEMitigations {
    param([string]$FilePath)

    $r = [ordered]@{
        File           = $FilePath
        Name           = [System.IO.Path]::GetFileName($FilePath)
        Arch           = 'Unknown'
        ASLR           = $false
        HighEntropyVA  = $false
        DEP            = $false
        ForceIntegrity = $false
        CFG            = $false
        SafeSEH        = 'N/A'
        Authenticode   = $false
        MissingCount   = 0
        Error          = $null
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)

        # MZ header check
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            $r.Error = 'Not a PE'; return $r
        }

        # Pointer to PE signature
        $peOff = [System.BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOff -lt 0 -or ($peOff + 24) -ge $bytes.Length) {
            $r.Error = 'Bad PE offset'; return $r
        }

        # Validate PE signature
        if ($bytes[$peOff] -ne 0x50 -or $bytes[$peOff+1] -ne 0x45) {
            $r.Error = 'No PE signature'; return $r
        }

        # Architecture from Machine field (COFF header starts at peOff+4)
        $machine = [System.BitConverter]::ToUInt16($bytes, $peOff + 4)
        $is64    = ($machine -eq 0x8664)
        $r.Arch  = if ($is64) { 'x64' } else { 'x86' }

        $numSections = [System.BitConverter]::ToUInt16($bytes, $peOff + 6)
        $optHdrSize  = [System.BitConverter]::ToUInt16($bytes, $peOff + 20)

        # Optional header starts at peOff + 4 (sig) + 20 (COFF) = peOff + 24
        $optOff = $peOff + 24

        # Validate magic (PE32=0x10B, PE32+=0x20B)
        $magic = [System.BitConverter]::ToUInt16($bytes, $optOff)
        if ($magic -ne 0x010B -and $magic -ne 0x020B) {
            $r.Error = "Unknown magic 0x{0:X4}" -f $magic; return $r
        }

        # DllCharacteristics: offset 70 from optional header start (same for both formats)
        $dllCharOff = $optOff + 70
        if (($dllCharOff + 2) -ge $bytes.Length) {
            $r.Error = 'Cannot read DllCharacteristics'; return $r
        }
        $dllChar = [System.BitConverter]::ToUInt16($bytes, $dllCharOff)

        $r.ASLR           = [bool]($dllChar -band $DC_DYNAMIC_BASE)
        $r.HighEntropyVA  = [bool]($dllChar -band $DC_HIGH_ENTROPY_VA)
        $r.DEP            = [bool]($dllChar -band $DC_NX_COMPAT)
        $r.ForceIntegrity = [bool]($dllChar -band $DC_FORCE_INTEGRITY)
        $r.CFG            = [bool]($dllChar -band $DC_GUARD_CF)
        $noSEH            = [bool]($dllChar -band $DC_NO_SEH)

        # Section table offset
        $secTableOff = $optOff + $optHdrSize

        # DataDirectory base: PE32=optOff+96, PE32+=optOff+112
        $dataDirBase = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        # ── Authenticode: Security Directory = DataDirectory[4] ───────────────
        $secDirOff = $dataDirBase + (4 * 8)
        if (($secDirOff + 8) -lt $bytes.Length) {
            $secDirSize  = [System.BitConverter]::ToUInt32($bytes, $secDirOff + 4)
            $r.Authenticode = ($secDirSize -gt 8)
        }

        # ── SafeSEH (x86 only) ────────────────────────────────────────────────
        if ($is64) {
            $r.SafeSEH = 'N/A (x64)'
        } elseif ($noSEH) {
            $r.SafeSEH = 'NO_SEH'
        } else {
            # Load Config Directory = DataDirectory[10]
            $lcDirOff = $dataDirBase + (10 * 8)
            if (($lcDirOff + 8) -lt $bytes.Length) {
                $lcRVA  = [System.BitConverter]::ToUInt32($bytes, $lcDirOff)
                $lcSize = [System.BitConverter]::ToUInt32($bytes, $lcDirOff + 4)
                if ($lcRVA -gt 0 -and $lcSize -gt 68) {
                    $lcFileOff = Convert-RVAToOffset -Bytes $bytes -RVA $lcRVA `
                        -SectionTableOffset $secTableOff -NumSections $numSections
                    if ($lcFileOff -gt 0) {
                        # SEHandlerTable is at Load Config offset 64 (x86)
                        $sehTableOff = $lcFileOff + 64
                        if (($sehTableOff + 4) -lt $bytes.Length) {
                            $sehTable  = [System.BitConverter]::ToUInt32($bytes, $sehTableOff)
                            $r.SafeSEH = ($sehTable -ne 0)
                        }
                    } else {
                        $r.SafeSEH = $false
                    }
                } else {
                    $r.SafeSEH = $false
                }
            } else {
                $r.SafeSEH = $false
            }
        }

        # ── Missing count (used for coloring) ─────────────────────────────────
        $missing = 0
        if (-not $r.ASLR)          { $missing++ }
        if (-not $r.DEP)           { $missing++ }
        if (-not $r.CFG)           { $missing++ }
        if (-not $r.Authenticode)  { $missing++ }
        if ($r.SafeSEH -eq $false) { $missing++ }
        $r.MissingCount = $missing

    } catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Status '[*]' '=== PE MITIGATIONS AUDIT ==='
Write-Host ''

$files = @()
if (Test-Path $Path -PathType Leaf) {
    $files = @(Get-Item $Path)
} elseif (Test-Path $Path -PathType Container) {
    $gci = @{ Path = $Path; Include = @('*.exe','*.dll','*.sys') }
    if ($Recurse) { $gci['Recurse'] = $true }
    $files = Get-ChildItem @gci
} else {
    Write-Status '[-]' "Path not found: $Path"; exit 1
}

if ($files.Count -eq 0) {
    Write-Status '[!]' 'No PE files found.'; exit 0
}

Write-Status '[*]' "Analyzing $($files.Count) file(s)..."
Write-Host ''

$results = @()
foreach ($f in $files) {
    $results += [PSCustomObject](Get-PEMitigations -FilePath $f.FullName)
}

$display = if ($ShowVulnOnly) {
    $results | Where-Object { $_.MissingCount -gt 0 -and -not $_.Error }
} else { $results }

# ── Table header ──────────────────────────────────────────────────────────────
$W = 40
$hdr = "{0,-$W} {1,-5} {2,-4} {3,-4} {4,-4} {5,-7} {6,-8} {7,-4} {8,-4}" -f `
    'File','Arch','ASLR','DEP','CFG','SafeSEH','AuthCode','HEVA','FI'
Write-Host $hdr -ForegroundColor DarkGray
Write-Host ('-' * 100) -ForegroundColor DarkGray

foreach ($r in $display) {
    if ($r.Error) {
        Write-Host ("{0,-$W} ERROR: {1}" -f $r.Name, $r.Error) -ForegroundColor DarkGray
        continue
    }
    $color = if ($r.MissingCount -ge 3) { 'Red' } elseif ($r.MissingCount -ge 1) { 'Yellow' } else { 'Green' }

    $name = if ($r.Name.Length -gt $W) { $r.Name.Substring(0,$W-3)+'...' } else { $r.Name.PadRight($W) }
    $line = "{0} {1,-5} {2,-4} {3,-4} {4,-4} {5,-7} {6,-8} {7,-4} {8,-4}" -f `
        $name, $r.Arch,
        (if ($r.ASLR)           {'YES'} else {'NO'}),
        (if ($r.DEP)            {'YES'} else {'NO'}),
        (if ($r.CFG)            {'YES'} else {'NO'}),
        ($r.SafeSEH.ToString().PadRight(7)),
        (if ($r.Authenticode)   {'YES'} else {'NO'}),
        (if ($r.HighEntropyVA)  {'YES'} else {'NO'}),
        (if ($r.ForceIntegrity) {'YES'} else {'NO'})
    Write-Host $line -ForegroundColor $color
}
Write-Host ''

# ── Summary ───────────────────────────────────────────────────────────────────
$valid   = $results | Where-Object { -not $_.Error }
$noASLR  = @($valid | Where-Object { -not $_.ASLR }).Count
$noDEP   = @($valid | Where-Object { -not $_.DEP }).Count
$noCFG   = @($valid | Where-Object { -not $_.CFG }).Count
$noAuth  = @($valid | Where-Object { -not $_.Authenticode }).Count
$noSEH   = @($valid | Where-Object { $_.SafeSEH -eq $false }).Count
$vulnCnt = @($valid | Where-Object { $_.MissingCount -gt 0 }).Count

Write-Status '[*]' '=== SUMMARY ==='
Write-Host ("  Total analyzed : {0}" -f $valid.Count)
Write-Host ("  Vulnerable     : {0}" -f $vulnCnt)  -ForegroundColor $(if ($vulnCnt -gt 0)  {'Yellow'} else {'Green'})
Write-Host ("  No ASLR        : {0}" -f $noASLR)   -ForegroundColor $(if ($noASLR -gt 0)   {'Red'}    else {'Green'})
Write-Host ("  No DEP         : {0}" -f $noDEP)    -ForegroundColor $(if ($noDEP -gt 0)    {'Red'}    else {'Green'})
Write-Host ("  No CFG         : {0}" -f $noCFG)    -ForegroundColor $(if ($noCFG -gt 0)    {'Yellow'} else {'Green'})
Write-Host ("  No Authenticode: {0}" -f $noAuth)   -ForegroundColor $(if ($noAuth -gt 0)   {'Yellow'} else {'Green'})
Write-Host ("  No SafeSEH     : {0}" -f $noSEH)    -ForegroundColor $(if ($noSEH -gt 0)    {'Yellow'} else {'Green'})
Write-Host ''

# ── CSV export ────────────────────────────────────────────────────────────────
if ($CsvOutput) {
    try {
        $results | Select-Object Name, Arch, ASLR, HighEntropyVA, DEP, ForceIntegrity,
            CFG, SafeSEH, Authenticode, MissingCount, Error, File |
            Export-Csv -Path $CsvOutput -NoTypeInformation -Encoding UTF8
        Write-Status '[+]' "Results saved to: $CsvOutput"
    } catch {
        Write-Status '[-]' "CSV export failed: $($_.Exception.Message)"
    }
}
