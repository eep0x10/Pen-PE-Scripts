#Requires -Version 5.0
<#
.SYNOPSIS
    Extrai e analisa o manifesto embutido em um PE para detectar vetores de escalada de privilégio.
.DESCRIPTION
    Navega o resource directory do PE, extrai o manifesto XML (RT_MANIFEST, tipo 24),
    e analisa:
    - requestedExecutionLevel: nível de elevação requerido
    - autoElevate: binários COM autoelevados (vetor de UAC bypass)
    - uiAccess: acesso a processos elevados sem UAC
    - Supported OS list: versões de Windows suportadas
    - DPI awareness: indicador de aplicação moderna
    Binários com autoElevate=true que carregam DLLs de caminhos graváveis
    são candidatos a UAC bypass sem exploração adicional.
.PARAMETER ExePath
    Caminho do arquivo PE.
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Check-ManifestPrivileges.ps1 -ExePath "C:\Windows\System32\fodhelper.exe"
    .\Check-ManifestPrivileges.ps1 -ExePath "C:\App\app.exe" -JsonOutput "C:\report\manifest.json"
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

# ── PE Resource directory parser ──────────────────────────────────────────────
function Get-EmbeddedManifest {
    param([byte[]]$Bytes)

    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $null }
        $peOff   = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $magic   = [System.BitConverter]::ToUInt16($Bytes, $peOff + 24)
        $is64    = ($magic -eq 0x020B)
        $numSec  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $optOff  = $peOff + 24
        $secBase = $optOff + $optSize
        $ddBase  = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        $rva2off = { param([uint32]$r)
            for ($s = 0; $s -lt $numSec; $s++) {
                $b   = $secBase + ($s * 40)
                $vsz = [System.BitConverter]::ToUInt32($Bytes, $b + 8)
                $va  = [System.BitConverter]::ToUInt32($Bytes, $b + 12)
                $raw = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
                if ($r -ge $va -and $r -lt ($va + $vsz)) { return [int]($raw + ($r - $va)) }
            }; return 0 }

        # Resource Directory = DataDirectory[2]
        $rsrcRVA = [System.BitConverter]::ToUInt32($Bytes, $ddBase + (2 * 8))
        if ($rsrcRVA -eq 0) { return $null }
        $rsrcOff = & $rva2off $rsrcRVA
        if ($rsrcOff -eq 0) { return $null }

        # IMAGE_RESOURCE_DIRECTORY: 16 bytes header
        # Named entries: Characteristics(4) + TimeDateStamp(4) + Major(2) + Minor(2) + NamedCount(2) + IdCount(2)
        # Then: NamedCount + IdCount entries of 8 bytes each
        #   Entry: NameOffset(4, high bit = named) + DataEntryOffset(4, high bit = subdir)

        # Walk level 1: find type RT_MANIFEST = 24 = 0x18
        $readResDir = {
            param([int]$dirOff)
            $namedCnt = [System.BitConverter]::ToUInt16($Bytes, $dirOff + 12)
            $idCnt    = [System.BitConverter]::ToUInt16($Bytes, $dirOff + 14)
            $entries  = @()
            $eBase    = $dirOff + 16
            for ($i = 0; $i -lt ($namedCnt + $idCnt); $i++) {
                $eOff  = $eBase + ($i * 8)
                $nameV = [System.BitConverter]::ToUInt32($Bytes, $eOff)
                $dataV = [System.BitConverter]::ToUInt32($Bytes, $eOff + 4)
                $entries += [PSCustomObject]@{
                    IsNamed  = ($nameV -band 0x80000000) -ne 0
                    Id       = $nameV -band 0x7FFFFFFF
                    IsSubDir = ($dataV -band 0x80000000) -ne 0
                    Offset   = [int]($dataV -band 0x7FFFFFFF)
                }
            }
            return $entries
        }

        # Level 1: type directory
        $l1Entries = & $readResDir $rsrcOff
        $manifestType = $l1Entries | Where-Object { -not $_.IsNamed -and $_.Id -eq 24 }  # RT_MANIFEST = 24
        if (-not $manifestType) { return $null }

        # Level 2: name/id directory (ID 1 = app manifest, ID 2 = DLL manifest)
        $l2Off     = $rsrcOff + $manifestType.Offset
        $l2Entries = & $readResDir $l2Off
        $manifestId = $l2Entries | Where-Object { -not $_.IsNamed -and ($_.Id -eq 1 -or $_.Id -eq 2) } | Select-Object -First 1
        if (-not $manifestId) { $manifestId = $l2Entries | Select-Object -First 1 }
        if (-not $manifestId) { return $null }

        # Level 3: language directory
        $l3Off     = $rsrcOff + $manifestId.Offset
        $l3Entries = & $readResDir $l3Off
        $langEntry = $l3Entries | Select-Object -First 1
        if (-not $langEntry) { return $null }

        # Data entry: RVA(4) + Size(4) + CodePage(4) + Reserved(4)
        $dataEntryOff = $rsrcOff + $langEntry.Offset
        $dataRVA  = [System.BitConverter]::ToUInt32($Bytes, $dataEntryOff)
        $dataSize = [System.BitConverter]::ToUInt32($Bytes, $dataEntryOff + 4)
        $dataOff  = & $rva2off $dataRVA
        if ($dataOff -eq 0 -or $dataSize -eq 0) { return $null }

        # Extract manifest bytes (try UTF-8 first, fall back to UTF-16 LE)
        $manifestBytes = $Bytes[$dataOff..([int]($dataOff + $dataSize) - 1)]
        try {
            # Check for UTF-16 BOM or XML declaration with encoding="UTF-16"
            if ($manifestBytes.Length -ge 2 -and $manifestBytes[0] -eq 0xFF -and $manifestBytes[1] -eq 0xFE) {
                return [System.Text.Encoding]::Unicode.GetString($manifestBytes)
            }
            $text = [System.Text.Encoding]::UTF8.GetString($manifestBytes)
            if ($text.TrimStart()[0] -eq '<') { return $text }
            return [System.Text.Encoding]::Unicode.GetString($manifestBytes)
        } catch {
            return [System.Text.Encoding]::ASCII.GetString($manifestBytes)
        }
    } catch { return $null }
}

# ── Known autoElevate binaries (for cross-reference) ─────────────────────────
$knownAutoElevate = @(
    'fodhelper.exe','eventvwr.exe','computerdefaults.exe','sdclt.exe','slui.exe',
    'wscript.exe','cscript.exe','mmc.exe','wusa.exe','pkgmgr.exe','cliconfg.exe',
    'msconfig.exe','sysprep.exe','oobe.exe','wsreset.exe','inetmgr.exe'
)

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "Not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== MANIFEST PRIVILEGES ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

$bytes       = [System.IO.File]::ReadAllBytes($ExePath)
$exeName     = [System.IO.Path]::GetFileName($ExePath)
$manifestXml = Get-EmbeddedManifest -Bytes $bytes

$result = [PSCustomObject]@{
    Script               = 'Check-ManifestPrivileges'
    Target               = $ExePath
    Timestamp            = (Get-Date -Format 'o')
    RiskLevel            = 'NONE'
    ManifestFound        = $false
    ExecutionLevel       = 'unknown'
    AutoElevate          = $false
    UIAccess             = $false
    IsKnownAutoElevate   = $false
    SupportedOS          = @()
    ManifestRaw          = ''
    Findings             = @()
}

if (-not $manifestXml) {
    Write-Status '[!]' 'No embedded manifest found'
    Write-Status '[!]' 'Binary runs as invoker by default (no explicit elevation)'
    $result.RiskLevel = 'LOW'
} else {
    $result.ManifestFound = $true
    $result.ManifestRaw   = $manifestXml

    Write-Status '[+]' 'Manifest extracted successfully'
    Write-Host ''

    try {
        [xml]$xml = $manifestXml
        $ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
        $ns.AddNamespace('asm', 'urn:schemas-microsoft-com:asm.v1')
        $ns.AddNamespace('asm3','urn:schemas-microsoft-com:asm.v3')
        $ns.AddNamespace('win','http://schemas.microsoft.com/SMI/2005/WindowsSettings')

        # requestedExecutionLevel
        $trustNode = $xml.SelectSingleNode('//asm3:requestedExecutionLevel', $ns)
        if (-not $trustNode) { $trustNode = $xml.SelectSingleNode('//*[local-name()="requestedExecutionLevel"]') }
        if ($trustNode) {
            $result.ExecutionLevel = $trustNode.GetAttribute('level')
            $uiAccessAttr          = $trustNode.GetAttribute('uiAccess')
            $result.UIAccess       = ($uiAccessAttr -eq 'true')
        }

        # autoElevate
        $autoNode = $xml.SelectSingleNode('//*[local-name()="autoElevate"]')
        if ($autoNode) {
            $result.AutoElevate = ($autoNode.InnerText.Trim().ToLower() -eq 'true')
        }
        # Also check as attribute
        if (-not $result.AutoElevate) {
            $result.AutoElevate = ($manifestXml -match '(?i)autoElevate\s*[=:]\s*["\']?true')
        }

        # Supported OS
        $osNodes = $xml.SelectNodes('//*[local-name()="supportedOS"]')
        foreach ($osNode in $osNodes) {
            $id = $osNode.GetAttribute('Id')
            $osName = switch ($id) {
                '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}' { 'Windows 10/11' }
                '{1f676c76-80e1-4239-95bb-83d0f6d0da78}' { 'Windows 8.1'   }
                '{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}' { 'Windows 8'     }
                '{35138b9a-5d96-4fbd-8e2d-a2440225f93a}' { 'Windows 7'     }
                '{e2011457-1546-43c5-a5fe-008deee3d3f0}' { 'Windows Vista' }
                default { $id }
            }
            $result.SupportedOS += $osName
        }
    } catch {
        # Fallback: regex parsing if XML is malformed
        if ($manifestXml -match 'level\s*=\s*["\']([^"\']+)["\']') { $result.ExecutionLevel = $Matches[1] }
        $result.AutoElevate = ($manifestXml -imatch 'autoElevate[^>]*true')
        $result.UIAccess    = ($manifestXml -imatch 'uiAccess[^>]*true')
    }

    # ── Report findings ───────────────────────────────────────────────────────
    $col = switch ($result.ExecutionLevel) {
        'requireAdministrator' { 'Red'    }
        'highestAvailable'     { 'Yellow' }
        'asInvoker'            { 'Green'  }
        default                { 'White'  }
    }
    Write-Host ("  Execution Level : {0}" -f $result.ExecutionLevel) -ForegroundColor $col
    Write-Host ("  autoElevate     : {0}" -f $result.AutoElevate)    -ForegroundColor $(if($result.AutoElevate){'Red'}else{'Green'})
    Write-Host ("  uiAccess        : {0}" -f $result.UIAccess)       -ForegroundColor $(if($result.UIAccess){'Red'}else{'Green'})
    if ($result.SupportedOS.Count -gt 0) {
        Write-Host ("  Supported OS    : {0}" -f ($result.SupportedOS -join ', ')) -ForegroundColor White
    }
    Write-Host ''

    # Check against known autoelevate list
    $result.IsKnownAutoElevate = $knownAutoElevate -contains $exeName.ToLower()
    if ($result.IsKnownAutoElevate) {
        Write-Status '[-]' "[CRITICAL] '$exeName' is a KNOWN autoElevate binary — classic UAC bypass target"
    }

    # Risk assessment
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($result.AutoElevate -and $result.ExecutionLevel -eq 'requireAdministrator') {
        Write-Status '[-]' '[CRITICAL] autoElevate=true + requireAdministrator — elevates silently without UAC prompt'
        Write-Status '[-]' '           Attack: plant DLL in writable dir loaded by this binary → instant admin shell'
        $findings.Add([PSCustomObject]@{ Severity='CRITICAL'; Category='UAC Bypass'; Detail='autoElevate=true + requireAdministrator: silent elevation, combine with DLL hijacking for immediate admin access' })
        $result.RiskLevel = 'CRITICAL'
    } elseif ($result.AutoElevate) {
        Write-Status '[-]' '[HIGH] autoElevate=true — elevates without UAC prompt, potential bypass vector'
        $findings.Add([PSCustomObject]@{ Severity='HIGH'; Category='UAC Bypass'; Detail='autoElevate=true: can be used as UAC bypass carrier via DLL sideloading or registry hijacking' })
        $result.RiskLevel = 'HIGH'
    } elseif ($result.ExecutionLevel -eq 'requireAdministrator') {
        Write-Status '[!]' '[MEDIUM] requireAdministrator — shows UAC prompt, but autoElevate may be forced via COM'
        $findings.Add([PSCustomObject]@{ Severity='MEDIUM'; Category='Elevation Required'; Detail='requireAdministrator: standard UAC prompt, evaluate COM autoelevation paths' })
        $result.RiskLevel = 'MEDIUM'
    } elseif ($result.ExecutionLevel -eq 'highestAvailable') {
        Write-Status '[!]' '[LOW] highestAvailable — elevates if running as admin, may be bypassed via token manipulation'
        $findings.Add([PSCustomObject]@{ Severity='LOW'; Category='Conditional Elevation'; Detail='highestAvailable: elevates only if user is admin — evaluate token impersonation paths' })
        $result.RiskLevel = 'LOW'
    } else {
        Write-Status '[+]' '[OK] asInvoker or no manifest — no automatic elevation'
        $result.RiskLevel = 'NONE'
    }

    if ($result.UIAccess) {
        Write-Status '[-]' '[HIGH] uiAccess=true — can inject keyboard/mouse input into elevated processes (accessibility bypass)'
        $findings.Add([PSCustomObject]@{ Severity='HIGH'; Category='UI Access'; Detail='uiAccess=true: can interact with elevated windows, useful for privilege escalation via UI injection' })
        if ($riskOrder[$result.RiskLevel] -lt 3) { $result.RiskLevel = 'HIGH' }
    }

    $result.Findings = @($findings)
}

Write-Host ''
Write-Status '[*]' "Risk Level: $($result.RiskLevel)"
Write-Host ''

if ($JsonOutput -ne '') {
    $result | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}

$riskOrder = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }
