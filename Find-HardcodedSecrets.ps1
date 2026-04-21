#Requires -Version 5.0
<#
.SYNOPSIS
    Extrai e classifica segredos hardcoded em binários PE do Windows.
.DESCRIPTION
    Faz extração de strings ASCII e Unicode do binário, aplica ~30 padrões de detecção
    (credenciais, tokens, chaves de API, URLs com auth, connection strings, chaves criptográficas)
    e calcula entropia de Shannon para detectar blobs codificados.
    Reporta cada achado com severidade, seção PE de origem e contexto.
.PARAMETER ExePath
    Caminho do arquivo PE (.exe ou .dll) a analisar.
.PARAMETER MinLength
    Comprimento mínimo de string para análise (padrão: 6).
.PARAMETER MinEntropy
    Limiar de entropia para alertar strings suspeitas (padrão: 4.5, máximo teórico: ~6.0).
.PARAMETER OutputFile
    Exporta resultados em JSON para o caminho especificado.
.PARAMETER ShowAll
    Exibe todas as strings encontradas, não apenas as classificadas como suspeitas.
.EXAMPLE
    .\Find-HardcodedSecrets.ps1 -ExePath "C:\App\app.exe"
    .\Find-HardcodedSecrets.ps1 -ExePath "C:\App\app.dll" -MinEntropy 4.0 -OutputFile "C:\results.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [int]$MinLength  = 6,
    [double]$MinEntropy = 4.5,
    [string]$OutputFile = '',
    [switch]$ShowAll
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

# Shannon entropy of a string (base 2)
function Get-Entropy {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s) -or $s.Length -lt 2) { return 0.0 }
    $freq = @{}
    foreach ($c in $s.ToCharArray()) { $freq[$c] = ($freq[$c] ?? 0) + 1 }
    $e = 0.0
    foreach ($cnt in $freq.Values) {
        $p = $cnt / $s.Length
        $e -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($e, 3)
}

# Build PE section map: list of {Name, Start, End} in raw file offsets
function Get-SectionMap {
    param([byte[]]$Bytes)
    $sections = @()
    try {
        if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $sections }
        $peOff    = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        if ($Bytes[$peOff] -ne 0x50 -or $Bytes[$peOff+1] -ne 0x45) { return $sections }
        $numSec   = [System.BitConverter]::ToUInt16($Bytes, $peOff + 6)
        $optSize  = [System.BitConverter]::ToUInt16($Bytes, $peOff + 20)
        $secBase  = $peOff + 24 + $optSize   # first section header
        for ($i = 0; $i -lt $numSec; $i++) {
            $b       = $secBase + ($i * 40)
            $nameBytes = $Bytes[$b..($b+7)]
            $secName = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd("`0")
            $rawSz   = [System.BitConverter]::ToUInt32($Bytes, $b + 16)
            $rawOff  = [System.BitConverter]::ToUInt32($Bytes, $b + 20)
            if ($rawOff -gt 0 -and $rawSz -gt 0) {
                $sections += [PSCustomObject]@{
                    Name  = $secName
                    Start = [int]$rawOff
                    End   = [int]($rawOff + $rawSz)
                }
            }
        }
    } catch {}
    return $sections
}

# Determine which PE section a file offset belongs to
function Get-SectionForOffset {
    param([int]$Offset, [object[]]$Sections)
    foreach ($s in $Sections) {
        if ($Offset -ge $s.Start -and $Offset -lt $s.End) { return $s.Name }
    }
    return 'HEADER'
}

# Extract ASCII and Unicode strings, return list of {Value, Offset, Encoding}
function Get-AllStrings {
    param([byte[]]$Bytes, [int]$MinLen)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sb      = [System.Text.StringBuilder]::new()
    $start   = 0

    # ASCII
    for ($i = 0; $i -le $Bytes.Length; $i++) {
        $b = if ($i -lt $Bytes.Length) { $Bytes[$i] } else { 0 }
        if ($b -ge 0x20 -and $b -le 0x7E) {
            if ($sb.Length -eq 0) { $start = $i }
            [void]$sb.Append([char]$b)
        } else {
            if ($sb.Length -ge $MinLen) {
                $results.Add([PSCustomObject]@{ Value=$sb.ToString(); Offset=$start; Encoding='ASCII' })
            }
            [void]$sb.Clear()
        }
    }

    # Unicode (LE)
    $i = 0
    while ($i -lt $Bytes.Length - 1) {
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i+1] -eq 0x00) {
            if ($sb.Length -eq 0) { $start = $i }
            [void]$sb.Append([char]$Bytes[$i])
            $i += 2
        } else {
            if ($sb.Length -ge $MinLen) {
                $results.Add([PSCustomObject]@{ Value=$sb.ToString(); Offset=$start; Encoding='Unicode' })
            }
            [void]$sb.Clear()
            $i++
        }
    }

    return $results
}

# Secret detection rules: {Name, Severity, Regex, Description}
function Get-SecretRules {
    return @(
        # ── Credentials ──────────────────────────────────────────────────────
        [PSCustomObject]@{ Severity='CRITICAL'; Name='Private Key';        Regex='-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' }
        [PSCustomObject]@{ Severity='CRITICAL'; Name='Password in URL';    Regex='https?://[^:@\s/]{3,}:[^:@\s/]{3,}@[^\s]{5,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Password field';     Regex='(?i)(password|passwd|pass|pwd)\s*[=:]\s*[^\s&]{4,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Secret field';       Regex='(?i)(secret|client_secret|app_secret)\s*[=:]\s*[^\s&]{4,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Token field';        Regex='(?i)(token|auth_token|access_token|api_token)\s*[=:]\s*[^\s&]{8,}' }
        # ── Cloud provider keys ───────────────────────────────────────────────
        [PSCustomObject]@{ Severity='CRITICAL'; Name='AWS Access Key';     Regex='(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[0-9A-Z]{16}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='AWS Secret Key';     Regex='(?i)aws.{0,20}secret.{0,10}[=:]\s*[A-Za-z0-9/+]{40}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Azure Storage Key';  Regex='AccountKey=[A-Za-z0-9+/]{60,}==' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Azure SAS Token';    Regex='sig=[A-Za-z0-9%]{30,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Azure ConnStr';      Regex='DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=' }
        [PSCustomObject]@{ Severity='HIGH';     Name='GCP API Key';        Regex='AIza[0-9A-Za-z\-_]{35}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='GCP Service Account';Regex='"type"\s*:\s*"service_account"' }
        # ── Tokens / Auth ─────────────────────────────────────────────────────
        [PSCustomObject]@{ Severity='HIGH';     Name='JWT Token';          Regex='eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}' }
        [PSCustomObject]@{ Severity='MEDIUM';   Name='Bearer Token';       Regex='(?i)Bearer\s+[A-Za-z0-9\-_\.]{20,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='GitHub Token';       Regex='gh[pousr]_[A-Za-z0-9]{36}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Slack Token';        Regex='xox[baprs]-[0-9A-Za-z\-]{10,}' }
        [PSCustomObject]@{ Severity='MEDIUM';   Name='Generic API Key';    Regex='(?i)api[_-]?key\s*[=:]\s*[A-Za-z0-9\-_]{16,}' }
        # ── Database / Connection strings ─────────────────────────────────────
        [PSCustomObject]@{ Severity='HIGH';     Name='DB ConnectionStr';   Regex='(?i)(Server|Data Source)=[^;]{3,};.*?(Password|PWD)=[^;]{3,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='MongoDB URI';        Regex='mongodb(\+srv)?://[^:@\s]{3,}:[^:@\s]{3,}@[^\s]{5,}' }
        [PSCustomObject]@{ Severity='HIGH';     Name='Redis URL with auth'; Regex='redis://:[^@\s]{4,}@[^\s]{5,}' }
        # ── Cryptographic material ────────────────────────────────────────────
        [PSCustomObject]@{ Severity='HIGH';     Name='Base64 blob (≥64B)'; Regex='[A-Za-z0-9+/]{64,}={0,2}' }
        [PSCustomObject]@{ Severity='MEDIUM';   Name='Hex key (≥32B)';    Regex='[0-9A-Fa-f]{64,}' }
        [PSCustomObject]@{ Severity='MEDIUM';   Name='PEM Certificate';    Regex='-----BEGIN CERTIFICATE-----' }
        # ── Windows / network specifics ───────────────────────────────────────
        [PSCustomObject]@{ Severity='LOW';      Name='Windows cred path';  Regex='(?i)C:\\Users\\[^\\]{3,}\\(AppData|Desktop|Documents)' }
        [PSCustomObject]@{ Severity='MEDIUM';   Name='UNC with creds';     Regex='\\\\[^\\]{3,}\\[^\\]{3,}\\.*password' }
        [PSCustomObject]@{ Severity='LOW';      Name='Internal IP:port';   Regex='(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+:\d{2,5}' }
        [PSCustomObject]@{ Severity='LOW';      Name='Hardcoded localhost', Regex='(?i)(http://localhost|127\.0\.0\.1):\d{2,5}/[^\s]{5,}' }
    )
}

# ── Main ──────────────────────────────────────────────────────────────────────

if (-not (Test-Path $ExePath)) {
    Write-Status '[-]' "File not found: $ExePath"; exit 1
}

Write-Status '[*]' '=== HARDCODED SECRETS SCAN ==='
Write-Status '[*]' "Target  : $ExePath"
Write-Status '[*]' "MinLen  : $MinLength chars | Entropy threshold: $MinEntropy"
Write-Host ''

$bytes    = [System.IO.File]::ReadAllBytes($ExePath)
$sections = Get-SectionMap -Bytes $bytes
$rules    = Get-SecretRules

Write-Status '[*]' "File size: $([Math]::Round($bytes.Length/1KB,1)) KB | Sections: $($sections.Count)"
Write-Status '[*]' 'Extracting strings...'

$allStrings = Get-AllStrings -Bytes $bytes -MinLen $MinLength
Write-Status '[*]' "Strings found: $($allStrings.Count) (ASCII + Unicode)"
Write-Host ''

# ── Apply detection rules ─────────────────────────────────────────────────────
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$seen     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

foreach ($str in $allStrings) {
    $section  = Get-SectionForOffset -Offset $str.Offset -Sections $sections
    $entropy  = Get-Entropy -s $str.Value
    $matched  = $false

    foreach ($rule in $rules) {
        if ($str.Value -match $rule.Regex) {
            $key = "$($rule.Name)|$($str.Value)"
            if ($seen.Contains($key)) { continue }
            [void]$seen.Add($key)
            $matched = $true
            $findings.Add([PSCustomObject]@{
                Severity = $rule.Severity
                Type     = $rule.Name
                Value    = $str.Value
                Section  = $section
                Offset   = '0x{0:X}' -f $str.Offset
                Encoding = $str.Encoding
                Entropy  = $entropy
            })
        }
    }

    # High-entropy strings not matched by named rules (possible encoded keys/tokens)
    if (-not $matched -and $entropy -ge $MinEntropy -and $str.Value.Length -ge 20) {
        $key = "ENTROPY|$($str.Value)"
        if (-not $seen.Contains($key)) {
            [void]$seen.Add($key)
            $findings.Add([PSCustomObject]@{
                Severity = 'MEDIUM'
                Type     = "High Entropy ($entropy)"
                Value    = $str.Value
                Section  = $section
                Offset   = '0x{0:X}' -f $str.Offset
                Encoding = $str.Encoding
                Entropy  = $entropy
            })
        }
    }
}

# ── Display results ───────────────────────────────────────────────────────────
$order    = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3 }
$sorted   = $findings | Sort-Object { $order[$_.Severity] }, Type

if ($sorted.Count -eq 0) {
    Write-Status '[+]' 'No secrets or high-entropy strings detected'
    exit 0
}

$sevColors = @{ CRITICAL='Red'; HIGH='Red'; MEDIUM='Yellow'; LOW='DarkYellow' }
$groups    = $sorted | Group-Object Severity | Sort-Object { $order[$_.Name] }

foreach ($grp in $groups) {
    $col = $sevColors[$grp.Name]
    Write-Host ("── [{0}] {1} finding(s) ──" -f $grp.Name, $grp.Count) -ForegroundColor $col
    Write-Host ''
    foreach ($f in $grp.Group) {
        Write-Host ("  Type    : {0}" -f $f.Type)     -ForegroundColor $col
        Write-Host ("  Value   : {0}" -f $(if ($f.Value.Length -gt 120) { $f.Value.Substring(0,117)+'...' } else { $f.Value })) -ForegroundColor White
        Write-Host ("  Section : {0} | Offset: {1} | {2} | Entropy: {3}" -f $f.Section, $f.Offset, $f.Encoding, $f.Entropy) -ForegroundColor DarkGray
        Write-Host ''
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Status '[*]' '=== SUMMARY ==='
foreach ($grp in $groups) {
    $col  = $sevColors[$grp.Name]
    $line = "  {0,-8}: {1}" -f $grp.Name, $grp.Count
    Write-Host $line -ForegroundColor $col
}
Write-Host ''

# ── JSON export ───────────────────────────────────────────────────────────────
if ($OutputFile -ne '') {
    try {
        $sorted | ConvertTo-Json -Depth 3 |
            [System.IO.File]::WriteAllText($OutputFile, [System.Text.Encoding]::UTF8)
        Write-Status '[+]' "Results saved to: $OutputFile"
    } catch {
        Write-Status '[-]' "JSON export failed: $($_.Exception.Message)"
    }
}
