#Requires -Version 5.0
<#
.SYNOPSIS
    Monitora named pipes criados por um processo e avalia vulnerabilidade de impersonation.
.DESCRIPTION
    Executa o alvo e compara o namespace de named pipes antes e depois, identificando
    novos pipes criados pelo processo. Para cada pipe detectado:
    - Verifica permissão de conexão para o usuário atual (low-priv)
    - Avalia ACL se acessível
    - Tenta conexão como cliente (confirma acesso)
    - Detecta padrão de ImpersonateNamedPipeClient nos imports do servidor
    Um pipe criado por processo elevado com ACL "Everyone: Connect" =
    vetor direto de token theft por impersonation.
.PARAMETER ExePath
    Caminho do executável alvo.
.PARAMETER ScanSeconds
    Tempo de monitoramento em segundos após iniciar o processo (padrão: 15).
.PARAMETER JsonOutput
    Exporta resultado estruturado em JSON para uso pelo orquestrador.
.EXAMPLE
    .\Check-NamedPipes.ps1 -ExePath "C:\Program Files\App\service.exe"
    .\Check-NamedPipes.ps1 -ExePath "C:\App\app.exe" -ScanSeconds 30 -JsonOutput "C:\report\pipes.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [int]$ScanSeconds = 15,
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

# P/Invoke for named pipe operations
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class NamedPipeOps {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSec, uint dwCreation, uint dwFlags, IntPtr hTemplate);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool WaitNamedPipe(string lpNamedPipeName, uint nTimeOut);

    const uint GENERIC_READ    = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING   = 3;
    const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    // Try to open pipe for read — returns true if accessible
    public static bool CanConnect(string pipeName) {
        string path = @"\\.\pipe\" + pipeName.TrimStart('\\').Replace(@"\\.\pipe\","");
        try {
            if (!WaitNamedPipe(path, 50)) return false;
            IntPtr h = CreateFile(path, GENERIC_READ, FILE_SHARE_READ,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
            if (h == INVALID_HANDLE) return false;
            CloseHandle(h);
            return true;
        } catch { return false; }
    }
}
'@ -ErrorAction SilentlyContinue

function Get-AllNamedPipes {
    $pipes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $items = [System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($p in $items) {
            $name = [System.IO.Path]::GetFileName($p)
            [void]$pipes.Add($name)
        }
    } catch {}
    # Fallback: WMI
    if ($pipes.Count -eq 0) {
        try {
            Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | ForEach-Object {
                [void]$pipes.Add($_.Name)
            }
        } catch {}
    }
    return $pipes
}

function Get-PipeACL {
    param([string]$PipeName)
    try {
        $acl = Get-Acl -Path "\\.\pipe\$PipeName" -ErrorAction SilentlyContinue
        if ($acl) {
            return $acl.AccessToString
        }
    } catch {}
    return $null
}

function Test-PipeConnectable {
    param([string]$PipeName)
    try {
        return [NamedPipeOps]::CanConnect($PipeName)
    } catch {
        # Fallback using .NET NamedPipeClientStream
        try {
            $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName,
                [System.IO.Pipes.PipeDirection]::In,
                [System.IO.Pipes.PipeOptions]::None)
            $client.Connect(100)
            $client.Close()
            return $true
        } catch { return $false }
    }
}

function Test-PipeImpersonationRisk {
    param([string]$PipeName, [bool]$IsConnectable, [string]$ACLText)
    # High risk: connectable by low-priv user
    if (-not $IsConnectable) { return @{ Risk='LOW'; Reason='Not connectable by current user' } }

    # Check ACL for Everyone / Authenticated Users / INTERACTIVE
    $broadAccess = $false
    if ($ACLText) {
        $broadAccess = ($ACLText -match 'Everyone|Authenticated Users|INTERACTIVE|NT AUTHORITY\\Everyone') -and
                       ($ACLText -match 'Allow.*?(FullControl|ReadWrite|Write)')
    }

    if ($broadAccess) {
        return @{ Risk='CRITICAL'; Reason='Connectable by Everyone with write access — impersonation vector if server calls ImpersonateNamedPipeClient' }
    }
    return @{ Risk='MEDIUM'; Reason='Connectable by current user — evaluate if server process is elevated' }
}

function Get-ImportsContainImpersonate {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peOff   = [System.BitConverter]::ToInt32($bytes, 0x3C)
        $magic   = [System.BitConverter]::ToUInt16($bytes, $peOff + 24)
        $is64    = ($magic -eq 0x020B)
        $numSec  = [System.BitConverter]::ToUInt16($bytes, $peOff + 6)
        $optSize = [System.BitConverter]::ToUInt16($bytes, $peOff + 20)
        $optOff  = $peOff + 24
        $secBase = $optOff + $optSize
        $ddBase  = if ($is64) { $optOff + 112 } else { $optOff + 96 }

        # Quick string scan for ImpersonateNamedPipeClient
        $pattern = [System.Text.Encoding]::ASCII.GetBytes('ImpersonateNamedPipeClient')
        $str = [System.Text.Encoding]::ASCII.GetString($bytes)
        return $str.Contains('ImpersonateNamedPipeClient')
    } catch { return $false }
}

# ── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) { Write-Status '[-]' "Not found: $ExePath"; exit 1 }

Write-Status '[*]' '=== NAMED PIPE SECURITY ANALYSIS ==='
Write-Status '[*]' "Target: $ExePath"
Write-Host ''

# Check if target binary itself uses impersonation
$usesImpersonation = Get-ImportsContainImpersonate -FilePath $ExePath
if ($usesImpersonation) {
    Write-Status '[!]' "Target binary imports ImpersonateNamedPipeClient — is a pipe server that impersonates clients"
    Write-Host ''
}

# Snapshot before
Write-Status '[*]' 'Taking pre-launch pipe snapshot...'
$pipesBefore = Get-AllNamedPipes
Write-Status '[*]' "Existing pipes: $($pipesBefore.Count)"

# Launch process
Write-Status '[*]' "Launching target for ${ScanSeconds}s..."
$proc = $null
try { $proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction Stop } catch {
    Write-Status '[-]' "Failed to launch: $($_.Exception.Message)"; exit 1
}
Write-Status '[*]' "PID: $($proc.Id)"

# Wait and collect pipes at intervals
$allNewPipes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$elapsed = 0
$interval = 2
while ($elapsed -lt $ScanSeconds) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    $current = Get-AllNamedPipes
    foreach ($p in $current) {
        if (-not $pipesBefore.Contains($p)) { [void]$allNewPipes.Add($p) }
    }
    Write-Host "  [$elapsed/${ScanSeconds}s] New pipes detected: $($allNewPipes.Count)" -ForegroundColor DarkGray
}

# Stop process
if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch {} }

Write-Host ''
Write-Status '[*]' "New pipes created during run: $($allNewPipes.Count)"
Write-Host ''

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$riskOrder = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; NONE=0 }
$overallRisk = 'NONE'

if ($allNewPipes.Count -eq 0) {
    Write-Status '[+]' 'No new named pipes detected during scan window'
    Write-Status '[!]' 'Try increasing -ScanSeconds or interact with the application'
} else {
    Write-Status '[*]' '=== PIPE ANALYSIS ==='
    Write-Host ''

    foreach ($pipeName in $allNewPipes) {
        $connectable = Test-PipeConnectable -PipeName $pipeName
        $aclText     = Get-PipeACL -PipeName $pipeName
        $riskInfo    = Test-PipeImpersonationRisk -PipeName $pipeName -IsConnectable $connectable -ACLText $aclText
        $risk        = $riskInfo.Risk

        $col = switch ($risk) { 'CRITICAL'{'Red'} 'MEDIUM'{'Yellow'} default{'Green'} }
        Write-Host ("  [$risk] \\.\pipe\$pipeName") -ForegroundColor $col
        Write-Host ("         Connectable : $connectable") -ForegroundColor White
        if ($aclText) { Write-Host ("         ACL         : $($aclText -replace '\n',' | ')") -ForegroundColor DarkGray }
        Write-Host ("         Assessment  : $($riskInfo.Reason)") -ForegroundColor $col
        Write-Host ''

        if ($riskOrder[$risk] -gt $riskOrder[$overallRisk]) { $overallRisk = $risk }

        $findings.Add([PSCustomObject]@{
            PipeName    = $pipeName
            Connectable = $connectable
            ACL         = $aclText
            Risk        = $risk
            Reason      = $riskInfo.Reason
        })
    }

    # Escalation path if impersonation is used
    if ($usesImpersonation -and ($findings | Where-Object { $_.Risk -in @('CRITICAL','MEDIUM') })) {
        Write-Status '[-]' '[CRITICAL] Server uses ImpersonateNamedPipeClient + pipe accessible by low-priv user'
        Write-Status '[-]' '           → Connect as low-priv client → server impersonates → token with server privileges'
        Write-Status '[-]' '           Tools: pipePotato, PrintSpoofer pattern, or custom ImpersonatePipe PoC'
    }
}

Write-Host ''
Write-Status '[*]' "Overall Risk: $overallRisk"

if ($JsonOutput -ne '') {
    $json = [PSCustomObject]@{
        Script             = 'Check-NamedPipes'
        Target             = $ExePath
        Timestamp          = (Get-Date -Format 'o')
        RiskLevel          = $overallRisk
        UsesImpersonation  = $usesImpersonation
        NewPipesDetected   = $allNewPipes.Count
        Findings           = @($findings)
    }
    $json | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOutput -Encoding UTF8
    Write-Status '[+]' "JSON saved: $JsonOutput"
}
