# Monitor de tráfico egress - v3.0 FINAL (WHOIS + CONTEXT)
param([int]$IntervalSeconds = 3)

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$domain = $env:USERDOMAIN
$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
$timestamp_inicio = Get-Date -Format "dd-MMM-yyyy HH:mm:ss"

$logfile = "C:\Logs\network-egress-final.log"
$ipdb = @{}
$seen = @{}

New-Item -ItemType Directory -Force -Path C:\Logs | Out-Null

function Get-IPInfo {
    param([string]$IP)
    if ($ipdb.ContainsKey($IP)) { return $ipdb[$IP] }
    $info = @{ IP = $IP; Hostname = "unknown"; Organization = "unknown" }
    try {
        $hostname = ([System.Net.Dns]::GetHostEntry($IP)).HostName -replace "\.$",""
        if ($hostname -and $hostname -ne $IP) {
            $info.Hostname = $hostname
            if ($hostname -match "akamaitechnologies") { $info.Organization = "Akamai" }
            elseif ($hostname -match "microsoft") { $info.Organization = "Microsoft" }
            elseif ($hostname -match "cloudflare") { $info.Organization = "Cloudflare" }
            elseif ($hostname -match "google") { $info.Organization = "Google" }
            elseif ($hostname -match "amazonaws") { $info.Organization = "AWS" }
        }
    }
    catch { $info.Hostname = "N/A" }
    $ipdb[$IP] = $info
    return $info
}

Write-Host "`n========================================================================================================" -ForegroundColor Yellow
Write-Host " NETWORK EGRESS MONITOR - v3.0 FINAL" -ForegroundColor Cyan
Write-Host "========================================================================================================" -ForegroundColor Yellow
Write-Host " [WHOIAM]" -ForegroundColor Magenta
Write-Host "   Usuario:        $user" -ForegroundColor Gray
Write-Host "   Dominio:        $domain" -ForegroundColor Gray
Write-Host "   Hostname:       $hostname" -ForegroundColor Gray
Write-Host " [SISTEMA]" -ForegroundColor Magenta
Write-Host "   SO:             $os" -ForegroundColor Gray
Write-Host "   Version:        $osVersion" -ForegroundColor Gray
Write-Host "   Inicio Audit:   $timestamp_inicio" -ForegroundColor Gray
Write-Host " [CONFIGURACION]" -ForegroundColor Magenta
Write-Host "   Log:            $logfile" -ForegroundColor Gray
Write-Host "   Intervalo:      ${IntervalSeconds}s" -ForegroundColor Gray
Write-Host "   Estado:         [EJECUTANDO]" -ForegroundColor Green
Write-Host " ========================================================================================================" -ForegroundColor Yellow
Write-Host ""

while ($true) {
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notlike "127.0.0.1" }
        
        foreach ($conn in $conns) {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $seen.ContainsKey($key)) {
                $proc = (Get-Process -Id $conn.OwningProcess -EA SilentlyContinue).ProcessName
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $ipInfo = Get-IPInfo -IP $conn.RemoteAddress
                
                $entry = "$timestamp | USER=$user | PROC=$proc | PID=$($conn.OwningProcess) | LOCAL=$($conn.LocalAddress):$($conn.LocalPort) | REMOTE=$($conn.RemoteAddress):$($conn.RemotePort) | HOSTNAME=$($ipInfo.Hostname) | ORG=$($ipInfo.Organization)"
                Write-Host "[+] $entry" -ForegroundColor Cyan
                Add-Content -Path $logfile -Value $entry
                
                $seen[$key] = @{ Time = Get-Date; Process = $proc; IPInfo = $ipInfo }
            }
        }
        
        $deadKeys = @()
        foreach ($key in $seen.Keys) {
            $stillExists = $conns | Where-Object { "$($_.RemoteAddress):$($_.RemotePort)" -eq $key }
            if (-not $stillExists) { $deadKeys += $key }
        }
        foreach ($key in $deadKeys) { $seen.Remove($key) }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
        Start-Sleep -Seconds 5
    }
}
