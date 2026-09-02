# Monitor de trafico egress - v4.0 HUMAN + TECHNICAL
param([int]$IntervalSeconds = 3)

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$domain = $env:USERDOMAIN
$computerName = $env:COMPUTERNAME
$osInfo = Get-CimInstance Win32_OperatingSystem
$logFile = "C:\Logs\network-egress-v4.log"
$jsonLogFile = "C:\Logs\network-egress-v4.jsonl"
$ipCache = @{}
$processCache = @{}
$signatureCache = @{}
$serviceCache = @{}
$seen = @{}
New-Item -ItemType Directory -Force -Path C:\Logs | Out-Null

function Get-IPInfo {
    param([string]$IP)
    if ($ipCache.ContainsKey($IP)) { return $ipCache[$IP] }
    $info = @{ IP = $IP; Hostname = $null; ProviderHint = $null; Scope = 'No determinado' }
    try {
        $address = [System.Net.IPAddress]::Parse($IP)
        if ($address.IsLoopback) { $info.Scope = 'Loopback' }
        elseif ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $address.IsIPv6LinkLocal) { $info.Scope = 'Link-local' }
        elseif ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and (
                ($bytes = $address.GetAddressBytes()) -and (($bytes[0] -eq 10) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)))) { $info.Scope = 'Privada' }
        elseif ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $address.IsIPv6UniqueLocal) { $info.Scope = 'Privada' }
        else { $info.Scope = 'Internet' }
    }
    catch { }
    try {
        $resolved = ([System.Net.Dns]::GetHostEntry($IP)).HostName -replace '\.$', ''
        if ($resolved -and $resolved -ne $IP) {
            $info.Hostname = $resolved
            if ($resolved -match 'akamaitechnologies') { $info.ProviderHint = 'Akamai' }
            elseif ($resolved -match 'microsoft') { $info.ProviderHint = 'Microsoft' }
            elseif ($resolved -match 'cloudflare') { $info.ProviderHint = 'Cloudflare' }
            elseif ($resolved -match 'google') { $info.ProviderHint = 'Google' }
            elseif ($resolved -match 'amazonaws') { $info.ProviderHint = 'AWS' }
        }
    }
    catch { }
    $ipCache[$IP] = $info
    return $info
}

function Get-ProcessInfo {
    param([int]$ProcessId)
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    $path = if ($process) { $process.ExecutablePath } else { $null }
    $cacheKey = "$ProcessId|$path"
    if ($processCache.ContainsKey($cacheKey)) { return $processCache[$cacheKey] }
    $info = @{ Name = if ($process) { $process.Name } else { 'Proceso no disponible' }; Path = $path; Hash = $null }
    if ($path -and (Test-Path -LiteralPath $path)) {
        try { $info.Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path -ErrorAction Stop).Hash } catch { }
    }
    $processCache[$cacheKey] = $info
    return $info
}

function Get-SignatureInfo {
    param([string]$Path)
    if (-not $Path) { return @{ Status = 'Unknown'; Signer = $null } }
    if ($signatureCache.ContainsKey($Path)) { return $signatureCache[$Path] }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject -replace '^.*?CN=([^,]+).*$', '$1' } else { $null }
        $info = @{ Status = [string]$signature.Status; Signer = $signer }
    }
    catch { $info = @{ Status = 'Unknown'; Signer = $null } }
    $signatureCache[$Path] = $info
    return $info
}

function Get-ServiceInfo {
    param([int]$ProcessId, [string]$Path)
    $cacheKey = "$ProcessId|$Path"
    if ($serviceCache.ContainsKey($cacheKey)) { return $serviceCache[$cacheKey] }
    $services = @(Get-CimInstance Win32_Service -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $value = if ($services.Count) { $services -join ',' } else { $null }
    $serviceCache[$cacheKey] = $value
    return $value
}

function Get-PortService {
    param([int]$Port)
    $ports = @{ 53 = 'DNS'; 80 = 'HTTP'; 443 = 'HTTPS'; 22 = 'SSH'; 25 = 'SMTP'; 3389 = 'RDP'; 445 = 'SMB'; 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS' }
    if ($ports.ContainsKey($Port)) { return $ports[$Port] }
    return 'No identificado'
}

function Get-DisplayValue {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return 'No determinado' }
    return [string]$Value
}

function Get-ConnectionContext {
    param($ProcessInfo, $SignatureInfo, [string]$Service, $IPInfo, [int]$RemotePort)
    $reasons = @()
    $suspiciousPath = $ProcessInfo.Path -match '\\(Users\\Public|AppData\\Local\\Temp|Downloads|Recycle\.Bin)\\'
    $recognized = $ProcessInfo.Name -match '^(svchost|msedge|chrome|Code|MsMpEng|MpDefenderCoreService)\.exe$'
    $signedMicrosoft = $SignatureInfo.Status -eq 'Valid' -and $SignatureInfo.Signer -match 'Microsoft'
    $unusualPort = (Get-PortService $RemotePort) -eq 'No identificado'
    $unknownDestination = -not $IPInfo.ProviderHint -and -not $IPInfo.Hostname
    if ($signedMicrosoft) { $reasons += 'SIGNED_MICROSOFT_BINARY' }
    if ($Service) { $reasons += 'SYSTEM_SERVICE' }
    if ($recognized) { $reasons += 'RECOGNIZED_PROCESS' }
    if ($suspiciousPath) { $reasons += 'SUSPICIOUS_EXECUTABLE_PATH' }
    if ($IPInfo.Scope -eq 'Internet') { $reasons += 'INTERNET_DESTINATION' }
    if ($unusualPort) { $reasons += 'UNUSUAL_PORT' }
    if (-not $unusualPort) { $reasons += "EXPECTED_$((Get-PortService $RemotePort).ToUpper().Replace(' ', '_'))" }
    if ($unknownDestination) { $reasons += 'DESTINATION_NOT_IDENTIFIED' }
    if (-not $recognized -and $suspiciousPath -and $IPInfo.Scope -eq 'Internet' -and $unusualPort) { $risk = 'ALERT'; $label = 'ALERTA' }
    elseif ($suspiciousPath -or $unusualPort -or ($SignatureInfo.Status -in @('NotTrusted', 'HashMismatch', 'Unknown') -and $ProcessInfo.Path)) { $risk = 'REVIEW'; $label = 'REVISAR' }
    else { $risk = 'NORMAL'; $label = 'NORMAL' }
    return @{ Risk = $risk; Label = $label; Reasons = $reasons -join ';'; IdentityKnown = (-not $unknownDestination) }
}

Write-Host "`n========================================================================================================" -ForegroundColor Yellow
Write-Host ' NETWORK EGRESS MONITOR - v4.0 HUMAN + TECHNICAL' -ForegroundColor Cyan
Write-Host "========================================================================================================" -ForegroundColor Yellow
Write-Host " Usuario: $user | Dominio: $domain | Equipo: $computerName" -ForegroundColor Gray
Write-Host " SO: $($osInfo.Caption) $($osInfo.Version) | Log: $logFile | Intervalo: ${IntervalSeconds}s" -ForegroundColor Gray
Write-Host ' Estado: [EJECUTANDO]' -ForegroundColor Green
Write-Host "========================================================================================================`n" -ForegroundColor Yellow

while ($true) {
    try {
        $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notlike '127.0.0.1' })
        foreach ($connection in $connections) {
            $key = "$($connection.OwningProcess)|$($connection.LocalPort)|$($connection.RemoteAddress)|$($connection.RemotePort)"
            if (-not $seen.ContainsKey($key)) {
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
                $processInfo = Get-ProcessInfo $connection.OwningProcess
                $signatureInfo = Get-SignatureInfo $processInfo.Path
                $service = Get-ServiceInfo $connection.OwningProcess $processInfo.Path
                $ipInfo = Get-IPInfo $connection.RemoteAddress
                $expectedService = Get-PortService $connection.RemotePort
                $context = Get-ConnectionContext $processInfo $signatureInfo $service $ipInfo $connection.RemotePort
                $displayPath = Get-DisplayValue $processInfo.Path
                $displaySigner = Get-DisplayValue $signatureInfo.Signer
                $displayService = Get-DisplayValue $service
                $displayHostname = Get-DisplayValue $ipInfo.Hostname
                $displayProviderHint = Get-DisplayValue $ipInfo.ProviderHint
                $color = if ($context.Risk -eq 'ALERT') { 'Red' } elseif ($context.Risk -eq 'REVIEW') { 'Yellow' } else { 'Green' }
                Write-Host "[$($context.Label)] CONEXION SALIENTE" -ForegroundColor $color
                Write-Host "  Proceso: $($processInfo.Name) | PID: $($connection.OwningProcess)" -ForegroundColor Gray
                Write-Host "  Ejecutable: $displayPath" -ForegroundColor Gray
                Write-Host "  Firma: $displaySigner | Estado firma: $($signatureInfo.Status) | Servicios: $displayService" -ForegroundColor Gray
                Write-Host "  Destino: $($connection.RemoteAddress):$($connection.RemotePort) | Protocolo: TCP / $expectedService esperado" -ForegroundColor Gray
                Write-Host "  DNS: $displayHostname | Provider hint: $displayProviderHint | Alcance: $($ipInfo.Scope)" -ForegroundColor Gray
                Write-Host "  Evaluacion: $($context.Risk) | Motivo: $($context.Reasons)" -ForegroundColor Gray
                $hashDisplay = Get-DisplayValue $processInfo.Hash
                $entry = "TIMESTAMP=$timestamp | USER=$user | HOST=$computerName | PROCESS=$($processInfo.Name) | PID=$($connection.OwningProcess) | PATH=$displayPath | SHA256=$hashDisplay | SIGNATURE_STATUS=$($signatureInfo.Status) | SIGNER=$displaySigner | SERVICE=$displayService | LOCAL_ADDRESS=$($connection.LocalAddress) | LOCAL_PORT=$($connection.LocalPort) | REMOTE_ADDRESS=$($connection.RemoteAddress) | REMOTE_PORT=$($connection.RemotePort) | HOSTNAME=$displayHostname | PROVIDER_HINT=$displayProviderHint | SCOPE=$($ipInfo.Scope) | PROTOCOL=TCP | CONTEXT=$($context.Label) | RISK=$($context.Risk) | REASON=$($context.Reasons)"
                Add-Content -Path $logFile -Value $entry
                $jsonEvent = [ordered]@{
                    timestamp   = $timestamp
                    user        = $user
                    host        = $computerName
                    process     = [ordered]@{ name = $processInfo.Name; pid = [int]$connection.OwningProcess; path = $processInfo.Path; sha256 = $processInfo.Hash; signature = [ordered]@{ status = $signatureInfo.Status; signer = $signatureInfo.Signer }; services = $service }
                    network     = [ordered]@{ direction = 'egress'; protocol = 'TCP'; local_address = $connection.LocalAddress; local_port = [int]$connection.LocalPort; remote_ip = $connection.RemoteAddress; remote_port = [int]$connection.RemotePort; expected_service = $expectedService }
                    destination = [ordered]@{ dns = $ipInfo.Hostname; provider_hint = $ipInfo.ProviderHint; scope = $ipInfo.Scope }
                    assessment  = [ordered]@{ context = $context.Label; risk = $context.Risk; reason = @($context.Reasons -split ';' | Where-Object { $_ }) }
                }
                Add-Content -Path $jsonLogFile -Value ($jsonEvent | ConvertTo-Json -Compress -Depth 6)
                $seen[$key] = Get-Date
            }
        }
        foreach ($key in @($seen.Keys)) {
            if (-not ($connections | Where-Object { "$($_.OwningProcess)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)" -eq $key })) { $seen.Remove($key) }
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
        Start-Sleep -Seconds 5
    }
}
