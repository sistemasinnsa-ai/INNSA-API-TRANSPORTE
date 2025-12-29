# Nombre único para la regla de firewall
$ruleName = "Bloqueo API automático"

# Crear la regla si no existe
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound -RemoteAddress "0.0.0.0" `
        -Action Block -Protocol TCP -LocalPort 443
}

# Ruta al log
$logPath = "C:\Users\aleja\Downloads\INNSA-API\api.log"
$regex = 'Intento acceso prohibido desde IP: (::ffff:)?(\d{1,3}(\.\d{1,3}){3})'

# Leer IPs detectadas
$ips = @()
$lines = Get-Content $logPath
foreach ($line in $lines) {
    if ($line -match $regex) {
        $ips += $matches[2]
    }
}

# Limpiar IPs
$ipsClean = $ips | ForEach-Object {
    $_.Trim() -replace '^::ffff:', ''
} | Where-Object { $_ -ne '' }

# Quitar duplicados
$ipsClean = $ipsClean | Sort-Object -Unique

# Validar sólo IPs IPv4 válidas
$ipRegex = '^(([0-9]{1,3}\.){3}[0-9]{1,3})$'
$ipsValidas = $ipsClean | Where-Object { $_ -match $ipRegex }

Write-Host "IPs válidas para bloquear:"
$ipsValidas | ForEach-Object { Write-Host "'$_'" }

# Actualizar regla firewall
Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress ($ipsValidas -join ",")
