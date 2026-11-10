# Завершает включение брандмауэра после перезагрузки: включает профили и добавляет правила
# только для Mumble Server (64738 TCP/UDP), затем удаляет одноразовую задачу, которая его запустила.
# Запускается автоматически при старте Windows (задача 'VoiceChat Firewall Finish') либо вручную от администратора.
$log = 'C:\MyProjects\project1\tools\firewall-finish.log'
$exe = "$env:ProgramFiles\Mumble\server\mumble-server.exe"
function Log($m) { "$(Get-Date -Format s) $m" | Out-File -Append -Encoding utf8 $log }

Log 'start'
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    if ((Get-Service mpssvc).Status -eq 'Running') { $ok = $true; break }
    try { Start-Service mpssvc -ErrorAction Stop } catch { }
    Start-Sleep -Seconds 4
}
if (-not $ok) {
    Log 'mpssvc is not running - nothing changed'
    exit 2
}

try {
    Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
    Get-NetFirewallRule -Group 'VoiceChat' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (TCP 64738)' -Group 'VoiceChat' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 64738 -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (UDP 64738)' -Group 'VoiceChat' `
        -Direction Inbound -Action Allow -Protocol UDP -LocalPort 64738 -Profile Any -ErrorAction Stop | Out-Null
    # Ответ на ping нужен, чтобы друзья могли измерить задержку до сервера.
    New-NetFirewallRule -DisplayName 'VoiceChat ping (ICMPv4 echo)' -Group 'VoiceChat' `
        -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any -ErrorAction Stop | Out-Null
    # ZeroTier: входящий UDP нужен для прямых соединений с друзьями (без ретранслятора).
    $zt = 'C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe'
    if (Test-Path $zt) {
        New-NetFirewallRule -DisplayName 'VoiceChat ZeroTier (UDP)' -Group 'VoiceChat' `
            -Direction Inbound -Action Allow -Protocol UDP -Program $zt -Profile Any -ErrorAction Stop | Out-Null
    }
    Log ('profiles: ' + ((Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ' '))
    Log ('rules: ' + ((Get-NetFirewallRule -Group 'VoiceChat' | ForEach-Object { $_.DisplayName }) -join '; '))
    Unregister-ScheduledTask -TaskName 'VoiceChat Firewall Finish' -Confirm:$false -ErrorAction SilentlyContinue
    Log 'done'
}
catch {
    Log "error: $($_.Exception.Message)"
    exit 1
}
