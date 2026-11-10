# Включает службу брандмауэра Windows и добавляет правила только для Mumble Server (64738 TCP/UDP).
# Запускать с правами администратора. Откат: tools\rollback-firewall.ps1
$exe = "$env:ProgramFiles\Mumble\server\mumble-server.exe"

"--- before ---"
$before = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc').Start
"mpssvc Start = $before"

"--- sc config ---"
sc.exe config mpssvc start= auto
if ($LASTEXITCODE -ne 0) {
    "sc config failed ($LASTEXITCODE), writing registry directly"
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc' -Name Start -Value 2
}
"mpssvc Start = $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc').Start)"

"--- start service ---"
try {
    Start-Service mpssvc -ErrorAction Stop
}
catch {
    "Start-Service failed: $($_.Exception.Message)"
}
Start-Sleep -Seconds 3
Get-Service mpssvc, mpsdrv | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String

if ((Get-Service mpssvc).Status -ne 'Running') {
    "RESULT: service not running yet (reboot required)"
    exit 2
}

"--- enable profiles ---"
Set-NetFirewallProfile -All -Enabled True
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String

"--- rules ---"
Get-NetFirewallRule -DisplayName 'VoiceChat Mumble*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (TCP 64738)' -Group 'VoiceChat' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 64738 -Program $exe -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (UDP 64738)' -Group 'VoiceChat' `
    -Direction Inbound -Action Allow -Protocol UDP -LocalPort 64738 -Program $exe -Profile Any | Out-Null
Get-NetFirewallRule -Group 'VoiceChat' | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize | Out-String
"RESULT: ok"
