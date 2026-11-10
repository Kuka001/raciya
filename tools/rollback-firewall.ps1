# Откат: удаляет правила VoiceChat и возвращает брандмауэр Windows в прежнее состояние
# (служба отключена, все профили выключены — так было до начала работ).
# Запускать с правами администратора.
Get-NetFirewallRule -Group 'VoiceChat' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Set-NetFirewallProfile -All -Enabled False
Stop-Service mpssvc -Force -ErrorAction SilentlyContinue
sc.exe config mpssvc start= disabled
if ($LASTEXITCODE -ne 0) {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc' -Name Start -Value 4
}
"mpssvc Start = $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc').Start) (4 = disabled). Reboot to apply fully."
