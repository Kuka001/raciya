# Включает «Планировщик пакетов QoS» на адаптере Ethernet (без него политики QoS не работают)
# и добавляет политику для ZeroTier: именно его пакеты несут голос друзьям по проводу.
# Запускать с правами администратора. Сеть может прерваться на 1-3 секунды.
# Откат: Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_pacer  и  tools\rollback-qos.ps1
$ErrorActionPreference = 'Stop'
"before:"
Get-NetAdapterBinding -ComponentID ms_pacer | Select-Object Name, Enabled | Format-Table -AutoSize | Out-String
Enable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_pacer
Start-Sleep -Seconds 4

Remove-NetQosPolicy -Name 'VoiceChat ZeroTier Voice' -Confirm:$false -ErrorAction SilentlyContinue
New-NetQosPolicy -Name 'VoiceChat ZeroTier Voice' -AppPathNameMatchCondition 'zerotier-one_x64.exe' `
    -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All | Out-Null

"after:"
Get-NetAdapterBinding -ComponentID ms_pacer | Select-Object Name, Enabled | Format-Table -AutoSize | Out-String
Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat*' } |
    Select-Object Name, AppPathNameMatchCondition, DSCPAction | Format-Table -AutoSize | Out-String -Width 200
"ethernet status: $((Get-NetAdapter -Name Ethernet).Status)"
