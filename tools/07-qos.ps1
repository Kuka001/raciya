# QoS в Windows: помечает голосовой трафик как DSCP EF (46) — у клиента и у сервера.
# Запускать с правами администратора. Откат: tools\rollback-qos.ps1
#
# Важно: метка DSCP даёт эффект только там, где её учитывает оборудование по пути
# (роутер с QoS, Wi-Fi с WMM). Ваш роутер QoS не поддерживает, поэтому это задел на будущее,
# а главный практический эффект дают ограничения фоновых загрузок (tools\game-mode-on.ps1).
$ErrorActionPreference = 'Stop'

# Без этого параметра Windows применяет DSCP из политик только в доменных сетях.
$qosKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS'
if (-not (Test-Path $qosKey)) { New-Item $qosKey -Force | Out-Null }
Set-ItemProperty $qosKey -Name 'Do not use NLA' -Value '1' -Type String

Get-NetQosPolicy -Name 'VoiceChat*' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
foreach ($n in 'VoiceChat Client Voice', 'VoiceChat Server Voice') {
    Remove-NetQosPolicy -Name $n -Confirm:$false -ErrorAction SilentlyContinue
}
New-NetQosPolicy -Name 'VoiceChat Client Voice' -AppPathNameMatchCondition 'raciya.exe' `
    -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All | Out-Null
New-NetQosPolicy -Name 'VoiceChat Server Voice' -AppPathNameMatchCondition 'mumble-server.exe' `
    -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All | Out-Null

Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat*' } |
    Select-Object Name, AppPathNameMatchCondition, IPProtocolMatchCondition, DSCPAction, ThrottleRateAction |
    Format-Table -AutoSize | Out-String -Width 200
"pacer (QoS Packet Scheduler) binding:"
Get-NetAdapterBinding -ComponentID ms_pacer | Select-Object Name, Enabled | Format-Table -AutoSize | Out-String
