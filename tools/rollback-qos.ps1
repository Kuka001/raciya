# Откат QoS: удаляет все политики VoiceChat (метки DSCP, приоритет игр, ограничения загрузок)
# и параметр 'Do not use NLA'. Запускать с правами администратора.
Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat*' } | ForEach-Object {
    Remove-NetQosPolicy -Name $_.Name -Confirm:$false
    "removed: $($_.Name)"
}
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -Name 'Do not use NLA' -ErrorAction SilentlyContinue
# До начала работ «Планировщик пакетов QoS» на Ethernet был отключён — возвращаем как было.
# Сеть может прерваться на 1-3 секунды.
Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_pacer -ErrorAction SilentlyContinue
"done"
