# Выключает «игровой режим» сети: снимает ограничения с фоновых загрузчиков и Центра обновления.
# Запускать с правами администратора.
Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat Limit *' } | ForEach-Object {
    Remove-NetQosPolicy -Name $_.Name -Confirm:$false
}
$do = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
foreach ($v in 'DODownloadMode', 'DOPercentageMaxBackgroundBandwidth', 'DOPercentageMaxForegroundBandwidth') {
    Remove-ItemProperty $do -Name $v -ErrorAction SilentlyContinue
}
"game mode OFF: limits removed"
