# «Игровой режим» для сети: на время игры ограничивает скорость фоновых загрузчиков,
# чтобы они не занимали канал и не поднимали пинг. Запускать с правами администратора.
# Вернуть как было: tools\game-mode-off.ps1
#
#   .\tools\game-mode-on.ps1              # ограничить каждому загрузчику 1 Мбит/с
#   .\tools\game-mode-on.ps1 -Mbit 0.5    # жёстче
param([double]$Mbit = 1)

$bits = [uint64]($Mbit * 1000000)
# Программы, которые качают в фоне. Сами игры и голосовой чат сюда не входят.
$apps = @(
    'steam.exe', 'steamwebhelper.exe', 'steamservice.exe',
    'EpicGamesLauncher.exe', 'EpicWebHelper.exe',
    'Battle.net.exe', 'Agent.exe',
    'RiotClientServices.exe',
    'EADesktop.exe', 'EABackgroundService.exe',
    'upc.exe', 'UbisoftConnect.exe',
    'GalaxyClient.exe', 'GalaxyClientService.exe',
    'OneDrive.exe', 'Dropbox.exe', 'GoogleDriveFS.exe',
    'qbittorrent.exe', 'uTorrent.exe',
    'MoUsoCoreWorker.exe', 'wuauclt.exe'
)
foreach ($a in $apps) {
    $name = "VoiceChat Limit $a"
    Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue
    New-NetQosPolicy -Name $name -AppPathNameMatchCondition $a -ThrottleRateActionBitsPerSecond $bits -NetworkProfile All | Out-Null
}

# Центр обновления Windows качает через службу «Оптимизация доставки» — её ограничиваем отдельно:
# без раздачи другим компьютерам и не больше 10 % канала в фоне.
$do = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
if (-not (Test-Path $do)) { New-Item $do -Force | Out-Null }
Set-ItemProperty $do -Name 'DODownloadMode' -Value 0 -Type DWord
Set-ItemProperty $do -Name 'DOPercentageMaxBackgroundBandwidth' -Value 10 -Type DWord
Set-ItemProperty $do -Name 'DOPercentageMaxForegroundBandwidth' -Value 10 -Type DWord

"game mode ON: $($apps.Count) background apps limited to $Mbit Mbit/s each; Windows Update limited to 10%"
