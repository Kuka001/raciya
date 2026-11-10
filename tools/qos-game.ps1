# Приоритет трафику игры: помечает её пакеты как DSCP EF (46), как и голос.
# Запускать с правами администратора:
#   .\tools\qos-game.ps1 -Exe cs2.exe
#   .\tools\qos-game.ps1 -Exe cs2.exe -Remove
# Имя файла игры видно в Диспетчере задач (вкладка «Подробности»).
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [switch]$Remove
)
$name = "VoiceChat Game $Exe"
Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue
if ($Remove) {
    "removed: $name"
}
else {
    New-NetQosPolicy -Name $name -AppPathNameMatchCondition $Exe -DSCPAction 46 -NetworkProfile All | Out-Null
    Get-NetQosPolicy -Name $name | Select-Object Name, AppPathNameMatchCondition, DSCPAction | Format-Table -AutoSize | Out-String
}
