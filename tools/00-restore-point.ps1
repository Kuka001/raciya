# Создаёт точку восстановления Windows перед системными изменениями.
$ErrorActionPreference = 'Stop'
Checkpoint-Computer -Description 'VoiceChat: before system changes' -RestorePointType 'MODIFY_SETTINGS'
Get-ComputerRestorePoint | Select-Object -Last 2 SequenceNumber, Description, CreationTime | Format-Table -AutoSize | Out-String
