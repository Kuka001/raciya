# Регистрирует одноразовую задачу: при следующем старте Windows дописать правила брандмауэра.
# Запускать с правами администратора.
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\MyProjects\project1\tools\04-firewall-finish.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'VoiceChat Firewall Finish' -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'One-time: enable Windows Firewall profiles and add VoiceChat rules after reboot.' -Force | Out-Null
schtasks.exe /Query /TN 'VoiceChat Firewall Finish' /FO CSV /NH
schtasks.exe /Query /TN 'VoiceChat Mumble Server' /FO CSV /NH
