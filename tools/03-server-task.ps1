# Автозапуск Mumble Server в фоне без окна: задача Планировщика, запуск при старте Windows
# от имени служебной учётной записи LOCAL SERVICE, приоритет процесса «Ниже среднего».
# Запускать с правами администратора. Откат: tools\rollback-server-task.ps1
$ErrorActionPreference = 'Stop'
$task = 'VoiceChat Mumble Server'
$exe = "$env:ProgramFiles\Mumble\server\mumble-server.exe"
$dir = 'C:\MyProjects\project1\server'
$ini = "$dir\mumble-server.ini"

# Служебной учётной записи нужен доступ на запись к папке сервера (база и журнал).
icacls $dir /grant '*S-1-5-19:(OI)(CI)M' | Out-Null

$action = New-ScheduledTaskAction -Execute $exe -Argument "-ini `"$ini`"" -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
# Priority 7 = класс приоритета BELOW_NORMAL («Ниже среднего»).
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -Priority 7 -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'Mumble Server for the voice chat (port 64738). Runs in background without a window.' -Force | Out-Null

Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-ScheduledTask -TaskName $task
Start-Sleep -Seconds 6

Get-ScheduledTask -TaskName $task | Select-Object TaskName, State | Format-Table -AutoSize | Out-String
Get-CimInstance Win32_Process -Filter "Name='mumble-server.exe'" | ForEach-Object {
    $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
    $pr = Get-Process -Id $_.ProcessId
    "pid=$($_.ProcessId) owner=$($o.Domain)\$($o.User) session=$($_.SessionId) priority=$($pr.PriorityClass) ram_mb=$([math]::Round($pr.WorkingSet64/1MB,1)) cmd=$($_.CommandLine)"
}
"--- listening ---"
Get-NetTCPConnection -LocalPort 64738 -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-String
Get-NetUDPEndpoint -LocalPort 64738 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-String
