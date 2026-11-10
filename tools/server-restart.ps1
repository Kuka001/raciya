# Перезапускает Mumble Server (после изменения server\mumble-server.ini).
# Запускать с правами администратора, либо через: tools\run-elevated.ps1 -ScriptFile tools\server-restart.ps1
$task = 'VoiceChat Mumble Server'
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='mumble-server.exe'" |
    Where-Object { $_.CommandLine -like '*project1\server\mumble-server.ini*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 1
Start-ScheduledTask -TaskName $task
Start-Sleep -Seconds 4
Get-CimInstance Win32_Process -Filter "Name='mumble-server.exe'" |
    Where-Object { $_.CommandLine -like '*project1\server\mumble-server.ini*' } |
    ForEach-Object {
        $p = Get-Process -Id $_.ProcessId
        "running: pid=$($_.ProcessId) priority=$($p.PriorityClass) ram_mb=$([math]::Round($p.WorkingSet64/1MB,1))"
    }
Get-Content 'C:\MyProjects\project1\server\mumble-server.log' -Tail 3
