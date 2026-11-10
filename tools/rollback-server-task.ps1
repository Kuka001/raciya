# Останавливает сервер, запущенный задачей Планировщика, и удаляет эту задачу.
# Запускать с правами администратора. С версии 0.2 сервер запускает сама «Рация».
$task = 'VoiceChat Mumble Server'
schtasks.exe /End /TN $task 2>$null | Out-Null
schtasks.exe /Delete /TN $task /F 2>$null | Out-Null
Get-CimInstance Win32_Process -Filter "Name='mumble-server.exe'" |
    Where-Object { $_.CommandLine -like '*project1\server\mumble-server.ini*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
icacls 'C:\MyProjects\project1\server' /remove '*S-1-5-19' | Out-Null
schtasks.exe /Query /TN $task 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { "task '$task' is STILL present" } else { "task '$task' removed, server stopped" }
