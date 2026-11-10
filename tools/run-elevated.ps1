# Запускает указанный .ps1 с правами администратора и печатает его вывод.
# Использование: .\tools\run-elevated.ps1 -ScriptFile <путь> [-TimeoutSec 600]
param(
    [Parameter(Mandatory = $true)][string]$ScriptFile,
    [int]$TimeoutSec = 600
)

$ScriptFile = (Resolve-Path $ScriptFile).Path
$log = Join-Path $env:TEMP ("elev_" + [guid]::NewGuid().ToString('N') + ".log")

$inner = "& { try { & '$ScriptFile' *>&1 | Out-File -Encoding utf8 -FilePath '$log' } catch { `$_ | Out-String | Out-File -Append -Encoding utf8 -FilePath '$log'; exit 1 } }"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru `
    -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc

if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    Write-Output "TIMEOUT after $TimeoutSec s (process still running, pid $($p.Id))"
}
else {
    Write-Output "exit code: $($p.ExitCode)"
}

if (Test-Path $log) {
    Get-Content $log -Encoding utf8
    Remove-Item $log -ErrorAction SilentlyContinue
}
