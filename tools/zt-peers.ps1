# Показывает участников виртуальной сети и то, как с каждым установлено соединение:
# DIRECT — напрямую (хорошо), RELAY — через ретранслятор ZeroTier (задержка выше).
# Запускать с правами администратора:  .\tools\run-elevated.ps1 -ScriptFile .\tools\zt-peers.ps1
$ztDir = 'C:\ProgramData\ZeroTier\One'
$token = (Get-Content "$ztDir\authtoken.secret" -Raw).Trim()
$port = (Get-Content "$ztDir\zerotier-one.port" -Raw).Trim()
$h = @{ 'X-ZT1-Auth' = $token }
$api = "http://127.0.0.1:$port"
# Номер сети — из настроек «Рации» (поле zt_network).
$cfg = Join-Path $env:APPDATA 'Raciya\config.toml'
$nwid = @((Get-Content $cfg -Encoding UTF8) -match '^\s*zt_network\s*=') -replace '^\s*zt_network\s*=\s*"?([0-9a-fA-F]{16})"?.*$', '$1' | Select-Object -First 1
if (-not $nwid) { throw "в $cfg не задана сеть ZeroTier (zt_network)" }

$members = Invoke-RestMethod "$api/controller/network/$nwid/member" -Headers $h
$peers = Invoke-RestMethod "$api/peer" -Headers $h
$me = (Invoke-RestMethod "$api/status" -Headers $h).address

"network $nwid, this PC = $me"
"{0,-12} {1,-14} {2,-8} {3,-9} {4,-24} {5}" -f 'node', 'vpn ip', 'link', 'zt ms', 'real address', 'ping ms'
foreach ($id in $members.PSObject.Properties.Name) {
    if ($id -eq $me) { continue }
    $m = Invoke-RestMethod "$api/controller/network/$nwid/member/$id" -Headers $h
    $ip = ($m.ipAssignments | Select-Object -First 1)
    $p = $peers | Where-Object { $_.address -eq $id }
    $path = $null
    if ($p) { $path = $p.paths | Where-Object { $_.active -and $_.preferred } | Select-Object -First 1 }
    $link = if (-not $p) { 'offline' } elseif ($path) { 'DIRECT' } else { 'RELAY' }
    $ping = ''
    if ($ip -and $p) {
        $r = Test-Connection -ComputerName $ip -Count 4 -ErrorAction SilentlyContinue
        if ($r) { $ping = '{0:N0}' -f ($r | Measure-Object -Property ResponseTime -Average).Average }
    }
    "{0,-12} {1,-14} {2,-8} {3,-9} {4,-24} {5}" -f $id, $ip, $link, $(if ($p) { $p.latency } else { '' }), $(if ($path) { $path.address } else { '' }), $ping
}
"--- root servers (used only to find each other) ---"
$peers | Where-Object { $_.role -eq 'PLANET' } | ForEach-Object { "{0} latency {1} ms" -f $_.address, $_.latency }
