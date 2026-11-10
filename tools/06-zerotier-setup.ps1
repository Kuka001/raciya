# Создаёт виртуальную сеть ZeroTier с контроллером на этом ПК и подключает к ней этот ПК.
# Сеть пропускает только голосовой чат (порт 64738) и ping; всё остальное между участниками запрещено.
# Запускать с правами администратора. Повторный запуск безопасен: существующая сеть переиспользуется.
$ErrorActionPreference = 'Stop'
$ztDir = 'C:\ProgramData\ZeroTier\One'
$cli = "$ztDir\zerotier-one_x64.exe"
$out = 'C:\MyProjects\project1\server\zerotier-network.txt'
$subnet = '10.77.64'

$token = (Get-Content "$ztDir\authtoken.secret" -Raw).Trim()
$port = (Get-Content "$ztDir\zerotier-one.port" -Raw).Trim()
$h = @{ 'X-ZT1-Auth' = $token }
$api = "http://127.0.0.1:$port"

$status = Invoke-RestMethod "$api/status" -Headers $h
$node = $status.address
"node: $node  version: $($status.version)  online: $($status.online)"

$ctl = Invoke-RestMethod "$api/controller" -Headers $h
"controller: $($ctl | ConvertTo-Json -Compress)"

$existing = @(Invoke-RestMethod "$api/controller/network" -Headers $h)
if ($existing.Count -gt 0 -and $existing[0]) {
    $nwid = [string]$existing[0]
    "reusing network $nwid"
}
else {
    $nwid = "${node}______"
}

$rules = @(
    @{ type = 'MATCH_ETHERTYPE'; not = $false; or = $false; etherType = 2054 }, @{ type = 'ACTION_ACCEPT' },
    @{ type = 'MATCH_IP_PROTOCOL'; not = $false; or = $false; ipProtocol = 1 }, @{ type = 'ACTION_ACCEPT' },
    @{ type = 'MATCH_IP_DEST_PORT_RANGE'; not = $false; or = $false; start = 64738; end = 64738 }, @{ type = 'ACTION_ACCEPT' },
    @{ type = 'MATCH_IP_SOURCE_PORT_RANGE'; not = $false; or = $false; start = 64738; end = 64738 }, @{ type = 'ACTION_ACCEPT' },
    @{ type = 'ACTION_DROP' }
)
$net = @{
    name              = 'voicechat'
    private           = $false
    enableBroadcast   = $false
    multicastLimit    = 0
    v4AssignMode      = @{ zt = $true }
    v6AssignMode      = @{ zt = $false; rfc4193 = $false; '6plane' = $false }
    ipAssignmentPools = @(@{ ipRangeStart = "$subnet.10"; ipRangeEnd = "$subnet.250" })
    routes            = @(@{ target = "$subnet.0/24" })
    rules             = $rules
}
$created = Invoke-RestMethod "$api/controller/network/$nwid" -Method Post -Headers $h -ContentType 'application/json' `
    -Body ($net | ConvertTo-Json -Depth 6)
$nwid = $created.id
"network: $nwid  private=$($created.private)  rules=$($created.rules.Count)"

# Этому ПК — постоянный адрес .1 (по нему друзья подключаются к серверу).
$member = @{ authorized = $true; noAutoAssignIps = $true; ipAssignments = @("$subnet.1") }
Invoke-RestMethod "$api/controller/network/$nwid/member/$node" -Method Post -Headers $h -ContentType 'application/json' `
    -Body ($member | ConvertTo-Json) | Out-Null

& $cli -q join $nwid
# Не менять маршрут по умолчанию и DNS, не принимать чужие публичные маршруты.
Start-Sleep -Seconds 2
& $cli -q set $nwid allowDefault=0 | Out-Null
& $cli -q set $nwid allowGlobal=0 | Out-Null
& $cli -q set $nwid allowDNS=0 | Out-Null

for ($i = 0; $i -lt 15; $i++) {
    $n = Invoke-RestMethod "$api/network/$nwid" -Headers $h
    if ($n.status -eq 'OK' -and $n.assignedAddresses.Count -gt 0) { break }
    Start-Sleep -Seconds 2
}
"joined: status=$($n.status) type=$($n.type) addresses=$($n.assignedAddresses -join ',') device=$($n.portDeviceName)"

"network=$nwid`r`nserver_ip=$subnet.1`r`nport=64738" | Out-File -Encoding ascii $out
"saved: $out"

# Значок ZeroTier в трее не нужен: сеть работает через службу.
Get-Process zerotier_desktop_ui -ErrorAction SilentlyContinue | Stop-Process -Force
$lnk = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", `
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Filter '*ZeroTier*' -ErrorAction SilentlyContinue
foreach ($l in $lnk) { "startup shortcut: $($l.FullName)" }
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    $p.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value -match 'zerotier' } | ForEach-Object { "run key: $k -> $($_.Name) = $($_.Value)" }
}
"--- adapter ---"
Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'ZeroTier' } | Select-Object Name, Status, LinkSpeed | Format-Table -AutoSize | Out-String
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$subnet.*" } | Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String
