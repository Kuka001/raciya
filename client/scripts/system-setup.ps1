# System setup for Raciya. Runs elevated, started by raciya.exe (--system-setup).
# The program prepends these variables: $Mode, $Network, $Port, $Exe, $UserDir, $Log.
# Keep this file ASCII-only: it is embedded into the executable.
#
# Only what a mode needs is changed. Modes:
#   client       - install ZeroTier and join $Network (only for invites with a ZeroTier network)
#   server       - firewall rules for the server on $Port and program $Exe, pin $Port against
#                  Hyper-V/WSL port reservations (administered port exclusion)
#   qos-on       - mark voice traffic DSCP EF (46)        qos-off      - undo
#   gamemode-on  - limit background downloaders           gamemode-off - undo
#   remove       - undo everything this script has ever done (uninstall)

$ErrorActionPreference = 'Stop'
$script:failed = $false
$zt = 'C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe'
$ztVersion = '1.16.2'
$appKey = 'HKLM:\SOFTWARE\Raciya'

function Step([string]$name, [scriptblock]$body) {
    try {
        $r = & $body
        $line = "OK   $name"
        if ($r) { $line += ": $r" }
    }
    catch {
        $line = "FAIL $name" + ": " + $_.Exception.Message
        $script:failed = $true
    }
    "$(Get-Date -Format 'HH:mm:ss') $line" | Out-File -Append -Encoding utf8 $Log
}

function Set-Marker([string]$name, $value, [string]$type = 'DWord') {
    if (-not (Test-Path $appKey)) { New-Item $appKey -Force | Out-Null }
    Set-ItemProperty $appKey -Name $name -Value $value -Type $type
}

function Get-Marker([string]$name) {
    (Get-ItemProperty $appKey -Name $name -ErrorAction SilentlyContinue).$name
}

function Firewall-Running { (Get-Service mpssvc).Status -eq 'Running' }

# --- port exclusions (Hyper-V/WSL/Docker reserve random port ranges at every boot) -------------

function Get-Ranges([string]$proto) {
    $out = @()
    foreach ($l in (netsh int ipv4 show excludedportrange protocol=$proto)) {
        if ($l -match '^\s*(\d+)\s+(\d+)\s*(\*)?\s*$') {
            $out += [pscustomobject]@{ Start = [int]$Matches[1]; End = [int]$Matches[2]; Admin = [bool]$Matches[3] }
        }
    }
    $out
}

function Is-Pinned([string]$proto, [int]$p) {
    [bool](Get-Ranges $proto | Where-Object { $_.Admin -and $p -ge $_.Start -and $p -le $_.End })
}

function Add-Pins([int]$p) {
    foreach ($proto in 'tcp', 'udp') {
        if (-not (Is-Pinned $proto $p)) {
            netsh int ipv4 add excludedportrange protocol=$proto startport=$p numberofports=1 store=persistent | Out-Null
        }
    }
}

function Pin-Port([int]$p) {
    $was = (Is-Pinned 'tcp' $p) -and (Is-Pinned 'udp' $p)
    if (-not $was) {
        Add-Pins $p
        if (-not ((Is-Pinned 'tcp' $p) -and (Is-Pinned 'udp' $p))) {
            # The port is inside a range reserved right now: the NAT driver holds it until stopped.
            net stop winnat /y 2>&1 | Out-Null
            try { Add-Pins $p }
            finally { net start winnat 2>&1 | Out-Null }
        }
        if (-not ((Is-Pinned 'tcp' $p) -and (Is-Pinned 'udp' $p))) {
            net stop hns /y 2>&1 | Out-Null
            net stop winnat /y 2>&1 | Out-Null
            try { Add-Pins $p }
            finally {
                net start hns 2>&1 | Out-Null
                net start winnat 2>&1 | Out-Null
            }
        }
        if (-not ((Is-Pinned 'tcp' $p) -and (Is-Pinned 'udp' $p))) { throw "could not pin port $p" }
    }
    # Remembered so that uninstall can remove the exclusion again.
    $list = @(@(Get-Marker 'PinnedPorts') -split ',' | Where-Object { $_ }) + "$p" | Select-Object -Unique
    Set-Marker 'PinnedPorts' ($list -join ',') 'String'
    if ($was) { "port $p already pinned" } else { "port $p pinned" }
}

function Unpin-Ports {
    $done = @()
    foreach ($p in (@(Get-Marker 'PinnedPorts') -split ',' | Where-Object { $_ })) {
        foreach ($proto in 'tcp', 'udp') {
            netsh int ipv4 delete excludedportrange protocol=$proto startport=$p numberofports=1 2>&1 | Out-Null
        }
        $done += $p
    }
    if ($done.Count) { 'unpinned ' + ($done -join ', ') } else { 'nothing pinned' }
}

# --- QoS ----------------------------------------------------------------------------------------

function Set-QosPolicy([string]$name, [string]$exe) {
    Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue
    New-NetQosPolicy -Name $name -AppPathNameMatchCondition $exe -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All | Out-Null
}

function Remove-Qos {
    Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'VoiceChat*' -and $_.Name -notlike 'VoiceChat Limit *' } |
        ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false }
    Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -Name 'Do not use NLA' -ErrorAction SilentlyContinue
    Remove-ItemProperty $appKey -Name 'TweaksVersion' -ErrorAction SilentlyContinue
}

# --- game mode ----------------------------------------------------------------------------------

function Remove-GameMode {
    Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'VoiceChat Limit *' } |
        ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false }
    $do = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
    foreach ($v in 'DODownloadMode', 'DOPercentageMaxBackgroundBandwidth', 'DOPercentageMaxForegroundBandwidth') {
        Remove-ItemProperty $do -Name $v -ErrorAction SilentlyContinue
    }
    if (Test-Path $appKey) { Set-ItemProperty $appKey -Name 'GameMode' -Value 0 -Type DWord }
}

"--- $Mode $(Get-Date -Format s) ---" | Out-File -Append -Encoding utf8 $Log

if ($Mode -eq 'client' -and -not $Network) {
    "FAIL client: no network given" | Out-File -Append -Encoding utf8 $Log
    exit 1
}
if ($Mode -eq 'server' -and -not $Port) {
    "FAIL server: no port given" | Out-File -Append -Encoding utf8 $Log
    exit 1
}

if ($Mode -eq 'client') {
    Step 'zerotier-install' {
        if (Test-Path $zt) { return 'already installed' }
        $msi = Join-Path $env:TEMP "ZeroTierOne-$ztVersion.msi"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "https://download.zerotier.com/RELEASES/$ztVersion/dist/ZeroTier%20One.msi" -OutFile $msi -UseBasicParsing
        $sig = Get-AuthenticodeSignature $msi
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'ZEROTIER, INC') {
            throw "installer signature check failed ($($sig.Status))"
        }
        $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait -PassThru
        if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec exit code $($p.ExitCode)" }
        for ($i = 0; $i -lt 40 -and -not (Test-Path $zt); $i++) { Start-Sleep -Seconds 1 }
        if (-not (Test-Path $zt)) { throw 'ZeroTier files not found after install' }
        "installed $ztVersion"
    }
    Step 'zerotier-service' {
        Set-Service ZeroTierOneService -StartupType Automatic
        Start-Service ZeroTierOneService
        Start-Sleep -Seconds 3
        (Get-Service ZeroTierOneService).Status
    }
    Step 'zerotier-join' {
        & $zt -q join $Network | Out-Null
        Start-Sleep -Seconds 2
        # The network must not change the default route or DNS.
        & $zt -q set $Network allowDefault=0 | Out-Null
        & $zt -q set $Network allowGlobal=0 | Out-Null
        & $zt -q set $Network allowDNS=0 | Out-Null
        $line = ''
        for ($i = 0; $i -lt 30; $i++) {
            $line = (& $zt -q listnetworks) | Where-Object { $_ -match $Network }
            if ($line -match ' OK ' -and $line -match '\d+\.\d+\.\d+\.\d+/\d+') { break }
            Start-Sleep -Seconds 2
        }
        if ($line -notmatch ' OK ') { throw "network did not come up (server PC offline?): $line" }
        Set-Marker 'ZeroTierNetwork' $Network 'String'
        ($line -split '\s+')[-1]
    }
    Step 'zerotier-token' {
        # Lets the app ask the local ZeroTier service whether the link to the server is direct.
        if (-not (Test-Path $UserDir)) { New-Item -ItemType Directory -Force $UserDir | Out-Null }
        Copy-Item 'C:\ProgramData\ZeroTier\One\authtoken.secret' (Join-Path $UserDir 'zt.token') -Force
        Copy-Item 'C:\ProgramData\ZeroTier\One\zerotier-one.port' (Join-Path $UserDir 'zt.port') -Force
        'copied'
    }
    Step 'zerotier-tray' {
        Get-Process zerotier_desktop_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        'closed'
    }
    Step 'zerotier-firewall' {
        if (-not (Firewall-Running)) { return 'firewall service is not running - skipped' }
        if (Get-NetFirewallRule -DisplayName 'VoiceChat ZeroTier (UDP)' -ErrorAction SilentlyContinue) { return 'rule present' }
        New-NetFirewallRule -DisplayName 'VoiceChat ZeroTier (UDP)' -Group 'VoiceChat' -Direction Inbound -Action Allow -Protocol UDP -Program $zt -Profile Any | Out-Null
        'rule added'
    }
}
elseif ($Mode -eq 'server') {
    Step 'firewall' {
        if (-not (Firewall-Running)) { return 'firewall service is not running - skipped' }
        # A block rule (created when someone pressed Cancel in the Windows prompt) beats any allow rule.
        $blocked = 0
        foreach ($f in (Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -like '*\raciya.exe' })) {
            $r = $f | Get-NetFirewallRule
            if ($r.Action -eq 'Block') { $r | Remove-NetFirewallRule; $blocked++ }
        }
        # Rules of version 0.2 (Mumble Server) and earlier server rules of this program.
        Get-NetFirewallRule -Group 'VoiceChat' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'VoiceChat Mumble Server*' } | Remove-NetFirewallRule
        Get-NetFirewallRule -Group 'Raciya' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "Raciya server (TCP $Port)" -Group 'Raciya' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "Raciya server (UDP $Port)" -Group 'Raciya' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $Port -Profile Any | Out-Null
        if ($Exe) {
            # Without a rule for the program Windows shows its own prompt, and "Cancel" there blocks the server.
            New-NetFirewallRule -DisplayName 'Raciya app' -Group 'Raciya' -Direction Inbound -Action Allow -Program $Exe -Profile Any | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName 'VoiceChat ping (ICMPv4 echo)' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'Raciya ping (ICMPv4 echo)' -Group 'Raciya' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
        }
        "rules for port $Port; block rules removed: $blocked"
    }
    Step 'port-pin' { Pin-Port ([int]$Port) }
    Step 'marker' {
        Set-Marker 'ServerPort' ([int]$Port)
        "server port $Port"
    }
}
elseif ($Mode -eq 'qos-on') {
    Step 'qos-nla' {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS'
        if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
        Set-ItemProperty $k -Name 'Do not use NLA' -Value '1' -Type String
        'set'
    }
    Step 'qos-policies' {
        Set-QosPolicy 'VoiceChat Client Voice' 'raciya.exe'
        Remove-NetQosPolicy -Name 'VoiceChat Server Voice' -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path $zt) { Set-QosPolicy 'VoiceChat ZeroTier Voice' 'zerotier-one_x64.exe' }
        'DSCP 46 for raciya.exe' + $(if (Test-Path $zt) { ' and ZeroTier' } else { '' })
    }
    Step 'qos-pacer' {
        $changed = @()
        foreach ($a in (Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })) {
            $b = Get-NetAdapterBinding -Name $a.Name -ComponentID ms_pacer -ErrorAction SilentlyContinue
            if ($b -and -not $b.Enabled) {
                Enable-NetAdapterBinding -Name $a.Name -ComponentID ms_pacer
                $changed += $a.Name
            }
        }
        if ($changed.Count) { 'enabled on ' + ($changed -join ', ') } else { 'already enabled' }
    }
    Step 'marker' { Set-Marker 'TweaksVersion' 1; 'qos on' }
}
elseif ($Mode -eq 'qos-off') {
    Step 'qos' { Remove-Qos; 'removed' }
}
elseif ($Mode -eq 'gamemode-on') {
    Step 'limit-downloaders' {
        $apps = @(
            'steam.exe', 'steamwebhelper.exe', 'steamservice.exe',
            'EpicGamesLauncher.exe', 'EpicWebHelper.exe',
            'Battle.net.exe', 'Agent.exe', 'RiotClientServices.exe',
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
            New-NetQosPolicy -Name $name -AppPathNameMatchCondition $a -ThrottleRateActionBitsPerSecond 1000000 -NetworkProfile All | Out-Null
        }
        "$($apps.Count) background apps limited to 1 Mbit/s"
    }
    Step 'limit-windows-update' {
        $do = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        if (-not (Test-Path $do)) { New-Item $do -Force | Out-Null }
        Set-ItemProperty $do -Name 'DODownloadMode' -Value 0 -Type DWord
        Set-ItemProperty $do -Name 'DOPercentageMaxBackgroundBandwidth' -Value 10 -Type DWord
        Set-ItemProperty $do -Name 'DOPercentageMaxForegroundBandwidth' -Value 10 -Type DWord
        'no peer upload, 10% of the link'
    }
    Step 'marker' { Set-Marker 'GameMode' 1; 'on' }
}
elseif ($Mode -eq 'gamemode-off') {
    Step 'gamemode' { Remove-GameMode; 'removed' }
}
elseif ($Mode -eq 'remove') {
    Step 'gamemode' { Remove-GameMode; 'removed' }
    Step 'qos' { Remove-Qos; 'removed' }
    Step 'firewall' {
        if (-not (Firewall-Running)) { return 'firewall service is not running - skipped' }
        Get-NetFirewallRule -Group 'Raciya' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Get-NetFirewallRule -Group 'VoiceChat' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        'removed'
    }
    Step 'port-pins' { Unpin-Ports }
    if ($Network -and (Test-Path $zt)) {
        Step 'zerotier-leave' { & $zt -q leave $Network | Out-Null; 'left' }
    }
    Step 'marker' {
        Remove-Item $appKey -Recurse -Force -ErrorAction SilentlyContinue
        'removed'
    }
}
else {
    "FAIL unknown mode $Mode" | Out-File -Append -Encoding utf8 $Log
    $script:failed = $true
}

if ($script:failed) { exit 1 } else { exit 0 }
