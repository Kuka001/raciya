# System setup for Raciya. Runs elevated, started by raciya.exe (--system-setup).
# The program prepends these variables: $Mode, $Network, $UserDir, $Log, $TweaksVersion.
# Keep this file ASCII-only: it is embedded into the executable.
#
# Modes:
#   apply        - install/join ZeroTier (if $Network is set) and apply the network tweaks
#   remove       - undo the tweaks and leave the ZeroTier network
#   gamemode-on  - limit background downloaders while playing
#   gamemode-off - remove those limits

$ErrorActionPreference = 'Stop'
$script:failed = $false
$zt = 'C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe'
$ztVersion = '1.16.2'
$mumble = "$env:ProgramFiles\Mumble\server\mumble-server.exe"

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

function Set-QosPolicy([string]$name, [string]$exe, [switch]$UdpOnly) {
    Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue
    if ($UdpOnly) {
        New-NetQosPolicy -Name $name -AppPathNameMatchCondition $exe -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All | Out-Null
    }
    else {
        New-NetQosPolicy -Name $name -AppPathNameMatchCondition $exe -DSCPAction 46 -NetworkProfile All | Out-Null
    }
}

"--- $Mode $(Get-Date -Format s) ---" | Out-File -Append -Encoding utf8 $Log

if ($Mode -eq 'apply') {
    if ($Network) {
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
            ($line -split '\s+')[-1]
        }
    }
    if (Test-Path $zt) {
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
    }
    Step 'qos-nla' {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS'
        if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
        Set-ItemProperty $k -Name 'Do not use NLA' -Value '1' -Type String
        'set'
    }
    Step 'qos-policies' {
        Set-QosPolicy 'VoiceChat Client Voice' 'raciya.exe' -UdpOnly
        Set-QosPolicy 'VoiceChat ZeroTier Voice' 'zerotier-one_x64.exe' -UdpOnly
        Set-QosPolicy 'VoiceChat Server Voice' 'mumble-server.exe' -UdpOnly
        'DSCP 46 for raciya.exe, zerotier-one_x64.exe, mumble-server.exe'
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
    Step 'firewall' {
        if ((Get-Service mpssvc).Status -ne 'Running') { return 'firewall service is not running - skipped' }
        $made = @()
        if ((Test-Path $zt) -and -not (Get-NetFirewallRule -DisplayName 'VoiceChat ZeroTier (UDP)' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'VoiceChat ZeroTier (UDP)' -Group 'VoiceChat' -Direction Inbound -Action Allow -Protocol UDP -Program $zt -Profile Any | Out-Null
            $made += 'zerotier'
        }
        if (Test-Path $mumble) {
            if (-not (Get-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (TCP 64738)' -ErrorAction SilentlyContinue)) {
                # By port, not by program path: the server is started from a copy named raciya.exe.
                New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (TCP 64738)' -Group 'VoiceChat' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 64738 -Profile Any | Out-Null
                $made += 'server tcp'
            }
            if (-not (Get-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (UDP 64738)' -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName 'VoiceChat Mumble Server (UDP 64738)' -Group 'VoiceChat' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 64738 -Profile Any | Out-Null
                $made += 'server udp'
            }
            if (-not (Get-NetFirewallRule -DisplayName 'VoiceChat ping (ICMPv4 echo)' -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName 'VoiceChat ping (ICMPv4 echo)' -Group 'VoiceChat' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
                $made += 'ping'
            }
        }
        if ($made.Count) { 'rules added: ' + ($made -join ', ') } else { 'rules already present' }
    }
    Step 'marker' {
        $k = 'HKLM:\SOFTWARE\Raciya'
        if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
        Set-ItemProperty $k -Name 'TweaksVersion' -Value ([int]$TweaksVersion) -Type DWord
        "tweaks version $TweaksVersion"
    }
}
elseif ($Mode -eq 'remove') {
    Step 'gamemode-off' {
        Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat Limit *' } | ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false }
        'removed'
    }
    Step 'qos-policies' {
        Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat*' } | ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false }
        Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -Name 'Do not use NLA' -ErrorAction SilentlyContinue
        'removed'
    }
    Step 'firewall' {
        if ((Get-Service mpssvc).Status -eq 'Running') {
            Get-NetFirewallRule -Group 'VoiceChat' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
        'removed'
    }
    if ($Network -and (Test-Path $zt)) {
        Step 'zerotier-leave' { & $zt -q leave $Network | Out-Null; 'left' }
    }
    Step 'marker' {
        Remove-Item 'HKLM:\SOFTWARE\Raciya' -Recurse -Force -ErrorAction SilentlyContinue
        'removed'
    }
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
    Step 'marker' {
        $k = 'HKLM:\SOFTWARE\Raciya'
        if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
        Set-ItemProperty $k -Name 'GameMode' -Value 1 -Type DWord
        'on'
    }
}
elseif ($Mode -eq 'gamemode-off') {
    Step 'limit-downloaders' {
        Get-NetQosPolicy | Where-Object { $_.Name -like 'VoiceChat Limit *' } | ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false }
        'removed'
    }
    Step 'limit-windows-update' {
        $do = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        foreach ($v in 'DODownloadMode', 'DOPercentageMaxBackgroundBandwidth', 'DOPercentageMaxForegroundBandwidth') {
            Remove-ItemProperty $do -Name $v -ErrorAction SilentlyContinue
        }
        'removed'
    }
    Step 'marker' {
        $k = 'HKLM:\SOFTWARE\Raciya'
        if (Test-Path $k) { Set-ItemProperty $k -Name 'GameMode' -Value 0 -Type DWord }
        'off'
    }
}
else {
    "FAIL unknown mode $Mode" | Out-File -Append -Encoding utf8 $Log
    $script:failed = $true
}

if ($script:failed) { exit 1 } else { exit 0 }
