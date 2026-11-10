# Только чтение: состояние службы брандмауэра, профилей и службы QoS (qWAVE).
"--- services ---"
Get-Service mpssvc, BFE, mpsdrv, QWAVE, Schedule -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String

"--- mpssvc registry ---"
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc' |
    Select-Object Start, DelayedAutostart, ObjectName | Format-List | Out-String
(Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc').Access |
    Select-Object IdentityReference, RegistryRights, AccessControlType | Format-Table -AutoSize | Out-String -Width 200

"--- firewall profiles (registry) ---"
foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p"
    $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
    "{0}: EnableFirewall={1} DefaultInboundAction={2} DisableNotifications={3}" -f $p, $v.EnableFirewall, $v.DefaultInboundAction, $v.DisableNotifications
}
"--- policy overrides ---"
Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Name; ($_ | Get-ItemProperty | Out-String) }

"--- listening TCP ports (non-loopback) ---"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
    Select-Object LocalAddress, LocalPort, @{n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } } |
    Sort-Object LocalPort -Unique | Format-Table -AutoSize | Out-String

"--- project folder ACL ---"
(Get-Acl 'C:\MyProjects\project1').Access |
    Select-Object IdentityReference, FileSystemRights, AccessControlType | Format-Table -AutoSize | Out-String -Width 200

"--- network profile ---"
Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory | Format-Table -AutoSize | Out-String
