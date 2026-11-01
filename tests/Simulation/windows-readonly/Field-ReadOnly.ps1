# MyPC PrintDoctor pre-field evidence collector. Windows PowerShell 5.1, Windows 10/11.
# READ-ONLY. Does not create, modify, or delete firewall/network/printer settings.
[CmdletBinding()]
param(
    [ValidateSet('Server','Client')][string]$Role = 'Client',
    [string]$TargetIPv4 = '',
    [switch]$Deep
)
$ErrorActionPreference = 'Stop'
if ($Role -eq 'Client' -and [string]::IsNullOrWhiteSpace($TargetIPv4)) {
    $TargetIPv4 = Read-Host 'Enter current IPv4 of Windows print server'
}
if ($Role -eq 'Client') {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($TargetIPv4,[ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'INVALID_SERVER_IPV4: Only numeric IPv4 addresses are accepted.'
    }
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$root = Join-Path $env:TEMP ("MyPC-PrintDoctor-" + $env:COMPUTERNAME + "-" + $Role + "-" + $stamp)
New-Item -Path $root -ItemType Directory -Force | Out-Null
$script:collection = [ordered]@{
    type = 'PREFIELD_READ_ONLY_REAL_WINDOWS_OBSERVATION'
    script_version = '1.0'
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    role = $Role
    target = $TargetIPv4
    caution = 'IPs, MACs, computer names and printer names appear in this report; keep private.'
    checks = [ordered]@{}
}
function AddCheck([string]$name, [scriptblock]$collector) {
    try {
        $obj = @(& $collector)
        if ($obj.Count -eq 0) {
            $script:collection.checks[$name] = [ordered]@{status='NOT_OBSERVED'; data=@()}
        } else {
            $script:collection.checks[$name] = [ordered]@{status='COLLECTED';data=$obj}
        }
    } catch {
        $script:collection.checks[$name] = [ordered]@{status='UNKNOWN';error=$_.Exception.Message}
    }
}
function PingIPv4([string]$ip) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $r = $p.Send($ip,1500)
        return [ordered]@{status=$(if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {'PASS'} else {'FAIL'}); detail=[string]$r.Status; rtt_ms=$(if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {$r.RoundtripTime} else {$null})}
    } catch {
        return [ordered]@{status='UNKNOWN'; detail=$_.Exception.Message}
    } finally { $p.Dispose() }
}
function ProbeTcp([string]$ip,[int]$port) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $op = $null
    try {
        $op = $tcp.BeginConnect($ip,$port,$null,$null)
        if (-not $op.AsyncWaitHandle.WaitOne(1700,$false)) {
            return [ordered]@{port=$port;status='FAIL'; detail='CONNECT_TIMEOUT'}
        }
        try {
            $tcp.EndConnect($op)
            return [ordered]@{port=$port;status='PASS';detail='TCP_CONNECTED_NOT_APPLICATION_VERIFIED'}
        } catch {
            return [ordered]@{port=$port;status='FAIL';detail=$_.Exception.Message}
        }
    } catch {
        return [ordered]@{port=$port;status='UNKNOWN';detail=$_.Exception.Message}
    } finally {
        if ($null -ne $op) { $op.AsyncWaitHandle.Close() }
        $tcp.Close()
    }
}
function ListenerPort([int]$port) {
    $conns = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop)
    if ($conns.Count -eq 0) { return [ordered]@{port=$port;status='NOT_LISTENING'} }
    return @($conns | Select-Object @{n='port';e={$_.LocalPort}},LocalAddress,OwningProcess,State)
}
AddCheck 'OS' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime }
AddCheck 'ADAPTERS' { Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,ifIndex,MacAddress,LinkSpeed }
AddCheck 'IPV4' { Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState }
AddCheck 'IP_CONFIGURATION' { Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,@{n='IPv4';e={@($_.IPv4Address | ForEach-Object IPAddress)}},@{n='Gateway';e={@($_.IPv4DefaultGateway | ForEach-Object NextHop)}},@{n='DNS';e={@($_.DNSServer | ForEach-Object ServerAddresses)}} }
AddCheck 'NETWORK_PROFILE' { Get-NetConnectionProfile | Select-Object InterfaceAlias,InterfaceIndex,Name,NetworkCategory }
AddCheck 'INTERFACE_METRIC' { Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,InterfaceIndex,InterfaceMetric,Dhcp,ConnectionState }
AddCheck 'LAN_BINDING' { Get-NetAdapterBinding -ComponentID ms_server,ms_msclient | Select-Object Name,ComponentID,Enabled }
AddCheck 'GATEWAY_ROUTES' { Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric }
AddCheck 'FIREWALL_PROFILES' { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,AllowLocalFirewallRules,AllowInboundRules }
AddCheck 'SHARING_FIREWALL_RULES' { Get-NetFirewallRule -Name 'FPS-*' -ErrorAction Stop | Select-Object -First 70 Name,Enabled,Profile,Direction,Action,PolicyStoreSourceType }
AddCheck 'OWNED_FIREWALL_RULES' { Get-NetFirewallRule -Name 'MyPC.PrintDoctor*' -ErrorAction Stop | Select-Object -First 50 Name,Enabled,Profile,Direction,Action }
AddCheck 'SERVICES' { Get-Service -Name Spooler,LanmanServer,LanmanWorkstation,FDResPub -ErrorAction Stop | Select-Object Name,Status,StartType }
AddCheck 'SMB_SERVER_CONFIG' { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EnableAuthenticateUserSharing }
AddCheck 'SMB_CLIENT_CONFIG' { Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons,RequireSecuritySignature,EnableSecuritySignature }
AddCheck 'PRINTERS' { Get-Printer -ErrorAction Stop | Select-Object Name,Shared,ShareName,PrinterStatus,DriverName,PortName }
AddCheck 'PRINTER_PORTS' { Get-PrinterPort -ErrorAction Stop | Select-Object -First 50 Name,PrinterHostAddress,PortNumber,Protocol }
AddCheck 'SHA_PROCESS' { Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -match '^Sha.?Print' } | Select-Object Id,ProcessName,Path,StartTime }
AddCheck 'TCP_LOCAL_LISTENERS' { Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 135,445,48631,48632,9100,631 } | Select-Object LocalAddress,LocalPort,OwningProcess,State }
AddCheck 'UDP_48633_ENDPOINTS' { Get-NetUDPEndpoint | Where-Object { $_.LocalPort -eq 48633 } | Select-Object LocalAddress,LocalPort,OwningProcess }
if ($Role -eq 'Server') {
    AddCheck 'GATEWAY_ICMP' {
        $gw = @(Get-NetIPConfiguration | ForEach-Object { $_.IPv4DefaultGateway } | Where-Object { $_ })
        foreach ($g in $gw) { [pscustomobject]@{gateway=$g.NextHop;probe=(PingIPv4 $g.NextHop)} }
    }
    AddCheck 'LOCAL_PORT_445' { ListenerPort 445 }
    AddCheck 'LOCAL_PORT_135' { ListenerPort 135 }
    AddCheck 'LOCAL_PORT_48631' { ListenerPort 48631 }
} else {
    AddCheck 'ICMP_SERVER' { PingIPv4 $TargetIPv4 }
    AddCheck 'TCP_TO_SERVER' {
        foreach ($port in @(445,135,48631)) { ProbeTcp $TargetIPv4 $port }
    }
    AddCheck 'SERVER_NEIGHBOR' { Get-NetNeighbor -IPAddress $TargetIPv4 -ErrorAction Stop | Select-Object IPAddress,LinkLayerAddress,State,InterfaceIndex }
}
if ($Deep) {
    AddCheck 'RECENT_SYSTEM_EVENTS' {
        Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddDays(-3)} -MaxEvents 100 -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'TCPIP|Dhcp|Ndis|Network|Service Control Manager|Kernel-PnP' } |
            Select-Object -First 30 TimeCreated,Id,ProviderName,LevelDisplayName,Message
    }
    AddCheck 'RECENT_PRINT_EVENTS' {
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Admin';StartTime=(Get-Date).AddDays(-3)} -MaxEvents 25 -ErrorAction Stop |
            Select-Object TimeCreated,Id,ProviderName,Message
    }
}
$jsonFile = Join-Path $root 'Snapshot.json'
$script:collection | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFile -Encoding UTF8
$summary = Join-Path $root 'Quick-Results.txt'
$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add('MyPC PrintDoctor Pre-field read-only observation')
$lines.Add(('Machine: {0}; Role: {1}; Target: {2}' -f $env:COMPUTERNAME,$Role,$TargetIPv4))
$lines.Add('No settings were changed by this script.')
if ($Role -eq 'Client') {
    $checks = $script:collection.checks
    $icmp = if ($checks['ICMP_SERVER'].status -eq 'COLLECTED') { $checks['ICMP_SERVER'].data[0] } else { $null }
    $lines.Add(('ICMP result: {0}' -f $(if ($null -ne $icmp) {$icmp.status} else {'UNKNOWN'})))
    if ($checks['TCP_TO_SERVER'].status -eq 'COLLECTED') {
        foreach ($v in $checks['TCP_TO_SERVER'].data) {
            $lines.Add(('TCP {0}: {1} ({2})' -f $v.port,$v.status,$v.detail))
        }
    } else { $lines.Add('TCP results: UNKNOWN') }
    $lines.Add('ICMP FAIL + any TCP PASS means destination is reachable; do not conclude host offline.')
    $lines.Add('All ICMP/TCP FAIL requires server-side and path evidence, not automatic firewall fix.')
} else {
    $lines.Add('Check Snapshot.json: adapter status, gateway, firewall profile, SMB/Spooler, listeners 445/135/48631.')
}
$lines.Add('TCP 48631 PASS does not prove ShaPrint IPPS/TLS/printing is healthy.')
$lines.Add('Keep original report private; IPs, MACs, computer and printer names are present.')
$lines | Set-Content -Path $summary -Encoding UTF8
$zip = $root + '.zip'
try { Compress-Archive -Path (Join-Path $root '*') -DestinationPath $zip -CompressionLevel Optimal -Force; Write-Host ('REPORT_ZIP: ' + $zip) -ForegroundColor Green }
catch { Write-Host ('ZIP_FAILED: ' + $_.Exception.Message); Write-Host ('REPORT_FOLDER: ' + $root) }
Write-Host ('QUICK_RESULTS: ' + $summary)
Get-Content $summary
