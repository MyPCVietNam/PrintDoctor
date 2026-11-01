using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Abstractions.Validation;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class PowerShellWindowsServiceInspector : IWindowsServiceInspector
{
    private readonly IProcessRunner _runner;
    public PowerShellWindowsServiceInspector(IProcessRunner runner) => _runner = runner;

    public async Task<WindowsServiceInfo?> GetServiceAsync(string serviceName, CancellationToken ct = default)
        => (await GetServicesAsync(new[] { serviceName }, ct)).FirstOrDefault();

    public async Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(IEnumerable<string> serviceNames, CancellationToken ct = default)
    {
        var names = string.Join("','", serviceNames.Select(EscapePs));
        var script = $"Get-Service -Name @('{names}') -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return serviceNames.Select(n => new WindowsServiceInfo { Name = n, Status = "Unknown" }).ToList();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new WindowsServiceInfo
            {
                Name = PowerShellJson.GetString(el, "Name") ?? "",
                DisplayName = PowerShellJson.GetString(el, "DisplayName"),
                Status = PowerShellJson.NormalizeServiceStatus(el),
                StartType = PowerShellJson.NormalizeStartType(el)
            }).ToList();
        }
        catch
        {
            return serviceNames.Select(n => new WindowsServiceInfo { Name = n, Status = "Unknown" }).ToList();
        }
    }

    public async Task<bool> StartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Start-Service -Name '{EscapePs(serviceName)}'; (Get-Service -Name '{EscapePs(serviceName)}').Status";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0 && result.StdOut.Contains("Running", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<bool> RestartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Restart-Service -Name '{EscapePs(serviceName)}' -Force; (Get-Service -Name '{EscapePs(serviceName)}').Status";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0 && result.StdOut.Contains("Running", StringComparison.OrdinalIgnoreCase);
    }

    private static string EscapePs(string value) => value.Replace("'", "''");
}

public sealed class PowerShellFirewallInspector : IFirewallInspector
{
    private readonly IProcessRunner _runner;
    private ProbeOutcome _thirdPartyStatus = ProbeOutcome.Unknown;

    public PowerShellFirewallInspector(IProcessRunner runner) => _runner = runner;

    public async Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress";
        var result = await Run(script, ct);
        if (result is null) return Array.Empty<FirewallProfileState>();
        using var doc = JsonDocument.Parse(result);
        return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
        {
            var name = (PowerShellJson.GetString(el, "Name") ?? "").ToLowerInvariant();
            return new FirewallProfileState
            {
                Profile = name switch
                {
                    "domain" or "1" => FirewallProfileKind.Domain,
                    "private" or "2" => FirewallProfileKind.Private,
                    _ => FirewallProfileKind.Public
                },
                Enabled = el.TryGetProperty("Enabled", out var en) && PowerShellJson.IsTruthy(en),
                DefaultInboundAction = PowerShellJson.GetString(el, "DefaultInboundAction"),
                DefaultOutboundAction = PowerShellJson.GetString(el, "DefaultOutboundAction")
            };
        }).ToList();
    }

    public async Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
    {
        // Language-independent: rule Name (FPS-*) + group id + protocol/port filters
        const string script = @"
$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match 'FPS-|CoreNet-ICMP|SMB' -or $_.Group -eq '@FirewallAPI.dll,-28502' -or $_.DisplayName -match 'Echo|ICMP|ShaPrint|48631|48633|SMB|File and Printer|Tệp và máy in|Chia sẻ tệp'
} | Select-Object -First 120
$result = foreach ($r in $rules) {
  $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue | Select-Object -First 1
  $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{
    Name = $r.Name
    DisplayName = $r.DisplayName
    Enabled = [bool]$r.Enabled
    Direction = [string]$r.Direction
    Action = [string]$r.Action
    Profile = [string]$r.Profile
    Grouping = [string]$r.Group
    Protocol = [string]$port.Protocol
    LocalPorts = [string]$port.LocalPort
    LocalAddresses = [string]$addr.LocalAddress
    RemoteAddresses = [string]$addr.RemoteAddress
    IcmpTypesAndCodes = [string]$port.IcmpType
    PolicyStore = [string]$r.PolicyStore
  }
}
$result | ConvertTo-Json -Compress
";
        var raw = await Run(script, ct);
        if (raw is null) return Array.Empty<FirewallRuleInfo>();
        try
        {
            using var doc = JsonDocument.Parse(raw);
            return PowerShellJson.Enumerate(doc.RootElement).Select(ParseRule).ToList();
        }
        catch
        {
            return Array.Empty<FirewallRuleInfo>();
        }
    }

    internal static FirewallRuleInfo ParseRule(JsonElement el) => new()
    {
        RuleId = PowerShellJson.GetString(el, "Name") ?? PowerShellJson.GetString(el, "RuleId"),
        Name = PowerShellJson.GetString(el, "DisplayName") ?? PowerShellJson.GetString(el, "Name") ?? "",
        DisplayName = PowerShellJson.GetString(el, "DisplayName"),
        Enabled = el.TryGetProperty("Enabled", out var en) && PowerShellJson.IsTruthy(en),
        Direction = PowerShellJson.GetString(el, "Direction") ?? "",
        Action = PowerShellJson.GetString(el, "Action") ?? "",
        Profiles = PowerShellJson.GetString(el, "Profile") ?? PowerShellJson.GetString(el, "Profiles"),
        Grouping = PowerShellJson.GetString(el, "Grouping"),
        Protocol = PowerShellJson.GetString(el, "Protocol"),
        LocalPorts = PowerShellJson.GetString(el, "LocalPorts"),
        LocalAddresses = PowerShellJson.GetString(el, "LocalAddresses"),
        RemoteAddresses = PowerShellJson.GetString(el, "RemoteAddresses"),
        IcmpTypesAndCodes = PowerShellJson.GetString(el, "IcmpTypesAndCodes"),
        PolicyStore = PowerShellJson.GetString(el, "PolicyStore")
    };

    public async Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
    {
        const string script = @"
try {
  $items = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct,FirewallProduct -ErrorAction Stop |
    Select-Object displayName, companyName, __CLASS
  if (-not $items) { '[]' } else { $items | ConvertTo-Json -Compress }
} catch { 'ERROR:' + $_.Exception.Message }
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var stdout = result.StdOut.Trim();
        if (result.ExitCode != 0 || stdout.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase))
        {
            _thirdPartyStatus = ProbeOutcome.Unknown;
            return Array.Empty<ThirdPartySecurityProduct>();
        }

        if (string.IsNullOrWhiteSpace(stdout) || stdout == "[]")
        {
            _thirdPartyStatus = ProbeOutcome.Pass; // collected successfully, none found
            return Array.Empty<ThirdPartySecurityProduct>();
        }

        try
        {
            using var doc = JsonDocument.Parse(stdout);
            _thirdPartyStatus = ProbeOutcome.Pass;
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new ThirdPartySecurityProduct
            {
                Name = PowerShellJson.GetString(el, "displayName") ?? "Unknown",
                Vendor = PowerShellJson.GetString(el, "companyName"),
                Kind = PowerShellJson.GetString(el, "__CLASS"),
                CollectionStatus = ProbeOutcome.Pass
            }).Where(p => !p.Name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
                          && !p.Name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        catch
        {
            _thirdPartyStatus = ProbeOutcome.Unknown;
            return Array.Empty<ThirdPartySecurityProduct>();
        }
    }

    public Task<ProbeOutcome> GetThirdPartyCollectionStatusAsync(CancellationToken ct = default)
        => Task.FromResult(_thirdPartyStatus);

    public async Task<bool> EnableScopedIcmpEchoAsync(CancellationToken ct = default)
    {
        // Scope FIRST (while disabled / before enable) — never widen then narrow.
        // Skip GPO-managed rules. ErrorAction Stop; require Private+LocalSubnet+Enabled.
        const string script = @"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -PolicyStore ActiveStore -ErrorAction Stop
if ($r.PolicyStore -match 'GP|GroupPolicy') { throw 'GPO_MANAGED' }
# Narrow before enable
Set-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -Profile Private -Direction Inbound -Action Allow -ErrorAction Stop
Set-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction Stop) -RemoteAddress LocalSubnet -ErrorAction Stop
Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction Stop
$v = Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction Stop
$addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $v -ErrorAction Stop
if ($v.Enabled -ne 'True' -and $v.Enabled -ne $true) { throw 'NOT_ENABLED' }
if ([string]$v.Profile -notmatch 'Private' -or [string]$v.Profile -match 'Public|Domain') { throw 'BAD_PROFILE:' + $v.Profile }
if ([string]$addr.RemoteAddress -notmatch 'LocalSubnet') { throw 'BAD_REMOTE:' + $addr.RemoteAddress }
'OK'
";
        var raw = await Run(script, ct);
        return raw?.Contains("OK", StringComparison.Ordinal) == true;
    }

    public async Task<bool> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson);
            var priorEl = PowerShellJson.Enumerate(doc.RootElement)
                .Select(ParseRule)
                .FirstOrDefault(r => (r.RuleId ?? r.Name ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase)
                                     || (r.DisplayName ?? "").Contains("Echo", StringComparison.OrdinalIgnoreCase));
            if (priorEl is null)
                return false;

            var id = Escape(priorEl.RuleId ?? "FPS-ICMP4-ERQ-In");
            var profile = Escape(string.IsNullOrWhiteSpace(priorEl.Profiles) ? "Private" : priorEl.Profiles!);
            var remote = Escape(string.IsNullOrWhiteSpace(priorEl.RemoteAddresses) ? "Any" : priorEl.RemoteAddresses!);
            var enable = priorEl.Enabled ? "Enable-NetFirewallRule" : "Disable-NetFirewallRule";
            var script = $@"
$ErrorActionPreference = 'Stop'
Set-NetFirewallRule -Name '{id}' -Profile {QuoteProfile(profile)} -ErrorAction Stop
Set-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name '{id}' -ErrorAction Stop) -RemoteAddress {QuoteRemote(remote)} -ErrorAction Stop
{enable} -Name '{id}' -ErrorAction Stop
'OK'
";
            var raw = await Run(script, ct);
            if (raw?.Contains("OK", StringComparison.Ordinal) != true)
                return false;

            // Must re-read and match — do not trust OK alone
            var after = await GetRelevantRulesAsync(ct);
            var cur = after.FirstOrDefault(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase));
            if (cur is null) return false;
            if (cur.Enabled != priorEl.Enabled) return false;
            if (!string.IsNullOrWhiteSpace(priorEl.Profiles) &&
                !string.Equals(NormalizeProfile(cur.Profiles), NormalizeProfile(priorEl.Profiles), StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(priorEl.RemoteAddresses) &&
                !string.Equals((cur.RemoteAddresses ?? "").Trim(), priorEl.RemoteAddresses.Trim(), StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> EnableFileAndPrinterSharingAsync(CancellationToken ct = default)
    {
        // NEVER Enable-NetFirewallRule -Group (would enable Public/Domain members).
        // Enable only approved inbound FPS rules by name after setting Private + LocalSubnet.
        const string script = @"
$ErrorActionPreference = 'Stop'
$approved = @(
  'FPS-SMB-In-TCP',
  'FPS-SMB-In-TCP-NoScope',
  'FPS-NBSession-In-TCP',
  'FPS-NBSession-In-TCP-NoScope',
  'FPS-RPCSS-In-TCP',
  'FPS-SpoolSvc-In-TCP',
  'FPS-SpoolSvc-In-TCP-NoScope'
)
$changed = 0
foreach ($name in $approved) {
  $r = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue
  if (-not $r) { continue }
  if ($r.PolicyStore -match 'GP|GroupPolicy') { continue }
  if ([string]$r.Direction -notmatch 'Inbound|In') { continue }
  Set-NetFirewallRule -Name $name -Profile Private -Direction Inbound -Action Allow -ErrorAction Stop
  try { Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -RemoteAddress LocalSubnet -ErrorAction Stop } catch { }
  Enable-NetFirewallRule -Name $name -ErrorAction Stop
  $v = Get-NetFirewallRule -Name $name -ErrorAction Stop
  if (($v.Enabled -eq $true -or $v.Enabled -eq 'True') -and ([string]$v.Profile -match 'Private') -and ([string]$v.Profile -notmatch 'Public')) { $changed++ }
}
if ($changed -lt 1) { throw 'NO_SCOPED_FPS_RULE_ENABLED' }
'OK:' + $changed
";
        var raw = await Run(script, ct);
        return raw?.Contains("OK:", StringComparison.Ordinal) == true;
    }

    public async Task<bool> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson);
            var priors = PowerShellJson.Enumerate(doc.RootElement).Select(ParseRule)
                .Where(r =>
                {
                    var id = r.RuleId ?? r.Name ?? "";
                    return id.StartsWith("FPS-", StringComparison.OrdinalIgnoreCase)
                           || (r.Grouping?.Contains("FirewallAPI.dll,-28502") ?? false);
                }).ToList();
            if (priors.Count == 0) return false;

            foreach (var prior in priors)
            {
                var id = Escape(prior.RuleId ?? prior.Name);
                if (string.IsNullOrWhiteSpace(id)) continue;
                if (FirewallRuleScope.IsGpoManaged(prior)) continue;
                var profile = string.IsNullOrWhiteSpace(prior.Profiles) ? "Any" : prior.Profiles!;
                var remote = string.IsNullOrWhiteSpace(prior.RemoteAddresses) ? "Any" : prior.RemoteAddresses!;
                var enable = prior.Enabled ? "Enable-NetFirewallRule" : "Disable-NetFirewallRule";
                var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{id}' -ErrorAction Stop
if ($r.PolicyStore -match 'GP|GroupPolicy') {{ throw 'GPO' }}
Set-NetFirewallRule -Name '{id}' -Profile {QuoteProfile(Escape(profile))} -ErrorAction Stop
try {{ Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -RemoteAddress {QuoteRemote(Escape(remote))} -ErrorAction Stop }} catch {{}}
{enable} -Name '{id}' -ErrorAction Stop
'OK'
";
                var raw = await Run(script, ct);
                if (raw?.Contains("OK", StringComparison.Ordinal) != true)
                    return false;
            }

            var after = await GetRelevantRulesAsync(ct);
            foreach (var prior in priors)
            {
                var id = prior.RuleId ?? prior.Name;
                var cur = after.FirstOrDefault(r => string.Equals(r.RuleId ?? r.Name, id, StringComparison.OrdinalIgnoreCase));
                if (cur is null || cur.Enabled != prior.Enabled)
                    return false;
                if (!string.IsNullOrWhiteSpace(prior.Profiles) &&
                    !string.Equals(NormalizeProfile(cur.Profiles), NormalizeProfile(prior.Profiles), StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task<string?> Run(string script, CancellationToken ct)
    {
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut)) return null;
        return result.StdOut.Trim();
    }

    private static string Escape(string value) => value.Replace("'", "''");
    private static string QuoteProfile(string p) => p.Contains(',') ? $"'{p}'" : p;
    private static string QuoteRemote(string r) => $"'{r}'";
    private static string NormalizeProfile(string? p) => (p ?? "").Replace(" ", "", StringComparison.Ordinal);
}

public sealed class PowerShellNetworkProfileService : INetworkProfileService
{
    private readonly IProcessRunner _runner;
    public PowerShellNetworkProfileService(IProcessRunner runner) => _runner = runner;

    public async Task<IReadOnlyList<NetworkConnectionProfile>> GetConnectionProfilesAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<NetworkConnectionProfile>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
            {
                var cat = PowerShellJson.GetString(el, "NetworkCategory") ?? "Unknown";
                cat = cat switch { "0" => "Public", "1" => "Private", "2" => "DomainAuthenticated", _ => cat };
                return new NetworkConnectionProfile
                {
                    Name = PowerShellJson.GetString(el, "Name"),
                    InterfaceAlias = PowerShellJson.GetString(el, "InterfaceAlias"),
                    InterfaceIndex = PowerShellJson.GetInt(el, "InterfaceIndex") ?? 0,
                    NetworkCategory = cat,
                    IsDomainManaged = cat.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase)
                };
            }).ToList();
        }
        catch
        {
            return Array.Empty<NetworkConnectionProfile>();
        }
    }

    public async Task<bool> SetPrivateAsync(int interfaceIndex, CancellationToken ct = default)
        => await SetCategoryAsync(interfaceIndex, "Private", ct);

    public async Task<bool> SetCategoryAsync(int interfaceIndex, string category, CancellationToken ct = default)
    {
        if (category.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase))
            return false;
        var script = $"Set-NetConnectionProfile -InterfaceIndex {interfaceIndex} -NetworkCategory {category}; (Get-NetConnectionProfile -InterfaceIndex {interfaceIndex}).NetworkCategory";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        return result.ExitCode == 0 && result.StdOut.Contains(category, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class PowerShellSmbInspector : ISmbInspector
{
    private readonly IProcessRunner _runner;
    private readonly INetworkProbe _probe;

    public PowerShellSmbInspector(IProcessRunner runner, INetworkProbe probe)
    {
        _runner = runner;
        _probe = probe;
    }

    public async Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default)
    {
        // EnableInsecureGuestLogons is an SMB *client* setting — do not read from server config alone.
        const string script = @"
$srv = Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol,RequireSecuritySignature
$cli = Get-SmbClientConfiguration -ErrorAction Stop | Select-Object EnableInsecureGuestLogons,RequireSecuritySignature
[pscustomobject]@{
  EnableSMB1Protocol = $srv.EnableSMB1Protocol
  RequireSecuritySignature = $srv.RequireSecuritySignature
  EnableInsecureGuestLogons = $cli.EnableInsecureGuestLogons
  ClientRequireSecuritySignature = $cli.RequireSecuritySignature
} | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return new SmbConfiguration { Notes = "Unable to read SMB server+client configuration", CollectionStatus = ProbeOutcome.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var el = doc.RootElement;
            return new SmbConfiguration
            {
                EnableSMB1Protocol = el.TryGetProperty("EnableSMB1Protocol", out var s1) ? PowerShellJson.IsTruthy(s1) : null,
                RequireSecuritySignature = el.TryGetProperty("RequireSecuritySignature", out var sig) ? PowerShellJson.IsTruthy(sig) : null,
                EnableInsecureGuestLogons = el.TryGetProperty("EnableInsecureGuestLogons", out var g) ? PowerShellJson.IsTruthy(g) : null,
                CollectionStatus = ProbeOutcome.Pass,
                Notes = "Guest logons from Get-SmbClientConfiguration; SMB1/signing from Get-SmbServerConfiguration"
            };
        }
        catch
        {
            return new SmbConfiguration { CollectionStatus = ProbeOutcome.Unknown, Notes = "JSON parse failed" };
        }
    }

    public async Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default)
    {
        const string script = "Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<ShareInfo>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new ShareInfo
            {
                Name = PowerShellJson.GetString(el, "Name") ?? "",
                Path = PowerShellJson.GetString(el, "Path"),
                Description = PowerShellJson.GetString(el, "Description")
            }).ToList();
        }
        catch
        {
            return Array.Empty<ShareInfo>();
        }
    }

    public async Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default)
    {
        if (!InputValidator.TryParseHost(host, out var safe))
            return new SmbProbeResult { Target = host, Tcp445 = ProbeOutcome.Fail, Detail = "invalid host" };

        var t445 = await _probe.TcpConnectAsync(safe, 445, TimeSpan.FromSeconds(3), ct);
        var t135 = await _probe.TcpConnectAsync(safe, 135, TimeSpan.FromSeconds(3), ct);
        var unc = ProbeOutcome.NotTested;
        var detail = $"445={t445.Outcome};135={t135.Outcome}";

        if (t445.Outcome == ProbeOutcome.Pass)
        {
            // Attempt non-destructive UNC probe; distinguish auth denied vs unreachable vs not tested
            var uncPath = $@"\\{safe}\IPC$";
            var script = $@"
$path = '{uncPath.Replace("'", "''")}'
try {{
  $r = Test-Path -LiteralPath $path -ErrorAction Stop
  if ($r) {{ 'PASS' }} else {{ 'FAIL' }}
}} catch {{
  $m = $_.Exception.Message
  if ($m -match 'Access is denied|Logon failure|AccessDenied|đăng nhập|từ chối') {{ 'AUTH_DENIED' }}
  elseif ($m -match 'network path was not found|The network name cannot be found|không tìm thấy') {{ 'FAIL' }}
  else {{ 'UNKNOWN:' + $m }}
}}
";
            var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(15), ct);
            var outp = result.StdOut.Trim();
            unc = outp switch
            {
                "PASS" => ProbeOutcome.Pass,
                "FAIL" => ProbeOutcome.Fail,
                "AUTH_DENIED" => ProbeOutcome.AuthDenied,
                _ when outp.StartsWith("UNKNOWN", StringComparison.OrdinalIgnoreCase) => ProbeOutcome.Unknown,
                _ when result.ExitCode != 0 => ProbeOutcome.Unknown,
                _ => ProbeOutcome.Unknown
            };
            detail += $";UNC={unc}:{outp}";
        }
        else
        {
            detail += ";UNC=NotTested(tcp445-not-open)";
        }

        return new SmbProbeResult
        {
            Target = safe,
            Tcp445 = t445.Outcome,
            Tcp135 = t135.Outcome,
            Unc = unc,
            Detail = detail
        };
    }

    public async Task<SharingToggleState> GetSharingTogglesAsync(CancellationToken ct = default)
    {
        // Use firewall group enablement + NetConnectionProfile — not hard-coded true/true
        const string script = @"
$fps = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' }).Count
$nd = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' }).Count
# Network Discovery group id @FirewallAPI.dll,-32752
[pscustomobject]@{ FilePrintEnabled = ($fps -gt 0); NetworkDiscoveryEnabled = ($nd -gt 0); FpsCount = $fps; NdCount = $nd } | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(45), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
        {
            return new SharingToggleState
            {
                NetworkDiscovery = ProbeOutcome.Unknown,
                FileAndPrinterSharing = ProbeOutcome.Unknown,
                Detail = "collector failed or insufficient rights"
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var el = doc.RootElement;
            var fps = el.TryGetProperty("FilePrintEnabled", out var f) && PowerShellJson.IsTruthy(f);
            var nd = el.TryGetProperty("NetworkDiscoveryEnabled", out var n) && PowerShellJson.IsTruthy(n);
            return new SharingToggleState
            {
                FileAndPrinterSharing = fps ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                NetworkDiscovery = nd ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                Detail = result.StdOut.Trim()
            };
        }
        catch
        {
            return new SharingToggleState { NetworkDiscovery = ProbeOutcome.Unknown, FileAndPrinterSharing = ProbeOutcome.Unknown, Detail = "parse error" };
        }
    }
}
