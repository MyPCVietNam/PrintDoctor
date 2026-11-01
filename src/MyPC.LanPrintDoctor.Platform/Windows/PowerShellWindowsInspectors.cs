using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class PowerShellWindowsServiceInspector : IWindowsServiceInspector
{
    private readonly IProcessRunner _runner;
    public PowerShellWindowsServiceInspector(IProcessRunner runner) => _runner = runner;

    public async Task<WindowsServiceInfo?> GetServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var all = await GetServicesAsync(new[] { serviceName }, ct);
        return all.FirstOrDefault();
    }

    public async Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(IEnumerable<string> serviceNames, CancellationToken ct = default)
    {
        var names = string.Join("','", serviceNames.Select(EscapePsSingleQuoted));
        var script = $"Get-Service -Name @('{names}') -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return serviceNames.Select(n => new WindowsServiceInfo { Name = n, Status = "Unknown" }).ToList();
        return ParseServices(result.StdOut);
    }

    public async Task<bool> StartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Start-Service -Name '{EscapePsSingleQuoted(serviceName)}'";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0;
    }

    public async Task<bool> RestartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Restart-Service -Name '{EscapePsSingleQuoted(serviceName)}' -Force";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0;
    }

    private static string EscapePsSingleQuoted(string value) => value.Replace("'", "''");

    private static IReadOnlyList<WindowsServiceInfo> ParseServices(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var list = new List<WindowsServiceInfo>();
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in doc.RootElement.EnumerateArray())
                list.Add(FromElement(el));
        }
        else list.Add(FromElement(doc.RootElement));
        return list;
    }

    private static WindowsServiceInfo FromElement(JsonElement el)
        => new()
        {
            Name = el.GetProperty("Name").GetString() ?? "",
            DisplayName = el.TryGetProperty("DisplayName", out var d) ? d.GetString() : null,
            Status = el.TryGetProperty("Status", out var s) ? s.ToString() : "Unknown",
            StartType = el.TryGetProperty("StartType", out var t) ? t.ToString() : "Unknown"
        };
}

public sealed class PowerShellFirewallInspector : IFirewallInspector
{
    private readonly IProcessRunner _runner;
    public PowerShellFirewallInspector(IProcessRunner runner) => _runner = runner;

    public async Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<FirewallProfileState>();
        using var doc = JsonDocument.Parse(result.StdOut);
        var list = new List<FirewallProfileState>();
        foreach (var el in Enumerate(doc.RootElement))
        {
            var name = el.GetProperty("Name").GetString() ?? "";
            list.Add(new FirewallProfileState
            {
                Profile = name.ToLowerInvariant() switch
                {
                    "domain" => FirewallProfileKind.Domain,
                    "private" => FirewallProfileKind.Private,
                    _ => FirewallProfileKind.Public
                },
                Enabled = el.TryGetProperty("Enabled", out var en) && IsTruthy(en),
                DefaultInboundAction = el.TryGetProperty("DefaultInboundAction", out var i) ? i.ToString() : null,
                DefaultOutboundAction = el.TryGetProperty("DefaultOutboundAction", out var o) ? o.ToString() : null
            });
        }
        return list;
    }

    public async Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
    {
        const string script = @"Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Echo|File and Printer|SMB|ShaPrint|48631|48633|RPC' } | Select-Object DisplayName,Enabled,Direction,Action,Profile -First 80 | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(45), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<FirewallRuleInfo>();
        using var doc = JsonDocument.Parse(result.StdOut);
        var list = new List<FirewallRuleInfo>();
        foreach (var el in Enumerate(doc.RootElement))
        {
            list.Add(new FirewallRuleInfo
            {
                Name = el.TryGetProperty("DisplayName", out var n) ? n.GetString() ?? "" : "",
                Enabled = el.TryGetProperty("Enabled", out var en) && IsTruthy(en),
                Direction = el.TryGetProperty("Direction", out var d) ? d.ToString() : "",
                Action = el.TryGetProperty("Action", out var a) ? a.ToString() : "",
                Profiles = el.TryGetProperty("Profile", out var p) ? p.ToString() : null
            });
        }
        return list;
    }

    public Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<ThirdPartySecurityProduct>)Array.Empty<ThirdPartySecurityProduct>());

    private static IEnumerable<JsonElement> Enumerate(JsonElement root)
        => root.ValueKind == JsonValueKind.Array ? root.EnumerateArray() : new[] { root };

    private static bool IsTruthy(JsonElement el)
        => el.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => el.GetInt32() != 0,
            JsonValueKind.String => el.GetString() is "True" or "true" or "1" or "Enabled",
            _ => false
        };
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
        const string script = "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return new SmbConfiguration { Notes = "Unable to read SMB configuration" };
        using var doc = JsonDocument.Parse(result.StdOut);
        var el = doc.RootElement;
        return new SmbConfiguration
        {
            EnableSMB1Protocol = el.TryGetProperty("EnableSMB1Protocol", out var s1) ? s1.GetBoolean() : null,
            RequireSecuritySignature = el.TryGetProperty("RequireSecuritySignature", out var sig) ? sig.GetBoolean() : null
        };
    }

    public async Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default)
    {
        const string script = "Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<ShareInfo>();
        using var doc = JsonDocument.Parse(result.StdOut);
        var list = new List<ShareInfo>();
        foreach (var el in doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray() : new[] { doc.RootElement }.AsEnumerable())
        {
            list.Add(new ShareInfo
            {
                Name = el.GetProperty("Name").GetString() ?? "",
                Path = el.TryGetProperty("Path", out var p) ? p.GetString() : null,
                Description = el.TryGetProperty("Description", out var d) ? d.GetString() : null
            });
        }
        return list;
    }

    public async Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default)
    {
        var t445 = await _probe.TcpConnectAsync(host, 445, TimeSpan.FromSeconds(3), ct);
        var t135 = await _probe.TcpConnectAsync(host, 135, TimeSpan.FromSeconds(3), ct);
        return new SmbProbeResult
        {
            Target = host,
            Tcp445Open = t445.Success,
            Tcp135Open = t135.Success,
            UncReachable = false, // UNC auth probe is optional and may require credentials; leave false unless enriched
            Detail = $"445={t445.Detail};135={t135.Detail}"
        };
    }

    public Task<(bool NetworkDiscovery, bool FileAndPrinterSharing)> GetSharingTogglesAsync(CancellationToken ct = default)
        => Task.FromResult((true, true)); // detailed profile toggles via advanced sharing API on Windows enricher
}

public sealed class PowerShellPrinterInspector : IPrinterInspector
{
    private readonly IProcessRunner _runner;
    private readonly INetworkProbe _probe;
    public PowerShellPrinterInspector(IProcessRunner runner, INetworkProbe probe)
    {
        _runner = runner;
        _probe = probe;
    }

    public async Task<IReadOnlyList<PrinterInfo>> GetPrintersAsync(CancellationToken ct = default)
    {
        const string script = "Get-Printer -ErrorAction SilentlyContinue | Select-Object Name,DriverName,PortName,Shared,ShareName,PrinterStatus,Type | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(45), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<PrinterInfo>();
        using var doc = JsonDocument.Parse(result.StdOut);
        var list = new List<PrinterInfo>();
        foreach (var el in doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray() : new[] { doc.RootElement }.AsEnumerable())
        {
            var status = el.TryGetProperty("PrinterStatus", out var st) ? st.ToString() : "";
            list.Add(new PrinterInfo
            {
                Name = el.GetProperty("Name").GetString() ?? "",
                DriverName = el.TryGetProperty("DriverName", out var dr) ? dr.GetString() : null,
                PortName = el.TryGetProperty("PortName", out var po) ? po.GetString() : null,
                Shared = el.TryGetProperty("Shared", out var sh) && sh.ValueKind == JsonValueKind.True,
                ShareName = el.TryGetProperty("ShareName", out var sn) ? sn.GetString() : null,
                Offline = status.Contains("Offline", StringComparison.OrdinalIgnoreCase),
                StatusText = status
            });
        }
        return list;
    }

    public Task<IReadOnlyList<PrintQueueJob>> GetJobsAsync(string printerName, CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<PrintQueueJob>)Array.Empty<PrintQueueJob>());

    public async Task<bool> IsPortReachableAsync(string host, int port, CancellationToken ct = default)
        => (await _probe.TcpConnectAsync(host, port, TimeSpan.FromSeconds(3), ct)).Success;
}

public sealed class WindowsShaPrintInspector : IShaPrintInspector
{
    private readonly INetworkProbe _probe;
    public WindowsShaPrintInspector(INetworkProbe probe) => _probe = probe;

    public Task<ShaPrintInstallInfo> GetInstallInfoAsync(CancellationToken ct = default)
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ShaPrint"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ShaPrint"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "sha-print")
        };
        var path = candidates.FirstOrDefault(Directory.Exists);
        var procs = System.Diagnostics.Process.GetProcesses().Where(p =>
        {
            try { return p.ProcessName.Contains("shaprint", StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }).ToList();

        return Task.FromResult(new ShaPrintInstallInfo
        {
            Installed = path is not null || procs.Count > 0,
            InstallPath = path,
            ProcessRunning = procs.Count > 0,
            ProcessId = procs.FirstOrDefault()?.Id,
            ListeningEndpoints = Array.Empty<string>()
        });
    }

    public async Task<ShaPrintConnectivity> ProbeConnectivityAsync(string? serverHost, CancellationToken ct = default)
    {
        var detail = new List<string>();
        var serverOk = false;
        if (!string.IsNullOrWhiteSpace(serverHost))
        {
            var r = await _probe.TcpConnectAsync(serverHost!, ShaPrintPorts.ServerTcp, TimeSpan.FromSeconds(3), ct);
            serverOk = r.Success;
            detail.Add($"server:{ShaPrintPorts.ServerTcp}={(r.Success ? "PASS" : "FAIL")}:{r.Detail}");
        }
        var loop = await _probe.TcpConnectAsync("127.0.0.1", ShaPrintPorts.ClientLoopbackTcp, TimeSpan.FromSeconds(1), ct);
        detail.Add($"loopback:{ShaPrintPorts.ClientLoopbackTcp}={(loop.Success ? "PASS" : "FAIL")}");
        return new ShaPrintConnectivity
        {
            ServerEndpointReachable = serverOk,
            ClientProxyListening = loop.Success,
            DiscoveryPortOpen = false,
            Detail = string.Join("; ", detail)
        };
    }

    public Task<IReadOnlyList<string>> GetRelatedFirewallRulesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<string>)Array.Empty<string>());
}

public static class PlatformComposition
{
    public static (INetworkProbe net, IFirewallInspector fw, IWindowsServiceInspector svc, ISmbInspector smb, IPrinterInspector prn, IShaPrintInspector sha, IElevationService elev)
        CreateWindowsStack()
    {
        var runner = new ProcessRunner();
        var net = new WindowsNetworkProbe();
        var elev = new WindowsElevationService();
        return (net,
            new PowerShellFirewallInspector(runner),
            new PowerShellWindowsServiceInspector(runner),
            new PowerShellSmbInspector(runner, net),
            new PowerShellPrinterInspector(runner, net),
            new WindowsShaPrintInspector(net),
            elev);
    }
}
