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

namespace MyPC.LanPrintDoctor.Platform.Windows;

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
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
            {
                var status = PowerShellJson.GetString(el, "PrinterStatus") ?? "";
                return new PrinterInfo
                {
                    Name = PowerShellJson.GetString(el, "Name") ?? "",
                    DriverName = PowerShellJson.GetString(el, "DriverName"),
                    PortName = PowerShellJson.GetString(el, "PortName"),
                    Shared = el.TryGetProperty("Shared", out var sh) && PowerShellJson.IsTruthy(sh),
                    ShareName = PowerShellJson.GetString(el, "ShareName"),
                    Offline = PowerShellJson.IsPrinterOffline(status),
                    StatusText = status
                };
            }).ToList();
        }
        catch
        {
            return Array.Empty<PrinterInfo>();
        }
    }

    public Task<IReadOnlyList<PrintQueueJob>> GetJobsAsync(string printerName, CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<PrintQueueJob>)Array.Empty<PrintQueueJob>());

    public async Task<bool> IsPortReachableAsync(string host, int port, CancellationToken ct = default)
        => (await _probe.TcpConnectAsync(host, port, TimeSpan.FromSeconds(3), ct)).Outcome == ProbeOutcome.Pass;
}

public sealed class WindowsShaPrintInspector : IShaPrintInspector
{
    private readonly INetworkProbe _probe;
    private readonly IProcessRunner _runner;

    public WindowsShaPrintInspector(INetworkProbe probe, IProcessRunner runner)
    {
        _probe = probe;
        _runner = runner;
    }

    public async Task<ShaPrintInstallInfo> GetInstallInfoAsync(CancellationToken ct = default)
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

        var listening = await CollectListeningAsync(ct);
        var runKey = await HasStartupAsync(ct);

        return new ShaPrintInstallInfo
        {
            Installed = path is not null || procs.Count > 0,
            InstallPath = path,
            ProcessRunning = procs.Count > 0,
            ProcessId = procs.FirstOrDefault()?.Id,
            StartsWithWindows = runKey,
            ListeningEndpoints = listening.Endpoints,
            ListeningCollectionStatus = listening.Status
        };
    }

    public async Task<ShaPrintConnectivity> ProbeConnectivityAsync(string? serverHost, CancellationToken ct = default)
    {
        var detail = new List<string>();
        var server = ProbeOutcome.NotTested;
        if (!string.IsNullOrWhiteSpace(serverHost))
        {
            var r = await _probe.TcpConnectAsync(serverHost!, ShaPrintPorts.ServerTcp, TimeSpan.FromSeconds(3), ct);
            server = r.Outcome;
            detail.Add($"server:{ShaPrintPorts.ServerTcp}={server}:{r.Detail}");
        }

        var loop = await _probe.TcpConnectAsync("127.0.0.1", ShaPrintPorts.ClientLoopbackTcp, TimeSpan.FromSeconds(1), ct);
        detail.Add($"loopback:{ShaPrintPorts.ClientLoopbackTcp}={loop.Outcome}");

        var discovery = await ProbeUdpListenLocalAsync(ct);
        detail.Add($"discoveryUdp:{ShaPrintPorts.DiscoveryUdp}={discovery}");

        return new ShaPrintConnectivity
        {
            ServerEndpoint = server,
            ClientProxy = loop.Outcome,
            DiscoveryPort = discovery,
            Detail = string.Join("; ", detail)
        };
    }

    public async Task<IReadOnlyList<string>> GetRelatedFirewallRulesAsync(CancellationToken ct = default)
    {
        const string script = @"Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ShaPrint|48631|48633' -or $_.Name -match 'ShaPrint' } | Select-Object -ExpandProperty DisplayName";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<string>();
        return result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private async Task<(IReadOnlyList<string> Endpoints, ProbeOutcome Status)> CollectListeningAsync(CancellationToken ct)
    {
        // Only ShaPrint executable identity — NEVER assume PrintBridge == ShaPrint.
        var script = $@"
$ErrorActionPreference = 'Stop'
function Test-ShaPrintProc($p) {{
  try {{
    $path = $p.Path
    if (-not $path) {{ $path = (Get-CimInstance Win32_Process -Filter (""ProcessId="" + $p.Id) -ErrorAction SilentlyContinue).ExecutablePath }}
    if (-not $path) {{ return $false }}
    $name = [IO.Path]::GetFileNameWithoutExtension($path)
    return ($name -match '^(?i)ShaPrint') -and ($path -match '(?i)ShaPrint') -and ($path -notmatch '(?i)PrintBridge')
  }} catch {{ return $false }}
}}
$sha = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {{ Test-ShaPrintProc $_ }})
$shaPids = @($sha | Select-Object -ExpandProperty Id)
$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object {{ $_.LocalPort -in {ShaPrintPorts.ServerTcp},{ShaPrintPorts.ClientLoopbackTcp} }} |
  ForEach-Object {{
    $own = $_.OwningProcess
    if ($shaPids -contains $own) {{ 'TCP:' + $_.LocalAddress + ':' + $_.LocalPort + ':pid=' + $own }}
    else {{ 'FOREIGN_PROCESS:PORT_CONFLICT:' + $_.LocalAddress + ':' + $_.LocalPort + ':pid=' + $own }}
  }}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
  Where-Object {{ $_.LocalPort -eq {ShaPrintPorts.DiscoveryUdp} }} |
  ForEach-Object {{
    $own = $_.OwningProcess
    if ($shaPids -contains $own) {{ 'UDP:' + $_.LocalAddress + ':' + $_.LocalPort + ':pid=' + $own }}
    else {{ 'FOREIGN_PROCESS:PORT_CONFLICT:' + $_.LocalAddress + ':' + $_.LocalPort + ':pid=' + $own }}
  }}
@($tcp + $udp) | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0)
            return (Array.Empty<string>(), ProbeOutcome.Unknown);
        if (string.IsNullOrWhiteSpace(result.StdOut) || result.StdOut.Trim() is "null" or "[]")
            return (Array.Empty<string>(), ProbeOutcome.Pass);

        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var all = PowerShellJson.Enumerate(doc.RootElement)
                .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : e.ToString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToList();
            // FOREIGN_PROCESS / PORT_CONFLICT are evidence of conflict — not ShaPrint PASS listeners
            var owned = all.Where(s => !s.StartsWith("FOREIGN", StringComparison.OrdinalIgnoreCase)).ToList();
            return (owned, ProbeOutcome.Pass);
        }
        catch
        {
            var line = result.StdOut.Trim().Trim('"');
            if (line.StartsWith("FOREIGN", StringComparison.OrdinalIgnoreCase))
                return (Array.Empty<string>(), ProbeOutcome.Pass);
            if (!string.IsNullOrWhiteSpace(line))
                return (new[] { line }, ProbeOutcome.Pass);
            return (Array.Empty<string>(), ProbeOutcome.Unknown);
        }
    }

    private async Task<ProbeOutcome> ProbeUdpListenLocalAsync(CancellationToken ct)
    {
        var script = $"if (Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalPort -eq {ShaPrintPorts.DiscoveryUdp} }}) {{ 'PASS' }} else {{ 'FAIL' }}";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(15), ct);
        if (result.ExitCode != 0) return ProbeOutcome.Unknown;
        return result.StdOut.Contains("PASS", StringComparison.OrdinalIgnoreCase) ? ProbeOutcome.Pass
            : result.StdOut.Contains("FAIL", StringComparison.OrdinalIgnoreCase) ? ProbeOutcome.Fail
            : ProbeOutcome.Unknown;
    }

    private async Task<bool> HasStartupAsync(CancellationToken ct)
    {
        const string script = @"$r = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue; if ($r -and ($r.PSObject.Properties.Name -match 'ShaPrint')) { 'YES' } else { 'NO' }";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(10), ct);
        return result.StdOut.Contains("YES", StringComparison.OrdinalIgnoreCase);
    }
}

public static class PlatformComposition
{
    public static (
        INetworkProbe net,
        IFirewallInspector fw,
        IWindowsServiceInspector svc,
        ISmbInspector smb,
        IPrinterInspector prn,
        IShaPrintInspector sha,
        IElevationService elev,
        INetworkProfileService profiles)
        CreateWindowsStack()
    {
        var runner = new ProcessRunner();
        var net = new WindowsNetworkProbe(runner);
        var elev = new WindowsElevationService();
        var fw = new PowerShellFirewallInspector(runner);
        var profiles = new PowerShellNetworkProfileService(runner);
        return (net, fw,
            new PowerShellWindowsServiceInspector(runner),
            new PowerShellSmbInspector(runner, net),
            new PowerShellPrinterInspector(runner, net),
            new WindowsShaPrintInspector(net, runner),
            elev,
            profiles);
    }
}
