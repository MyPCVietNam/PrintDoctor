using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Abstractions.Validation;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Orchestration;

public sealed class DiagnosticOrchestrator
{
    private readonly INetworkProbe _network;
    private readonly IFirewallInspector _firewall;
    private readonly IWindowsServiceInspector _services;
    private readonly ISmbInspector _smb;
    private readonly IPrinterInspector _printers;
    private readonly IShaPrintInspector _shaPrint;
    private readonly DecisionEngine _engine = new();

    public DiagnosticOrchestrator(
        INetworkProbe network,
        IFirewallInspector firewall,
        IWindowsServiceInspector services,
        ISmbInspector smb,
        IPrinterInspector printers,
        IShaPrintInspector shaPrint)
    {
        _network = network;
        _firewall = firewall;
        _services = services;
        _smb = smb;
        _printers = printers;
        _shaPrint = shaPrint;
    }

    public Task<DiagnosticSnapshot> RunAsync(DiagnosticRequest request, CancellationToken ct = default)
        => RunAsync(request, progress: null, ct);

    public async Task<DiagnosticSnapshot> RunAsync(
        DiagnosticRequest request,
        IProgress<string>? progress,
        CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(request.TargetHost) &&
            !InputValidator.TryParseHost(request.TargetHost, out var normalized))
        {
            throw new ArgumentException("Invalid target host/IP.", nameof(request));
        }

        normalized = string.IsNullOrWhiteSpace(request.TargetHost)
            ? null
            : (InputValidator.TryParseHost(request.TargetHost, out var n) ? n : request.TargetHost.Trim());

        var deep = request.DeepScan;
        ct.ThrowIfCancellationRequested();
        Report(progress, deep ? "Khởi tạo quét SÂU..." : "Khởi tạo quét NHANH...");

        var snap = new DiagnosticSnapshot
        {
            SessionId = $"LPD-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}",
            StartedAt = DateTimeOffset.UtcNow,
            Role = request.Role,
            TargetHost = normalized
        };

        Report(progress, "Đang đọc adapter mạng...");
        ct.ThrowIfCancellationRequested();
        snap.Adapters = await _network.GetAdaptersAsync(ct);

        if (deep)
        {
            Report(progress, "Đang thu thập routes / neighbors...");
            var routesTask = _network.GetRoutesAsync(ct);
            var neighborsTask = _network.GetNeighborsAsync(ct);
            await Task.WhenAll(routesTask, neighborsTask);
            snap.Routes = await routesTask;
            snap.Neighbors = await neighborsTask;
        }
        else
        {
            // Quick: skip heavy route/neighbor inventory
            snap.Routes = Array.Empty<RouteEntry>();
            snap.Neighbors = Array.Empty<NeighborEntry>();
        }

        Report(progress, "Đang kiểm tra kết nối (song song)...");
        ct.ThrowIfCancellationRequested();
        snap.Probes = await CollectConnectivityProbesAsync(snap, normalized, deep, ct);
        ct.ThrowIfCancellationRequested();

        if (deep)
        {
            Report(progress, "Đang đọc firewall / bảo mật bên thứ ba...");
            var profilesTask = _firewall.GetProfilesAsync(ct);
            var rulesTask = _firewall.GetRelevantRulesAsync(ct);
            var thirdTask = _firewall.DetectThirdPartySecurityAsync(ct);
            var thirdStatusTask = _firewall.GetThirdPartyCollectionStatusAsync(ct);
            await Task.WhenAll(profilesTask, rulesTask, thirdTask, thirdStatusTask);
            snap.FirewallProfiles = await profilesTask;
            snap.FirewallRules = await rulesTask;
            snap.ThirdPartySecurity = await thirdTask;
            snap.ThirdPartyCollectionStatus = await thirdStatusTask;
        }
        else
        {
            Report(progress, "Đang đọc hồ sơ firewall (nhanh)...");
            var profilesTask = _firewall.GetProfilesAsync(ct);
            var rulesTask = _firewall.GetRelevantRulesAsync(ct);
            await Task.WhenAll(profilesTask, rulesTask);
            snap.FirewallProfiles = await profilesTask;
            snap.FirewallRules = await rulesTask;
            snap.ThirdPartySecurity = Array.Empty<ThirdPartySecurityProduct>();
            snap.ThirdPartyCollectionStatus = ProbeOutcome.NotTested;
        }

        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "ThirdPartySecurity",
            Outcome = snap.ThirdPartyCollectionStatus,
            Detail = snap.ThirdPartySecurity.Count == 0 ? "none-or-unknown" : string.Join(",", snap.ThirdPartySecurity.Select(p => p.Name))
        });

        Report(progress, "Đang kiểm tra dịch vụ Windows...");
        var serviceNames = deep
            ? new[] { "LanmanServer", "LanmanWorkstation", "FDResPub", "Spooler", "SSDPSRV", "upnphost" }
            : new[] { "LanmanServer", "LanmanWorkstation", "Spooler" };
        snap.Services = await _services.GetServicesAsync(serviceNames, ct);

        Report(progress, "Đang kiểm tra SMB / chia sẻ...");
        if (deep)
        {
            var smbCfgTask = _smb.GetConfigurationAsync(ct);
            var sharesTask = _smb.GetSharesAsync(ct);
            var togglesTask = _smb.GetSharingTogglesAsync(ct);
            await Task.WhenAll(smbCfgTask, sharesTask, togglesTask);
            snap.SmbConfiguration = await smbCfgTask;
            snap.Shares = await sharesTask;
            snap.SharingToggles = await togglesTask;
        }
        else
        {
            var smbCfgTask = _smb.GetConfigurationAsync(ct);
            var togglesTask = _smb.GetSharingTogglesAsync(ct);
            await Task.WhenAll(smbCfgTask, togglesTask);
            snap.SmbConfiguration = await smbCfgTask;
            snap.Shares = Array.Empty<ShareInfo>();
            snap.SharingToggles = await togglesTask;
        }

        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "SharingToggles",
            Outcome = snap.SharingToggles is null
                ? ProbeOutcome.NotTested
                : snap.SharingToggles.NetworkDiscovery == ProbeOutcome.Unknown || snap.SharingToggles.FileAndPrinterSharing == ProbeOutcome.Unknown
                    ? ProbeOutcome.Unknown
                    : ProbeOutcome.Pass,
            Detail = snap.SharingToggles?.Detail
        });

        if (!string.IsNullOrWhiteSpace(normalized) && request.Role == MachineRole.Client)
        {
            Report(progress, $"Đang probe SMB tới {normalized}...");
            snap.SmbProbe = await _smb.ProbeRemoteAsync(normalized!, ct);
        }

        if (deep)
        {
            Report(progress, "Đang liệt kê máy in / ShaPrint...");
            var printersTask = _printers.GetPrintersAsync(ct);
            var shaTask = _shaPrint.GetInstallInfoAsync(ct);
            await Task.WhenAll(printersTask, shaTask);
            snap.Printers = await printersTask;
            snap.ShaPrint = await shaTask;
        }
        else
        {
            Report(progress, "Đang kiểm tra ShaPrint (nhanh)...");
            snap.Printers = Array.Empty<PrinterInfo>();
            snap.ShaPrint = await _shaPrint.GetInstallInfoAsync(ct);
        }

        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "ShaPrintListening",
            Outcome = snap.ShaPrint?.ListeningCollectionStatus ?? ProbeOutcome.NotTested,
            Detail = snap.ShaPrint is null ? "skipped" : string.Join(",", snap.ShaPrint.ListeningEndpoints)
        });

        Report(progress, "Đang kiểm tra kết nối ShaPrint...");
        snap.ShaPrintConnectivity = await _shaPrint.ProbeConnectivityAsync(normalized, ct);

        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "Routes",
            Outcome = deep
                ? (snap.Routes.Count > 0 ? ProbeOutcome.Pass : ProbeOutcome.Unknown)
                : ProbeOutcome.NotTested,
            Detail = deep ? $"count={snap.Routes.Count}" : "quick-scan-skipped"
        });
        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "Neighbors",
            Outcome = deep
                ? (snap.Neighbors.Count > 0 ? ProbeOutcome.Pass : ProbeOutcome.Unknown)
                : ProbeOutcome.NotTested,
            Detail = deep ? $"count={snap.Neighbors.Count}" : "quick-scan-skipped"
        });
        snap.CollectorNotes.Add(new CollectorStatusNote
        {
            Collector = "ScanMode",
            Outcome = ProbeOutcome.Pass,
            Detail = deep ? "DeepScan" : "QuickScan"
        });

        Report(progress, "Đang đánh giá rule engine...");
        foreach (var f in _engine.Evaluate(snap))
            snap.Findings.Add(f);

        snap.CompletedAt = DateTimeOffset.UtcNow;
        Report(progress, "Hoàn tất thu thập.");
        return snap;
    }

    private async Task<IReadOnlyList<ConnectivityProbeResult>> CollectConnectivityProbesAsync(
        DiagnosticSnapshot snap,
        string? normalized,
        bool deep,
        CancellationToken ct)
    {
        var tasks = new List<Task<ConnectivityProbeResult>>
        {
            _network.PingAsync("127.0.0.1", ct)
        };

        foreach (var adapter in snap.Adapters.Where(a => a.IsUp && a.IPv4Addresses.Count > 0 && a.Kind != AdapterKind.Loopback))
        {
            tasks.Add(_network.PingAsync(adapter.IPv4Addresses[0], ct));
            if (!string.IsNullOrWhiteSpace(adapter.DefaultGateway))
                tasks.Add(_network.PingAsync(adapter.DefaultGateway!, ct));
        }

        if (!string.IsNullOrWhiteSpace(normalized))
        {
            tasks.Add(_network.PingAsync(normalized!, ct));

            // Quick: connectivity-critical ports only (445 + ShaPrint TCP).
            // Deep: also 135 + 9100.
            var ports = deep
                ? new[] { 445, 135, 9100, ShaPrintPorts.ServerTcp }
                : new[] { 445, ShaPrintPorts.ServerTcp };
            var tcpTimeout = deep ? TimeSpan.FromSeconds(3) : TimeSpan.FromSeconds(2);
            foreach (var port in ports)
                tasks.Add(_network.TcpConnectAsync(normalized!, port, tcpTimeout, ct));

            if (!IPAddressLike(normalized!))
                tasks.Add(_network.ResolveDnsAsync(normalized!, ct));
        }

        return await Task.WhenAll(tasks);
    }

    private static void Report(IProgress<string>? progress, string stage)
        => progress?.Report(stage);

    private static bool IPAddressLike(string host)
        => System.Net.IPAddress.TryParse(host, out _);
}
