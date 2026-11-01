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

    public async Task<DiagnosticSnapshot> RunAsync(DiagnosticRequest request, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(request.TargetHost) &&
            !InputValidator.TryParseHost(request.TargetHost, out var normalized))
        {
            throw new ArgumentException("Invalid target host/IP.", nameof(request));
        }
        else
        {
            normalized = request.TargetHost?.Trim();
        }

        var snap = new DiagnosticSnapshot
        {
            SessionId = $"LPD-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}",
            StartedAt = DateTimeOffset.UtcNow,
            Role = request.Role,
            TargetHost = normalized
        };

        snap.Adapters = await _network.GetAdaptersAsync(ct);
        snap.Routes = await _network.GetRoutesAsync(ct);
        snap.Neighbors = await _network.GetNeighborsAsync(ct);

        var probes = new List<ConnectivityProbeResult>();
        probes.Add(await _network.PingAsync("127.0.0.1", ct));

        foreach (var adapter in snap.Adapters.Where(a => a.IsUp && a.IPv4Addresses.Count > 0 && a.Kind != AdapterKind.Loopback))
        {
            probes.Add(await _network.PingAsync(adapter.IPv4Addresses[0], ct));
            if (!string.IsNullOrWhiteSpace(adapter.DefaultGateway))
                probes.Add(await _network.PingAsync(adapter.DefaultGateway!, ct));
        }

        if (!string.IsNullOrWhiteSpace(normalized))
        {
            probes.Add(await _network.PingAsync(normalized!, ct));
            foreach (var port in new[] { 445, 135, 9100, ShaPrintPorts.ServerTcp })
                probes.Add(await _network.TcpConnectAsync(normalized!, port, TimeSpan.FromSeconds(3), ct));

            if (!IPAddressLike(normalized!))
                probes.Add(await _network.ResolveDnsAsync(normalized!, ct));
        }

        snap.Probes = probes;
        snap.FirewallProfiles = await _firewall.GetProfilesAsync(ct);
        snap.FirewallRules = await _firewall.GetRelevantRulesAsync(ct);
        snap.ThirdPartySecurity = await _firewall.DetectThirdPartySecurityAsync(ct);

        snap.Services = await _services.GetServicesAsync(
            new[] { "LanmanServer", "LanmanWorkstation", "FDResPub", "Spooler", "SSDPSRV", "upnphost" }, ct);

        snap.SmbConfiguration = await _smb.GetConfigurationAsync(ct);
        snap.Shares = await _smb.GetSharesAsync(ct);
        snap.SharingToggles = await _smb.GetSharingTogglesAsync(ct);
        if (!string.IsNullOrWhiteSpace(normalized) && request.Role == MachineRole.Client)
            snap.SmbProbe = await _smb.ProbeRemoteAsync(normalized!, ct);

        snap.Printers = await _printers.GetPrintersAsync(ct);
        snap.ShaPrint = await _shaPrint.GetInstallInfoAsync(ct);
        snap.ShaPrintConnectivity = await _shaPrint.ProbeConnectivityAsync(normalized, ct);

        foreach (var f in _engine.Evaluate(snap))
            snap.Findings.Add(f);

        snap.CompletedAt = DateTimeOffset.UtcNow;
        return snap;
    }

    private static bool IPAddressLike(string host)
        => System.Net.IPAddress.TryParse(host, out _);
}
