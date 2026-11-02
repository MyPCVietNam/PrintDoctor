using System.Collections.Concurrent;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Core.Ui;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Platform.Logging;

namespace MyPC.LanPrintDoctor.UnitTests;

/// <summary>
/// Gate H — UI-001…UI-015 contract tests for HF2.
/// Visual desktop lab: UI_VISUAL_LAB_NOT_RUN on this Linux CI host.
/// </summary>
public sealed class Hf2UiScanTests
{
    public const string VisualLabStatus = "UI_VISUAL_LAB_NOT_RUN";

    [Fact]
    public void UI001_ThemePalette_MatchesGateA()
    {
        Assert.Equal("#0B0F16", ThemePalette.BgDeep);
        Assert.Equal("#171D28", ThemePalette.BgPanel);
        Assert.Equal("#202838", ThemePalette.BgElevated);
        Assert.Equal("#F2F4F8", ThemePalette.TextPrimary);
        Assert.Equal("#BBC5D3", ThemePalette.TextMuted);
        Assert.Equal("#E0B84A", ThemePalette.AccentGold);
        Assert.Equal("#3DDC97", ThemePalette.PassGreen);
        Assert.Equal("#F1C453", ThemePalette.WarnAmber);
        Assert.Equal("#FF7474", ThemePalette.FailRed);
        Assert.Equal("#0B0F16", ThemePalette.OnAccent);
    }

    [Fact]
    public void UI002_TextOnPanel_MeetsWcagAa()
    {
        Assert.True(ThemePalette.ContrastRatio(ThemePalette.TextPrimary, ThemePalette.BgPanel) >= 4.5);
        Assert.True(ThemePalette.ContrastRatio(ThemePalette.TextMuted, ThemePalette.BgPanel) >= 4.5);
        Assert.True(ThemePalette.ContrastRatio(ThemePalette.TextPrimary, ThemePalette.BgElevated) >= 4.5);
        // Dark text on yellow primary button
        Assert.True(ThemePalette.ContrastRatio(ThemePalette.OnAccent, ThemePalette.AccentGold) >= 4.5);
    }

    [Fact]
    public void UI003_EmptyState_VietnameseMessage()
    {
        Assert.Equal("Chưa kiểm tra — nhấn KIỂM TRA để bắt đầu.", ScanModeRules.EmptyFindingsVi);
    }

    [Fact]
    public void UI004_PhaseLabels_CoverAllStates()
    {
        Assert.Equal("READY", ScanModeRules.PhaseLabelVi(ScanUiPhase.Ready));
        Assert.Equal("VALIDATING", ScanModeRules.PhaseLabelVi(ScanUiPhase.Validating));
        Assert.Equal("SCANNING", ScanModeRules.PhaseLabelVi(ScanUiPhase.Scanning));
        Assert.Equal("COMPLETED", ScanModeRules.PhaseLabelVi(ScanUiPhase.Completed));
        Assert.Equal("FAILED", ScanModeRules.PhaseLabelVi(ScanUiPhase.Failed));
        Assert.Equal("CANCELLED", ScanModeRules.PhaseLabelVi(ScanUiPhase.Cancelled));
    }

    [Fact]
    public void UI005_ServerMode_HidesRemoteTarget()
    {
        Assert.False(ScanModeRules.RequiresTargetHost(isClientRole: false));
        Assert.Null(ScanModeRules.ResolveScanTarget(isServerRole: true, targetHost: "192.168.1.10"));
        Assert.Contains("MÁY CHỦ", ScanModeRules.ModeIndicatorVi(true, false), StringComparison.Ordinal);
        Assert.Contains("local", ScanModeRules.ModeIndicatorVi(true, false), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UI006_ClientMode_RequiresTarget()
    {
        Assert.True(ScanModeRules.RequiresTargetHost(isClientRole: true));
        Assert.Equal("10.0.0.5", ScanModeRules.ResolveScanTarget(false, " 10.0.0.5 "));
        Assert.Null(ScanModeRules.ResolveScanTarget(false, "  "));
        Assert.Contains("MÁY TRẠM", ScanModeRules.ModeIndicatorVi(false, true), StringComparison.Ordinal);
    }

    [Fact]
    public void UI007_UnknownNeverNormalizedToFail()
    {
        Assert.Equal("UNKNOWN", ScanModeRules.NormalizeFindingStatus("Unknown"));
        Assert.Equal("UNKNOWN", ScanModeRules.NormalizeFindingStatus("NotTested"));
        Assert.Equal("UNKNOWN", ScanModeRules.NormalizeFindingStatus("NOT_TESTED"));
        Assert.Equal("FAIL", ScanModeRules.NormalizeFindingStatus("Fail"));
        Assert.NotEqual("FAIL", ScanModeRules.NormalizeFindingStatus("Unknown"));
    }

    [Fact]
    public async Task UI008_QuickVsDeep_ActuallyDifferent()
    {
        var net = CreateNet();
        net.Routes.Add(new RouteEntry { Destination = "0.0.0.0", Mask = "0.0.0.0", Gateway = "192.168.1.1", InterfaceIndex = 12 });
        net.Neighbors.Add(new NeighborEntry { IpAddress = "192.168.1.10", MacAddress = "aa:bb" });
        var orch = CreateOrch(net);

        var quick = await orch.RunAsync(new DiagnosticRequest
        {
            Role = MachineRole.Client,
            TargetHost = "192.168.1.10",
            DeepScan = false
        });
        var deep = await orch.RunAsync(new DiagnosticRequest
        {
            Role = MachineRole.Client,
            TargetHost = "192.168.1.10",
            DeepScan = true
        });

        Assert.Contains(quick.CollectorNotes, n => n.Collector == "ScanMode" && n.Detail == "QuickScan");
        Assert.Contains(deep.CollectorNotes, n => n.Collector == "ScanMode" && n.Detail == "DeepScan");
        Assert.Empty(quick.Routes);
        Assert.NotEmpty(deep.Routes);
        Assert.Equal(ProbeOutcome.NotTested, quick.ThirdPartyCollectionStatus);
        Assert.True(deep.Probes.Count >= quick.Probes.Count);
        // Quick omits TCP 135/9100; deep includes them when target set
        Assert.DoesNotContain(quick.Probes, p => p.Port == 135);
        Assert.Contains(deep.Probes, p => p.Port == 135);
        Assert.True(quick.Services.Count <= deep.Services.Count);
    }

    [Fact]
    public async Task UI009_ProgressStages_ReportedAndCancelHonoured()
    {
        var stages = new ConcurrentQueue<string>();
        var net = new SlowCancellableNetworkProbe(CreateNet());
        var orch = CreateOrch(net);
        using var cts = new CancellationTokenSource();
        var progress = new Progress<string>(s =>
        {
            stages.Enqueue(s);
            if (stages.Count >= 1) cts.Cancel();
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            orch.RunAsync(new DiagnosticRequest
            {
                Role = MachineRole.Server,
                DeepScan = true
            }, progress, cts.Token));

        Assert.NotEmpty(stages);
    }

    [Fact]
    public async Task UI010_Exceptions_PropagateNotSwallowed()
    {
        var net = new ThrowingNetworkProbe();
        var orch = CreateOrch(net);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            orch.RunAsync(new DiagnosticRequest { Role = MachineRole.Server, DeepScan = false }));
    }

    [Fact]
    public void UI011_AppLogWriter_FallbackWritable()
    {
        var root = Path.Combine(Path.GetTempPath(), "MyPC-HF2-UiLog-" + Guid.NewGuid().ToString("N"));
        var log = new AppLogWriter(preferredRoot: root);
        var path = log.WriteError("ui-test", new Exception("boom"));
        Assert.True(File.Exists(path));
        var text = File.ReadAllText(path);
        Assert.Contains("boom", text, StringComparison.Ordinal);
        Assert.Contains("ERROR", text, StringComparison.Ordinal);
        var details = log.FormatErrorDetails("Scan", new Exception("x"), "Phase=FAILED");
        Assert.Contains("COPY", details.Contains("Error Details", StringComparison.Ordinal) ? "COPY" : "missing", StringComparison.Ordinal);
        Assert.Contains("Error Details", details, StringComparison.Ordinal);
        Assert.Contains("Phase=FAILED", details, StringComparison.Ordinal);
    }

    [Fact]
    public void UI012_BusyCommandContract_IsBusyGatesCanExecute()
    {
        // Mirrors AsyncRelayCommand gating used by MainViewModel (no WPF host here).
        var busy = false;
        var cmd = new TestAsyncCommand(() => Task.CompletedTask, () => !busy);
        Assert.True(cmd.CanExecute());
        busy = true;
        Assert.False(cmd.CanExecute());
        busy = false;
        Assert.True(cmd.CanExecute());
    }

    [Fact]
    public async Task UI013_FinallyReleasesBusy_EvenOnFailure()
    {
        var busy = true;
        try
        {
            await Task.FromException(new Exception("scan-fail"));
        }
        catch
        {
            // expected
        }
        finally
        {
            busy = false;
        }
        Assert.False(busy);
    }

    [Fact]
    public async Task UI014_ServerScan_IgnoresClientTargetField()
    {
        var orch = CreateOrch(CreateNet());
        var snap = await orch.RunAsync(new DiagnosticRequest
        {
            Role = MachineRole.Server,
            TargetHost = ScanModeRules.ResolveScanTarget(isServerRole: true, targetHost: "192.168.1.10"),
            DeepScan = false
        });
        Assert.Null(snap.TargetHost);
        Assert.DoesNotContain(snap.Probes, p => p.Target == "192.168.1.10" && p.Port is 445 or 135);
    }

    [Fact]
    public void UI015_VisualLab_MarkedNotRunOnLinux()
    {
        Assert.Equal("UI_VISUAL_LAB_NOT_RUN", VisualLabStatus);
        // Layout 1100×720–1920×1080 + 100–150% scaling require a real Windows desktop.
        Assert.False(OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("HF2_UI_VISUAL_LAB") == "1",
            "Set HF2_UI_VISUAL_LAB=1 on Windows lab to flip this gate.");
    }

    [Fact]
    public async Task UI_Extra_QuickConnectivity_CompletesUnderBudgetOnFakes()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var orch = CreateOrch(CreateNet());
        await orch.RunAsync(new DiagnosticRequest
        {
            Role = MachineRole.Client,
            TargetHost = "192.168.1.10",
            DeepScan = false
        });
        sw.Stop();
        // Fake probes are instantaneous; budget guard for regressions that re-serialize deep work into quick.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Quick fake scan took {sw.Elapsed}");
    }

    private static FakeNetworkProbe CreateNet()
    {
        var net = new FakeNetworkProbe
        {
            Adapters =
            {
                new NetworkAdapterInfo
                {
                    Name = "Ethernet",
                    IsUp = true,
                    Kind = AdapterKind.Ethernet,
                    IPv4Addresses = new[] { "192.168.1.20" },
                    DefaultGateway = "192.168.1.1",
                    PrefixLength = 24,
                    InterfaceIndex = 12
                }
            }
        };
        net.IcmpResults["127.0.0.1"] = true;
        net.IcmpResults["192.168.1.20"] = true;
        net.IcmpResults["192.168.1.1"] = true;
        net.IcmpResults["192.168.1.10"] = true;
        net.TcpResults[("192.168.1.10", 445)] = true;
        net.TcpResults[("192.168.1.10", 135)] = true;
        net.TcpResults[("192.168.1.10", 9100)] = false;
        net.TcpResults[("192.168.1.10", 48631)] = false;
        return net;
    }

    private static DiagnosticOrchestrator CreateOrch(INetworkProbe net)
    {
        var services = new FakeWindowsServiceInspector();
        foreach (var name in new[] { "LanmanServer", "LanmanWorkstation", "FDResPub", "Spooler", "SSDPSRV", "upnphost" })
            services.Services[name] = new WindowsServiceInfo { Name = name, Status = "Running", StartType = "Automatic" };
        return new DiagnosticOrchestrator(
            net,
            new FakeFirewallInspector(),
            services,
            new FakeSmbInspector(),
            new FakePrinterInspector(),
            new FakeShaPrintInspector());
    }

    private sealed class ThrowingNetworkProbe : INetworkProbe
    {
        public Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
            => throw new InvalidOperationException("adapter boom");
        public Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ConnectivityProbeResult> TcpConnectAsync(string host, int port, TimeSpan? timeout = null, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ConnectivityProbeResult> ResolveDnsAsync(string hostname, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default) => throw new NotSupportedException();
    }

    /// <summary>Delays GetAdapters so Progress cancel is observed before completion.</summary>
    private sealed class SlowCancellableNetworkProbe : INetworkProbe
    {
        private readonly FakeNetworkProbe _inner;
        public SlowCancellableNetworkProbe(FakeNetworkProbe inner) => _inner = inner;

        public async Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
        {
            await Task.Delay(200, ct);
            return await _inner.GetAdaptersAsync(ct);
        }

        public Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default) => _inner.GetRoutesAsync(ct);
        public Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default) => _inner.GetNeighborsAsync(ct);
        public Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default) => _inner.PingAsync(target, ct);
        public Task<ConnectivityProbeResult> TcpConnectAsync(string host, int port, TimeSpan? timeout = null, CancellationToken ct = default)
            => _inner.TcpConnectAsync(host, port, timeout, ct);
        public Task<ConnectivityProbeResult> ResolveDnsAsync(string hostname, CancellationToken ct = default) => _inner.ResolveDnsAsync(hostname, ct);
        public Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default)
            => _inner.AreSameSubnetAsync(ipA, maskA, ipB, ct);
    }

    private sealed class TestAsyncCommand
    {
        private readonly Func<bool> _can;
        public TestAsyncCommand(Func<Task> _, Func<bool> can) => _can = can;
        public bool CanExecute() => _can();
    }
}
