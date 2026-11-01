using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.IntegrationTests;

public class SafeRepairIntegrationTests
{
    [Fact]
    public async Task Repair_RequiresExplicitConfirmation()
    {
        var services = new FakeWindowsServiceInspector();
        services.Services["Spooler"] = new WindowsServiceInfo { Name = "Spooler", Status = "Stopped", StartType = "Automatic" };
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new ServiceStartRepair("Spooler", "SVC-SPOOLER-START", "Start Spooler", services, elev);
        var exec = new RepairExecutor(new RepairJournal(TempDir()));
        var result = await exec.ExecuteAsync(op, userConfirmed: false);
        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.False(result.Applied);
        Assert.Equal("Stopped", services.Services["Spooler"].Status);
    }

    [Fact]
    public async Task ServiceRepair_StartsAndVerifies()
    {
        var services = new FakeWindowsServiceInspector();
        services.Services["Spooler"] = new WindowsServiceInfo { Name = "Spooler", Status = "Stopped", StartType = "Automatic" };
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new ServiceStartRepair("Spooler", "SVC-SPOOLER-START", "Start Spooler", services, elev);
        var exec = new RepairExecutor(new RepairJournal(TempDir()));
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(result.Applied);
        Assert.True(result.Verified);
        Assert.Equal(DiagnosticStatus.Pass, result.Status);
        Assert.Equal("Running", services.Services["Spooler"].Status);
    }

    [Fact]
    public async Task ReportExporter_WritesEvidenceZip()
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
                    PrefixLength = 24,
                    DefaultGateway = "192.168.1.1"
                }
            },
            IcmpResults =
            {
                ["127.0.0.1"] = true,
                ["192.168.1.20"] = true,
                ["192.168.1.1"] = true,
                ["192.168.1.10"] = false
            },
            TcpResults =
            {
                [("192.168.1.10", 445)] = false,
                [("192.168.1.10", 135)] = false,
                [("192.168.1.10", 9100)] = false,
                [("192.168.1.10", 48631)] = false
            }
        };

        var orch = new DiagnosticOrchestrator(net, new FakeFirewallInspector(), new FakeWindowsServiceInspector(),
            new FakeSmbInspector(), new FakePrinterInspector(), new FakeShaPrintInspector());
        var snap = await orch.RunAsync(new DiagnosticRequest { Role = MachineRole.Client, TargetHost = "192.168.1.10" });

        var exporter = new ReportExporter
        {
            DefaultRoot = Path.Combine(Path.GetTempPath(), "lpd-reports-" + Guid.NewGuid().ToString("N"))
        };
        var zip = await exporter.ExportZipAsync(snap, redact: false);
        Assert.True(File.Exists(zip));
        Assert.True(new FileInfo(zip).Length > 0);
    }

    [Fact]
    public async Task SafeIsolation_NoDestructiveNetworkResetsInRepairSurface()
    {
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new NetworkProfilePrivateRepair(elev);
        var preview = await op.PreviewChangesAsync();
        var blob = string.Join(" ", preview.Changes) + " " + preview.Description;
        Assert.DoesNotContain("winsock reset", blob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ip reset", blob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("disable firewall", blob, StringComparison.OrdinalIgnoreCase);
    }

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-it-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
