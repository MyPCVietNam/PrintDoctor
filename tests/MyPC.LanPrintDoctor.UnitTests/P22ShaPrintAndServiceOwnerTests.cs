using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

public class P22ShaPrintAndServiceOwnerTests
{
    [Fact]
    public void P22_005_ServiceFindings_HaveRepairOwner()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "s",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            TargetHost = "192.168.1.10",
            Services = new[]
            {
                new WindowsServiceInfo { Name = "LanmanServer", Status = "Stopped" },
                new WindowsServiceInfo { Name = "Spooler", Status = "Stopped" }
            }
        };
        var findings = new DecisionEngine().Evaluate(snap);
        var smb = Assert.Single(findings, f => f.Id == "SMB-002");
        Assert.Equal("SVC-LANMANSERVER-START", smb.RepairId);
        Assert.Equal(RepairOwnerRole.LocalServer, smb.RepairOwner);
        var prn = Assert.Single(findings, f => f.Id == "PRN-001");
        Assert.Equal(RepairOwnerRole.LocalAny, prn.RepairOwner);
    }

    [Fact]
    public void P22_007_ShaPrintStart_ResolveExe_RequiresPositiveIdentity()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sha-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.Null(ShaPrintStartRepair.ResolveVerifiedExecutable(dir));
            var exe = Path.Combine(dir, "ShaPrint.exe");
            File.WriteAllText(exe, "dummy");
            Assert.Equal(exe, ShaPrintStartRepair.ResolveVerifiedExecutable(dir));
            File.Delete(exe);
            File.WriteAllText(Path.Combine(dir, "notepad.exe"), "x");
            Assert.Null(ShaPrintStartRepair.ResolveVerifiedExecutable(dir));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void P22_007_ShaPrintDiscovery_SuggestsOwnedUdpRule()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "s",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            TargetHost = "192.168.1.10",
            ShaPrint = new Abstractions.ShaPrint.ShaPrintInstallInfo
            {
                Installed = true,
                ProcessRunning = true,
                InstallPath = @"C:\Program Files\ShaPrint",
                ListeningCollectionStatus = ProbeOutcome.Pass,
                ListeningEndpoints = new[] { "UDP:48633", "TCP:48631" }
            }
        };
        var findings = new DecisionEngine().Evaluate(snap);
        Assert.Contains(findings, f => f.RepairId == "FW-OWNED-SHA48631");
        Assert.Contains(findings, f => f.RepairId == "FW-OWNED-SHA48633");
    }
}
