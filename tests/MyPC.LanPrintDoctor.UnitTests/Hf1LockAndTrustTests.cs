using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

/// <summary>
/// HF1 GATE D/E: ShaPrint executable trust + machine-wide lock fail-closed semantics (isolated locks).
/// </summary>
public class Hf1LockAndTrustTests
{
    [Fact]
    public void Lock_TwoProcessesSameUser_SecondBlocked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using var first = new MachineRepairLock(dir);
            Assert.True(first.TryAcquire(TimeSpan.Zero));
            using var second = new MachineRepairLock(dir);
            Assert.False(second.TryAcquire(TimeSpan.Zero));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Lock_AbandonedAfterDispose_AllowsReacquire()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var first = new MachineRepairLock(dir);
            Assert.True(first.TryAcquire(TimeSpan.Zero));
            first.Dispose(); // crash/restart simulation
            using var second = new MachineRepairLock(dir);
            Assert.True(second.TryAcquire(TimeSpan.FromMilliseconds(200)));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Lock_UnwritableDirectory_FailsClosed()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-lock-ro-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var chmod = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "chmod",
                    Arguments = "555 \"" + dir + "\"",
                    RedirectStandardOutput = true
                });
                chmod?.WaitForExit(3000);
            }

            using var locked = new MachineRepairLock(dir);
            // Production Global mutex is Windows-only; isolated test path uses file lock —
            // unwritable dir must fail closed (no acquire).
            var acquired = locked.TryAcquire(TimeSpan.Zero);
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                Assert.False(acquired);
        }
        finally
        {
            try
            {
                if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                {
                    var chmod = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "chmod",
                        Arguments = "755 \"" + dir + "\"",
                        RedirectStandardOutput = true
                    });
                    chmod?.WaitForExit(3000);
                }
                Directory.Delete(dir, true);
            }
            catch { /* ignore */ }
        }
    }

    [Fact]
    public void Lock_TwoRepairAttemptsAfterRestart_Serialize()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using (var a = new MachineRepairLock(dir))
            {
                Assert.True(a.TryAcquire(TimeSpan.Zero));
            }
            using (var b = new MachineRepairLock(dir))
            {
                Assert.True(b.TryAcquire(TimeSpan.Zero));
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ShaPrint_Trust_RejectsFilenameAloneOutsideInstall()
    {
        var userDir = Path.Combine(Path.GetTempPath(), "user-writable-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(userDir);
        try
        {
            File.WriteAllText(Path.Combine(userDir, "ShaPrint.exe"), "not-trusted");
            var trust = ShaPrintStartRepair.EvaluateExecutableTrust(userDir);
            // On non-Windows without ShaPrint marker path segment rules, must reject plain temp.
            Assert.False(trust.Trusted);
        }
        finally
        {
            try { Directory.Delete(userDir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ShaPrint_Trust_AcceptsMarkedTestInstallRoot()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sha-" + Guid.NewGuid().ToString("N"), "ShaPrint");
        Directory.CreateDirectory(dir);
        try
        {
            var exe = Path.Combine(dir, "ShaPrint.exe");
            File.WriteAllText(exe, "dummy");
            var trust = ShaPrintStartRepair.EvaluateExecutableTrust(dir);
            Assert.True(trust.Trusted);
            Assert.Equal(Path.GetFullPath(exe), trust.ExePath);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(dir)!, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ShaPrint_Trust_HashMismatchRejected()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sha-" + Guid.NewGuid().ToString("N"), "ShaPrint");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "ShaPrint.exe"), "dummy");
            var trust = ShaPrintStartRepair.EvaluateExecutableTrust(dir, expectedSha256: new string('0', 64));
            Assert.False(trust.Trusted);
            Assert.Contains("hash", trust.Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(dir)!, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ProductionLock_UsesStableMutexIdentity()
    {
        Assert.Equal(@"Global\MyPC.LanPrintDoctor.MachineRepair", MachineRepairLock.MutexName);
        Assert.False(string.IsNullOrWhiteSpace(MachineRepairLock.MachineWideDirectory));
    }
}
