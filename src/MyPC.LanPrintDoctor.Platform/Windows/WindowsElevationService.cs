using System.Runtime.InteropServices;
using System.Security.Principal;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class WindowsElevationService : IElevationService
{
    public bool IsAdministrator()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public Task<bool> EnsureElevatedAsync(CancellationToken ct = default)
        => Task.FromResult(IsAdministrator());
}
