namespace MyPC.LanPrintDoctor.Abstractions.Security;

public interface IElevationService
{
    bool IsAdministrator();
    Task<bool> EnsureElevatedAsync(CancellationToken ct = default);
}
