using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeElevationService : IElevationService
{
    public bool IsAdmin { get; set; }
    public bool IsAdministrator() => IsAdmin;
    public Task<bool> EnsureElevatedAsync(CancellationToken ct = default) => Task.FromResult(IsAdmin);
}
