using MyPC.LanPrintDoctor.Abstractions.Services;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeWindowsServiceInspector : IWindowsServiceInspector
{
    public Dictionary<string, WindowsServiceInfo> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Task<WindowsServiceInfo?> GetServiceAsync(string serviceName, CancellationToken ct = default)
        => Task.FromResult(Services.TryGetValue(serviceName, out var s) ? s : null);

    public Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(IEnumerable<string> serviceNames, CancellationToken ct = default)
    {
        var list = serviceNames.Select(n => Services.TryGetValue(n, out var s)
            ? s
            : new WindowsServiceInfo { Name = n, Status = "Missing" }).ToList();
        return Task.FromResult((IReadOnlyList<WindowsServiceInfo>)list);
    }

    public Task<bool> StartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        if (!Services.TryGetValue(serviceName, out var s)) return Task.FromResult(false);
        Services[serviceName] = new WindowsServiceInfo { Name = s.Name, DisplayName = s.DisplayName, Status = "Running", StartType = s.StartType };
        return Task.FromResult(true);
    }

    public Task<bool> RestartServiceAsync(string serviceName, CancellationToken ct = default)
        => StartServiceAsync(serviceName, ct);
}
