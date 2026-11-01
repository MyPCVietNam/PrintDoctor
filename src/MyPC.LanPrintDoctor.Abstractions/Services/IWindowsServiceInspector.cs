namespace MyPC.LanPrintDoctor.Abstractions.Services;

public sealed class WindowsServiceInfo
{
    public required string Name { get; init; }
    public string? DisplayName { get; init; }
    public string Status { get; init; } = "Unknown";
    public string StartType { get; init; } = "Unknown";
}

public interface IWindowsServiceInspector
{
    Task<WindowsServiceInfo?> GetServiceAsync(string serviceName, CancellationToken ct = default);
    Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(IEnumerable<string> serviceNames, CancellationToken ct = default);
    Task<bool> StartServiceAsync(string serviceName, CancellationToken ct = default);
    Task<bool> RestartServiceAsync(string serviceName, CancellationToken ct = default);
}
