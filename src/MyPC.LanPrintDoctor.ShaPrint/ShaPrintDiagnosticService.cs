using MyPC.LanPrintDoctor.Abstractions.ShaPrint;

namespace MyPC.LanPrintDoctor.ShaPrint;

public sealed class ShaPrintDiagnosticService
{
    private readonly IShaPrintInspector _inspector;
    public ShaPrintDiagnosticService(IShaPrintInspector inspector) => _inspector = inspector;

    public Task<ShaPrintInstallInfo> GetInstallInfoAsync(CancellationToken ct = default)
        => _inspector.GetInstallInfoAsync(ct);

    public static IReadOnlyList<int> ExpectedTcpPorts { get; } = new[] { ShaPrintPorts.ServerTcp, ShaPrintPorts.ClientLoopbackTcp };
    public static int ExpectedUdpPort => ShaPrintPorts.DiscoveryUdp;
}
