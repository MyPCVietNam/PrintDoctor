using MyPC.LanPrintDoctor.Abstractions.Smb;

namespace MyPC.LanPrintDoctor.Smb;

public sealed class SmbDiagnosticService
{
    private readonly ISmbInspector _inspector;
    public SmbDiagnosticService(ISmbInspector inspector) => _inspector = inspector;

    public Task<SmbProbeResult> ProbeAsync(string host, CancellationToken ct = default)
        => _inspector.ProbeRemoteAsync(host, ct);
}
