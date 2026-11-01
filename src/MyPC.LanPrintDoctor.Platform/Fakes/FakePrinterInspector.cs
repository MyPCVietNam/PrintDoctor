using MyPC.LanPrintDoctor.Abstractions.Printing;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakePrinterInspector : IPrinterInspector
{
    public List<PrinterInfo> Printers { get; set; } = new();
    public Dictionary<(string, int), bool> Ports { get; set; } = new();

    public Task<IReadOnlyList<PrinterInfo>> GetPrintersAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<PrinterInfo>)Printers);

    public Task<IReadOnlyList<PrintQueueJob>> GetJobsAsync(string printerName, CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<PrintQueueJob>)Array.Empty<PrintQueueJob>());

    public Task<bool> IsPortReachableAsync(string host, int port, CancellationToken ct = default)
        => Task.FromResult(Ports.TryGetValue((host, port), out var v) && v);
}
