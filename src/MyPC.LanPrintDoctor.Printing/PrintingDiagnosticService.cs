using MyPC.LanPrintDoctor.Abstractions.Printing;

namespace MyPC.LanPrintDoctor.Printing;

public sealed class PrintingDiagnosticService
{
    private readonly IPrinterInspector _inspector;
    public PrintingDiagnosticService(IPrinterInspector inspector) => _inspector = inspector;

    public Task<IReadOnlyList<PrinterInfo>> GetPrintersAsync(CancellationToken ct = default)
        => _inspector.GetPrintersAsync(ct);
}
