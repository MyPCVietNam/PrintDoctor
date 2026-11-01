namespace MyPC.LanPrintDoctor.Abstractions.Printing;

public sealed class PrinterInfo
{
    public required string Name { get; init; }
    public string? DriverName { get; init; }
    public string? PortName { get; init; }
    public bool Shared { get; init; }
    public string? ShareName { get; init; }
    public bool Offline { get; init; }
    public bool IsLocal { get; init; }
    public bool IsNetwork { get; init; }
    public int JobCount { get; init; }
    public string? StatusText { get; init; }
}

public sealed class PrintQueueJob
{
    public int Id { get; init; }
    public string? Document { get; init; }
    public string? Status { get; init; }
}

public interface IPrinterInspector
{
    Task<IReadOnlyList<PrinterInfo>> GetPrintersAsync(CancellationToken ct = default);
    Task<IReadOnlyList<PrintQueueJob>> GetJobsAsync(string printerName, CancellationToken ct = default);
    Task<bool> IsPortReachableAsync(string host, int port, CancellationToken ct = default);
}
