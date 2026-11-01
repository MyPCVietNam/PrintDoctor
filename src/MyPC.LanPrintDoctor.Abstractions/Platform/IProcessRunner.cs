namespace MyPC.LanPrintDoctor.Abstractions.Platform;

public sealed class ProcessResult
{
    public int ExitCode { get; init; }
    public string StdOut { get; init; } = "";
    public string StdErr { get; init; } = "";
    public bool TimedOut { get; init; }
}

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default);
}
