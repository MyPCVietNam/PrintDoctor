using MyPC.LanPrintDoctor.Abstractions.Platform;

namespace MyPC.LanPrintDoctor.IntegrationTests;

/// <summary>
/// Captures PowerShell scripts without executing them — safe in CI (no firewall mutation).
/// </summary>
public sealed class RecordingProcessRunner : IProcessRunner
{
    public List<(string FileName, IReadOnlyList<string> Args)> Calls { get; } = new();
    public Func<string, string, ProcessResult>? Handler { get; set; }

    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        Calls.Add((fileName, arguments));
        var script = arguments.LastOrDefault() ?? "";
        if (Handler is not null)
            return Task.FromResult(Handler(fileName, script));
        return Task.FromResult(new ProcessResult { ExitCode = 0, StdOut = "CHANGED:FPS-ICMP4-ERQ-In" });
    }

    public IEnumerable<string> Scripts =>
        Calls.Select(c => c.Args.LastOrDefault() ?? "");
}
