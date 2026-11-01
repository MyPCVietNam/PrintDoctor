using System.Diagnostics;
using System.Text;
using MyPC.LanPrintDoctor.Abstractions.Platform;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var reg = ct.Register(() => { try { proc.Kill(entireProcessTree: true); } catch { } });
        var completed = await Task.Run(() => proc.WaitForExit((int)(timeout ?? TimeSpan.FromSeconds(30)).TotalMilliseconds), ct);
        if (!completed)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return new ProcessResult { ExitCode = -1, StdOut = stdout.ToString(), StdErr = stderr.ToString(), TimedOut = true };
        }

        return new ProcessResult { ExitCode = proc.ExitCode, StdOut = stdout.ToString(), StdErr = stderr.ToString() };
    }
}
