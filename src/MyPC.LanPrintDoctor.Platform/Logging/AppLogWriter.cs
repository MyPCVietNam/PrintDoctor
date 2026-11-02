using System.Text;
using MyPC.LanPrintDoctor.Abstractions.Platform;

namespace MyPC.LanPrintDoctor.Platform.Logging;

/// <summary>
/// Gate F — durable app/error logs under ProgramData with LocalAppData/temp writability fallback.
/// Optional icacls hardening when an <see cref="IProcessRunner"/> is provided on Windows.
/// </summary>
public sealed class AppLogWriter
{
    private readonly object _gate = new();
    private readonly string _logDirectory;
    private readonly string _activeRoot;
    private readonly IProcessRunner? _runner;

    public AppLogWriter(string? preferredRoot = null, IProcessRunner? processRunner = null)
    {
        _runner = processRunner;
        var programData = preferredRoot
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MyPC", "LanPrintDoctor");
        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MyPC", "LanPrintDoctor");

        _activeRoot = TryEnsureWritable(programData) ?? TryEnsureWritable(local)
                      ?? Path.Combine(Path.GetTempPath(), "MyPC", "LanPrintDoctor");
        _logDirectory = Path.Combine(_activeRoot, "Logs");
        Directory.CreateDirectory(_logDirectory);
        _ = TryApplyAclAsync(_logDirectory);
    }

    public string Root => _activeRoot;
    public string LogDirectory => _logDirectory;

    public string Write(string level, string message, Exception? ex = null)
    {
        var path = Path.Combine(_logDirectory, $"app-{DateTime.UtcNow:yyyyMMdd}.log");
        var sb = new StringBuilder();
        sb.Append(DateTimeOffset.Now.ToString("O"));
        sb.Append(" [").Append(level).Append("] ");
        sb.Append(message);
        if (ex is not null)
        {
            sb.AppendLine();
            sb.Append(ex);
        }
        sb.AppendLine();

        lock (_gate)
        {
            File.AppendAllText(path, sb.ToString(), Encoding.UTF8);
        }
        return path;
    }

    public string WriteError(string message, Exception? ex = null)
        => Write("ERROR", message, ex);

    public string WriteInfo(string message)
        => Write("INFO", message);

    public string FormatErrorDetails(string context, Exception? ex, string? extra = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("MyPC LAN & Print Doctor — Error Details");
        sb.AppendLine("Version: " + (typeof(AppLogWriter).Assembly.GetName().Version?.ToString() ?? "?"));
        sb.AppendLine("Utc: " + DateTimeOffset.UtcNow.ToString("O"));
        sb.AppendLine("Machine: " + Environment.MachineName);
        sb.AppendLine("LogRoot: " + _activeRoot);
        sb.AppendLine("Context: " + context);
        if (!string.IsNullOrWhiteSpace(extra))
            sb.AppendLine(extra);
        if (ex is not null)
        {
            sb.AppendLine("--- Exception ---");
            sb.AppendLine(ex.ToString());
        }
        return sb.ToString();
    }

    private static string? TryEnsureWritable(string root)
    {
        try
        {
            var logs = Path.Combine(root, "Logs");
            Directory.CreateDirectory(logs);
            var probe = Path.Combine(logs, ".write-probe");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return root;
        }
        catch
        {
            return null;
        }
    }

    private async Task TryApplyAclAsync(string directory)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || _runner is null) return;
            var user = Environment.UserName.Replace("'", "''");
            var escaped = directory.Replace("'", "''");
            var script =
                $"$ErrorActionPreference='Stop'; icacls '{escaped}' /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' '{user}:(OI)(CI)M'; 'OK'";
            await _runner.RunAsync(
                "powershell.exe",
                new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script },
                TimeSpan.FromSeconds(15));
        }
        catch
        {
            // ACL is best-effort; writability fallback already selected the root.
        }
    }
}
