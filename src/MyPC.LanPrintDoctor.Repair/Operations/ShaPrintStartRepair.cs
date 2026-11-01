using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Starts a positively identified ShaPrint executable. Never kills a foreign process.
/// Does not claim IPPS operational merely because the process started.
/// </summary>
public sealed class ShaPrintStartRepair : IRepairOperation
{
    private readonly IShaPrintInspector _sha;
    private readonly IProcessRunner _runner;
    private readonly IElevationService _elevation;
    private string? _exePath;
    private string? _beforeJson;

    public ShaPrintStartRepair(IShaPrintInspector sha, IProcessRunner runner, IElevationService elevation)
    {
        _sha = sha;
        _runner = runner;
        _elevation = elevation;
    }

    public string OperationId => "SHA-START-PROCESS";
    public string Title => "Start verified ShaPrint process";
    public bool IsImplemented => true;
    public bool SupportsRollback => false; // will not kill the process on rollback
    public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalServer;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

    public async Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Administrator required to start ShaPrint as a service-like host process." };

        var info = await _sha.GetInstallInfoAsync(ct);
        if (!info.Installed)
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "ShaPrint not installed — refusing start." };
        if (info.ProcessRunning)
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "ALREADY_RUNNING: ShaPrint process already present — no start/kill." };

        _exePath = ResolveVerifiedExecutable(info.InstallPath);
        if (_exePath is null)
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "EXECUTABLE_NOT_VERIFIED: could not positively identify ShaPrint.exe under InstallPath — repair disabled."
            };

        // Foreign listener on 48631 without our process → refuse
        if (info.ListeningEndpoints.Any(e => e.Contains("FOREIGN", StringComparison.OrdinalIgnoreCase)))
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "FOREIGN_PID: TCP 48631 owned by another process — refusing start/kill."
            };

        return new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = true };
    }

    public async Task CollectEvidenceAsync(CancellationToken ct = default)
    {
        var info = await _sha.GetInstallInfoAsync(ct);
        _beforeJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            info.Installed,
            info.InstallPath,
            info.ProcessRunning,
            info.ProcessId,
            info.ListeningEndpoints,
            exe = _exePath
        });
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = $"Start verified ShaPrint executable '{_exePath}'. Will not kill foreign PIDs. Will not open firewall. Process start ≠ IPPS operational.",
            Changes = new[] { $"Start-Process '{_exePath}'" },
            Risks = new[] { "Starts a user-facing host process", "Rollback will NOT terminate the process" },
            Reversible = false
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = _beforeJson ?? "{}"
        });

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_exePath))
            throw new InvalidOperationException("EXECUTABLE_NOT_VERIFIED");

        // Start via PowerShell Start-Process — never Stop-Process / taskkill.
        var script = $@"
$ErrorActionPreference = 'Stop'
$p = '{_exePath.Replace("'", "''")}'
if (-not (Test-Path -LiteralPath $p)) {{ throw 'EXE_MISSING:' + $p }}
$name = [IO.Path]::GetFileNameWithoutExtension($p)
if ($name -notmatch 'sha.?print') {{ throw 'REFUSE_NON_SHAPRINT:' + $name }}
Start-Process -FilePath $p -ErrorAction Stop | Out-Null
'STARTED:' + $p
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || !(result.StdOut ?? "").Contains("STARTED:", StringComparison.Ordinal))
            throw new InvalidOperationException(result.StdErr ?? result.StdOut ?? "ShaPrint Start-Process failed.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        // Brief settle — process may take a moment to appear.
        await Task.Delay(500, ct);
        var info = await _sha.GetInstallInfoAsync(ct);
        return info.ProcessRunning;
        // Deliberately does NOT require TCP 48631 listen or IPPS success.
    }

    public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        => Task.FromResult(new RollbackResult
        {
            Attempted = false,
            Succeeded = false,
            Verified = false,
            Unsupported = true,
            Message = "ShaPrint start is irreversible via this tool — process will not be killed (never kill foreign/own on rollback)."
        });

    public static string? ResolveVerifiedExecutable(string? installPath)
    {
        if (string.IsNullOrWhiteSpace(installPath) || !Directory.Exists(installPath))
            return null;

        var candidates = new[]
        {
            Path.Combine(installPath, "ShaPrint.exe"),
            Path.Combine(installPath, "sha-print.exe"),
            Path.Combine(installPath, "ShaPrint", "ShaPrint.exe")
        };
        foreach (var c in candidates)
        {
            if (!File.Exists(c)) continue;
            var stem = Path.GetFileNameWithoutExtension(c);
            if (stem.Contains("shaprint", StringComparison.OrdinalIgnoreCase)
                || stem.Contains("sha-print", StringComparison.OrdinalIgnoreCase)
                || stem.Contains("ShaPrint", StringComparison.OrdinalIgnoreCase))
                return c;
        }

        // Single *.exe under install root whose name contains sha+print
        try
        {
            var hits = Directory.GetFiles(installPath, "*.exe", SearchOption.TopDirectoryOnly)
                .Where(f => Path.GetFileNameWithoutExtension(f).Contains("sha", StringComparison.OrdinalIgnoreCase)
                            && Path.GetFileNameWithoutExtension(f).Contains("print", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (hits.Count == 1) return hits[0];
        }
        catch
        {
            /* ignore */
        }

        return null;
    }
}
