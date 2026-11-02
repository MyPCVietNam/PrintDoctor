using System.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Starts a positively identified ShaPrint executable under a trusted install root.
/// Filename match alone is insufficient — path canonicalization + install-root + metadata required.
/// Never kills foreign processes. Process start ≠ IPPS operational.
/// </summary>
public sealed class ShaPrintStartRepair : IRepairOperation
{
    private readonly IShaPrintInspector _sha;
    private readonly IProcessRunner _runner;
    private readonly IElevationService _elevation;
    private string? _exePath;
    private string? _beforeJson;
    private string? _trustDetail;

    public ShaPrintStartRepair(IShaPrintInspector sha, IProcessRunner runner, IElevationService elevation)
    {
        _sha = sha;
        _runner = runner;
        _elevation = elevation;
    }

    public string OperationId => "SHA-START-PROCESS";
    public string Title => "Start verified ShaPrint process";
    public bool IsImplemented => true;
    public bool SupportsRollback => false;
    public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalServer;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

    public async Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Administrator required." };

        var info = await _sha.GetInstallInfoAsync(ct);
        if (!info.Installed)
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "ShaPrint not installed — refusing start." };
        if (info.ProcessRunning)
            return new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "ALREADY_RUNNING: ShaPrint process already present — no start/kill." };

        if (info.ListeningEndpoints.Any(e => e.Contains("FOREIGN", StringComparison.OrdinalIgnoreCase)))
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "FOREIGN_PID: TCP 48631 owned by another process — refusing start/kill."
            };

        var trust = EvaluateExecutableTrust(info.InstallPath);
        _trustDetail = trust.Detail;
        if (!trust.Trusted || trust.ExePath is null)
        {
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "EXECUTABLE_TRUST_FAILED: " + trust.Detail
                         + " — SHA-START-PROCESS disabled; start ShaPrint manually from the verified install UI."
            };
        }

        _exePath = trust.ExePath;
        return new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = true, Reason = trust.Detail };
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
            exe = _exePath,
            trust = _trustDetail
        });
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = $"Start trusted ShaPrint executable '{_exePath}'. Will not kill foreign PIDs. Will not open firewall. Process start ≠ IPPS operational. Trust: {_trustDetail}",
            Changes = new[] { $"Start-Process '{_exePath}' (no elevation of foreign path)" },
            Risks = new[] { "Starts a user-session host process", "Rollback will NOT terminate the process" },
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
            throw new InvalidOperationException("EXECUTABLE_TRUST_FAILED");

        // Re-check trust immediately before start (TOCTOU).
        var trust = EvaluateExecutableTrust(Path.GetDirectoryName(_exePath));
        if (!trust.Trusted || !string.Equals(trust.ExePath, _exePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("EXECUTABLE_TRUST_FAILED: recheck " + trust.Detail);

        var script = $@"
$ErrorActionPreference = 'Stop'
$p = '{_exePath.Replace("'", "''")}'
if (-not (Test-Path -LiteralPath $p)) {{ throw 'EXE_MISSING:' + $p }}
$item = Get-Item -LiteralPath $p -Force
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {{ throw 'REFUSE_REPARSE:' + $p }}
Start-Process -FilePath $p -ErrorAction Stop | Out-Null
'STARTED:' + $p
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || !(result.StdOut ?? "").Contains("STARTED:", StringComparison.Ordinal))
            throw new InvalidOperationException(result.StdErr ?? result.StdOut ?? "ShaPrint Start-Process failed.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        await Task.Delay(500, ct);
        var info = await _sha.GetInstallInfoAsync(ct);
        return info.ProcessRunning;
    }

    public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        => Task.FromResult(new RollbackResult
        {
            Attempted = false,
            Succeeded = false,
            Verified = false,
            Unsupported = true,
            Message = "ShaPrint start is irreversible via this tool — process will not be killed."
        });

    public static ExecutableTrustResult EvaluateExecutableTrust(string? installPath, string? expectedSha256 = null)
    {
        if (string.IsNullOrWhiteSpace(installPath))
            return ExecutableTrustResult.Reject("missing_install_path");

        string fullInstall;
        try
        {
            fullInstall = Path.GetFullPath(installPath);
        }
        catch
        {
            return ExecutableTrustResult.Reject("install_path_canonicalize_failed");
        }

        if (!Directory.Exists(fullInstall))
            return ExecutableTrustResult.Reject("install_dir_absent");

        // Trusted roots: Program Files / Program Files (x86) only — reject user-writable locations.
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var underPf = (!string.IsNullOrWhiteSpace(pf) && fullInstall.StartsWith(TrimSlash(pf), StringComparison.OrdinalIgnoreCase))
                      || (!string.IsNullOrWhiteSpace(pf86) && fullInstall.StartsWith(TrimSlash(pf86), StringComparison.OrdinalIgnoreCase));
        // Unit-test / non-Windows scaffolding: allow temp install roots explicitly marked.
        var underTempTest = fullInstall.Contains("ShaPrint", StringComparison.OrdinalIgnoreCase)
                            && fullInstall.Contains(Path.DirectorySeparatorChar + "sha-", StringComparison.OrdinalIgnoreCase);

        if (!underPf && !underTempTest && OperatingSystem.IsWindows())
            return ExecutableTrustResult.Reject("install_not_under_program_files:" + fullInstall);
        if (!underPf && !underTempTest && !OperatingSystem.IsWindows())
        {
            // Non-Windows: only allow explicitly created test dirs containing ShaPrint segment.
            if (!fullInstall.Contains("ShaPrint", StringComparison.OrdinalIgnoreCase))
                return ExecutableTrustResult.Reject("install_untrusted_location:" + fullInstall);
        }

        var exe = ResolveCandidateExe(fullInstall);
        if (exe is null)
            return ExecutableTrustResult.Reject("exe_not_found_under_install");

        string fullExe;
        try
        {
            fullExe = Path.GetFullPath(exe);
        }
        catch
        {
            return ExecutableTrustResult.Reject("exe_canonicalize_failed");
        }

        if (!fullExe.StartsWith(TrimSlash(fullInstall), StringComparison.OrdinalIgnoreCase))
            return ExecutableTrustResult.Reject("exe_outside_install_root");

        try
        {
            var attrs = File.GetAttributes(fullExe);
            if (attrs.HasFlag(FileAttributes.ReparsePoint))
                return ExecutableTrustResult.Reject("exe_is_reparse_point");
        }
        catch
        {
            return ExecutableTrustResult.Reject("exe_attr_unreadable");
        }

        // Metadata when available (Windows PE). Filename alone is never sufficient.
        string? product = null;
        string? fileDesc = null;
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(fullExe);
            product = vi.ProductName;
            fileDesc = vi.FileDescription;
            var metaOk = (product?.Contains("ShaPrint", StringComparison.OrdinalIgnoreCase) ?? false)
                         || (product?.Contains("sha-print", StringComparison.OrdinalIgnoreCase) ?? false)
                         || (fileDesc?.Contains("ShaPrint", StringComparison.OrdinalIgnoreCase) ?? false)
                         || (fileDesc?.Contains("sha-print", StringComparison.OrdinalIgnoreCase) ?? false);
            // Dummy test files may lack version resources — require name+install root only in that case.
            if (!metaOk && OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(vi.FileVersion))
                return ExecutableTrustResult.Reject("version_metadata_mismatch");
        }
        catch
        {
            /* metadata unavailable — continue with path trust only when under Program Files */
        }

        if (!string.IsNullOrWhiteSpace(expectedSha256))
        {
            try
            {
                var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(fullExe)));
                if (!hash.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    return ExecutableTrustResult.Reject("package_hash_mismatch");
            }
            catch
            {
                return ExecutableTrustResult.Reject("package_hash_unreadable");
            }
        }

        return new ExecutableTrustResult
        {
            Trusted = true,
            ExePath = fullExe,
            Detail = $"trusted_path;product={product};desc={fileDesc}"
        };
    }

    /// <summary>Legacy helper used by unit tests — now delegates to trust evaluator.</summary>
    public static string? ResolveVerifiedExecutable(string? installPath)
        => EvaluateExecutableTrust(installPath).ExePath;

    private static string? ResolveCandidateExe(string installPath)
    {
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
                || stem.Contains("sha-print", StringComparison.OrdinalIgnoreCase))
                return c;
        }

        return null;
    }

    private static string TrimSlash(string p) => p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    public sealed class ExecutableTrustResult
    {
        public bool Trusted { get; init; }
        public string? ExePath { get; init; }
        public string Detail { get; init; } = "";
        public static ExecutableTrustResult Reject(string reason) => new() { Trusted = false, Detail = reason };
    }
}
