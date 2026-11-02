using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.Services;

namespace MyPC.LanPrintDoctor.Repair.Operations;

public sealed class ServiceStartRepair : IRepairOperation
{
    private readonly string _serviceName;
    private readonly IWindowsServiceInspector _services;
    private readonly IElevationService _elevation;
    private string _before = "Unknown";

    public ServiceStartRepair(string serviceName, string operationId, string title, IWindowsServiceInspector services, IElevationService elevation)
    {
        _serviceName = serviceName;
        OperationId = operationId;
        Title = title;
        _services = services;
        _elevation = elevation;
    }

    public string OperationId { get; }
    public string Title { get; }
    public bool IsImplemented => true;
    public bool SupportsRollback => false; // starting a required service is not auto-stopped
    public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalAny;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPrerequisiteResult
        {
            CanProceed = _elevation.IsAdministrator(),
            RequiresAdmin = true,
            Reason = _elevation.IsAdministrator() ? null : "Administrator elevation required."
        });

    public async Task CollectEvidenceAsync(CancellationToken ct = default)
    {
        var svc = await _services.GetServiceAsync(_serviceName, ct);
        _before = svc?.Status ?? "Missing";
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = $"Start Windows service '{_serviceName}' if stopped. Spooler restart may affect active print jobs. Rollback is NOT supported (will not stop the service again).",
            Changes = new[] { $"Start {_serviceName}" },
            Risks = _serviceName.Equals("Spooler", StringComparison.OrdinalIgnoreCase)
                ? new[] { "May interrupt active print jobs", "Irreversible via this tool (no auto-stop)" }
                : new[] { "Irreversible via this tool (no auto-stop)" },
            Reversible = false
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = $"{{\"service\":\"{_serviceName}\",\"status\":\"{_before}\"}}"
        });

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        var ok = await _services.StartServiceAsync(_serviceName, ct);
        if (!ok)
            throw new InvalidOperationException($"Start-Service {_serviceName} failed.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var svc = await _services.GetServiceAsync(_serviceName, ct);
        return ServiceStatusParser.IsRunning(svc?.Status);
    }

    public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        => Task.FromResult(new RollbackResult
        {
            Attempted = false,
            Succeeded = false,
            Verified = false,
            Unsupported = true,
            Message = "Service start is irreversible via this tool; service will not be stopped automatically."
        });
}

public static class ServiceStatusParser
{
    public static bool IsRunning(string? status)
    {
        if (string.IsNullOrWhiteSpace(status)) return false;
        if (status.Equals("Running", StringComparison.OrdinalIgnoreCase)) return true;
        if (status.Equals("4", StringComparison.Ordinal)) return true; // ServiceControllerStatus.Running
        return false;
    }

    public static bool IsStopped(string? status)
    {
        if (string.IsNullOrWhiteSpace(status)) return false;
        if (status.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("Missing", StringComparison.OrdinalIgnoreCase))
            return false;
        if (status.Equals("Stopped", StringComparison.OrdinalIgnoreCase)) return true;
        if (status.Equals("1", StringComparison.Ordinal)) return true;
        return !IsRunning(status)
               && !status.Contains("Pending", StringComparison.OrdinalIgnoreCase);
    }

    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "Unknown";
        return raw switch
        {
            "1" => "Stopped",
            "2" => "StartPending",
            "3" => "StopPending",
            "4" => "Running",
            "5" => "ContinuePending",
            "6" => "PausePending",
            "7" => "Paused",
            _ => raw
        };
    }
}
