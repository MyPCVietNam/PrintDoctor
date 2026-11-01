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
            Description = $"Start Windows service '{_serviceName}' if stopped. Spooler restart may affect active print jobs.",
            Changes = new[] { $"Start {_serviceName}" },
            Risks = _serviceName.Equals("Spooler", StringComparison.OrdinalIgnoreCase)
                ? new[] { "May interrupt active print jobs" }
                : Array.Empty<string>(),
            Reversible = false
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "memory",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = $"{{\"service\":\"{_serviceName}\",\"status\":\"{_before}\"}}"
        });

    public Task ApplyAsync(CancellationToken ct = default)
        => _services.StartServiceAsync(_serviceName, ct);

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var svc = await _services.GetServiceAsync(_serviceName, ct);
        return svc?.Status.Equals("Running", StringComparison.OrdinalIgnoreCase) == true;
    }

    public Task RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        => Task.CompletedTask; // starting a required service is not auto-stopped
}
