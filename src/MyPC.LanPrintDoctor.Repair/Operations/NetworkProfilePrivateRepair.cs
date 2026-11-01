using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

public sealed class NetworkProfilePrivateRepair : IRepairOperation
{
    private readonly INetworkProfileService _profiles;
    private readonly IElevationService _elevation;
    private List<NetworkConnectionProfile> _before = new();
    private int? _targetIndex;

    public NetworkProfilePrivateRepair(INetworkProfileService profiles, IElevationService elevation)
    {
        _profiles = profiles;
        _elevation = elevation;
    }

    public string OperationId => "NET-PROFILE-PRIVATE";
    public string Title => "Set network category to Private (user confirmed trusted LAN)";
    public bool IsImplemented => true;
    public bool SupportsRollback => true;

    public async Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
        {
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "Administrator elevation required."
            };
        }

        var profiles = await _profiles.GetConnectionProfilesAsync(ct);
        if (profiles.Count == 0)
        {
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "No connection profiles readable (collector UNKNOWN/failed)."
            };
        }

        if (profiles.Any(p => p.IsDomainManaged || p.NetworkCategory.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase)))
        {
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "Domain-managed / DomainAuthenticated profile — blocked (policy)."
            };
        }

        var publicProfile = profiles.FirstOrDefault(p => p.NetworkCategory.Equals("Public", StringComparison.OrdinalIgnoreCase));
        if (publicProfile is null)
        {
            return new RepairPrerequisiteResult
            {
                CanProceed = false,
                RequiresAdmin = true,
                Reason = "No Public profile found to change."
            };
        }

        _targetIndex = publicProfile.InterfaceIndex;
        return new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = true };
    }

    public async Task CollectEvidenceAsync(CancellationToken ct = default)
    {
        _before = (await _profiles.GetConnectionProfilesAsync(ct)).ToList();
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = "Set-NetConnectionProfile NetworkCategory Public → Private for the selected interface after user confirms trusted LAN. Domain profiles are blocked.",
            Changes = new[] { $"InterfaceIndex={_targetIndex?.ToString() ?? "?"}: NetworkCategory=Private" },
            Risks = new[] { "Exposes more sharing surfaces on that network" },
            Reversible = true
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = JsonSerializer.Serialize(_before)
        });

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        if (_targetIndex is null)
            throw new InvalidOperationException("No target interface selected.");
        var ok = await _profiles.SetPrivateAsync(_targetIndex.Value, ct);
        if (!ok)
            throw new InvalidOperationException("Set-NetConnectionProfile Private failed.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        if (_targetIndex is null) return false;
        var profiles = await _profiles.GetConnectionProfilesAsync(ct);
        var p = profiles.FirstOrDefault(x => x.InterfaceIndex == _targetIndex.Value);
        return p?.NetworkCategory.Equals("Private", StringComparison.OrdinalIgnoreCase) == true;
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        try
        {
            var prior = JsonSerializer.Deserialize<List<NetworkConnectionProfile>>(backup.PayloadJson ?? "[]") ?? new();
            var ok = true;
            foreach (var p in prior)
            {
                if (!await _profiles.SetCategoryAsync(p.InterfaceIndex, p.NetworkCategory, ct))
                    ok = false;
            }

            var now = await _profiles.GetConnectionProfilesAsync(ct);
            var verified = prior.All(old =>
            {
                var cur = now.FirstOrDefault(n => n.InterfaceIndex == old.InterfaceIndex);
                return cur is not null && string.Equals(cur.NetworkCategory, old.NetworkCategory, StringComparison.OrdinalIgnoreCase);
            });

            return new RollbackResult
            {
                Attempted = true,
                Succeeded = ok,
                Verified = verified,
                Message = verified ? "Network category restored." : "Category rollback not fully verified."
            };
        }
        catch (Exception ex)
        {
            return new RollbackResult { Attempted = true, Succeeded = false, Verified = false, Message = ex.Message };
        }
    }
}
