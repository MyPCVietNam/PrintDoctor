using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairExecutor
{
    private readonly RepairJournal _journal;

    public RepairExecutor(RepairJournal journal) => _journal = journal;

    public async Task<RepairResult> ExecuteAsync(
        IRepairOperation operation,
        bool userConfirmed,
        CancellationToken ct = default,
        MachineRole? localRole = null,
        RepairOwnerRole? findingOwner = null)
    {
        var tx = Guid.NewGuid().ToString("N");

        // Prior unfinished / corrupt journal — BLOCK immediately (engine-level; UI-independent).
        // Never warn-and-continue into Apply.
        var recovery = _journal.GetRecoveryState();
        if (recovery is RepairRecoveryState.UncertainState
            or RepairRecoveryState.Incomplete
            or RepairRecoveryState.CorruptJournal)
        {
            var code = recovery switch
            {
                RepairRecoveryState.CorruptJournal => "CORRUPT_JOURNAL",
                RepairRecoveryState.Incomplete => "INCOMPLETE",
                _ => "UNCERTAIN_STATE"
            };
            try
            {
                if (!_journal.IsCorrupt)
                    _journal.Record(tx, operation.OperationId, "BlockedPriorTransaction", false,
                        $"{code}: prior transaction unfinished — further Apply blocked until technician review.");
            }
            catch
            {
                // Corrupt journal refuses append — still return BLOCKED below.
            }

            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Blocked,
                Message = $"{code}: prior repair journal requires technician review; Apply blocked (no auto-rollback)."
            };
        }

        if (findingOwner == RepairOwnerRole.ServerActionRequired
            || operation.OwnerRole == RepairOwnerRole.ServerActionRequired
            || operation.TargetMachine == RepairTargetMachine.RemoteUnsupported)
        {
            _journal.Record(tx, operation.OperationId, "ServerActionRequired", false);
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                ServerActionRequired = true,
                Status = DiagnosticStatus.Blocked,
                Message = "SERVER_ACTION_REQUIRED: repair targets another machine; local apply blocked."
            };
        }

        if (localRole is MachineRole role && !OwnerAllows(operation.OwnerRole, role))
        {
            _journal.Record(tx, operation.OperationId, "OwnerMismatch", false, $"local={role}, owner={operation.OwnerRole}");
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                ServerActionRequired = operation.OwnerRole == RepairOwnerRole.LocalServer && role == MachineRole.Client,
                Status = DiagnosticStatus.Blocked,
                Message = $"Repair owner {operation.OwnerRole} does not match local role {role}."
            };
        }

        if (!operation.IsImplemented)
        {
            _journal.Record(tx, operation.OperationId, "NotImplemented", false, "Repair is NOT_IMPLEMENTED and disabled.");
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                NotImplemented = true,
                Status = DiagnosticStatus.Blocked,
                Message = "NOT_IMPLEMENTED: repair is disabled until a real Apply/Verify path exists. No success claimed."
            };
        }

        if (!userConfirmed)
        {
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Blocked,
                Message = "User confirmation required. No changes applied."
            };
        }

        var prereq = await operation.CheckPrerequisitesAsync(ct);
        _journal.Record(tx, operation.OperationId, "Prerequisites", prereq.CanProceed, prereq.Reason);
        if (prereq.NotImplemented || !operation.IsImplemented)
        {
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                NotImplemented = true,
                Status = DiagnosticStatus.Blocked,
                Message = prereq.Reason ?? "NOT_IMPLEMENTED"
            };
        }

        if (!prereq.CanProceed)
        {
            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Blocked,
                Message = prereq.Reason
            };
        }

        await operation.CollectEvidenceAsync(ct);
        _journal.Record(tx, operation.OperationId, "Evidence", true);
        var preview = await operation.PreviewChangesAsync(ct);
        _journal.Record(tx, operation.OperationId, "Preview", true, preview.Description);

        RepairBackup? backup = null;
        try
        {
            backup = await operation.BackupAsync(ct);
            _journal.Record(tx, operation.OperationId, "Backup", true, backup.BackupId, backup.BackupId, backup.PayloadJson);

            // Persist BEFORE mutation
            _journal.Record(tx, operation.OperationId, "ApplyStarted", true, "About to mutate system state");
            await operation.ApplyAsync(ct);
            _journal.Record(tx, operation.OperationId, "Applied", true);
            _journal.Record(tx, operation.OperationId, "Apply", true);

            using var verifyCts = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
            verifyCts.CancelAfter(TimeSpan.FromMinutes(2));
            var verified = await operation.VerifyAsync(verifyCts.Token);
            _journal.Record(tx, operation.OperationId, "Verify", verified);

            if (!verified)
            {
                var rb = await SafeRollbackAsync(tx, operation, backup, preview.Reversible && operation.SupportsRollback);
                return new RepairResult
                {
                    OperationId = operation.OperationId,
                    TransactionId = tx,
                    Applied = true,
                    Verified = false,
                    BackupId = backup.BackupId,
                    RollbackAttempted = rb.Attempted,
                    RolledBack = rb.Succeeded && rb.Verified && !rb.Partial,
                    RollbackVerified = rb.Verified && !rb.Partial,
                    RollbackUnsupported = rb.Unsupported || !operation.SupportsRollback,
                    Status = DiagnosticStatus.Fail,
                    Message = BuildFailMessage("Repair applied but verification failed.", rb, operation.SupportsRollback)
                        + (rb.Partial ? " PARTIAL_ROLLBACK." : "")
                };
            }

            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = true,
                Verified = true,
                BackupId = backup.BackupId,
                Status = DiagnosticStatus.Pass,
                Message = "Repair applied and verified."
            };
        }
        catch (Exception ex)
        {
            _journal.Record(tx, operation.OperationId, "Error", false, ex.Message);
            if (backup is not null)
            {
                var rb = await SafeRollbackAsync(tx, operation, backup, operation.SupportsRollback);
                return new RepairResult
                {
                    OperationId = operation.OperationId,
                    TransactionId = tx,
                    Applied = false,
                    Verified = false,
                    BackupId = backup.BackupId,
                    RollbackAttempted = rb.Attempted,
                    RolledBack = rb.Succeeded && rb.Verified,
                    RollbackVerified = rb.Verified,
                    RollbackUnsupported = rb.Unsupported || !operation.SupportsRollback,
                    Status = DiagnosticStatus.Fail,
                    Message = BuildFailMessage($"Repair failed: {ex.Message}.", rb, operation.SupportsRollback)
                };
            }

            return new RepairResult
            {
                OperationId = operation.OperationId,
                TransactionId = tx,
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Fail,
                Message = ex.Message
            };
        }
    }

    private static bool OwnerAllows(RepairOwnerRole owner, MachineRole local) => owner switch
    {
        RepairOwnerRole.None => false,
        RepairOwnerRole.ServerActionRequired => false,
        RepairOwnerRole.LocalAny => true,
        RepairOwnerRole.LocalServer => local == MachineRole.Server,
        RepairOwnerRole.LocalClient => local == MachineRole.Client,
        _ => false
    };

    private async Task<RollbackResult> SafeRollbackAsync(string tx, IRepairOperation operation, RepairBackup backup, bool supported)
    {
        if (!supported)
        {
            var unsupported = new RollbackResult
            {
                Attempted = false,
                Succeeded = false,
                Verified = false,
                Unsupported = true,
                Message = "Rollback not supported for this operation; state may not be reversible."
            };
            _journal.Record(tx, operation.OperationId, "Rollback", false, unsupported.Message);
            return unsupported;
        }

        try
        {
            _journal.Record(tx, operation.OperationId, "RollbackStarted", true);
            var result = await operation.RollbackAsync(backup, CancellationToken.None);
            _journal.Record(tx, operation.OperationId, "Rollback", result.Succeeded && result.Verified && !result.Partial,
                result.Message ?? (result.Verified ? "Rollback verified" : "Rollback attempted"));
            if (result.Verified && !result.Partial)
                _journal.Record(tx, operation.OperationId, "RollbackVerified", true, result.Message);
            else
                _journal.Record(tx, operation.OperationId, "RollbackVerified", false, result.Message ?? "PARTIAL_ROLLBACK or unverified");
            return result;
        }
        catch (Exception ex)
        {
            _journal.Record(tx, operation.OperationId, "RollbackStarted", false, ex.Message);
            _journal.Record(tx, operation.OperationId, "Rollback", false, ex.Message);
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = false,
                Verified = false,
                Message = ex.Message
            };
        }
    }

    private static string BuildFailMessage(string prefix, RollbackResult rb, bool supportsRollback)
    {
        if (!supportsRollback || rb.Unsupported)
            return prefix + " Rollback unsupported — irreversible change may remain.";
        if (!rb.Attempted)
            return prefix + " Rollback was not attempted.";
        if (rb.Partial)
            return prefix + " PARTIAL_ROLLBACK — some attributes/rules not restored; keep evidence.";
        if (rb.Succeeded && rb.Verified)
            return prefix + " Rollback verified.";
        if (rb.Attempted && !rb.Verified)
            return prefix + " Rollback attempted but not verified — do not assume restored.";
        return prefix + " Rollback failed.";
    }
}
