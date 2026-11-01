using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairExecutor
{
    private readonly RepairJournal _journal;

    public RepairExecutor(RepairJournal journal) => _journal = journal;

    public async Task<RepairResult> ExecuteAsync(IRepairOperation operation, bool userConfirmed, CancellationToken ct = default)
    {
        if (!operation.IsImplemented)
        {
            _journal.Record(operation.OperationId, "NotImplemented", false, "Repair is NOT_IMPLEMENTED and disabled.");
            return new RepairResult
            {
                OperationId = operation.OperationId,
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
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Blocked,
                Message = "User confirmation required. No changes applied."
            };
        }

        var prereq = await operation.CheckPrerequisitesAsync(ct);
        _journal.Record(operation.OperationId, "Prerequisites", prereq.CanProceed, prereq.Reason);
        if (prereq.NotImplemented || !operation.IsImplemented)
        {
            return new RepairResult
            {
                OperationId = operation.OperationId,
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
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Blocked,
                Message = prereq.Reason
            };
        }

        await operation.CollectEvidenceAsync(ct);
        _journal.Record(operation.OperationId, "Evidence", true);
        var preview = await operation.PreviewChangesAsync(ct);
        _journal.Record(operation.OperationId, "Preview", true, preview.Description);

        RepairBackup? backup = null;
        try
        {
            backup = await operation.BackupAsync(ct);
            _journal.Record(operation.OperationId, "Backup", true, backup.BackupId, backup.BackupId, backup.PayloadJson);
            await operation.ApplyAsync(ct);
            _journal.Record(operation.OperationId, "Apply", true);

            // Verification must not be skipped; cancelled token after Apply uses a fresh token for verify/rollback.
            using var verifyCts = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
            verifyCts.CancelAfter(TimeSpan.FromMinutes(2));
            var verified = await operation.VerifyAsync(verifyCts.Token);
            _journal.Record(operation.OperationId, "Verify", verified);

            if (!verified)
            {
                var rb = await SafeRollbackAsync(operation, backup, preview.Reversible && operation.SupportsRollback);
                return new RepairResult
                {
                    OperationId = operation.OperationId,
                    Applied = true,
                    Verified = false,
                    BackupId = backup.BackupId,
                    RollbackAttempted = rb.Attempted,
                    RolledBack = rb.Succeeded && rb.Verified,
                    RollbackVerified = rb.Verified,
                    RollbackUnsupported = rb.Unsupported || !operation.SupportsRollback,
                    Status = DiagnosticStatus.Fail,
                    Message = BuildFailMessage("Repair applied but verification failed.", rb, operation.SupportsRollback)
                };
            }

            return new RepairResult
            {
                OperationId = operation.OperationId,
                Applied = true,
                Verified = true,
                BackupId = backup.BackupId,
                Status = DiagnosticStatus.Pass,
                Message = "Repair applied and verified."
            };
        }
        catch (Exception ex)
        {
            _journal.Record(operation.OperationId, "Error", false, ex.Message);
            if (backup is not null)
            {
                var rb = await SafeRollbackAsync(operation, backup, operation.SupportsRollback);
                return new RepairResult
                {
                    OperationId = operation.OperationId,
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
                Applied = false,
                Verified = false,
                Status = DiagnosticStatus.Fail,
                Message = ex.Message
            };
        }
    }

    private async Task<RollbackResult> SafeRollbackAsync(IRepairOperation operation, RepairBackup backup, bool supported)
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
            _journal.Record(operation.OperationId, "Rollback", false, unsupported.Message);
            return unsupported;
        }

        try
        {
            // Never reuse a cancelled caller token for rollback.
            var result = await operation.RollbackAsync(backup, CancellationToken.None);
            _journal.Record(operation.OperationId, "Rollback", result.Succeeded && result.Verified,
                result.Message ?? (result.Verified ? "Rollback verified" : "Rollback attempted"));
            // Only claim RolledBack when Succeeded && Verified
            return result;
        }
        catch (Exception ex)
        {
            _journal.Record(operation.OperationId, "Rollback", false, ex.Message);
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
        if (rb.Succeeded && rb.Verified)
            return prefix + " Rollback verified.";
        if (rb.Attempted && !rb.Verified)
            return prefix + " Rollback attempted but not verified — do not assume restored.";
        return prefix + " Rollback failed.";
    }
}
