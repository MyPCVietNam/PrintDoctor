using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairExecutor
{
    private readonly RepairJournal _journal;

    public RepairExecutor(RepairJournal journal) => _journal = journal;

    public async Task<RepairResult> ExecuteAsync(IRepairOperation operation, bool userConfirmed, CancellationToken ct = default)
    {
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
            _journal.Record(operation.OperationId, "Backup", true, backup.BackupId);
            await operation.ApplyAsync(ct);
            _journal.Record(operation.OperationId, "Apply", true);
            var verified = await operation.VerifyAsync(ct);
            _journal.Record(operation.OperationId, "Verify", verified);
            if (!verified)
            {
                await operation.RollbackAsync(backup, ct);
                _journal.Record(operation.OperationId, "Rollback", true, "Verify failed");
                return new RepairResult
                {
                    OperationId = operation.OperationId,
                    Applied = true,
                    Verified = false,
                    RolledBack = true,
                    BackupId = backup.BackupId,
                    Status = DiagnosticStatus.Fail,
                    Message = "Repair applied but verification failed; rollback attempted."
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
                try
                {
                    await operation.RollbackAsync(backup, ct);
                    _journal.Record(operation.OperationId, "Rollback", true, "After exception");
                    return new RepairResult
                    {
                        OperationId = operation.OperationId,
                        Applied = false,
                        Verified = false,
                        RolledBack = true,
                        BackupId = backup.BackupId,
                        Status = DiagnosticStatus.Fail,
                        Message = $"Repair failed: {ex.Message}. Rollback attempted."
                    };
                }
                catch (Exception rex)
                {
                    _journal.Record(operation.OperationId, "Rollback", false, rex.Message);
                }
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
}
