using System.Text.Json;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairJournalEntry
{
    public required string TransactionId { get; init; }
    public required string OperationId { get; init; }
    public required string Phase { get; init; }
    public DateTimeOffset AtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string? Detail { get; init; }
    public bool Success { get; init; }
    public string? BackupId { get; init; }
    public string? BackupPayloadJson { get; init; }
}

public enum RepairRecoveryState
{
    Clean,
    Incomplete,
    /// <summary>ApplyStarted recorded but no Applied/Verified/Rollback — crash mid-mutation.</summary>
    UncertainState
}

/// <summary>
/// Durable per-transaction journal. Two runs of the same OperationId must not merge.
/// ApplyStarted is persisted before mutation; crash ⇒ UNCERTAIN_STATE (never auto-claim recovered).
/// </summary>
public sealed class RepairJournal
{
    private readonly List<RepairJournalEntry> _entries = new();
    private readonly string _path;
    private readonly string _directory;

    public RepairJournal(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "repair-journal.json");
        if (File.Exists(_path))
        {
            try
            {
                var loaded = JsonSerializer.Deserialize<List<RepairJournalEntry>>(File.ReadAllText(_path));
                if (loaded is not null) _entries.AddRange(loaded);
            }
            catch
            {
                // keep empty; corrupt journal is recorded on next write
            }
        }
    }

    public string DirectoryPath => _directory;
    public IReadOnlyList<RepairJournalEntry> Entries => _entries;

    public void Record(string transactionId, string operationId, string phase, bool success, string? detail = null, string? backupId = null, string? backupPayload = null)
    {
        _entries.Add(new RepairJournalEntry
        {
            TransactionId = transactionId,
            OperationId = operationId,
            Phase = phase,
            Success = success,
            Detail = detail,
            BackupId = backupId,
            BackupPayloadJson = backupPayload
        });
        Persist();
    }

    /// <summary>Legacy overload — generates a new transaction id (tests / callers without tx).</summary>
    public void Record(string operationId, string phase, bool success, string? detail = null, string? backupId = null, string? backupPayload = null)
        => Record(Guid.NewGuid().ToString("N"), operationId, phase, success, detail, backupId, backupPayload);

    public IReadOnlyList<RepairJournalEntry> LoadIncomplete()
    {
        var incomplete = new List<RepairJournalEntry>();
        foreach (var group in _entries.GroupBy(e => e.TransactionId))
        {
            var phases = group.Select(g => g.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (phases.Contains("Apply") && !phases.Contains("Verify") && !phases.Contains("Rollback") && !phases.Contains("Applied"))
                incomplete.Add(group.Last(e => e.Phase.Equals("Apply", StringComparison.OrdinalIgnoreCase)
                                              || e.Phase.Equals("ApplyStarted", StringComparison.OrdinalIgnoreCase)));
            else if (phases.Contains("ApplyStarted") && !phases.Contains("Applied") && !phases.Contains("Verify") && !phases.Contains("Rollback"))
                incomplete.Add(group.Last(e => e.Phase.Equals("ApplyStarted", StringComparison.OrdinalIgnoreCase)));
        }
        return incomplete;
    }

    public RepairRecoveryState GetRecoveryState(string? transactionId = null)
    {
        IEnumerable<IGrouping<string, RepairJournalEntry>> groups = transactionId is null
            ? _entries.GroupBy(e => e.TransactionId)
            : _entries.Where(e => e.TransactionId == transactionId).GroupBy(e => e.TransactionId);

        var anyUncertain = false;
        var anyIncomplete = false;
        foreach (var group in groups)
        {
            var phases = group.Select(g => g.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (phases.Contains("ApplyStarted") && !phases.Contains("Applied") && !phases.Contains("Verify") && !phases.Contains("Rollback"))
                anyUncertain = true;
            else if (phases.Contains("Apply") && !phases.Contains("Verify") && !phases.Contains("Rollback"))
                anyIncomplete = true;
        }

        if (anyUncertain) return RepairRecoveryState.UncertainState;
        if (anyIncomplete) return RepairRecoveryState.Incomplete;
        return RepairRecoveryState.Clean;
    }

    public string ToJson() => JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });

    private void Persist()
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, ToJson());
        File.Copy(tmp, _path, overwrite: true);
        File.Delete(tmp);
    }
}
