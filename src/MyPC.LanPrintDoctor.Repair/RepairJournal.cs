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
    /// <summary>Mutation recorded without verified completion — technician must review.</summary>
    UncertainState
}

/// <summary>
/// Durable per-transaction journal. Scans can span session directories.
/// Phases: ApplyStarted → Applied → Verify | RollbackStarted → RollbackVerified.
/// Applied without Verify ⇒ UNCERTAIN_STATE (never Clean).
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
        LoadFile(_path);
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

    public void Record(string operationId, string phase, bool success, string? detail = null, string? backupId = null, string? backupPayload = null)
        => Record(Guid.NewGuid().ToString("N"), operationId, phase, success, detail, backupId, backupPayload);

    public IReadOnlyList<RepairJournalEntry> LoadIncomplete()
    {
        var incomplete = new List<RepairJournalEntry>();
        foreach (var group in _entries.GroupBy(e => e.TransactionId))
        {
            if (IsUncertain(group.Select(g => g.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase)))
                incomplete.Add(group.Last());
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
            if (IsUncertain(phases)) anyUncertain = true;
            else if (IsIncomplete(phases)) anyIncomplete = true;
        }

        if (anyUncertain) return RepairRecoveryState.UncertainState;
        if (anyIncomplete) return RepairRecoveryState.Incomplete;
        return RepairRecoveryState.Clean;
    }

    /// <summary>Scan Journals root for unfinished transactions across prior sessions.</summary>
    public static RepairRecoveryState ScanAllSessions(string journalsRoot)
    {
        if (!Directory.Exists(journalsRoot)) return RepairRecoveryState.Clean;
        var anyUncertain = false;
        var anyIncomplete = false;
        foreach (var dir in Directory.EnumerateDirectories(journalsRoot))
        {
            var j = new RepairJournal(dir);
            var st = j.GetRecoveryState();
            if (st == RepairRecoveryState.UncertainState) anyUncertain = true;
            else if (st == RepairRecoveryState.Incomplete) anyIncomplete = true;
        }
        // Also scan loose journal files
        foreach (var file in Directory.EnumerateFiles(journalsRoot, "repair-journal.json", SearchOption.AllDirectories))
        {
            var j = new RepairJournal(Path.GetDirectoryName(file)!);
            var st = j.GetRecoveryState();
            if (st == RepairRecoveryState.UncertainState) anyUncertain = true;
            else if (st == RepairRecoveryState.Incomplete) anyIncomplete = true;
        }

        if (anyUncertain) return RepairRecoveryState.UncertainState;
        if (anyIncomplete) return RepairRecoveryState.Incomplete;
        return RepairRecoveryState.Clean;
    }

    public static IReadOnlyList<(string SessionPath, string TransactionId, string OperationId, string Detail)> ListUncertain(string journalsRoot)
    {
        var list = new List<(string, string, string, string)>();
        if (!Directory.Exists(journalsRoot)) return list;
        foreach (var file in Directory.EnumerateFiles(journalsRoot, "repair-journal.json", SearchOption.AllDirectories))
        {
            var dir = Path.GetDirectoryName(file)!;
            var j = new RepairJournal(dir);
            foreach (var e in j.LoadIncomplete())
                list.Add((dir, e.TransactionId, e.OperationId, e.Phase + ": " + (e.Detail ?? "")));
        }
        return list;
    }

    public string ToJson() => JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });

    private void LoadFile(string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            var loaded = JsonSerializer.Deserialize<List<RepairJournalEntry>>(File.ReadAllText(path));
            if (loaded is not null) _entries.AddRange(loaded);
        }
        catch { /* keep empty */ }
    }

    private void Persist()
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, ToJson());
        File.Copy(tmp, _path, overwrite: true);
        File.Delete(tmp);
    }

    /// <summary>
    /// Mutation started or applied without Verify and without completed rollback ⇒ uncertain.
    /// Does NOT auto-rollback.
    /// </summary>
    internal static bool IsUncertain(HashSet<string> phases)
    {
        var terminalOk = phases.Contains("Verify") || phases.Contains("RollbackVerified");
        if (terminalOk) return false;
        // ApplyStarted without Applied (crash mid-mutation)
        if (phases.Contains("ApplyStarted") && !phases.Contains("Applied") && !phases.Contains("RollbackStarted"))
            return true;
        // Applied (mutation done) without Verify
        if (phases.Contains("Applied") && !phases.Contains("Verify") && !phases.Contains("RollbackVerified"))
            return true;
        // Legacy "Apply" phase without Verify
        if (phases.Contains("Apply") && !phases.Contains("Verify") && !phases.Contains("Rollback") && !phases.Contains("RollbackVerified"))
            return true;
        // RollbackStarted without RollbackVerified
        if (phases.Contains("RollbackStarted") && !phases.Contains("RollbackVerified"))
            return true;
        return false;
    }

    private static bool IsIncomplete(HashSet<string> phases)
        => phases.Contains("Backup") && !phases.Contains("ApplyStarted") && !phases.Contains("Verify");
}
