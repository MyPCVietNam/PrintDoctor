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
    UncertainState,
    /// <summary>Journal JSON unreadable / corrupt — treat as BLOCKED, never Clean.</summary>
    CorruptJournal
}

/// <summary>
/// Durable per-transaction journal. Scans can span session directories.
/// Phases: ApplyStarted → Applied → Verify | RollbackStarted → RollbackVerified.
/// Terminal success requires Phase AND Success=true. Verify=false / RollbackVerified=false ⇒ UNCERTAIN.
/// Corrupt journal ⇒ CORRUPT_JOURNAL (never Clean).
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
    public bool IsCorrupt { get; private set; }
    public string? CorruptDetail { get; private set; }

    public void Record(string transactionId, string operationId, string phase, bool success, string? detail = null, string? backupId = null, string? backupPayload = null)
    {
        if (IsCorrupt)
            throw new InvalidOperationException("CORRUPT_JOURNAL: refusing to append — technician must quarantine/replace journal.");

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
        if (IsCorrupt) return Array.Empty<RepairJournalEntry>();
        var incomplete = new List<RepairJournalEntry>();
        foreach (var group in _entries.GroupBy(e => e.TransactionId))
        {
            if (IsUncertain(group.ToList()) || IsIncomplete(group.ToList()))
                incomplete.Add(group.Last());
        }
        return incomplete;
    }

    public RepairRecoveryState GetRecoveryState(string? transactionId = null)
    {
        if (IsCorrupt) return RepairRecoveryState.CorruptJournal;

        IEnumerable<IGrouping<string, RepairJournalEntry>> groups = transactionId is null
            ? _entries.GroupBy(e => e.TransactionId)
            : _entries.Where(e => e.TransactionId == transactionId).GroupBy(e => e.TransactionId);

        var anyUncertain = false;
        var anyIncomplete = false;
        foreach (var group in groups)
        {
            var list = group.ToList();
            if (IsUncertain(list)) anyUncertain = true;
            else if (IsIncomplete(list)) anyIncomplete = true;
        }

        if (anyUncertain) return RepairRecoveryState.UncertainState;
        if (anyIncomplete) return RepairRecoveryState.Incomplete;
        return RepairRecoveryState.Clean;
    }

    /// <summary>Scan Journals root for unfinished / corrupt transactions across prior sessions.</summary>
    public static RepairRecoveryState ScanAllSessions(string journalsRoot)
    {
        if (!Directory.Exists(journalsRoot)) return RepairRecoveryState.Clean;
        var anyCorrupt = false;
        var anyUncertain = false;
        var anyIncomplete = false;

        foreach (var file in Directory.EnumerateFiles(journalsRoot, "repair-journal.json", SearchOption.AllDirectories))
        {
            var j = new RepairJournal(Path.GetDirectoryName(file)!);
            var st = j.GetRecoveryState();
            if (st == RepairRecoveryState.CorruptJournal) anyCorrupt = true;
            else if (st == RepairRecoveryState.UncertainState) anyUncertain = true;
            else if (st == RepairRecoveryState.Incomplete) anyIncomplete = true;
        }

        // Empty session dirs without a journal file are ignored.
        if (anyCorrupt) return RepairRecoveryState.CorruptJournal;
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
            if (j.IsCorrupt)
            {
                list.Add((dir, "", "", "CORRUPT_JOURNAL: " + (j.CorruptDetail ?? "unreadable")));
                continue;
            }
            foreach (var e in j.LoadIncomplete())
                list.Add((dir, e.TransactionId, e.OperationId, e.Phase + "(Success=" + e.Success + "): " + (e.Detail ?? "")));
        }
        return list;
    }

    public string ToJson() => JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });

    private void LoadFile(string path)
    {
        // Missing file = fresh session (Clean). Existing empty/whitespace = CORRUPT (fail-closed).
        if (!File.Exists(path)) return;
        try
        {
            var text = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(text))
            {
                IsCorrupt = true;
                CorruptDetail = "repair-journal.json exists but is empty/whitespace";
                return;
            }

            var loaded = JsonSerializer.Deserialize<List<RepairJournalEntry>>(text);
            if (loaded is null)
            {
                IsCorrupt = true;
                CorruptDetail = "Deserialize returned null";
                return;
            }

            // Required fields missing ⇒ corrupt
            if (loaded.Any(e => string.IsNullOrWhiteSpace(e.TransactionId)
                                || string.IsNullOrWhiteSpace(e.OperationId)
                                || string.IsNullOrWhiteSpace(e.Phase)))
            {
                IsCorrupt = true;
                CorruptDetail = "Journal entries missing required fields";
                return;
            }

            _entries.AddRange(loaded);
        }
        catch (Exception ex)
        {
            IsCorrupt = true;
            CorruptDetail = ex.Message;
            _entries.Clear();
        }
    }

    /// <summary>
    /// Write-ahead durable persist: temp → flush → replace. Fails closed if disk write fails
    /// (caller must not mutate when Persist throws after MutationIntent / ApplyStarted).
    /// </summary>
    private void Persist()
    {
        if (IsCorrupt)
            throw new InvalidOperationException("CORRUPT_JOURNAL: refusing to overwrite corrupt repair-journal.json");
        var tmp = _path + ".tmp";
        var json = ToJson();
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        using (var sw = new StreamWriter(fs))
        {
            sw.Write(json);
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }

        // Atomic replace where supported
        if (File.Exists(_path))
            File.Replace(tmp, _path, _path + ".bak", ignoreMetadataErrors: true);
        else
            File.Move(tmp, _path);

        try { if (File.Exists(_path + ".bak")) File.Delete(_path + ".bak"); } catch { /* best-effort */ }
        try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best-effort */ }
    }

    /// <summary>Record mutation intent and force durable flush before any Windows change.</summary>
    public void RecordMutationIntent(string transactionId, string operationId, string expectedTargetIdsJson, string beforeSnapshotJson)
    {
        Record(transactionId, operationId, "MutationIntent", true,
            detail: expectedTargetIdsJson,
            backupId: "intent",
            backupPayload: beforeSnapshotJson);
    }

    /// <summary>
    /// Evaluates Phase AND Success. Verify=false / RollbackVerified=false never count as completed.
    /// Does NOT auto-rollback.
    /// </summary>
    internal static bool IsUncertain(IReadOnlyList<RepairJournalEntry> entries)
    {
        if (entries.Count == 0) return false;

        var verifyOk = entries.Any(e => PhaseEq(e, "Verify") && e.Success);
        var rollbackOk = entries.Any(e => PhaseEq(e, "RollbackVerified") && e.Success);
        if (verifyOk || rollbackOk) return false;

        // Explicit failed terminals without successful recovery
        if (entries.Any(e => PhaseEq(e, "Verify") && !e.Success)) return true;
        if (entries.Any(e => PhaseEq(e, "RollbackVerified") && !e.Success)) return true;

        var phases = entries.Select(e => e.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Durable MutationIntent / ApplyStarted without successful Applied (crash mid-mutation)
        if ((phases.Contains("MutationIntent") || phases.Contains("ApplyStarted"))
            && !entries.Any(e => PhaseEq(e, "Applied") && e.Success)
            && !phases.Contains("RollbackStarted")
            && !rollbackOk)
            return true;

        // Applied (mutation done) without successful Verify / RollbackVerified
        if (entries.Any(e => PhaseEq(e, "Applied") && e.Success))
            return true;

        // Legacy "Apply" phase without Verify
        if (phases.Contains("Apply")
            && !phases.Contains("Verify")
            && !phases.Contains("Rollback")
            && !phases.Contains("RollbackVerified"))
            return true;

        // RollbackStarted without successful RollbackVerified
        if (phases.Contains("RollbackStarted") && !rollbackOk)
            return true;

        return false;
    }

    private static bool IsIncomplete(IReadOnlyList<RepairJournalEntry> entries)
    {
        var phases = entries.Select(e => e.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return phases.Contains("Backup")
               && !phases.Contains("ApplyStarted")
               && !phases.Contains("Verify")
               && !phases.Contains("RollbackVerified");
    }

    private static bool PhaseEq(RepairJournalEntry e, string phase)
        => e.Phase.Equals(phase, StringComparison.OrdinalIgnoreCase);
}
