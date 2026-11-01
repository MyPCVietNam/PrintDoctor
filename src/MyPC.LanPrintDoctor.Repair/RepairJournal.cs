using System.Text.Json;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairJournalEntry
{
    public required string OperationId { get; init; }
    public required string Phase { get; init; }
    public DateTimeOffset AtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string? Detail { get; init; }
    public bool Success { get; init; }
    public string? BackupId { get; init; }
    public string? BackupPayloadJson { get; init; }
}

/// <summary>
/// Durable transaction journal. Survives process crash between phases;
/// unfinished Apply without Verify can be recovered via LoadIncomplete.
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

    public void Record(string operationId, string phase, bool success, string? detail = null, string? backupId = null, string? backupPayload = null)
    {
        _entries.Add(new RepairJournalEntry
        {
            OperationId = operationId,
            Phase = phase,
            Success = success,
            Detail = detail,
            BackupId = backupId,
            BackupPayloadJson = backupPayload
        });
        Persist();
    }

    public IReadOnlyList<RepairJournalEntry> LoadIncomplete()
    {
        var incomplete = new List<RepairJournalEntry>();
        foreach (var group in _entries.GroupBy(e => e.OperationId))
        {
            var phases = group.Select(g => g.Phase).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (phases.Contains("Apply") && !phases.Contains("Verify") && !phases.Contains("Rollback"))
                incomplete.Add(group.Last(e => e.Phase.Equals("Apply", StringComparison.OrdinalIgnoreCase)));
        }
        return incomplete;
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
