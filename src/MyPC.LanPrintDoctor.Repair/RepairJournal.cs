using System.Text.Json;

namespace MyPC.LanPrintDoctor.Repair;

public sealed class RepairJournalEntry
{
    public required string OperationId { get; init; }
    public required string Phase { get; init; }
    public DateTimeOffset At { get; init; } = DateTimeOffset.UtcNow;
    public string? Detail { get; init; }
    public bool Success { get; init; }
}

public sealed class RepairJournal
{
    private readonly List<RepairJournalEntry> _entries = new();
    private readonly string _path;

    public RepairJournal(string directory)
    {
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "repair-journal.json");
    }

    public IReadOnlyList<RepairJournalEntry> Entries => _entries;

    public void Record(string operationId, string phase, bool success, string? detail = null)
    {
        _entries.Add(new RepairJournalEntry
        {
            OperationId = operationId,
            Phase = phase,
            Success = success,
            Detail = detail
        });
        Persist();
    }

    private void Persist()
    {
        var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_path, json);
    }
}
