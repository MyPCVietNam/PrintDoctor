using System.IO.Compression;
using System.Text.Json;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Compare;

public sealed class ReportCompareService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    private readonly CompareEngine _engine = new();

    public CompareResult CompareFiles(string serverReportPath, IReadOnlyList<string> clientReportPaths)
    {
        var server = LoadSnapshot(serverReportPath);
        var clients = clientReportPaths.Select(LoadSnapshot).ToList();
        ValidateSchema(server);
        foreach (var c in clients) ValidateSchema(c);
        return _engine.Compare(new CompareInput { Server = server, Clients = clients });
    }

    public DiagnosticSnapshot LoadSnapshot(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Report not found", path);

        if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            return LoadFromZip(path);

        var json = File.ReadAllText(path);
        return Deserialize(json, path);
    }

    private static DiagnosticSnapshot LoadFromZip(string zipPath)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        var entry = zip.GetEntry("Diagnostics.json")
                    ?? zip.Entries.FirstOrDefault(e => e.FullName.EndsWith("Diagnostics.json", StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidDataException("ZIP missing Diagnostics.json");
        using var stream = entry.Open();
        using var reader = new StreamReader(stream);
        return Deserialize(reader.ReadToEnd(), zipPath);
    }

    private static DiagnosticSnapshot Deserialize(string json, string source)
    {
        var snap = JsonSerializer.Deserialize<DiagnosticSnapshot>(json, JsonOptions)
                   ?? throw new InvalidDataException($"Invalid diagnostics JSON: {source}");
        return snap;
    }

    private static void ValidateSchema(DiagnosticSnapshot snap)
    {
        if (string.IsNullOrWhiteSpace(snap.SchemaVersion))
            throw new InvalidDataException("Report missing SchemaVersion.");
        // Accept 1.0.x and 1.1.x
        if (!snap.SchemaVersion.StartsWith("1.", StringComparison.Ordinal))
            throw new InvalidDataException($"Unsupported schema version: {snap.SchemaVersion}");
    }
}
