using System.IO.Compression;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Compare;

public sealed class ReportCompareService
{
    public const long MaxZipBytes = 25 * 1024 * 1024; // 25 MiB

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    private readonly CompareEngine _engine = new();

    public CompareResult CompareFiles(string serverReportPath, IReadOnlyList<string> clientReportPaths)
    {
        if (clientReportPaths.Count == 0)
            throw new InvalidDataException("At least one client report is required.");
        if (clientReportPaths.Count > 16)
            throw new InvalidDataException("Too many client reports (max 16).");

        var server = LoadSnapshot(serverReportPath);
        var clients = clientReportPaths.Select(LoadSnapshot).ToList();
        ValidateSchema(server, expectRole: MachineRole.Server, path: serverReportPath);
        foreach (var (c, path) in clients.Zip(clientReportPaths))
            ValidateSchema(c, expectRole: null, path: path);

        var result = _engine.Compare(new CompareInput { Server = server, Clients = clients });
        if (IsRedacted(server) || clients.Any(IsRedacted))
        {
            var insufficient = result.InsufficientEvidence.ToList();
            insufficient.Add("One or more reports are redacted — correlation limited; do not treat identity mismatches as definitive.");
            return new CompareResult
            {
                Findings = result.Findings,
                ServerSideIssues = result.ServerSideIssues,
                ClientSpecificIssues = result.ClientSpecificIssues,
                InfrastructureHints = result.InfrastructureHints,
                InsufficientEvidence = insufficient,
                HasValidEvidence = result.HasValidEvidence && result.Findings.Count > 0
            };
        }
        return result;
    }

    public DiagnosticSnapshot LoadSnapshot(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Report not found", path);

        var info = new FileInfo(path);
        if (info.Length > MaxZipBytes)
            throw new InvalidDataException($"Report too large ({info.Length} bytes). Max {MaxZipBytes}.");

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
        if (entry.Length > MaxZipBytes)
            throw new InvalidDataException("Diagnostics.json entry too large.");
        using var stream = entry.Open();
        using var reader = new StreamReader(stream);
        return Deserialize(reader.ReadToEnd(), zipPath);
    }

    private static DiagnosticSnapshot Deserialize(string json, string source)
    {
        // Validate required fields exist in raw JSON before model defaults fill them in.
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (!root.TryGetProperty("schemaVersion", out _) && !root.TryGetProperty("SchemaVersion", out _))
            throw new InvalidDataException($"Report missing SchemaVersion field: {source}");
        if (!root.TryGetProperty("role", out _) && !root.TryGetProperty("Role", out _))
            throw new InvalidDataException($"Report missing Role field: {source}");
        if (!root.TryGetProperty("sessionId", out _) && !root.TryGetProperty("SessionId", out _))
            throw new InvalidDataException($"Report missing SessionId field: {source}");
        if (!root.TryGetProperty("startedAt", out _) && !root.TryGetProperty("StartedAt", out _))
            throw new InvalidDataException($"Report missing StartedAt field: {source}");

        var snap = JsonSerializer.Deserialize<DiagnosticSnapshot>(json, JsonOptions)
                   ?? throw new InvalidDataException($"Invalid diagnostics JSON: {source}");
        return snap;
    }

    private static void ValidateSchema(DiagnosticSnapshot snap, MachineRole? expectRole, string path)
    {
        if (string.IsNullOrWhiteSpace(snap.SchemaVersion))
            throw new InvalidDataException("Report missing SchemaVersion.");
        if (!snap.SchemaVersion.StartsWith("1.", StringComparison.Ordinal))
            throw new InvalidDataException($"Unsupported schema version: {snap.SchemaVersion}");
        if (expectRole is MachineRole er && snap.Role != er)
            throw new InvalidDataException($"Expected role {er} in {path}, got {snap.Role}.");
        if (snap.StartedAt == default)
            throw new InvalidDataException($"Report missing/invalid StartedAt: {path}");
    }

    private static bool IsRedacted(DiagnosticSnapshot snap)
        => (snap.MachineName?.StartsWith("tok:", StringComparison.OrdinalIgnoreCase) ?? false)
           || (snap.TargetHost?.StartsWith("tok:", StringComparison.OrdinalIgnoreCase) ?? false)
           || snap.Adapters.Any(a => a.IPv4Addresses.Any(ip => ip.StartsWith("tok:", StringComparison.OrdinalIgnoreCase)));
}
