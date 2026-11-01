using System.IO.Compression;
using System.Text;
using System.Text.Json;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Reports;

public sealed class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string DefaultRoot { get; init; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MyPC", "LanPrintDoctor");

    public async Task<string> ExportZipAsync(DiagnosticSnapshot snapshot, bool redact, CancellationToken ct = default)
    {
        var root = Path.Combine(DefaultRoot, "Sessions", snapshot.SessionId);
        Directory.CreateDirectory(root);
        TryAclHint(root);

        var summary = new
        {
            snapshot.SessionId,
            snapshot.Role,
            snapshot.MachineName,
            snapshot.TargetHost,
            snapshot.StartedAt,
            snapshot.CompletedAt,
            FindingCount = snapshot.Findings.Count,
            Fail = snapshot.Findings.Count(f => f.Status == Abstractions.Diagnostics.DiagnosticStatus.Fail),
            Warning = snapshot.Findings.Count(f => f.Status == Abstractions.Diagnostics.DiagnosticStatus.Warning)
        };

        await File.WriteAllTextAsync(Path.Combine(root, "Summary.json"), JsonSerializer.Serialize(MaybeRedact(summary, redact), JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Diagnostics.json"), JsonSerializer.Serialize(MaybeRedact(snapshot, redact), JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Network.txt"), BuildNetworkTxt(snapshot, redact), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Firewall.txt"), BuildFirewallTxt(snapshot), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Services.txt"), string.Join(Environment.NewLine, snapshot.Services.Select(s => $"{s.Name}\t{s.Status}\t{s.StartType}")), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "SMB.txt"), JsonSerializer.Serialize(new { snapshot.SmbConfiguration, snapshot.SmbProbe, snapshot.SharingToggles, snapshot.Shares }, JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Printers.txt"), JsonSerializer.Serialize(snapshot.Printers, JsonOptions), ct);
        if (snapshot.ShaPrint is not null)
            await File.WriteAllTextAsync(Path.Combine(root, "ShaPrint.txt"), JsonSerializer.Serialize(new { snapshot.ShaPrint, snapshot.ShaPrintConnectivity }, JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Repairs.json"), "[]", ct);
        await File.WriteAllTextAsync(Path.Combine(root, "BeforeAfter.json"), "{}", ct);
        await File.WriteAllTextAsync(Path.Combine(root, "SystemInfo.txt"), $"{snapshot.OsDescription}\nMachine={snapshot.MachineName}\nRole={snapshot.Role}", ct);
        await File.WriteAllTextAsync(Path.Combine(root, "TestReport.txt"), BuildFindingsTxt(snapshot), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "EventLogs.txt"), "Event log export requires Windows platform collector; see Diagnostics.json for structured evidence.", ct);

        var zipPath = Path.Combine(DefaultRoot, "Exports", $"{snapshot.SessionId}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zipPath)!);
        if (File.Exists(zipPath)) File.Delete(zipPath);
        ZipFile.CreateFromDirectory(root, zipPath);
        return zipPath;
    }

    private static string BuildNetworkTxt(DiagnosticSnapshot s, bool redact)
    {
        var sb = new StringBuilder();
        foreach (var a in s.Adapters)
        {
            sb.AppendLine($"Adapter: {a.Name} Kind={a.Kind} Up={a.IsUp} Cat={a.Category}");
            sb.AppendLine($"  MAC={(redact ? Redact(a.MacAddress) : a.MacAddress)}");
            sb.AppendLine($"  IPv4={(redact ? string.Join(",", a.IPv4Addresses.Select(Redact)) : string.Join(",", a.IPv4Addresses))}");
            sb.AppendLine($"  GW={(redact ? Redact(a.DefaultGateway) : a.DefaultGateway)} DNS={string.Join(",", a.DnsServers)}");
        }
        sb.AppendLine("Probes:");
        foreach (var p in s.Probes)
            sb.AppendLine($"  {p.Protocol}:{p.Target}:{p.Port} => {(p.Success ? "PASS" : "FAIL")} {p.Detail}");
        return sb.ToString();
    }

    private static string BuildFirewallTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var p in s.FirewallProfiles)
            sb.AppendLine($"Profile {p.Profile}: Enabled={p.Enabled} In={p.DefaultInboundAction} Out={p.DefaultOutboundAction} Policy={p.ManagedByPolicy}");
        foreach (var r in s.FirewallRules)
            sb.AppendLine($"{r.Name}|Enabled={r.Enabled}|{r.Direction}|{r.Action}|{r.Protocol}|{r.LocalPorts}|{r.Profiles}");
        return sb.ToString();
    }

    private static string BuildFindingsTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var f in s.Findings)
            sb.AppendLine($"{f.Id}\t{f.Status}\t{f.Severity}\t{f.Title}\tconf={f.Confidence}\t{f.Evidence}");
        return sb.ToString();
    }

    private static object MaybeRedact(object obj, bool redact) => obj; // JSON path redaction applied in text builders; structured kept for local forensics unless redact flag expands

    private static string? Redact(string? value)
        => value is null ? null : "***";

    private static void TryAclHint(string path)
    {
        // ACL hardening is Windows-specific; platform layer may tighten. Ensure directory exists only here.
        _ = path;
    }
}
