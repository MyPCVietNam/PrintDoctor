using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Reports;

public sealed class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    public string DefaultRoot { get; init; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MyPC", "LanPrintDoctor");

    public IProcessRunner? ProcessRunner { get; init; }

    public async Task<string> ExportZipAsync(
        DiagnosticSnapshot snapshot,
        bool redact,
        CancellationToken ct = default,
        string? repairsJson = null,
        string? beforeAfterJson = null,
        string? eventLogsText = null)
    {
        var root = Path.Combine(DefaultRoot, "Sessions", snapshot.SessionId);
        Directory.CreateDirectory(root);
        await ApplyAclAsync(root, ct);

        var utc = DateTimeOffset.UtcNow;
        var local = utc.ToLocalTime();

        var summaryObj = new JsonObject
        {
            ["schemaVersion"] = snapshot.SchemaVersion,
            ["sessionId"] = snapshot.SessionId,
            ["role"] = snapshot.Role.ToString(),
            ["machineName"] = redact ? Redact(snapshot.MachineName) : snapshot.MachineName,
            ["targetHost"] = redact ? Redact(snapshot.TargetHost) : snapshot.TargetHost,
            ["startedAtUtc"] = snapshot.StartedAt.UtcDateTime.ToString("o"),
            ["startedAtLocal"] = snapshot.StartedAt.ToLocalTime().ToString("o"),
            ["completedAtUtc"] = snapshot.CompletedAt?.UtcDateTime.ToString("o"),
            ["exportedAtUtc"] = utc.ToString("o"),
            ["exportedAtLocal"] = local.ToString("o"),
            ["findingCount"] = snapshot.Findings.Count,
            ["fail"] = snapshot.Findings.Count(f => f.Status == Abstractions.Diagnostics.DiagnosticStatus.Fail),
            ["warning"] = snapshot.Findings.Count(f => f.Status == Abstractions.Diagnostics.DiagnosticStatus.Warning),
            ["unknown"] = snapshot.Findings.Count(f => f.Status == Abstractions.Diagnostics.DiagnosticStatus.Unknown)
        };

        var diagnosticsJson = JsonSerializer.Serialize(snapshot, JsonOptions);
        if (redact)
            diagnosticsJson = RedactJson(diagnosticsJson);

        await File.WriteAllTextAsync(Path.Combine(root, "Summary.json"), summaryObj.ToJsonString(JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Diagnostics.json"), diagnosticsJson, ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Network.txt"), BuildNetworkTxt(snapshot, redact), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Firewall.txt"), BuildFirewallTxt(snapshot), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Services.txt"), string.Join(Environment.NewLine, snapshot.Services.Select(s => $"{s.Name}\t{s.Status}\t{s.StartType}")), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "SMB.txt"), MaybeRedactText(JsonSerializer.Serialize(new { snapshot.SmbConfiguration, snapshot.SmbProbe, snapshot.SharingToggles, snapshot.Shares }, JsonOptions), redact), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Printers.txt"), JsonSerializer.Serialize(snapshot.Printers, JsonOptions), ct);
        if (snapshot.ShaPrint is not null)
            await File.WriteAllTextAsync(Path.Combine(root, "ShaPrint.txt"), JsonSerializer.Serialize(new { snapshot.ShaPrint, snapshot.ShaPrintConnectivity }, JsonOptions), ct);

        var repairs = repairsJson ?? snapshot.RepairsJson ?? "[]";
        var beforeAfter = beforeAfterJson ?? snapshot.BeforeAfterJson ?? "{}";
        if (repairs == "[]" && string.IsNullOrWhiteSpace(snapshot.RepairsJson))
            repairs = """{"note":"No repairs executed in this session.","entries":[]}""";
        if (beforeAfter == "{}" && string.IsNullOrWhiteSpace(snapshot.BeforeAfterJson))
            beforeAfter = """{"note":"No repair before/after captured in this session."}""";

        await File.WriteAllTextAsync(Path.Combine(root, "Repairs.json"), repairs, ct);
        await File.WriteAllTextAsync(Path.Combine(root, "BeforeAfter.json"), beforeAfter, ct);

        var events = eventLogsText ?? snapshot.EventLogsText ?? await CollectEventLogsAsync(ct);
        await File.WriteAllTextAsync(Path.Combine(root, "EventLogs.txt"), events, ct);

        await File.WriteAllTextAsync(Path.Combine(root, "CollectorStatus.txt"),
            string.Join(Environment.NewLine, snapshot.CollectorNotes.Select(n => $"{n.Collector}\t{n.Outcome}\t{n.Detail}")), ct);

        var sys = new StringBuilder();
        sys.AppendLine(snapshot.OsDescription);
        sys.AppendLine($"Machine={(redact ? Redact(snapshot.MachineName) : snapshot.MachineName)}");
        sys.AppendLine($"Role={snapshot.Role}");
        sys.AppendLine($"Schema={snapshot.SchemaVersion}");
        sys.AppendLine($"ExportedUtc={utc:o}");
        sys.AppendLine($"ExportedLocal={local:o}");
        await File.WriteAllTextAsync(Path.Combine(root, "SystemInfo.txt"), sys.ToString(), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "TestReport.txt"), BuildFindingsTxt(snapshot), ct);

        var zipPath = Path.Combine(DefaultRoot, "Exports", $"{snapshot.SessionId}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zipPath)!);
        if (File.Exists(zipPath)) File.Delete(zipPath);
        ZipFile.CreateFromDirectory(root, zipPath);
        return zipPath;
    }

    private async Task<string> CollectEventLogsAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || ProcessRunner is null)
            return "EventLogs: NOT_COLLECTED (non-Windows or no process runner). Status=UNKNOWN.";

        const string script = @"
$errs = @()
try {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Admin'; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 30 -ErrorAction Stop |
    ForEach-Object { '{0:o} [{1}] {2}' -f $_.TimeCreated, $_.Id, $_.Message.Split([char]10)[0] }
} catch { $errs += 'PrintService: ' + $_.Exception.Message }
try {
  Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-SMBClient','Microsoft-Windows-SMBServer'; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 30 -ErrorAction Stop |
    ForEach-Object { '{0:o} [{1}] {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+',' ').Substring(0, [Math]::Min(160, $_.Message.Length)) }
} catch { $errs += 'SMB: ' + $_.Exception.Message }
if ($errs.Count -gt 0) { 'COLLECTOR_WARNINGS:'; $errs }
";
        var result = await ProcessRunner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(45), ct);
        if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.StdOut))
            return "EventLogs: NOT_COLLECTED — " + result.StdErr + " Status=UNKNOWN.";
        return string.IsNullOrWhiteSpace(result.StdOut)
            ? "EventLogs: collected with no matching events in window. Status=PASS."
            : result.StdOut;
    }

    private async Task ApplyAclAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || ProcessRunner is null) return;
        // Restrict to SYSTEM + Administrators + current user; no Everyone
        var user = Environment.UserName.Replace("'", "''");
        var script = $"icacls '{path.Replace("'", "''")}' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' '{user}:(OI)(CI)F' | Out-Null; 'OK'";
        await ProcessRunner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(20), ct);
    }

    private static string BuildNetworkTxt(DiagnosticSnapshot s, bool redact)
    {
        var sb = new StringBuilder();
        foreach (var a in s.Adapters)
        {
            sb.AppendLine($"Adapter: {a.Name} Kind={a.Kind} Up={a.IsUp} Cat={a.Category} IfIndex={a.InterfaceIndex} Metric={a.InterfaceMetric}");
            sb.AppendLine($"  MAC={(redact ? Redact(a.MacAddress) : a.MacAddress)} Profile={a.ProfileName}");
            sb.AppendLine($"  IPv4={(redact ? string.Join(",", a.IPv4Addresses.Select(Redact)) : string.Join(",", a.IPv4Addresses))} /{a.PrefixLength}");
            sb.AppendLine($"  GW={(redact ? Redact(a.DefaultGateway) : a.DefaultGateway)} DNS={string.Join(",", a.DnsServers)}");
        }
        sb.AppendLine("Routes:");
        foreach (var r in s.Routes.Take(50))
            sb.AppendLine($"  {r.Destination}/{r.Mask} via {r.Gateway} if={r.InterfaceIndex} metric={r.Metric}");
        sb.AppendLine("Neighbors:");
        foreach (var n in s.Neighbors.Take(50))
            sb.AppendLine($"  {n.IpAddress} -> {(redact ? Redact(n.MacAddress) : n.MacAddress)} state={n.State} if={n.InterfaceAlias}");
        sb.AppendLine("Probes:");
        foreach (var p in s.Probes)
            sb.AppendLine($"  {p.Protocol}:{p.Target}:{p.Port} => {p.Outcome} {p.Detail}");
        return sb.ToString();
    }

    private static string BuildFirewallTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var p in s.FirewallProfiles)
            sb.AppendLine($"Profile {p.Profile}: Enabled={p.Enabled} In={p.DefaultInboundAction} Out={p.DefaultOutboundAction} Policy={p.ManagedByPolicy}");
        foreach (var r in s.FirewallRules)
            sb.AppendLine($"{r.RuleId}|{r.Name}|Enabled={r.Enabled}|{r.Direction}|{r.Action}|{r.Protocol}|{r.LocalPorts}|{r.RemoteAddresses}|{r.Profiles}|{r.Grouping}");
        return sb.ToString();
    }

    private static string BuildFindingsTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var f in s.Findings)
            sb.AppendLine($"{f.Id}\t{f.Status}\t{f.Severity}\t{f.Title}\tconf={f.Confidence}\t{f.Evidence}");
        return sb.ToString();
    }

    private static string RedactJson(string json)
    {
        // Consistent field redaction for common sensitive keys
        try
        {
            var node = JsonNode.Parse(json);
            if (node is not null) RedactNode(node);
            return node?.ToJsonString(JsonOptions) ?? json;
        }
        catch
        {
            return MaybeRedactText(json, true);
        }
    }

    private static void RedactNode(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            foreach (var prop in obj.ToList())
            {
                var name = prop.Key;
                if (IsSensitiveName(name) && prop.Value is JsonValue)
                    obj[name] = "***";
                else if (prop.Value is not null)
                    RedactNode(prop.Value);
            }
        }
        else if (node is JsonArray arr)
        {
            foreach (var item in arr)
                if (item is not null) RedactNode(item);
        }
    }

    private static bool IsSensitiveName(string name)
        => name.Contains("Mac", StringComparison.OrdinalIgnoreCase)
           || name.Contains("Address", StringComparison.OrdinalIgnoreCase)
           || name.Equals("MachineName", StringComparison.OrdinalIgnoreCase)
           || name.Equals("TargetHost", StringComparison.OrdinalIgnoreCase)
           || name.Equals("IPv4Addresses", StringComparison.OrdinalIgnoreCase)
           || name.Equals("DefaultGateway", StringComparison.OrdinalIgnoreCase);

    private static string MaybeRedactText(string text, bool redact)
        => redact ? Redact(text) ?? "***" : text;

    private static string? Redact(string? value)
        => value is null ? null : "***";
}
