using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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

    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", RegexOptions.Compiled);
    private static readonly Regex MacRegex = new(@"\b(?:[0-9A-Fa-f]{2}([-:]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b", RegexOptions.Compiled);

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
        await ApplyAclAsync(root, ct, required: false);

        var utc = DateTimeOffset.UtcNow;
        var local = utc.ToLocalTime();
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string Tok(string? v) => StableToken(v, tokens);

        var summaryObj = new JsonObject
        {
            ["schemaVersion"] = snapshot.SchemaVersion,
            ["sessionId"] = snapshot.SessionId,
            ["role"] = snapshot.Role.ToString(),
            ["machineName"] = redact ? Tok(snapshot.MachineName) : snapshot.MachineName,
            ["targetHost"] = redact ? Tok(snapshot.TargetHost) : snapshot.TargetHost,
            ["redacted"] = redact,
            ["compareLimitation"] = redact ? "Redacted identifiers are stable tokens; cross-machine compare may be limited." : null,
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
        if (redact) diagnosticsJson = RedactJson(diagnosticsJson, tokens);

        await File.WriteAllTextAsync(Path.Combine(root, "Summary.json"), summaryObj.ToJsonString(JsonOptions), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Diagnostics.json"), diagnosticsJson, ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Network.txt"), RedactTextIf(BuildNetworkTxt(snapshot, redact, Tok), redact, tokens), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Firewall.txt"), RedactTextIf(BuildFirewallTxt(snapshot), redact, tokens), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "Services.txt"), string.Join(Environment.NewLine, snapshot.Services.Select(s => $"{s.Name}\t{s.Status}\t{s.StartType}")), ct);

        var smbJson = JsonSerializer.Serialize(new { snapshot.SmbConfiguration, snapshot.SmbProbe, snapshot.SharingToggles, snapshot.Shares }, JsonOptions);
        await File.WriteAllTextAsync(Path.Combine(root, "SMB.txt"), redact ? RedactJson(smbJson, tokens) : smbJson, ct);

        var printersJson = JsonSerializer.Serialize(snapshot.Printers, JsonOptions);
        await File.WriteAllTextAsync(Path.Combine(root, "Printers.txt"), redact ? RedactJson(printersJson, tokens) : printersJson, ct);
        if (snapshot.ShaPrint is not null)
        {
            var shaJson = JsonSerializer.Serialize(new { snapshot.ShaPrint, snapshot.ShaPrintConnectivity }, JsonOptions);
            await File.WriteAllTextAsync(Path.Combine(root, "ShaPrint.txt"), redact ? RedactJson(shaJson, tokens) : shaJson, ct);
        }

        var repairs = repairsJson ?? snapshot.RepairsJson ?? "[]";
        var beforeAfter = beforeAfterJson ?? snapshot.BeforeAfterJson ?? "{}";
        if (repairs == "[]" && string.IsNullOrWhiteSpace(snapshot.RepairsJson))
            repairs = """{"note":"No repairs executed in this session.","entries":[]}""";
        if (beforeAfter == "{}" && string.IsNullOrWhiteSpace(snapshot.BeforeAfterJson))
            beforeAfter = """{"note":"No repair before/after captured in this session."}""";

        await File.WriteAllTextAsync(Path.Combine(root, "Repairs.json"), redact ? RedactJson(repairs, tokens) : repairs, ct);
        await File.WriteAllTextAsync(Path.Combine(root, "BeforeAfter.json"), redact ? RedactJson(beforeAfter, tokens) : beforeAfter, ct);

        var events = eventLogsText ?? snapshot.EventLogsText ?? await CollectEventLogsAsync(ct);
        await File.WriteAllTextAsync(Path.Combine(root, "EventLogs.txt"), RedactTextIf(events, redact, tokens), ct);

        var collector = string.Join(Environment.NewLine, snapshot.CollectorNotes.Select(n => $"{n.Collector}\t{n.Outcome}\t{n.Detail}"));
        await File.WriteAllTextAsync(Path.Combine(root, "CollectorStatus.txt"), RedactTextIf(collector, redact, tokens), ct);

        var sys = new StringBuilder();
        sys.AppendLine(snapshot.OsDescription);
        sys.AppendLine($"Machine={(redact ? Tok(snapshot.MachineName) : snapshot.MachineName)}");
        sys.AppendLine($"Role={snapshot.Role}");
        sys.AppendLine($"Schema={snapshot.SchemaVersion}");
        sys.AppendLine($"ExportedUtc={utc:o}");
        sys.AppendLine($"ExportedLocal={local:o}");
        if (redact) sys.AppendLine("Redacted=true CompareLimitation=stable-tokens-only");
        await File.WriteAllTextAsync(Path.Combine(root, "SystemInfo.txt"), sys.ToString(), ct);
        await File.WriteAllTextAsync(Path.Combine(root, "TestReport.txt"), RedactTextIf(BuildFindingsTxt(snapshot), redact, tokens), ct);

        var zipPath = Path.Combine(DefaultRoot, "Exports", $"{snapshot.SessionId}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zipPath)!);
        if (File.Exists(zipPath)) File.Delete(zipPath);
        ZipFile.CreateFromDirectory(root, zipPath);
        await ApplyAclAsync(zipPath, ct, required: OperatingSystem.IsWindows() && ProcessRunner is not null);
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

    private async Task ApplyAclAsync(string path, CancellationToken ct, bool required)
    {
        if (!OperatingSystem.IsWindows() || ProcessRunner is null)
        {
            if (required) throw new InvalidOperationException("ACL hardening required but ProcessRunner/Windows unavailable.");
            return;
        }

        var user = Environment.UserName.Replace("'", "''");
        var escaped = path.Replace("'", "''");
        var script = $"$ErrorActionPreference='Stop'; icacls '{escaped}' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' '{user}:(OI)(CI)F'; if ($LASTEXITCODE -ne 0) {{ throw 'icacls failed' }}; 'OK'";
        var result = await ProcessRunner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(20), ct);
        if (result.ExitCode != 0 || !result.StdOut.Contains("OK", StringComparison.Ordinal))
        {
            if (required)
                throw new InvalidOperationException("icacls ACL hardening failed: " + result.StdErr);
        }
    }

    private static string BuildNetworkTxt(DiagnosticSnapshot s, bool redact, Func<string?, string> tok)
    {
        var sb = new StringBuilder();
        foreach (var a in s.Adapters)
        {
            sb.AppendLine($"Adapter: {a.Name} Kind={a.Kind} Up={a.IsUp} Cat={a.Category} IfIndex={a.InterfaceIndex} Metric={a.InterfaceMetric}");
            sb.AppendLine($"  MAC={(redact ? tok(a.MacAddress) : a.MacAddress)} Profile={a.ProfileName}");
            sb.AppendLine($"  IPv4={(redact ? string.Join(",", a.IPv4Addresses.Select(tok)) : string.Join(",", a.IPv4Addresses))} /{a.PrefixLength}");
            sb.AppendLine($"  GW={(redact ? tok(a.DefaultGateway) : a.DefaultGateway)} DNS={(redact ? string.Join(",", a.DnsServers.Select(tok)) : string.Join(",", a.DnsServers))}");
        }
        sb.AppendLine("Routes:");
        foreach (var r in s.Routes.Take(50))
            sb.AppendLine($"  {(redact ? tok(r.Destination) : r.Destination)}/{r.Mask} via {(redact ? tok(r.Gateway ?? r.NextHop) : r.Gateway ?? r.NextHop)} if={r.InterfaceIndex} metric={r.Metric}");
        sb.AppendLine("Neighbors:");
        foreach (var n in s.Neighbors.Take(50))
            sb.AppendLine($"  {(redact ? tok(n.IpAddress) : n.IpAddress)} -> {(redact ? tok(n.MacAddress) : n.MacAddress)} state={n.State} if={n.InterfaceAlias}");
        sb.AppendLine("Probes:");
        foreach (var p in s.Probes)
            sb.AppendLine($"  {p.Protocol}:{(redact ? tok(p.Target) : p.Target)}:{p.Port} => {p.Outcome} {p.Detail}");
        return sb.ToString();
    }

    private static string BuildFirewallTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var p in s.FirewallProfiles)
            sb.AppendLine($"Profile {p.Profile}: Enabled={p.Enabled} In={p.DefaultInboundAction} Out={p.DefaultOutboundAction} Policy={p.ManagedByPolicy}");
        foreach (var r in s.FirewallRules)
            sb.AppendLine($"{r.RuleId}|{r.Name}|Enabled={r.Enabled}|{r.Direction}|{r.Action}|{r.Protocol}|{r.LocalPorts}|{r.RemoteAddresses}|{r.Profiles}|{r.Grouping}|{r.PolicyStore}");
        return sb.ToString();
    }

    private static string BuildFindingsTxt(DiagnosticSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var f in s.Findings)
            sb.AppendLine($"{f.Id}\t{f.Status}\t{f.Severity}\t{f.Title}\towner={f.RepairOwner}\tconf={f.Confidence}\t{f.Evidence}");
        return sb.ToString();
    }

    private static string RedactJson(string json, Dictionary<string, string> tokens)
    {
        try
        {
            var node = JsonNode.Parse(json);
            if (node is not null) RedactNode(node, tokens);
            return node?.ToJsonString(JsonOptions) ?? RedactText(json, tokens);
        }
        catch
        {
            return RedactText(json, tokens);
        }
    }

    private static void RedactNode(JsonNode node, Dictionary<string, string> tokens)
    {
        if (node is JsonObject obj)
        {
            foreach (var prop in obj.ToList())
            {
                var name = prop.Key;
                if (IsSensitiveName(name))
                {
                    if (prop.Value is JsonValue jv && jv.TryGetValue<string>(out var s))
                        obj[name] = StableToken(s, tokens);
                    else if (prop.Value is JsonArray arr)
                    {
                        for (var i = 0; i < arr.Count; i++)
                        {
                            if (arr[i] is JsonValue av && av.TryGetValue<string>(out var item))
                                arr[i] = StableToken(item, tokens);
                            else if (arr[i] is not null)
                                RedactNode(arr[i]!, tokens);
                        }
                    }
                    else if (prop.Value is not null)
                        RedactNode(prop.Value, tokens);
                }
                else if (prop.Value is JsonValue free && free.TryGetValue<string>(out var text) && LooksSensitive(text))
                    obj[name] = RedactText(text, tokens);
                else if (prop.Value is not null)
                    RedactNode(prop.Value, tokens);
            }
        }
        else if (node is JsonArray arr)
        {
            for (var i = 0; i < arr.Count; i++)
            {
                if (arr[i] is JsonValue av && av.TryGetValue<string>(out var item) && LooksSensitive(item))
                    arr[i] = RedactText(item, tokens);
                else if (arr[i] is not null)
                    RedactNode(arr[i]!, tokens);
            }
        }
    }

    private static bool LooksSensitive(string text)
        => IpRegex.IsMatch(text) || MacRegex.IsMatch(text);

    private static bool IsSensitiveName(string name)
        => name.Contains("Mac", StringComparison.OrdinalIgnoreCase)
           || name.Contains("Address", StringComparison.OrdinalIgnoreCase)
           || name.Equals("MachineName", StringComparison.OrdinalIgnoreCase)
           || name.Equals("TargetHost", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Target", StringComparison.OrdinalIgnoreCase)
           || name.Equals("IPv4Addresses", StringComparison.OrdinalIgnoreCase)
           || name.Equals("IPv6Addresses", StringComparison.OrdinalIgnoreCase)
           || name.Equals("DnsServers", StringComparison.OrdinalIgnoreCase)
           || name.Equals("DefaultGateway", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Destination", StringComparison.OrdinalIgnoreCase)
           || name.Equals("NextHop", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Gateway", StringComparison.OrdinalIgnoreCase)
           || name.Equals("IpAddress", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Path", StringComparison.OrdinalIgnoreCase)
           || name.Equals("RemoteAddresses", StringComparison.OrdinalIgnoreCase)
           || name.Equals("LocalAddresses", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Evidence", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Detail", StringComparison.OrdinalIgnoreCase);

    private static string RedactTextIf(string text, bool redact, Dictionary<string, string> tokens)
        => redact ? RedactText(text, tokens) : text;

    private static string RedactText(string text, Dictionary<string, string> tokens)
    {
        var t = IpRegex.Replace(text, m => StableToken(m.Value, tokens));
        t = MacRegex.Replace(t, m => StableToken(m.Value, tokens));
        return t;
    }

    // Ephemeral HMAC key — never written into the shared ZIP (prevents rainbow reversal of SHA256(IP)).
    private static readonly byte[] SessionHmacKey = RandomNumberGenerator.GetBytes(32);

    private static string StableToken(string? value, Dictionary<string, string> tokens)
    {
        if (string.IsNullOrWhiteSpace(value)) return "***";
        if (tokens.TryGetValue(value, out var existing)) return existing;
        // Random per-export mapping preferred; HMAC with ephemeral key for within-session stability only.
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(SessionHmacKey, Encoding.UTF8.GetBytes(value.ToLowerInvariant()), mac);
        var token = "tok:" + Convert.ToHexString(mac)[..12].ToLowerInvariant();
        tokens[value] = token;
        return token;
    }
}
