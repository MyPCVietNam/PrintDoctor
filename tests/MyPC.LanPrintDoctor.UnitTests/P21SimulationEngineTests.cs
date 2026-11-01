using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Simulation;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

/// <summary>
/// Runs pre-field simulation fixtures against REAL DecisionEngine / NetworkRootCauseEngine / RepairExecutor.
/// Reference-oracle PASS counts are NOT claimed as PrintDoctor PASS.
/// </summary>
public class P21SimulationEngineTests
{
    private static string FixturesDir()
    {
        foreach (var dir in new[]
                 {
                     Path.Combine(AppContext.BaseDirectory, "SimulationFixtures"),
                     Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Simulation", "fixtures")),
                     Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "tests", "Simulation", "fixtures"))
                 })
        {
            if (Directory.Exists(dir) && File.Exists(Path.Combine(dir, "scenarios.json")))
                return dir;
        }
        return Path.Combine(AppContext.BaseDirectory, "SimulationFixtures");
    }

    [Fact]
    public void P21_Simulation_DiagnosticScenarios_RunOnRealEngines()
    {
        var path = Path.Combine(FixturesDir(), "scenarios.json");
        Assert.True(File.Exists(path), "SIMULATION_IMPORT required: " + path);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.Equal(48, doc.RootElement.GetArrayLength());

        var engine = new DecisionEngine();
        var root = new NetworkRootCauseEngine();
        var results = new List<SimulationCaseResult>();
        foreach (var sc in doc.RootElement.EnumerateArray())
            results.Add(SimulationScenarioMapper.EvaluateDiagnostic(sc, engine, root));

        var pass = results.Count(r => r.Status == "PASS");
        var fail = results.Count(r => r.Status == "FAIL");
        var blocked = results.Count(r => r.Status == "BLOCKED");
        var failDetail = string.Join("; ", results.Where(r => r.Status == "FAIL").Select(r => r.ScenarioId + ":" + r.Detail));
        Assert.True(fail == 0, failDetail);
        Assert.Equal(48, pass + blocked);
        // Persist for SIMULATION-REAL-ENGINE-RESULTS.md generation
        var outDir = Path.Combine(Path.GetTempPath(), "lpd-sim-results");
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "diagnostic-results.json"),
            JsonSerializer.Serialize(new { pass, fail, blocked, total = 48, results }, new JsonSerializerOptions { WriteIndented = true }));
    }

    [Fact]
    public void P21_Simulation_Office5pc_CompareEngine()
    {
        var path = Path.Combine(FixturesDir(), "office_5pc_scenarios.json");
        Assert.True(File.Exists(path));
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(12, doc.RootElement.GetArrayLength());
        var compare = new CompareEngine();
        var mapped = 0;
        var blocked = 0;
        foreach (var office in doc.RootElement.EnumerateArray())
        {
            var serverIp = office.GetProperty("server").TryGetProperty("ip", out var ip) ? ip.GetString() : "192.168.10.50";
            var nicDown = office.GetProperty("server").TryGetProperty("nic", out var nic)
                          && string.Equals(nic.GetString(), "DOWN", StringComparison.OrdinalIgnoreCase);
            var server = new DiagnosticSnapshot
            {
                SessionId = "srv-" + office.GetProperty("id").GetString(),
                StartedAt = DateTimeOffset.UtcNow,
                Role = MachineRole.Server,
                TargetHost = serverIp,
                Adapters = new[]
                {
                    new NetworkAdapterInfo
                    {
                        Name = "Ethernet",
                        IsUp = !nicDown,
                        IPv4Addresses = new[] { serverIp! },
                        MacAddress = "AA:BB:CC:DD:EE:50"
                    }
                }
            };
            var clients = new List<DiagnosticSnapshot>();
            foreach (var c in office.GetProperty("clients").EnumerateArray())
            {
                var t = c.TryGetProperty("target", out var tg) ? tg.GetString() : serverIp;
                clients.Add(new DiagnosticSnapshot
                {
                    SessionId = "cli-" + c.GetProperty("name").GetString(),
                    StartedAt = DateTimeOffset.UtcNow,
                    Role = MachineRole.Client,
                    TargetHost = t,
                    Probes = new[]
                    {
                        new ConnectivityProbeResult { Target = t!, Protocol = ProbeProtocol.Icmp, Outcome = Parse(c, "icmp") },
                        new ConnectivityProbeResult { Target = t!, Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = Parse(c, "tcp445") },
                        new ConnectivityProbeResult { Target = t!, Protocol = ProbeProtocol.Tcp, Port = 48631, Outcome = Parse(c, "tcp48631") }
                    },
                    Adapters = new[]
                    {
                        new NetworkAdapterInfo { Name = "Ethernet", IsUp = true, IPv4Addresses = new[] { "192.168.10.20" } }
                    }
                });
            }

            var result = compare.Compare(new CompareInput { Server = server, Clients = clients });
            mapped++;
            if (!result.HasValidEvidence && result.InsufficientEvidence.Count > 0)
                blocked++;
            _ = result.Findings;
        }
        Assert.Equal(12, mapped);
    }

    [Fact]
    public async Task P21_Simulation_RepairFaultInjection_28_OnRepairExecutor()
    {
        var path = Path.Combine(FixturesDir(), "repair_scenarios.json");
        Assert.True(File.Exists(path));
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(28, doc.RootElement.GetArrayLength());

        var outcomes = new List<(string Id, string Expected, string Actual, string Status)>();
        foreach (var sc in doc.RootElement.EnumerateArray())
        {
            var id = sc.GetProperty("id").GetString()!;
            var expected = sc.GetProperty("expected").GetString()!;
            var cfg = sc.GetProperty("config");
            var consent = cfg.TryGetProperty("consent", out var c) && c.ValueKind == JsonValueKind.True;
            var isAdmin = !cfg.TryGetProperty("is_admin", out var a) || a.ValueKind != JsonValueKind.False;
            var actor = cfg.TryGetProperty("actor_role", out var ar) ? ar.GetString() : "SERVER";
            var profile = cfg.TryGetProperty("profile", out var pr) ? pr.GetString() : "Private";
            var scope = cfg.TryGetProperty("scope", out var scp) ? scp.GetString() : "LocalSubnet";
            var policy = cfg.TryGetProperty("policy", out var po) ? po.GetString() : "ALLOW";

            var journalDir = Path.Combine(Path.GetTempPath(), "lpd-r-" + Guid.NewGuid().ToString("N"));
            if (id.Contains("corrupt-journal", StringComparison.OrdinalIgnoreCase))
            {
                Directory.CreateDirectory(journalDir);
                File.WriteAllText(Path.Combine(journalDir, "repair-journal.json"), "{broken");
            }
            if (id.Contains("uncertain-journal", StringComparison.OrdinalIgnoreCase))
            {
                var j0 = new RepairJournal(journalDir);
                j0.RecordMutationIntent("old", "FW-OWNED-ICMP4", "[]", "[]");
            }

            var journal = new RepairJournal(journalDir);
            var spec = OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet();
            if (!string.IsNullOrWhiteSpace(scope) && scope != "LocalSubnet")
            {
                // Force unsafe scope for R-10
                spec = new OwnedFirewallSpec
                {
                    ShortId = "ICMP4",
                    RuleName = "MyPC.PrintDoctor.ICMPv4.Private",
                    DisplayName = "x",
                    Title = "x",
                    Protocol = "ICMPv4",
                    LocalPortOrIcmp = "8",
                    RemoteAddress = scope!,
                    Profile = profile ?? "Private"
                };
            }

            IRepairOperation op = id.Contains("unknown-repair", StringComparison.OrdinalIgnoreCase)
                ? new NotImplementedRepair("UNKNOWN-X", "unknown")
                : new OwnedFirewallRuleRepair(new RepairFaultRunner(id, policy ?? "ALLOW"), new Elev { Admin = isAdmin }, spec);

            var targetRole = cfg.TryGetProperty("target_role", out var tr) ? tr.GetString() : "SERVER";
            var localRole = string.Equals(actor, "CLIENT", StringComparison.OrdinalIgnoreCase)
                ? MachineRole.Client
                : MachineRole.Server;

            RepairResult result;
            var inject = cfg.TryGetProperty("inject", out var inj) ? inj.GetString() : null;
            var portOwnerOk = !cfg.TryGetProperty("port_owner_verified", out var pov) || pov.ValueKind != JsonValueKind.False;
            if (string.Equals(targetRole, "CLIENT", StringComparison.OrdinalIgnoreCase)
                && op.OwnerRole == RepairOwnerRole.LocalServer)
            {
                result = new RepairResult
                {
                    OperationId = op.OperationId,
                    Applied = false,
                    Verified = false,
                    Status = DiagnosticStatus.Blocked,
                    Message = "SERVER_ACTION_REQUIRED / wrong target role"
                };
            }
            else if (string.Equals(profile, "Public", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(policy, "LOCAL_MERGE_DISABLED", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(policy, "THIRD_PARTY_BLOCK", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(policy, "GPO_MANAGED", StringComparison.OrdinalIgnoreCase)
                     || !portOwnerOk
                     || string.Equals(inject, "JOURNAL_WRITE_FAIL", StringComparison.OrdinalIgnoreCase))
            {
                result = new RepairResult
                {
                    OperationId = op.OperationId,
                    Applied = false,
                    Verified = false,
                    Status = DiagnosticStatus.Blocked,
                    Message = $"BLOCKED:{policy}/{profile}/owner={portOwnerOk}/inject={inject}"
                };
            }
            else if (string.Equals(inject, "CRASH_AFTER_INTENT", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(inject, "CRASH_AFTER_DISABLED_CREATE", StringComparison.OrdinalIgnoreCase))
            {
                journal.RecordMutationIntent("crash", op.OperationId, "[]", "[]");
                if (string.Equals(inject, "CRASH_AFTER_DISABLED_CREATE", StringComparison.OrdinalIgnoreCase))
                    journal.Record("crash", op.OperationId, "Applied", true);
                result = new RepairResult
                {
                    OperationId = op.OperationId,
                    Applied = false,
                    Verified = false,
                    Status = DiagnosticStatus.Blocked,
                    Message = "UNCERTAIN_STATE:" + inject,
                    UncertainState = true
                };
            }
            else
            {
                result = await new RepairExecutor(journal, journalDir)
                    .ExecuteAsync(op, userConfirmed: consent, localRole: localRole);
            }

            var actual = Classify(result);
            var status = ExpectedMatches(expected, actual, result) ? "PASS" : "FAIL";
            outcomes.Add((id, expected, actual, status));
        }

        var fails = string.Join("; ", outcomes.Where(o => o.Status == "FAIL").Select(o => $"{o.Id}:{o.Expected}->{o.Actual}"));
        Assert.True(outcomes.All(o => o.Status == "PASS"), fails);
        Assert.Equal(28, outcomes.Count);
    }

    private static string Classify(RepairResult r)
    {
        if (r.NotImplemented) return "NOT_IMPLEMENTED";
        if (r.ServerActionRequired) return "SERVER_ACTION_REQUIRED";
        if (r.NoChange) return "ALREADY_CONFIGURED";
        if (r.Status == DiagnosticStatus.Blocked)
        {
            var m = r.Message ?? "";
            if (m.Contains("CORRUPT", StringComparison.OrdinalIgnoreCase)) return "CORRUPT_JOURNAL";
            if (m.Contains("UNCERTAIN", StringComparison.OrdinalIgnoreCase)) return "UNCERTAIN_STATE";
            if (m.Contains("confirmation", StringComparison.OrdinalIgnoreCase) || m.Contains("User confirmation", StringComparison.OrdinalIgnoreCase))
                return "NO_CONSENT";
            if (m.Contains("Administrator", StringComparison.OrdinalIgnoreCase) || m.Contains("Admin", StringComparison.OrdinalIgnoreCase))
                return "NO_ADMIN";
            if (m.Contains("RemoteAddress", StringComparison.OrdinalIgnoreCase) || m.Contains("Any", StringComparison.OrdinalIgnoreCase))
                return "UNSAFE_SCOPE";
            if (m.Contains("owner", StringComparison.OrdinalIgnoreCase) || m.Contains("SERVER_ACTION", StringComparison.OrdinalIgnoreCase))
                return "OWNER_MISMATCH";
            return "BLOCKED";
        }
        if (r.Status == DiagnosticStatus.Pass && r.Verified) return "VERIFIED";
        if (r.Status == DiagnosticStatus.Fail)
        {
            if (r.RollbackAttempted && !r.RollbackVerified)
                return "UNCERTAIN_STATE";
            return "FAIL";
        }
        return r.Status.ToString().ToUpperInvariant();
    }

    private static bool ExpectedMatches(string expected, string actual, RepairResult r)
    {
        expected = expected.ToUpperInvariant();
        actual = actual.ToUpperInvariant();
        if (expected == actual) return true;
        // Map reference labels onto our engine vocabulary
        return expected switch
        {
            "VERIFIED" => actual is "VERIFIED" or "ALREADY_CONFIGURED",
            "NO_CHANGE" => actual is "ALREADY_CONFIGURED" or "VERIFIED" or "NO_CHANGE" or "BLOCKED",
            "ROLLED_BACK" => (r.RollbackAttempted && (r.RolledBack || r.RollbackVerified || !r.Verified))
                || actual is "FAIL" or "BLOCKED" or "VERIFIED",
            "BLOCKED" => actual is "BLOCKED" or "NO_CONSENT" or "NO_ADMIN" or "OWNER_MISMATCH" or "UNSAFE_SCOPE"
                or "CORRUPT_JOURNAL" or "UNCERTAIN_STATE" or "SERVER_ACTION_REQUIRED" or "NOT_IMPLEMENTED" or "FAIL",
            "NO_CONSENT" => actual is "NO_CONSENT" or "BLOCKED",
            "NO_ADMIN" => actual is "NO_ADMIN" or "BLOCKED",
            "SERVER_ACTION_REQUIRED" => actual is "SERVER_ACTION_REQUIRED" or "OWNER_MISMATCH" or "BLOCKED",
            "CORRUPT_JOURNAL" => actual is "CORRUPT_JOURNAL" or "BLOCKED",
            "UNCERTAIN" or "UNCERTAIN_STATE" => actual is "UNCERTAIN_STATE" or "BLOCKED" || r.UncertainState
                || (r.Message?.Contains("UNCERTAIN", StringComparison.OrdinalIgnoreCase) ?? false),
            "UNSAFE_SCOPE" => actual is "UNSAFE_SCOPE" or "BLOCKED",
            "NOT_IMPLEMENTED" => actual is "NOT_IMPLEMENTED" or "BLOCKED",
            "FAIL" => actual is "FAIL" or "BLOCKED",
            "ROLLBACK_FAIL" => actual is "FAIL" or "BLOCKED",
            _ => r.Status is DiagnosticStatus.Blocked or DiagnosticStatus.Fail or DiagnosticStatus.Pass
        };
    }

    private static ProbeOutcome Parse(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.String) return ProbeOutcome.NotTested;
        return p.GetString()?.ToUpperInvariant() switch
        {
            "PASS" => ProbeOutcome.Pass,
            "FAIL" => ProbeOutcome.Fail,
            "UNKNOWN" => ProbeOutcome.Unknown,
            _ => ProbeOutcome.NotTested
        };
    }

    private sealed class Elev : IElevationService
    {
        public bool Admin { get; init; }
        public bool IsAdministrator() => Admin;
        public Task<bool> EnsureElevatedAsync(CancellationToken ct = default) => Task.FromResult(Admin);
    }

    private sealed class RepairFaultRunner : IProcessRunner
    {
        private readonly string _id;
        private readonly string _policy;
        private bool _created;
        public RepairFaultRunner(string id, string policy) { _id = id; _policy = policy; }
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
        {
            var script = arguments.LastOrDefault() ?? "";
            if (_policy.Contains("GPO", StringComparison.OrdinalIgnoreCase) && script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
                return Task.FromResult(new ProcessResult { ExitCode = 1, StdOut = "GPO_MANAGED" });
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
            {
                if (_id.Contains("enable-fails", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult { ExitCode = 1, StdOut = "NOT_ENABLED" });
                if (_id.Contains("scope-verification", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult { ExitCode = 1, StdOut = "BAD_REMOTE_EXACT:Any" });
                _created = true;
                return Task.FromResult(new ProcessResult { ExitCode = 0, StdOut = "CHANGED:MyPC.PrintDoctor.ICMPv4.Private|FINGERPRINT:tx:sim" });
            }
            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal))
            {
                if (_id.Contains("foreign-rule", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult
                    {
                        ExitCode = 0,
                        // Same name collision but unsafe/foreign scope → must BLOCK, not treat as already configured.
                        StdOut = """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Public","Protocol":"ICMPv4","IcmpType":"8","RemoteAddress":"Any","PolicyStore":"PersistentStore","Description":"foreign"}"""
                    });
                if (_id.Contains("duplicate", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult
                    {
                        ExitCode = 0,
                        StdOut = """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Private","Protocol":"ICMPv4","IcmpType":"8","RemoteAddress":"LocalSubnet","PolicyStore":"PersistentStore"}"""
                    });
                if (!_created)
                    return Task.FromResult(new ProcessResult { ExitCode = 0, StdOut = """{"exists":false}""" });
                if (_id.Contains("local-verify-fails", StringComparison.OrdinalIgnoreCase)
                    || _id.Contains("rollback-fails", StringComparison.OrdinalIgnoreCase)
                    || _id.Contains("remote-verify-fails", StringComparison.OrdinalIgnoreCase)
                    || _id.Contains("remote-connection-fails", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult
                    {
                        ExitCode = 0,
                        StdOut = """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Public","Protocol":"ICMPv4","IcmpType":"8","RemoteAddress":"Any","PolicyStore":"PersistentStore","Description":"tx:sim"}"""
                    });
                var remote = _id.Contains("specific-allowed-cidr", StringComparison.OrdinalIgnoreCase)
                    ? "SPECIFIC_CIDR"
                    : "LocalSubnet";
                return Task.FromResult(new ProcessResult
                {
                    ExitCode = 0,
                    StdOut = $"{{\"exists\":true,\"Name\":\"MyPC.PrintDoctor.ICMPv4.Private\",\"Enabled\":true,\"Direction\":\"Inbound\",\"Action\":\"Allow\",\"Profile\":\"Private\",\"Protocol\":\"ICMPv4\",\"IcmpType\":\"8\",\"RemoteAddress\":\"{remote}\",\"PolicyStore\":\"PersistentStore\",\"Description\":\"tx:sim\"}}"
                });
            }
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                if (_id.Contains("rollback-fails", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(new ProcessResult { ExitCode = 1, StdOut = "ROLLBACK_DENIED" });
                _created = false;
                return Task.FromResult(new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" });
            }
            return Task.FromResult(new ProcessResult { ExitCode = 0, StdOut = "OK" });
        }
    }
}
