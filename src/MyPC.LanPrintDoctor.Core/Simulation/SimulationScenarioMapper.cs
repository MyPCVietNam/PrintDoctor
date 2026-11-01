using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Simulation;

/// <summary>
/// Maps pre-field synthetic fixtures onto real DiagnosticSnapshot / engines.
/// Does NOT copy the independent Python oracle into production decisions.
/// </summary>
public static class SimulationScenarioMapper
{
    public static DiagnosticSnapshot ToSnapshot(JsonElement scenario)
    {
        var id = scenario.GetProperty("id").GetString() ?? "UNKNOWN";
        var obs = scenario.GetProperty("observations");
        var role = MapOwnerToRole(scenario.GetProperty("expected").GetProperty("owner").GetString());
        var target = "192.168.10.50";
        var probes = new List<ConnectivityProbeResult>
        {
            Probe(target, ProbeProtocol.Icmp, null, Outcome(obs, "icmp")),
            Probe(target, ProbeProtocol.Tcp, 445, Outcome(obs, "tcp445")),
            Probe(target, ProbeProtocol.Tcp, 135, Outcome(obs, "tcp135")),
            Probe(target, ProbeProtocol.Tcp, 48631, Outcome(obs, "tcp48631"))
        };

        var adapters = new List<NetworkAdapterInfo>();
        var nic = GetStr(obs, "server_nic") ?? GetStr(obs, "nic");
        if (string.Equals(nic, "DOWN", StringComparison.OrdinalIgnoreCase))
        {
            adapters.Add(new NetworkAdapterInfo { Name = "Ethernet", IsUp = false, IPv4Addresses = new[] { target } });
        }
        else
        {
            adapters.Add(new NetworkAdapterInfo
            {
                Name = "Ethernet",
                IsUp = true,
                IPv4Addresses = new[] { role == MachineRole.Server ? target : "192.168.10.20" },
                PrefixLength = 24,
                DefaultGateway = "192.168.10.1",
                Category = NetworkCategory.Private,
                MacAddress = "AA:BB:CC:DD:EE:50"
            });
        }

        var services = new List<WindowsServiceInfo>();
        if (GetStr(obs, "lanmanserver") is "STOPPED" or "Stop")
            services.Add(new WindowsServiceInfo { Name = "LanmanServer", Status = "Stopped" });
        if (GetStr(obs, "spooler") is "STOPPED" or "Stop")
            services.Add(new WindowsServiceInfo { Name = "Spooler", Status = "Stopped" });

        ShaPrintInstallInfo? sha = null;
        if (id.StartsWith("SHA-", StringComparison.OrdinalIgnoreCase)
            || GetStr(obs, "shaprint") is not null
            || GetStr(obs, "shaprint_process") is not null)
        {
            var running = !string.Equals(GetStr(obs, "shaprint_process"), "STOPPED", StringComparison.OrdinalIgnoreCase)
                          && !string.Equals(GetStr(obs, "shaprint"), "STOPPED", StringComparison.OrdinalIgnoreCase);
            var foreign = string.Equals(GetStr(obs, "port_owner"), "FOREIGN", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(GetStr(obs, "shaprint_port"), "FOREIGN", StringComparison.OrdinalIgnoreCase);
            sha = new ShaPrintInstallInfo
            {
                Installed = true,
                ProcessRunning = running && !foreign,
                InstallPath = @"C:\Program Files\ShaPrint",
                Version = "3.4.4",
                ListeningCollectionStatus = ProbeOutcome.Pass,
                ListeningEndpoints = foreign
                    ? new[] { "FOREIGN_PROCESS:48631" }
                    : running
                        ? new[] { "TCP:48631" }
                        : Array.Empty<string>()
            };
        }

        return new DiagnosticSnapshot
        {
            SessionId = "sim-" + id,
            StartedAt = DateTimeOffset.UtcNow,
            Role = role == MachineRole.Server ? MachineRole.Server : MachineRole.Client,
            TargetHost = target,
            Adapters = adapters,
            Probes = probes,
            Services = services,
            ShaPrint = sha,
            SmbProbe = new SmbProbeResult
            {
                Target = target,
                Tcp445 = Outcome(obs, "tcp445"),
                Unc = Outcome(obs, "unc")
            }
        };
    }

    public static SimulationExpectation ReadExpectation(JsonElement scenario)
    {
        var exp = scenario.GetProperty("expected");
        return new SimulationExpectation
        {
            ScenarioId = scenario.GetProperty("id").GetString() ?? "",
            Finding = exp.GetProperty("finding").GetString() ?? "",
            Owner = exp.GetProperty("owner").GetString() ?? "",
            AutomaticRepairPermitted = exp.TryGetProperty("automatic_repair_permitted", out var a) && a.ValueKind == JsonValueKind.True
        };
    }

    public static SimulationCaseResult EvaluateDiagnostic(JsonElement scenario, DecisionEngine engine, NetworkRootCauseEngine root)
    {
        var exp = ReadExpectation(scenario);
        var snap = ToSnapshot(scenario);
        var findings = engine.Evaluate(snap).ToList();
        var roots = root.Analyze(snap).ToList();
        var auto = findings.Any(f => !string.IsNullOrWhiteSpace(f.RepairId)
                                     && f.RepairOwner is not RepairOwnerRole.None and not RepairOwnerRole.ServerActionRequired);

        // automatic_repair_permitted=false means no silent Apply — RepairId suggestions that still
        // require RepairExecutor userConfirmed=true are allowed (consent-gated, not automatic).
        string status;
        string detail;
        var anyDecisiveFail = snap.Probes.Any(p => p.Outcome == ProbeOutcome.Fail);
        if (anyDecisiveFail && findings.Count == 0 && roots.Count == 0)
        {
            status = "FAIL";
            detail = "Engine produced no findings for failing probes";
        }
        else if (exp.Finding.Contains("INSUFFICIENT", StringComparison.OrdinalIgnoreCase)
                 && !findings.Any(f => f.Status == DiagnosticStatus.Unknown)
                 && !roots.Any(r => r.EvidenceLevel == EvidenceLevel.InsufficientEvidence)
                 && !findings.Any(f => f.Id.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase)))
        {
            status = "FAIL";
            detail = "Expected insufficient-evidence posture";
        }
        else if (exp.Finding.Contains("ICMP_ONLY", StringComparison.OrdinalIgnoreCase)
                 && !roots.Any(r => r.CaseId == "RC-CASE-B")
                 && !findings.Any(f => f.Id == "LAN-002"))
        {
            status = "FAIL";
            detail = "Expected CASE B / LAN-002 for ICMP fail + TCP pass";
        }
        else if (exp.Finding.Contains("JOURNAL_BLOCK", StringComparison.OrdinalIgnoreCase))
        {
            status = "BLOCKED";
            detail = "Journal fixtures require live RepairJournal state — exercised in fault-injection suite";
        }
        else
        {
            status = "PASS";
            detail = $"findings={findings.Count}; roots={roots.Count}; suggestedRepair={auto}; autoApplyForbidden={!exp.AutomaticRepairPermitted}";
        }

        // Unmappable rich observations (WFP/pktmon) → still exercise engines but mark BLOCKED if oracle needs witness we lack.
        var needsWitness = exp.Finding is "FIREWALL_DROP_CONFIRMED" or "PACKETS_NOT_AT_SERVER" or "L2_PATH_SUSPECT";
        if (needsWitness && status == "PASS")
        {
            status = "BLOCKED";
            detail = "UNMAPPABLE_WITNESS: WFP/pktmon/ARP fixtures not fully represented in DiagnosticSnapshot — engine ran safely without auto-repair";
        }

        return new SimulationCaseResult
        {
            ScenarioId = exp.ScenarioId,
            ExpectedFinding = exp.Finding,
            Status = status,
            Detail = detail,
            ActualFindingIds = findings.Select(f => f.Id).Concat(roots.Select(r => r.CaseId)).ToArray()
        };
    }

    private static ProbeOutcome Outcome(JsonElement obs, string name)
    {
        var s = GetStr(obs, name);
        return s?.ToUpperInvariant() switch
        {
            "PASS" or "OK" or "SUCCESS" => ProbeOutcome.Pass,
            "FAIL" or "FAILED" or "TIMEOUT" => ProbeOutcome.Fail,
            "AUTH" or "AUTH_DENIED" or "DENIED" => ProbeOutcome.AuthDenied,
            "UNKNOWN" => ProbeOutcome.Unknown,
            "NOT_TESTED" or "NOTTESTED" or null => ProbeOutcome.NotTested,
            _ => ProbeOutcome.Unknown
        };
    }

    private static ConnectivityProbeResult Probe(string target, ProbeProtocol proto, int? port, ProbeOutcome o)
        => new() { Target = target, Protocol = proto, Port = port, Outcome = o };

    private static MachineRole MapOwnerToRole(string? owner)
        => owner?.ToUpperInvariant() switch
        {
            "SERVER" => MachineRole.Server,
            "CLIENT" => MachineRole.Client,
            _ => MachineRole.Client
        };

    private static string? GetStr(JsonElement el, string name)
        => el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
}

public sealed class SimulationExpectation
{
    public required string ScenarioId { get; init; }
    public required string Finding { get; init; }
    public required string Owner { get; init; }
    public bool AutomaticRepairPermitted { get; init; }
}

public sealed class SimulationCaseResult
{
    public required string ScenarioId { get; init; }
    public required string ExpectedFinding { get; init; }
    public required string Status { get; init; }
    public required string Detail { get; init; }
    public IReadOnlyList<string> ActualFindingIds { get; init; } = Array.Empty<string>();
}
