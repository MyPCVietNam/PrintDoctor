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
/// HF1: strict expected↔actual matching — no "any finding ⇒ PASS" fallbacks.
/// </summary>
public static class SimulationScenarioMapper
{
    /// <summary>Explicit expected-finding → accepted engine IDs (reviewed). No open-ended defaults.</summary>
    private static readonly Dictionary<string, string[]> AcceptedEngineIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SERVER_LINK_DOWN"] = new[] { "LAN-000", "RC-NO-ADAPTER" },
        ["SERVER_GATEWAY_FAIL"] = new[] { "LAN-004" },
        ["IP_CONFLICT_SUSPECT"] = new[] { "LAN-007" },
        ["ROUTING_OR_VLAN"] = new[] { "LAN-003" },
        ["SERVER_PUBLIC_PROFILE"] = new[] { "FW-001" },
        ["GPO_FIREWALL_OVERRIDE"] = new[] { "FW-002" },
        ["THIRD_PARTY_FIREWALL"] = new[] { "FW-003" },
        ["SMB_SERVER_SERVICE_STOPPED"] = new[] { "SMB-002" },
        ["SHAPRINT_PROCESS_STOPPED"] = new[] { "SHA-002" },
        ["SPOOLER_STOPPED"] = new[] { "PRN-001" },
        ["PRINTER_OFFLINE"] = new[] { "PRN-003" },
        ["SMB_AUTH_DENIED"] = new[] { "SMB-004B" },
        ["ICMP_ONLY_FILTERED"] = new[] { "LAN-002", "RC-CASE-B" },
        ["SERVER_AND_INFRA_UNKNOWN"] = new[] { "RC-CASE-A" },
        ["INSUFFICIENT_EVIDENCE"] = new[] { "LAN-001U", "RC-UNKNOWN-PROBES" },
        ["SMB_PORT_FAIL"] = new[] { "SMB-001" },
    };

    /// <summary>Findings that require witnesses/models the snapshot does not carry — BLOCKED, never false PASS.</summary>
    private static readonly HashSet<string> UnmappableFindings = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVER_POWER_OR_SLEEP",
        "PACKETS_NOT_AT_SERVER",
        "L2_PATH_SUSPECT",
        "FIREWALL_DROP_CONFIRMED",
        "SMB_SERVER_BINDING_DISABLED",
        "SHAPRINT_FOREIGN_PORT",
        "SHAPRINT_STARTUP_FAIL",
        "SHAPRINT_TLS_FAIL",
        "SHAPRINT_CLIENT_PROXY_FAIL",
        "SHAPRINT_DISCOVERY_FAIL",
        "PRINTER_USB_UNPLUGGED",
        "PRINTER_PAUSED",
        "PRINTER_SHARE_DISABLED",
        "SMB_SIGNING_INCOMPAT",
        "SMB_SHARE_NOT_FOUND",
        "RPC_ENDPOINT_FAIL",
        "RPC_DYNAMIC_FAIL",
        "PRINTER_DRIVER_POLICY",
        "LOCAL_PRINT_FAIL",
        "PHYSICAL_PRINT_NOT_VERIFIED",
        "DNS_RESOLUTION_FAIL",
        "NETWORK_UNSTABLE",
        "VPN_ROUTE_WRONG",
        "JOURNAL_BLOCK",
    };

    public static DiagnosticSnapshot ToSnapshot(JsonElement scenario)
    {
        var id = scenario.GetProperty("id").GetString() ?? "UNKNOWN";
        var obs = scenario.GetProperty("observations");
        // Machine role from scenario INPUT only — never from expected.owner.
        var role = ResolveRoleFromInput(scenario, obs, id);
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
        var profile = GetStr(obs, "server_profile") ?? GetStr(obs, "profile");
        var category = string.Equals(profile, "Public", StringComparison.OrdinalIgnoreCase)
            ? NetworkCategory.Public
            : NetworkCategory.Private;

        if (string.Equals(nic, "DOWN", StringComparison.OrdinalIgnoreCase))
        {
            adapters.Add(new NetworkAdapterInfo { Name = "Ethernet", IsUp = false, IPv4Addresses = new[] { target }, Category = category });
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
                Category = category,
                MacAddress = "AA:BB:CC:DD:EE:50"
            });
        }

        var services = new List<WindowsServiceInfo>();
        if (GetStr(obs, "lanmanserver") is "STOPPED" or "Stop")
            services.Add(new WindowsServiceInfo { Name = "LanmanServer", Status = "Stopped" });
        if (GetStr(obs, "spooler") is "STOPPED" or "Stop")
            services.Add(new WindowsServiceInfo { Name = "Spooler", Status = "Stopped" });

        ShaPrintInstallInfo? sha = null;
        var shaProcess = GetStr(obs, "shaprint_process") ?? GetStr(obs, "sha_process") ?? GetStr(obs, "shaprint");
        if (id.StartsWith("SHA-", StringComparison.OrdinalIgnoreCase)
            || shaProcess is not null
            || GetStr(obs, "port_owner") is not null
            || GetStr(obs, "sha_port_owner") is not null)
        {
            var running = !string.Equals(shaProcess, "STOPPED", StringComparison.OrdinalIgnoreCase)
                          && !string.Equals(shaProcess, "Stop", StringComparison.OrdinalIgnoreCase);
            var foreign = string.Equals(GetStr(obs, "port_owner"), "FOREIGN", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(GetStr(obs, "sha_port_owner"), "FOREIGN", StringComparison.OrdinalIgnoreCase)
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

        var uncRaw = GetStr(obs, "unc") ?? GetStr(obs, "smb_access") ?? GetStr(obs, "smb_unc");
        var unc = OutcomeFromToken(uncRaw);

        var (profiles, thirdParty) = BuildFirewallExtras(obs, category);

        // Gateway reachability (LAN-004): probe the adapter gateway when server_gateway=FAIL.
        var gwTok = GetStr(obs, "server_gateway") ?? GetStr(obs, "gateway");
        if (string.Equals(gwTok, "FAIL", StringComparison.OrdinalIgnoreCase)
            || string.Equals(gwTok, "DOWN", StringComparison.OrdinalIgnoreCase))
        {
            for (var i = 0; i < adapters.Count; i++)
            {
                var a = adapters[i];
                if (!a.IsUp) continue;
                adapters[i] = new NetworkAdapterInfo
                {
                    Name = a.Name,
                    IsUp = a.IsUp,
                    IPv4Addresses = a.IPv4Addresses,
                    PrefixLength = a.PrefixLength ?? 24,
                    DefaultGateway = string.IsNullOrWhiteSpace(a.DefaultGateway) ? "192.168.10.1" : a.DefaultGateway,
                    Category = a.Category,
                    MacAddress = a.MacAddress,
                    Kind = a.Kind
                };
            }
            var gw = adapters.FirstOrDefault(a => a.IsUp)?.DefaultGateway ?? "192.168.10.1";
            probes.Add(Probe(gw, ProbeProtocol.Icmp, null, ProbeOutcome.Fail));
        }

        // Off-subnet / routing (LAN-003): place local address outside target /24.
        if (string.Equals(GetStr(obs, "same_subnet"), "NO", StringComparison.OrdinalIgnoreCase)
            || string.Equals(GetStr(obs, "route_to_server"), "FAIL", StringComparison.OrdinalIgnoreCase))
        {
            for (var i = 0; i < adapters.Count; i++)
            {
                var a = adapters[i];
                adapters[i] = new NetworkAdapterInfo
                {
                    Name = a.Name,
                    IsUp = a.IsUp,
                    IPv4Addresses = new[] { "10.50.0.20" },
                    PrefixLength = 24,
                    DefaultGateway = a.DefaultGateway ?? "10.50.0.1",
                    Category = a.Category,
                    MacAddress = a.MacAddress,
                    Kind = a.Kind
                };
            }
        }

        // IP conflict soft signal (LAN-007): multiple neighbor MACs for target IP.
        var neighbors = new List<NeighborEntry>();
        var serverMac = GetStr(obs, "server_mac");
        var clientMac = GetStr(obs, "client_observed_mac") ?? GetStr(obs, "observed_mac");
        if (!string.IsNullOrWhiteSpace(serverMac) && !string.IsNullOrWhiteSpace(clientMac)
            && !string.Equals(serverMac, clientMac, StringComparison.OrdinalIgnoreCase))
        {
            neighbors.Add(new NeighborEntry { IpAddress = target, MacAddress = serverMac, State = "Reachable" });
            neighbors.Add(new NeighborEntry { IpAddress = target, MacAddress = clientMac, State = "Stale" });
        }
        else if (string.Equals(GetStr(obs, "server_mac_known"), "YES", StringComparison.OrdinalIgnoreCase)
                 && !string.IsNullOrWhiteSpace(clientMac))
        {
            neighbors.Add(new NeighborEntry { IpAddress = target, MacAddress = "AA:BB:CC:DD:EE:50", State = "Reachable" });
            neighbors.Add(new NeighborEntry { IpAddress = target, MacAddress = clientMac, State = "Stale" });
        }

        // Printer offline (PRN-003)
        var printers = new List<Abstractions.Printing.PrinterInfo>();
        if (string.Equals(GetStr(obs, "printer_status"), "OFFLINE", StringComparison.OrdinalIgnoreCase))
        {
            printers.Add(new Abstractions.Printing.PrinterInfo
            {
                Name = "SimPrinter",
                Offline = true,
                PortName = "USB001",
                DriverName = "SimDriver",
                JobCount = 0
            });
        }

        return new DiagnosticSnapshot
        {
            SessionId = "sim-" + id,
            StartedAt = DateTimeOffset.UtcNow,
            Role = role == MachineRole.Server ? MachineRole.Server : MachineRole.Client,
            TargetHost = target,
            Adapters = adapters,
            Neighbors = neighbors,
            Probes = probes,
            Services = services,
            ShaPrint = sha,
            Printers = printers,
            SmbProbe = new SmbProbeResult
            {
                Target = target,
                Tcp445 = Outcome(obs, "tcp445"),
                Unc = unc
            },
            FirewallProfiles = profiles,
            ThirdPartySecurity = thirdParty
        };
    }

    private static bool ClaimsSilentAutoApply(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (text.Contains("AUTO_APPLY", StringComparison.OrdinalIgnoreCase)) return true;
        if (text.Contains("without confirmation", StringComparison.OrdinalIgnoreCase)) return true;
        if (text.Contains("apply automatically", StringComparison.OrdinalIgnoreCase)) return true;
        if (text.Contains("automatically apply", StringComparison.OrdinalIgnoreCase)) return true;
        if (text.Contains("silent repair", StringComparison.OrdinalIgnoreCase)) return true;
        // Negations like "do not … automatically" are NOT unsafe auto claims.
        if (text.Contains("do not", StringComparison.OrdinalIgnoreCase)
            || text.Contains("don't", StringComparison.OrdinalIgnoreCase)
            || text.Contains("never", StringComparison.OrdinalIgnoreCase))
            return false;
        return text.Contains("automatic repair", StringComparison.OrdinalIgnoreCase);
    }

    private static (IReadOnlyList<Abstractions.Firewall.FirewallProfileState> Profiles, IReadOnlyList<Abstractions.Firewall.ThirdPartySecurityProduct> Third)
        BuildFirewallExtras(JsonElement obs, NetworkCategory category)
    {
        var profiles = new List<Abstractions.Firewall.FirewallProfileState>();
        var gpo = GetStr(obs, "gpo_firewall_block") ?? GetStr(obs, "gpo");
        var thirdTok = GetStr(obs, "third_party_security_block") ?? GetStr(obs, "third_party");
        var managed = string.Equals(gpo, "YES", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(gpo, "TRUE", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(gpo, "BLOCK", StringComparison.OrdinalIgnoreCase);
        if (category == NetworkCategory.Public || managed || GetStr(obs, "server_profile") is not null)
        {
            profiles.Add(new Abstractions.Firewall.FirewallProfileState
            {
                Profile = category == NetworkCategory.Public
                    ? Abstractions.Firewall.FirewallProfileKind.Public
                    : Abstractions.Firewall.FirewallProfileKind.Private,
                Enabled = true,
                ManagedByPolicy = managed ? true : null
            });
        }

        var third = new List<Abstractions.Firewall.ThirdPartySecurityProduct>();
        if (string.Equals(thirdTok, "YES", StringComparison.OrdinalIgnoreCase)
            || string.Equals(thirdTok, "TRUE", StringComparison.OrdinalIgnoreCase)
            || string.Equals(thirdTok, "BLOCK", StringComparison.OrdinalIgnoreCase))
        {
            third.Add(new Abstractions.Firewall.ThirdPartySecurityProduct { Name = "SimThirdPartyFirewall" });
        }

        return (profiles, third);
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
        // Ignore catalog-empty noise on server snapshots (PRN-002) for matching unless that is the expectation.
        var matchFindings = findings
            .Where(f => !(f.Id == "PRN-002" && !exp.Finding.Contains("PRINTER", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        var roots = root.Analyze(snap).ToList();
        var actualIds = matchFindings.Select(f => f.Id).Concat(roots.Select(r => r.CaseId)).ToArray();

        var proposesLocalRepair = matchFindings.Any(f =>
            !string.IsNullOrWhiteSpace(f.RepairId)
            && f.RepairOwner is RepairOwnerRole.LocalServer or RepairOwnerRole.LocalClient or RepairOwnerRole.LocalAny);
        // Consent-gated RepairId is allowed when automatic_repair_permitted=false.
        // FAIL only on affirmative silent/auto-apply language — not "do not … automatically".
        var unsafeAuto = !exp.AutomaticRepairPermitted
                         && matchFindings.Any(f =>
                             !string.IsNullOrWhiteSpace(f.RepairId)
                             && f.RepairOwner is RepairOwnerRole.LocalServer or RepairOwnerRole.LocalClient or RepairOwnerRole.LocalAny
                             && (f.RecommendedActions.Any(ClaimsSilentAutoApply)
                                 || ClaimsSilentAutoApply(f.Evidence)));

        string status;
        string detail;

        if (UnmappableFindings.Contains(exp.Finding) || IsWitnessFinding(exp.Finding))
        {
            status = "BLOCKED";
            detail = $"UNMAPPABLE_OR_WITNESS: '{exp.Finding}' requires observations/models not represented in DiagnosticSnapshot — engine ran without auto-repair";
        }
        else if (unsafeAuto)
        {
            status = "FAIL";
            detail = "UNSAFE_AUTO: automatic repair proposed without eligibility/consent";
        }
        else if (exp.Finding.Contains("INSUFFICIENT", StringComparison.OrdinalIgnoreCase))
        {
            var ok = matchFindings.Any(f => f.Status == DiagnosticStatus.Unknown || f.Id is "LAN-001U")
                     || roots.Any(r => r.EvidenceLevel == EvidenceLevel.InsufficientEvidence || r.CaseId.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase));
            status = ok ? "PASS" : "FAIL";
            detail = ok ? "insufficient-evidence posture matched" : "Expected insufficient-evidence posture";
        }
        else if (exp.Finding.Contains("ICMP_ONLY", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(exp.Finding, "ICMP_ONLY_FILTERED", StringComparison.OrdinalIgnoreCase))
        {
            var ok = roots.Any(r => r.CaseId == "RC-CASE-B") || matchFindings.Any(f => f.Id == "LAN-002");
            status = ok ? "PASS" : "FAIL";
            detail = ok ? "CASE B / LAN-002 matched" : "Expected CASE B / LAN-002 for ICMP fail + TCP pass";
        }
        else if (!FindingCategoryMatches(exp.Finding, matchFindings, roots))
        {
            if (!AcceptedEngineIds.ContainsKey(exp.Finding) && !UnmappableFindings.Contains(exp.Finding))
            {
                status = "BLOCKED";
                detail = $"NO_STRICT_MAPPING: '{exp.Finding}' has no reviewed engine-ID mapping — refusing false PASS";
            }
            else
            {
                status = "FAIL";
                detail = $"FINDING_MISMATCH: expected '{exp.Finding}' not in actual [{string.Join(",", actualIds)}]";
            }
        }
        else if (!OwnerMatches(exp.Owner, matchFindings, roots, snap.Role))
        {
            status = "FAIL";
            detail = $"OWNER_MISMATCH: expected owner '{exp.Owner}' role={snap.Role} owners=[{string.Join(",", matchFindings.Select(f => f.RepairOwner))}]";
        }
        else
        {
            status = "PASS";
            detail = $"matched; findings={matchFindings.Count}; roots={roots.Count}; localRepairSuggested={proposesLocalRepair}; autoApplyForbidden={!exp.AutomaticRepairPermitted}; role={snap.Role}";
        }

        return new SimulationCaseResult
        {
            ScenarioId = exp.ScenarioId,
            ExpectedFinding = exp.Finding,
            Status = status,
            Detail = detail,
            ActualFindingIds = actualIds
        };
    }

    /// <summary>Public for negative-control unit tests.</summary>
    public static bool FindingCategoryMatches(string expectedFinding, List<Finding> findings, List<RootCauseFinding> roots)
    {
        if (string.IsNullOrWhiteSpace(expectedFinding)) return false;
        if (UnmappableFindings.Contains(expectedFinding) || IsWitnessFinding(expectedFinding))
            return false;

        if (!AcceptedEngineIds.TryGetValue(expectedFinding, out var accepted) || accepted.Length == 0)
            return false;

        var ids = findings.Select(f => f.Id)
            .Concat(roots.Select(r => r.CaseId))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Require at least one explicitly accepted ID — never "any finding".
        return accepted.Any(a => ids.Contains(a));
    }

    /// <summary>Public for negative-control unit tests.</summary>
    public static bool OwnerMatches(string? expectedOwner, List<Finding> findings, List<RootCauseFinding> roots, MachineRole role)
    {
        if (string.IsNullOrWhiteSpace(expectedOwner)) return true;
        var o = expectedOwner.ToUpperInvariant();

        // Never always-true: owner must be defensible from role and/or finding RepairOwner.
        if (o is "INFRA" or "ADMIN")
        {
            // Infra/admin expectations must not claim a client-local apply RepairId.
            if (findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalClient && !string.IsNullOrWhiteSpace(f.RepairId)))
                return false;
            return true;
        }

        if (o == "LOCAL")
        {
            // Explicit local repair owners satisfy LOCAL.
            if (findings.Any(f => f.RepairOwner is RepairOwnerRole.LocalAny
                                  or RepairOwnerRole.LocalServer
                                  or RepairOwnerRole.LocalClient))
                return true;
            // Operator-local investigation (e.g. SERVER_AND_INFRA_UNKNOWN): accept when findings
            // exist and none claim a machine-local apply RepairId.
            return findings.Count + roots.Count > 0
                   && !findings.Any(f => !string.IsNullOrWhiteSpace(f.RepairId)
                                         && f.RepairOwner is RepairOwnerRole.LocalServer
                                             or RepairOwnerRole.LocalClient
                                             or RepairOwnerRole.LocalAny);
        }

        if (o == "SERVER")
        {
            if (role == MachineRole.Client)
            {
                // Client snapshot diagnosing server-side issue: ServerActionRequired / LocalServer label only.
                return findings.Any(f => f.RepairOwner is RepairOwnerRole.ServerActionRequired
                                         or RepairOwnerRole.LocalServer)
                       && !findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalClient
                                             && !string.IsNullOrWhiteSpace(f.RepairId));
            }

            if (role != MachineRole.Server) return false;
            // Server role: reject if the only apply owners are LocalClient.
            if (findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalClient && !string.IsNullOrWhiteSpace(f.RepairId))
                && !findings.Any(f => f.RepairOwner is RepairOwnerRole.LocalServer
                                      or RepairOwnerRole.LocalAny
                                      or RepairOwnerRole.ServerActionRequired
                                      or RepairOwnerRole.None))
                return false;
            return true;
        }

        if (o == "CLIENT")
        {
            if (role == MachineRole.Server)
            {
                return findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalClient)
                       && !findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalServer
                                             && !string.IsNullOrWhiteSpace(f.RepairId));
            }

            if (role != MachineRole.Client) return false;
            if (findings.Any(f => f.RepairOwner == RepairOwnerRole.LocalServer && !string.IsNullOrWhiteSpace(f.RepairId))
                && !findings.Any(f => f.RepairOwner is RepairOwnerRole.LocalClient or RepairOwnerRole.LocalAny))
                return false;
            return true;
        }

        return false;
    }

    private static bool IsWitnessFinding(string finding)
        => finding is "FIREWALL_DROP_CONFIRMED" or "PACKETS_NOT_AT_SERVER" or "L2_PATH_SUSPECT";

    private static MachineRole ResolveRoleFromInput(JsonElement scenario, JsonElement obs, string id)
    {
        if (scenario.TryGetProperty("role", out var roleEl) && roleEl.ValueKind == JsonValueKind.String)
            return MapRoleToken(roleEl.GetString());
        if (obs.TryGetProperty("actor_role", out var ar) && ar.ValueKind == JsonValueKind.String)
            return MapRoleToken(ar.GetString());
        if (obs.TryGetProperty("machine_role", out var mr) && mr.ValueKind == JsonValueKind.String)
            return MapRoleToken(mr.GetString());

        if (GetStr(obs, "server_nic") is not null
            || GetStr(obs, "server_power") is not null
            || GetStr(obs, "lanmanserver") is not null
            || GetStr(obs, "server_profile") is not null)
            return MachineRole.Server;

        if (id.StartsWith("CLIENT-", StringComparison.OrdinalIgnoreCase)
            || GetStr(obs, "client_gateway") is not null
            || GetStr(obs, "client_ip") is not null)
            return MachineRole.Client;

        // Auth/share permission failures are client-actor observations (not server NIC state).
        var smb = GetStr(obs, "smb_access") ?? GetStr(obs, "unc") ?? GetStr(obs, "smb_unc");
        if (smb is not null
            && (smb.Contains("DENIED", StringComparison.OrdinalIgnoreCase)
                || smb.Contains("AUTH", StringComparison.OrdinalIgnoreCase)))
            return MachineRole.Client;

        if (id.StartsWith("LAN-", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("SMB-", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("SHA-", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("FW-", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("PRT-", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("TX-", StringComparison.OrdinalIgnoreCase))
            return MachineRole.Server;

        return MachineRole.Server;
    }

    private static MachineRole MapRoleToken(string? token)
        => token?.ToUpperInvariant() switch
        {
            "SERVER" => MachineRole.Server,
            "CLIENT" => MachineRole.Client,
            _ => MachineRole.Server
        };

    private static ProbeOutcome Outcome(JsonElement obs, string name)
        => OutcomeFromToken(GetStr(obs, name));

    private static ProbeOutcome OutcomeFromToken(string? s)
        => s?.ToUpperInvariant() switch
        {
            "PASS" or "OK" or "SUCCESS" => ProbeOutcome.Pass,
            "FAIL" or "FAILED" or "TIMEOUT" => ProbeOutcome.Fail,
            "AUTH" or "AUTH_DENIED" or "ACCESS_DENIED" or "DENIED" => ProbeOutcome.AuthDenied,
            "UNKNOWN" => ProbeOutcome.Unknown,
            "NOT_TESTED" or "NOTTESTED" or null => ProbeOutcome.NotTested,
            _ => ProbeOutcome.Unknown
        };

    private static ConnectivityProbeResult Probe(string target, ProbeProtocol proto, int? port, ProbeOutcome o)
        => new() { Target = target, Protocol = proto, Port = port, Outcome = o };

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
