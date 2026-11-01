using System.Net;
using System.Net.Sockets;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Engine;

/// <summary>
/// Distinguishes infrastructure vs host firewall vs print-stack failures when clients cannot reach server.
/// Never defaults to a single cause without evidence. P21-003: exact host match (no substring).
/// </summary>
public sealed class NetworkRootCauseEngine
{
    public IReadOnlyList<RootCauseFinding> Analyze(DiagnosticSnapshot snap)
    {
        var list = new List<RootCauseFinding>();
        var target = snap.TargetHost;
        if (string.IsNullOrWhiteSpace(target))
        {
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-NO-TARGET",
                Confidence = Confidence.Low,
                EvidenceLevel = EvidenceLevel.InsufficientEvidence,
                Title = "No server IP/hostname provided",
                Status = DiagnosticStatus.Unknown,
                RecommendedAction = "Enter exact server IPv4 before diagnosing reachability.",
                Owner = RepairOwnerHint.Operator
            });
            return list;
        }

        var icmp = Decisive(snap.Probes, target, ProbeProtocol.Icmp);
        var tcp445 = Decisive(snap.Probes, target, ProbeProtocol.Tcp, 445);
        var tcp135 = Decisive(snap.Probes, target, ProbeProtocol.Tcp, 135);
        var tcp48631 = Decisive(snap.Probes, target, ProbeProtocol.Tcp, 48631);

        var upAdapters = snap.Adapters?.Where(a => a.IsUp).ToList() ?? new();
        if (upAdapters.Count == 0)
        {
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-NO-ADAPTER",
                Confidence = Confidence.High,
                EvidenceLevel = EvidenceLevel.Confirmed,
                Title = "No active LAN adapter",
                Status = DiagnosticStatus.Fail,
                RecommendedAction = "Check cable/Wi-Fi/driver before firewall repairs.",
                Owner = RepairOwnerHint.Local
            });
        }

        // CASE A: all decisive L3/L4 fail — do NOT confirm infrastructure without exclusion evidence.
        if (icmp == ProbeOutcome.Fail && tcp445 == ProbeOutcome.Fail
            && tcp48631 != ProbeOutcome.Pass && tcp135 != ProbeOutcome.Pass)
        {
            var hasServerWitness = snap.Adapters?.Any(a => a.IsUp && a.IPv4Addresses.Count > 0) == true
                                   && snap.Role == MachineRole.Server;
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-CASE-A",
                Confidence = Confidence.Medium,
                EvidenceLevel = hasServerWitness ? EvidenceLevel.Probable : EvidenceLevel.Possible,
                Title = "ICMP and primary TCP ports fail — do not jump to firewall-only fix",
                Status = DiagnosticStatus.Fail,
                Evidence = $"icmp={icmp}; tcp445={tcp445}; tcp135={tcp135}; tcp48631={tcp48631}",
                RecommendedAction =
                    "Verify server gateway/IP/prefix, client route/ARP/MAC, then server listener and firewall. " +
                    "Without WFP/pktmon/NIC-witness evidence, report INFRASTRUCTURE_INVESTIGATION_RECOMMENDED (not confirmed).",
                Owner = RepairOwnerHint.InvestigateBoth,
                InfrastructureActionRequired = false,
                InfrastructureInvestigationRecommended = true
            });
        }

        // CASE B: ICMP fail, TCP pass
        if (icmp == ProbeOutcome.Fail
            && (tcp445 == ProbeOutcome.Pass || tcp48631 == ProbeOutcome.Pass || tcp135 == ProbeOutcome.Pass))
        {
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-CASE-B",
                Confidence = Confidence.High,
                EvidenceLevel = EvidenceLevel.Confirmed,
                Title = "Server reachable on TCP; ICMP Echo blocked or filtered",
                Status = DiagnosticStatus.Warning,
                Evidence = $"icmp={icmp}; tcp445={tcp445}; tcp48631={tcp48631}",
                RecommendedAction =
                    "Do not treat server offline. Optional server-side scoped ICMPv4 owned rule (Private/LocalSubnet). " +
                    "Printing may still work without ping.",
                Owner = RepairOwnerHint.Server,
                SuggestedRepairId = snap.Role == MachineRole.Server ? "FW-OWNED-ICMP4" : null
            });
        }

        // CASE C: reachable, printing path may fail
        if (tcp445 == ProbeOutcome.Pass || tcp48631 == ProbeOutcome.Pass)
        {
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-CASE-C",
                Confidence = Confidence.Medium,
                EvidenceLevel = EvidenceLevel.Probable,
                Title = "Path reachable — evaluate SMB/RPC/ShaPrint/Spooler next",
                Status = DiagnosticStatus.Pass,
                Evidence = $"tcp445={tcp445}; tcp135={tcp135}; tcp48631={tcp48631}",
                RecommendedAction = "Do not reset network. Run SMB/RPC/printer/ShaPrint diagnostics on the correct role machine.",
                Owner = RepairOwnerHint.InvestigateBoth
            });
        }

        if (icmp is ProbeOutcome.Unknown or ProbeOutcome.NotTested
            || tcp445 is ProbeOutcome.Unknown or ProbeOutcome.NotTested)
        {
            list.Add(new RootCauseFinding
            {
                CaseId = "RC-UNKNOWN-PROBES",
                Confidence = Confidence.Low,
                EvidenceLevel = EvidenceLevel.InsufficientEvidence,
                Title = "Insufficient probe evidence",
                Status = DiagnosticStatus.Unknown,
                RecommendedAction = "Re-run scan with admin rights; do not Apply repairs on UNKNOWN evidence.",
                Owner = RepairOwnerHint.Operator
            });
        }

        return list;
    }

    /// <summary>Exact IP or hostname match — never substring (192.168.1.10 ≠ 192.168.1.100).</summary>
    public static bool TargetsMatch(string? probeTarget, string? expectedHost)
    {
        if (string.IsNullOrWhiteSpace(probeTarget) || string.IsNullOrWhiteSpace(expectedHost))
            return false;
        var a = probeTarget.Trim();
        var b = expectedHost.Trim();
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;

        if (IPAddress.TryParse(a, out var ipA) && IPAddress.TryParse(b, out var ipB))
            return ipA.Equals(ipB);

        // Bracketed IPv6
        if (a.StartsWith('[') && a.EndsWith(']'))
            a = a[1..^1];
        if (b.StartsWith('[') && b.EndsWith(']'))
            b = b[1..^1];
        if (IPAddress.TryParse(a, out ipA) && IPAddress.TryParse(b, out ipB))
            return ipA.Equals(ipB);

        return false;
    }

    private static ProbeOutcome Decisive(
        IReadOnlyList<ConnectivityProbeResult>? probes,
        string host,
        ProbeProtocol protocol,
        int? port = null)
    {
        if (probes is null) return ProbeOutcome.NotTested;
        foreach (var p in probes)
        {
            if (p.Protocol != protocol) continue;
            if (!TargetsMatch(p.Target, host)) continue;
            if (port is not null && p.Port != port) continue;
            return p.Outcome;
        }
        return ProbeOutcome.NotTested;
    }
}

public enum Confidence { Low, Medium, High }

public enum EvidenceLevel
{
    Confirmed,
    Probable,
    Possible,
    InsufficientEvidence
}

public enum RepairOwnerHint { Operator, Local, Server, Client, InvestigateBoth }

public sealed class RootCauseFinding
{
    public required string CaseId { get; init; }
    public required string Title { get; init; }
    public DiagnosticStatus Status { get; init; }
    public Confidence Confidence { get; init; }
    public EvidenceLevel EvidenceLevel { get; init; } = EvidenceLevel.Possible;
    public string? Evidence { get; init; }
    public string? RecommendedAction { get; init; }
    public RepairOwnerHint Owner { get; init; }
    /// <summary>Only when exclusion evidence confirms L2/switch/cable — otherwise prefer InvestigationRecommended.</summary>
    public bool InfrastructureActionRequired { get; init; }
    public bool InfrastructureInvestigationRecommended { get; init; }
    public string? SuggestedRepairId { get; init; }
}
