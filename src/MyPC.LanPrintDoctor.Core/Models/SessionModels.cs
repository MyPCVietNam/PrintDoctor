using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Abstractions.Services;

namespace MyPC.LanPrintDoctor.Core.Models;

public static class ReportSchema
{
    public const string Version = "1.1.0";
}

public sealed class DiagnosticRequest
{
    public required MachineRole Role { get; init; }
    public string? TargetHost { get; init; }
    public bool DeepScan { get; init; }
    public bool RedactSensitive { get; init; }
}

public sealed class DiagnosticSnapshot
{
    public string SchemaVersion { get; init; } = ReportSchema.Version;
    public required string SessionId { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset StartedAtLocal => StartedAt.ToLocalTime();
    public required MachineRole Role { get; set; }
    public string? TargetHost { get; set; }
    public string MachineName { get; set; } = Environment.MachineName;
    public string OsDescription { get; init; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public IReadOnlyList<NetworkAdapterInfo> Adapters { get; set; } = Array.Empty<NetworkAdapterInfo>();
    public IReadOnlyList<RouteEntry> Routes { get; set; } = Array.Empty<RouteEntry>();
    public IReadOnlyList<NeighborEntry> Neighbors { get; set; } = Array.Empty<NeighborEntry>();
    public IReadOnlyList<ConnectivityProbeResult> Probes { get; set; } = Array.Empty<ConnectivityProbeResult>();
    public IReadOnlyList<FirewallProfileState> FirewallProfiles { get; set; } = Array.Empty<FirewallProfileState>();
    public IReadOnlyList<FirewallRuleInfo> FirewallRules { get; set; } = Array.Empty<FirewallRuleInfo>();
    public IReadOnlyList<ThirdPartySecurityProduct> ThirdPartySecurity { get; set; } = Array.Empty<ThirdPartySecurityProduct>();
    public ProbeOutcome ThirdPartyCollectionStatus { get; set; } = ProbeOutcome.Unknown;
    public IReadOnlyList<WindowsServiceInfo> Services { get; set; } = Array.Empty<WindowsServiceInfo>();
    public SmbConfiguration? SmbConfiguration { get; set; }
    public SmbProbeResult? SmbProbe { get; set; }
    public SharingToggleState? SharingToggles { get; set; }
    public IReadOnlyList<ShareInfo> Shares { get; set; } = Array.Empty<ShareInfo>();
    public IReadOnlyList<PrinterInfo> Printers { get; set; } = Array.Empty<PrinterInfo>();
    public ShaPrintInstallInfo? ShaPrint { get; set; }
    public ShaPrintConnectivity? ShaPrintConnectivity { get; set; }
    public List<CollectorStatusNote> CollectorNotes { get; } = new();
    public List<Finding> Findings { get; } = new();
    public string? RepairsJson { get; set; }
    public string? BeforeAfterJson { get; set; }
    public string? EventLogsText { get; set; }
}

public sealed class CollectorStatusNote
{
    public required string Collector { get; init; }
    public required ProbeOutcome Outcome { get; init; }
    public string? Detail { get; init; }
}

public sealed class CompareInput
{
    public required DiagnosticSnapshot Server { get; init; }
    public required IReadOnlyList<DiagnosticSnapshot> Clients { get; init; }
}

public sealed class CompareResult
{
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    public IReadOnlyList<string> ServerSideIssues { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ClientSpecificIssues { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> InfrastructureHints { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> InsufficientEvidence { get; init; } = Array.Empty<string>();
    public bool HasValidEvidence { get; init; }
}
