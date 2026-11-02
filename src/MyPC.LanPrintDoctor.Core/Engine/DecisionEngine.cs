using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Engine;

public sealed class DecisionEngine
{
    public IReadOnlyList<Finding> Evaluate(DiagnosticSnapshot snap)
    {
        var findings = new List<Finding>();
        EvaluateNetwork(snap, findings);
        EvaluateFirewall(snap, findings);
        EvaluateServices(snap, findings);
        EvaluateSmb(snap, findings);
        EvaluatePrinters(snap, findings);
        EvaluateShaPrint(snap, findings);
        return findings;
    }

    private static void EvaluateNetwork(DiagnosticSnapshot snap, List<Finding> findings)
    {
        var upAdapters = snap.Adapters.Where(a => a.IsUp && a.Kind != AdapterKind.Loopback).ToList();
        if (upAdapters.Count == 0)
        {
            findings.Add(new Finding
            {
                Id = "LAN-000",
                Title = "No active network adapter",
                Severity = Severity.Critical,
                Status = DiagnosticStatus.Fail,
                Evidence = "No non-loopback adapter reports IsUp=true.",
                Confidence = 0.95,
                Category = "Network",
                PossibleCauses = new[] { "NIC disabled", "Driver failure", "Cable/Wi-Fi disconnect" },
                RecommendedActions = new[] { "Check physical link", "Review Device Manager", "Do not reset stack yet" },
                VerificationMethod = "Re-scan adapters after hardware check"
            });
        }

        var target = snap.TargetHost;
        var icmp = snap.Probes.Where(p => p.Protocol == ProbeProtocol.Icmp).ToList();
        var tcp = snap.Probes.Where(p => p.Protocol == ProbeProtocol.Tcp).ToList();
        // Target-scoped probes — local/gateway success must not mask target ICMP failure.
        var icmpToTarget = string.IsNullOrWhiteSpace(target)
            ? Array.Empty<ConnectivityProbeResult>()
            : icmp.Where(p => string.Equals(p.Target, target, StringComparison.OrdinalIgnoreCase)).ToArray();
        var tcpToTarget = string.IsNullOrWhiteSpace(target)
            ? Array.Empty<ConnectivityProbeResult>()
            : tcp.Where(p => string.Equals(p.Target, target, StringComparison.OrdinalIgnoreCase)).ToArray();

        // Only Pass/Fail are decisive. Unknown/NotTested/NotApplicable must NOT become Fail.
        static bool IsDecisive(ConnectivityProbeResult p)
            => p.Outcome is ProbeOutcome.Pass or ProbeOutcome.Fail;
        static bool IsFail(ConnectivityProbeResult p) => p.Outcome == ProbeOutcome.Fail;
        static bool IsPass(ConnectivityProbeResult p) => p.Outcome == ProbeOutcome.Pass;

        var icmpDecisive = icmpToTarget.Where(IsDecisive).ToArray();
        var tcpDecisive = tcpToTarget.Where(IsDecisive).ToArray();
        var icmpFail = icmpDecisive.Length > 0 && icmpDecisive.All(IsFail);
        var icmpPass = icmpDecisive.Any(IsPass);
        var tcpPass = tcpDecisive.Any(IsPass);
        var tcpFail = tcpDecisive.Length > 0 && tcpDecisive.All(IsFail);
        var icmpUnknownOnly = icmpToTarget.Length > 0 && icmpDecisive.Length == 0;
        var tcpUnknownOnly = tcpToTarget.Length > 0 && tcpDecisive.Length == 0;

        if (!string.IsNullOrWhiteSpace(target))
        {
            if (icmpUnknownOnly || (icmpToTarget.Length > 0 && !icmpFail && !icmpPass && tcpFail))
            {
                findings.Add(new Finding
                {
                    Id = "LAN-001U",
                    Title = "Insufficient ICMP evidence (Unknown/NotTested)",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = $"ICMP outcomes to {target}: {string.Join(",", icmpToTarget.Select(p => p.Outcome))}; TCP decisiveFail={tcpFail}",
                    Confidence = 0.55,
                    Category = "Network",
                    PossibleCauses = new[] { "Probe cancelled", "Insufficient rights", "Collector error" },
                    RecommendedActions = new[] { "Re-run probes", "Do not conclude host unreachable" },
                    RepairOwner = RepairOwnerRole.None,
                    VerificationMethod = "Decisive ICMP Pass/Fail required"
                });
            }

            if (icmpFail && tcpPass)
            {
                // Inbound ICMP on the *target* — client must not self-repair local firewall for a server issue.
                var serverSide = snap.Role == MachineRole.Client;
                findings.Add(new Finding
                {
                    Id = "LAN-002",
                    Title = serverSide ? "ICMP blocked suspected on SERVER (SERVER_ACTION_REQUIRED)" : "ICMP blocked suspected (local)",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Warning,
                    Evidence = $"ICMP to {target} failed while at least one TCP probe succeeded: {string.Join(", ", tcpDecisive.Where(IsPass).Select(t => t.Port?.ToString() ?? "?"))}",
                    Confidence = 0.8,
                    Category = "Network",
                    PossibleCauses = new[] { "Windows Firewall ICMP Echo rule disabled on target", "Third-party firewall ICMP filter", "Router ICMP filter" },
                    RecommendedActions = serverSide
                        ? new[] { "SERVER_ACTION_REQUIRED: run PrintDoctor as Server on the target host", "Do not modify this client firewall for server inbound ICMP" }
                        : new[] { "Prefer owned MyPC.PrintDoctor.ICMPv4.Private (Private/LocalSubnet)", "Do not treat host as offline" },
                    // P2-02: prefer PrintDoctor-owned rule over mutating system FPS group rules.
                    RepairId = serverSide ? null : "FW-OWNED-ICMP4",
                    RepairOwner = serverSide ? RepairOwnerRole.ServerActionRequired : RepairOwnerRole.LocalServer,
                    VerificationMethod = "Re-run ICMP + TCP probes on owning machine"
                });
            }
            else if (icmpFail && tcpFail)
            {
                findings.Add(new Finding
                {
                    Id = "LAN-001",
                    Title = "Server unreachable (ICMP and TCP failed)",
                    Severity = Severity.Critical,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"Decisive ICMP and TCP probes to {target} all Fail. Unknown/NotTested ignored.",
                    Confidence = 0.7,
                    Category = "Network",
                    PossibleCauses = new[]
                    {
                        "Host offline or wrong IP",
                        "Different subnet / gateway",
                        "ARP/routing failure",
                        "Switch/AP client isolation",
                        "Firewall blocking multiple ports",
                        "NIC/driver issue on server"
                    },
                    RecommendedActions = new[]
                    {
                        "Compare server/client adapter, gateway, subnet",
                        "Check ARP/neighbor MAC consistency",
                        "Verify listeners on server",
                        "Inspect switch/router if both ends look healthy"
                    },
                    RepairOwner = RepairOwnerRole.None,
                    VerificationMethod = "Server+client correlation report"
                });
            }
            else if (icmpFail && tcpUnknownOnly)
            {
                findings.Add(new Finding
                {
                    Id = "LAN-001P",
                    Title = "ICMP Fail but TCP not decisive — insufficient for unreachable",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = $"ICMP Fail to {target}; TCP outcomes: {string.Join(",", tcpToTarget.Select(p => p.Outcome))}",
                    Confidence = 0.5,
                    Category = "Network",
                    PossibleCauses = new[] { "TCP not tested", "Partial collector failure" },
                    RecommendedActions = new[] { "Complete TCP probes before concluding LAN-001" },
                    RepairOwner = RepairOwnerRole.None,
                    VerificationMethod = "Decisive TCP Pass/Fail"
                });
            }

            // Subnet check
            if (upAdapters.Count > 0 && IPLike(snap.TargetHost))
            {
                var local = upAdapters.FirstOrDefault(a => a.IPv4Addresses.Count > 0);
                if (local?.PrefixLength is int prefix)
                {
                    var localIp = local.IPv4Addresses[0];
                    if (!IpMath.SameSubnetPrefix(localIp, prefix, snap.TargetHost!))
                    {
                        findings.Add(new Finding
                        {
                            Id = "LAN-003",
                            Title = "Target appears off-subnet",
                            Severity = Severity.High,
                            Status = DiagnosticStatus.Fail,
                            Evidence = $"Local {localIp}/{prefix} vs target {snap.TargetHost}",
                            Confidence = 0.85,
                            Category = "Network",
                            PossibleCauses = new[] { "Wrong IP entered", "VLAN separation", "Stale DHCP lease" },
                            RecommendedActions = new[] { "Confirm server IP on server console", "Check VLAN/routing", "Do not reset NIC" },
                            VerificationMethod = "Compare both reports"
                        });
                    }
                }

                var gw = upAdapters.Select(a => a.DefaultGateway).FirstOrDefault(g => !string.IsNullOrWhiteSpace(g));
                var gwProbe = snap.Probes.FirstOrDefault(p => p.Protocol == ProbeProtocol.Icmp && p.Target == gw);
                if (gwProbe is { Success: false })
                {
                    findings.Add(new Finding
                    {
                        Id = "LAN-004",
                        Title = "Default gateway unreachable",
                        Severity = Severity.High,
                        Status = DiagnosticStatus.Fail,
                        Evidence = $"Gateway {gw} ICMP failed",
                        Confidence = 0.75,
                        Category = "Network",
                        PossibleCauses = new[] { "Wrong gateway", "Router down", "Local L2 issue" },
                        RecommendedActions = new[] { "Verify gateway on working host", "Check cabling/AP", "Infrastructure may be out of Windows repair scope" },
                        VerificationMethod = "Gateway ICMP + ARP"
                    });
                }
            }
        }

        // Multi-adapter / VPN
        if (upAdapters.Count(a => a.Kind is AdapterKind.Ethernet or AdapterKind.WiFi) > 1)
        {
            findings.Add(new Finding
            {
                Id = "LAN-005",
                Title = "Multiple active physical adapters",
                Severity = Severity.Low,
                Status = DiagnosticStatus.Warning,
                Evidence = string.Join("; ", upAdapters.Select(a => $"{a.Name}/{a.Kind}/{a.IPv4Addresses.FirstOrDefault()}")),
                Confidence = 0.6,
                Category = "Network",
                PossibleCauses = new[] { "Asymmetric routing", "Wrong metric" },
                RecommendedActions = new[] { "Confirm preferred adapter metric", "Disable unused path temporarily for test only with approval" },
                VerificationMethod = "Route table review"
            });
        }

        if (upAdapters.Any(a => a.Kind == AdapterKind.Vpn))
        {
            findings.Add(new Finding
            {
                Id = "LAN-006",
                Title = "VPN adapter active",
                Severity = Severity.Medium,
                Status = DiagnosticStatus.Warning,
                Evidence = string.Join(", ", upAdapters.Where(a => a.Kind == AdapterKind.Vpn).Select(a => a.Name)),
                Confidence = 0.7,
                Category = "Network",
                PossibleCauses = new[] { "VPN hijacking default route", "Split-tunnel misconfig" },
                RecommendedActions = new[] { "Test LAN print with VPN disconnected (user-approved)", "Inspect routes" },
                VerificationMethod = "Route + connectivity retest"
            });
        }

        // IP conflict soft signal
        if (!string.IsNullOrWhiteSpace(snap.TargetHost))
        {
            var neighbors = snap.Neighbors.Where(n => string.Equals(n.IpAddress, snap.TargetHost, StringComparison.OrdinalIgnoreCase)).ToList();
            if (neighbors.Count > 1)
            {
                findings.Add(new Finding
                {
                    Id = "LAN-007",
                    Title = "Possible IP conflict (multiple neighbor entries)",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Warning,
                    Evidence = string.Join(" | ", neighbors.Select(n => $"{n.MacAddress}/{n.State}")),
                    Confidence = 0.55,
                    Category = "Network",
                    PossibleCauses = new[] { "Duplicate static IP", "Stale ARP", "DHCP overlap" },
                    RecommendedActions = new[] { "Compare server-reported MAC with client-observed MAC", "Do not conclude from a single ARP entry" },
                    VerificationMethod = "Server/client MAC correlation over time"
                });
            }
        }

        if (icmpPass && !findings.Any(f => f.Id.StartsWith("LAN-", StringComparison.Ordinal)))
        {
            // keep quiet unless useful
        }
    }

    private static void EvaluateFirewall(DiagnosticSnapshot snap, List<Finding> findings)
    {
        foreach (var profile in snap.FirewallProfiles)
        {
            if (profile.Profile == Abstractions.Firewall.FirewallProfileKind.Public && profile.Enabled)
            {
                var hasPrivateAlt = snap.FirewallProfiles.Any(p => p.Profile == Abstractions.Firewall.FirewallProfileKind.Private);
                var adaptersPublic = snap.Adapters.Any(a => a.Category == NetworkCategory.Public && a.IsUp);
                if (adaptersPublic)
                {
                    findings.Add(new Finding
                    {
                        Id = "FW-001",
                        Title = "Network profile is Public",
                        Severity = Severity.High,
                        Status = DiagnosticStatus.Warning,
                        Evidence = "Active adapter categorized as Public; File/Printer Sharing often restricted.",
                        Confidence = 0.85,
                        Category = "Firewall",
                        PossibleCauses = new[] { "Network reclassified after reconnect", "User/policy change" },
                        RecommendedActions = new[] { "Confirm trusted LAN", "Offer Private profile change only with user consent" },
                        RepairId = "NET-PROFILE-PRIVATE",
                        RepairOwner = RepairOwnerRole.LocalAny,
                        VerificationMethod = "Re-read NetworkCategory + sharing rules"
                    });
                }
            }

            if (profile.ManagedByPolicy == true)
            {
                findings.Add(new Finding
                {
                    Id = "FW-002",
                    Title = "Firewall managed by Group Policy",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Blocked,
                    Evidence = $"{profile.Profile} appears policy-managed",
                    Confidence = 0.7,
                    Category = "Firewall",
                    PossibleCauses = new[] { "Domain GPO", "MDM policy" },
                    RecommendedActions = new[] { "Escalate to domain admin", "Do not fight policy from workstation tool" },
                    VerificationMethod = "gpresult / security center"
                });
            }
        }

        if (snap.ThirdPartySecurity.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "FW-003",
                Title = "Third-party security product detected",
                Severity = Severity.Medium,
                Status = DiagnosticStatus.Warning,
                Evidence = string.Join(", ", snap.ThirdPartySecurity.Select(p => p.Name)),
                Confidence = 0.65,
                Category = "Firewall",
                PossibleCauses = new[] { "Third-party firewall overriding Windows rules" },
                RecommendedActions = new[] { "Review third-party firewall logs", "Do not disable Windows Firewall wholesale" },
                VerificationMethod = "Vendor console + probe retest"
            });
        }

        var icmpRules = snap.FirewallRules.Where(r =>
            (r.Name?.Contains("Echo", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (r.Grouping?.Contains("File and Printer Sharing", StringComparison.OrdinalIgnoreCase) ?? false)).ToList();
        if (icmpRules.Any(r => !r.Enabled && r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding
            {
                Id = "FW-004",
                Title = "Relevant inbound sharing/ICMP rule disabled",
                Severity = Severity.Medium,
                Status = DiagnosticStatus.Warning,
                Evidence = string.Join("; ", icmpRules.Where(r => !r.Enabled).Select(r => r.Name)),
                Confidence = 0.75,
                Category = "Firewall",
                PossibleCauses = new[] { "Manual disable", "Profile mismatch", "Security software" },
                RecommendedActions = snap.Role == MachineRole.Client
                    ? new[] { "SERVER_ACTION_REQUIRED if rules are on the print server", "Do not widen client Public profile rules" }
                    : new[] { "Create owned MyPC.PrintDoctor.ICMPv4.Private (Disabled→verify→Enable)" },
                RepairId = snap.Role == MachineRole.Server ? "FW-OWNED-ICMP4" : null,
                RepairOwner = snap.Role == MachineRole.Server ? RepairOwnerRole.LocalServer : RepairOwnerRole.ServerActionRequired,
                VerificationMethod = "Rule dump + ICMP probe on owning machine"
            });
        }
    }

    private static void EvaluateServices(DiagnosticSnapshot snap, List<Finding> findings)
    {
        foreach (var svc in snap.Services)
        {
            // Unknown/Missing means inspector could not read — do not treat as stopped.
            if (svc.Status.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
                svc.Status.Equals("Missing", StringComparison.OrdinalIgnoreCase))
                continue;
            var stopped = !svc.Status.Equals("Running", StringComparison.OrdinalIgnoreCase);
            if (!stopped) continue;

            if (svc.Name.Equals("Spooler", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "PRN-001",
                    Title = "Print Spooler stopped",
                    Severity = Severity.Critical,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"Service Spooler status={svc.Status}, start={svc.StartType}",
                    Confidence = 0.95,
                    Category = "Printing",
                    PossibleCauses = new[] { "Crash", "Manual stop", "Dependency failure" },
                    RecommendedActions = new[] { "Start Spooler with user awareness of in-flight jobs" },
                    RepairId = "SVC-SPOOLER-START",
                    RepairOwner = RepairOwnerRole.LocalAny,
                    VerificationMethod = "Service status + printer enumeration"
                });
            }
            else if (svc.Name.Equals("LanmanServer", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "SMB-002",
                    Title = "LanmanServer stopped",
                    Severity = Severity.Critical,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"LanmanServer status={svc.Status}",
                    Confidence = 0.95,
                    Category = "SMB",
                    PossibleCauses = new[] { "Service disabled", "Policy", "Dependency" },
                    RecommendedActions = new[] { "Start LanmanServer if sharing is required" },
                    RepairId = "SVC-LANMANSERVER-START",
                    RepairOwner = snap.Role == MachineRole.Server ? RepairOwnerRole.LocalServer : RepairOwnerRole.ServerActionRequired,
                    VerificationMethod = "Service status + TCP 445 listen"
                });
            }
            else if (svc.Name.Equals("LanmanWorkstation", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "SMB-003",
                    Title = "LanmanWorkstation stopped",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"LanmanWorkstation status={svc.Status}",
                    Confidence = 0.95,
                    Category = "SMB",
                    PossibleCauses = new[] { "Service disabled" },
                    RecommendedActions = new[] { "Start LanmanWorkstation" },
                    RepairId = "SVC-LANMANWORKSTATION-START",
                    RepairOwner = RepairOwnerRole.LocalAny,
                    VerificationMethod = "Service status + UNC probe"
                });
            }
        }
    }

    private static void EvaluateSmb(DiagnosticSnapshot snap, List<Finding> findings)
    {
        if (snap.SmbConfiguration?.EnableSMB1Protocol == true)
        {
            findings.Add(new Finding
            {
                Id = "SMB-010",
                Title = "SMB1 enabled (security risk)",
                Severity = Severity.High,
                Status = DiagnosticStatus.Warning,
                Evidence = "EnableSMB1Protocol=true",
                Confidence = 0.9,
                Category = "SMB",
                PossibleCauses = new[] { "Legacy device requirement" },
                RecommendedActions = new[] { "Keep SMB1 disabled; this tool will not turn SMB1 on", "Plan migration off SMB1" },
                VerificationMethod = "Get-SmbServerConfiguration"
            });
        }

        if (snap.SmbConfiguration?.EnableInsecureGuestLogons == true)
        {
            findings.Add(new Finding
            {
                Id = "SMB-011",
                Title = "Insecure guest logons enabled",
                Severity = Severity.High,
                Status = DiagnosticStatus.Warning,
                Evidence = "EnableInsecureGuestLogons=true",
                Confidence = 0.9,
                Category = "SMB",
                PossibleCauses = new[] { "Legacy workaround" },
                RecommendedActions = new[] { "Do not turn on insecure guest logons", "Use proper accounts" },
                VerificationMethod = "SMB client configuration"
            });
        }

        if (snap.SmbProbe is { } probe)
        {
            if (probe.Tcp445 == ProbeOutcome.Fail)
            {
                // Do NOT auto-open firewall solely because a remote probe failed.
                // Owned SMB repair only when THIS machine is the server and LanmanServer is running
                // (listener expected) — still requires user consent; never opens RemoteAddress=Any.
                var lanmanUp = snap.Services.Any(s =>
                    s.Name.Equals("LanmanServer", StringComparison.OrdinalIgnoreCase)
                    && s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
                var serverOwned = snap.Role == MachineRole.Server && lanmanUp;
                findings.Add(new Finding
                {
                    Id = "SMB-001",
                    Title = "SMB connection failure (TCP 445)",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = probe.Detail ?? "TCP 445 closed/filtered",
                    Confidence = 0.8,
                    Category = "SMB",
                    PossibleCauses = new[] { "Network path", "Firewall", "LanmanServer down", "Infrastructure isolation" },
                    RecommendedActions = serverOwned
                        ? new[] { "Confirm listener + Private profile", "Optional owned MyPC.PrintDoctor.SMB445.Private (LocalSubnet only)" }
                        : new[] { "Correlate with server listener and firewall", "Distinguish auth vs network — do not open ports on client" },
                    RepairId = serverOwned ? "FW-OWNED-SMB445" : null,
                    RepairOwner = serverOwned ? RepairOwnerRole.LocalServer : RepairOwnerRole.ServerActionRequired,
                    VerificationMethod = "TCP 445 + service + firewall"
                });
            }
            else if (probe.Tcp445 == ProbeOutcome.Pass && probe.Unc == ProbeOutcome.NotTested)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-004A",
                    Title = "TCP 445 open; UNC not tested",
                    Severity = Severity.Low,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = probe.Detail ?? "UNC=NotTested",
                    Confidence = 0.9,
                    Category = "SMB",
                    PossibleCauses = new[] { "Collector skipped UNC probe" },
                    RecommendedActions = new[] { "Do not treat as SMB failure", "Re-run with UNC probe enabled" },
                    VerificationMethod = "UNC ProbeOutcome"
                });
            }
            else if (probe.Tcp445 == ProbeOutcome.Pass && probe.Unc == ProbeOutcome.AuthDenied)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-004B",
                    Title = "TCP 445 open; UNC authentication denied",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = probe.Detail ?? "UNC=AuthDenied",
                    Confidence = 0.85,
                    Category = "SMB",
                    PossibleCauses = new[] { "Credentials", "Share permissions", "Guest blocked" },
                    RecommendedActions = new[] { "Use proper account", "Do not enable insecure guest or disable SMB signing" },
                    VerificationMethod = "Authenticated share list"
                });
            }
            else if (probe.Tcp445 == ProbeOutcome.Pass && probe.Unc == ProbeOutcome.Fail)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-004",
                    Title = "TCP 445 open but UNC not reachable",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = probe.Detail ?? "UNC probe failed",
                    Confidence = 0.7,
                    Category = "SMB",
                    PossibleCauses = new[] { "Share permissions", "Name resolution", "SMB policy" },
                    RecommendedActions = new[] { "Check event logs", "Do not disable SMB signing" },
                    VerificationMethod = "Authenticated share list"
                });
            }
            else if (probe.Tcp445 == ProbeOutcome.Pass && probe.Unc == ProbeOutcome.Unknown)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-004C",
                    Title = "TCP 445 open; UNC result UNKNOWN",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = probe.Detail ?? "UNC=Unknown",
                    Confidence = 0.6,
                    Category = "SMB",
                    PossibleCauses = new[] { "Insufficient rights", "Ambiguous error" },
                    RecommendedActions = new[] { "Re-run elevated", "Inspect collector detail" },
                    VerificationMethod = "UNC ProbeOutcome"
                });
            }
        }

        if (snap.SharingToggles is { } toggles)
        {
            if (toggles.NetworkDiscovery == ProbeOutcome.Unknown || toggles.FileAndPrinterSharing == ProbeOutcome.Unknown)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-005U",
                    Title = "Sharing toggles UNKNOWN (collector)",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = toggles.Detail ?? "sharing toggles not collected",
                    Confidence = 0.7,
                    Category = "SMB",
                    PossibleCauses = new[] { "Insufficient rights", "PowerShell failure" },
                    RecommendedActions = new[] { "Re-run as Administrator", "Do not assume sharing is enabled" },
                    VerificationMethod = "Get-NetFirewallRule group status"
                });
            }
            else if (toggles.NetworkDiscovery == ProbeOutcome.Fail || toggles.FileAndPrinterSharing == ProbeOutcome.Fail)
            {
                findings.Add(new Finding
                {
                    Id = "SMB-005",
                    Title = "Network Discovery / File and Printer Sharing disabled",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Warning,
                    Evidence = $"Discovery={toggles.NetworkDiscovery}, Sharing={toggles.FileAndPrinterSharing}; {toggles.Detail}",
                    Confidence = 0.85,
                    Category = "SMB",
                    PossibleCauses = new[] { "Public profile", "Manual toggle" },
                    RecommendedActions = new[] { "Enable for Private profile only when LAN is trusted" },
                    RepairId = "FW-FILE-PRINT-SHARE",
                    RepairOwner = RepairOwnerRole.LocalAny,
                    VerificationMethod = "Sharing toggles + browse"
                });
            }
        }
    }

    private static void EvaluatePrinters(DiagnosticSnapshot snap, List<Finding> findings)
    {
        if (snap.Role == MachineRole.Server && snap.Printers.Count == 0)
        {
            findings.Add(new Finding
            {
                Id = "PRN-002",
                Title = "Server has no printers",
                Severity = Severity.High,
                Status = DiagnosticStatus.Fail,
                Evidence = "Printer catalog empty on server role scan",
                Confidence = 0.9,
                Category = "Printing",
                PossibleCauses = new[] { "Driver removed", "USB disconnect", "Spooler issue" },
                RecommendedActions = new[] { "Verify local printer installation on server" },
                VerificationMethod = "Printer enumeration"
            });
        }

        foreach (var p in snap.Printers.Where(x => x.Offline))
        {
            findings.Add(new Finding
            {
                Id = "PRN-003",
                Title = $"Printer offline: {p.Name}",
                Severity = Severity.High,
                Status = DiagnosticStatus.Fail,
                Evidence = $"Port={p.PortName}, Driver={p.DriverName}, Jobs={p.JobCount}",
                Confidence = 0.85,
                Category = "Printing",
                PossibleCauses = new[] { "Device powered off", "Bad port", "Network path" },
                RecommendedActions = new[] { "Check device power/cable", "Validate port", "Distinguish network vs pipeline" },
                VerificationMethod = "Printer status + test page (user confirmed)"
            });
        }
    }

    private static void EvaluateShaPrint(DiagnosticSnapshot snap, List<Finding> findings)
    {
        if (snap.ShaPrint is null)
            return;

        if (!snap.ShaPrint.Installed)
            return; // absence is not a finding by itself

        if (snap.ShaPrint.Installed && !snap.ShaPrint.ProcessRunning)
        {
            findings.Add(new Finding
            {
                Id = "SHA-002",
                Title = "ShaPrint installed but process not running",
                Severity = Severity.High,
                Status = DiagnosticStatus.Fail,
                Evidence = $"Path={snap.ShaPrint.InstallPath}, Version={snap.ShaPrint.Version}",
                Confidence = 0.9,
                Category = "ShaPrint",
                PossibleCauses = new[] { "Crash after login", "Startup task missing", "User exited tray app" },
                RecommendedActions = new[]
                {
                    "Start verified ShaPrint executable only",
                    "Do not open firewall before a listener exists",
                    "Do not uninstall/reinstall automatically"
                },
                RepairId = snap.Role == MachineRole.Server ? "SHA-START-PROCESS" : null,
                RepairOwner = snap.Role == MachineRole.Server ? RepairOwnerRole.LocalServer : RepairOwnerRole.ServerActionRequired,
                VerificationMethod = "Process list + TCP 48631 (not IPPS PASS)"
            });
        }

        if (snap.ShaPrint.ProcessRunning)
        {
            if (snap.ShaPrint.ListeningCollectionStatus is ProbeOutcome.Unknown or ProbeOutcome.NotTested)
            {
                findings.Add(new Finding
                {
                    Id = "SHA-003U",
                    Title = "ShaPrint listening endpoints UNKNOWN",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = "ListeningCollectionStatus=" + snap.ShaPrint.ListeningCollectionStatus,
                    Confidence = 0.7,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "Collector rights", "Get-NetTCPConnection failed" },
                    RecommendedActions = new[] { "Do not conclude not-listening", "Re-run elevated" },
                    VerificationMethod = "Get-NetTCPConnection / Get-NetUDPEndpoint"
                });
            }
            else if (snap.ShaPrint.ListeningCollectionStatus == ProbeOutcome.Pass && snap.ShaPrint.ListeningEndpoints.Count == 0)
            {
                findings.Add(new Finding
                {
                    Id = "SHA-003",
                    Title = "ShaPrint running but not listening expected ports",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = "Collected listen table empty for 48631/48632/48633",
                    Confidence = 0.8,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "Sharing not started", "Port conflict", "Failed bind" },
                    RecommendedActions = new[] { "Inspect ShaPrint logs if accessible", "Check port ownership — do not open firewall without listener" },
                    VerificationMethod = "netstat/Get-NetTCPConnection"
                });
            }
            else if (snap.Role == MachineRole.Server
                     && snap.ShaPrint.ListeningEndpoints.Any(e =>
                         e.Contains("48631", StringComparison.OrdinalIgnoreCase)
                         && !e.Contains("FOREIGN", StringComparison.OrdinalIgnoreCase)))
            {
                // Listener present on server — owned inbound rule is eligible (user consent still required).
                findings.Add(new Finding
                {
                    Id = "SHA-004",
                    Title = "ShaPrint IPPS listener present — owned firewall rule may be required",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Warning,
                    Evidence = "TCP 48631 listening; offer MyPC.PrintDoctor.ShaPrint48631.Private (Private/LocalSubnet only)",
                    Confidence = 0.7,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "Inbound firewall filter", "Profile mismatch" },
                    RecommendedActions = new[] { "Create owned rule only after confirming Private LAN", "Never open TCP 48632 to LAN" },
                    RepairId = "FW-OWNED-SHA48631",
                    RepairOwner = RepairOwnerRole.LocalServer,
                    VerificationMethod = "Rule re-read + client TCP 48631 (still not IPPS PASS)"
                });
            }

            if (snap.Role == MachineRole.Server
                && snap.ShaPrint.ListeningEndpoints.Any(e =>
                    e.Contains("48633", StringComparison.OrdinalIgnoreCase)
                    && !e.Contains("FOREIGN", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new Finding
                {
                    Id = "SHA-005",
                    Title = "ShaPrint discovery UDP 48633 listening — owned firewall rule may be required",
                    Severity = Severity.Medium,
                    Status = DiagnosticStatus.Warning,
                    Evidence = "UDP 48633 listening; offer MyPC.PrintDoctor.ShaPrint48633.Private (Private/LocalSubnet only). Never expose TCP 48632 to LAN.",
                    Confidence = 0.65,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "Inbound UDP filter", "Profile mismatch" },
                    RecommendedActions = new[] { "Create owned UDP discovery rule only on Private/LocalSubnet" },
                    RepairId = "FW-OWNED-SHA48633",
                    RepairOwner = RepairOwnerRole.LocalServer,
                    VerificationMethod = "Rule re-read + discovery probe (not IPPS PASS)"
                });
            }
        }

        if (snap.ShaPrintConnectivity is { } conn && !string.IsNullOrWhiteSpace(snap.TargetHost))
        {
            if (conn.ServerEndpoint == ProbeOutcome.Fail)
            {
                findings.Add(new Finding
                {
                    Id = "SHA-001",
                    Title = "ShaPrint endpoint unavailable",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Fail,
                    Evidence = conn.Detail ?? $"TCP {ShaPrintPorts.ServerTcp} unreachable",
                    Confidence = 0.75,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "Process down", "Not listening", "Port blocked", "No route" },
                    RecommendedActions = new[] { "Separate process/listen/firewall/route causes", "Avoid blaming ShaPrint without evidence", "SERVER_ACTION_REQUIRED for inbound firewall" },
                    RepairOwner = RepairOwnerRole.ServerActionRequired,
                    VerificationMethod = "Local listen check + remote TCP probe"
                });
            }
            else if (conn.ServerEndpoint is ProbeOutcome.NotTested or ProbeOutcome.Unknown)
            {
                findings.Add(new Finding
                {
                    Id = "SHA-001U",
                    Title = "ShaPrint endpoint not tested / UNKNOWN",
                    Severity = Severity.Low,
                    Status = DiagnosticStatus.Unknown,
                    Evidence = conn.Detail ?? conn.ServerEndpoint.ToString(),
                    Confidence = 0.8,
                    Category = "ShaPrint",
                    PossibleCauses = new[] { "No target", "Collector failure" },
                    RecommendedActions = new[] { "Provide server IP and re-scan" },
                    VerificationMethod = "TCP 48631 probe"
                });
            }
        }
    }

    private static bool IPLike(string? host)
        => host is not null && System.Net.IPAddress.TryParse(host, out _);
}
