using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Core.Models;

namespace MyPC.LanPrintDoctor.Core.Engine;

public sealed class CompareEngine
{
    public CompareResult Compare(CompareInput input)
    {
        var findings = new List<Finding>();
        var serverIssues = new List<string>();
        var clientIssues = new List<string>();
        var infra = new List<string>();
        var insufficient = new List<string>();

        var server = input.Server;
        var clients = input.Clients;

        if (clients.Count == 0)
        {
            insufficient.Add("No client reports provided.");
            return new CompareResult
            {
                Findings = findings,
                ServerSideIssues = serverIssues,
                ClientSpecificIssues = clientIssues,
                InfrastructureHints = infra,
                InsufficientEvidence = insufficient,
                HasValidEvidence = false
            };
        }

        var serverIp = server.Adapters.FirstOrDefault(a => a.IsUp && a.IPv4Addresses.Count > 0)?.IPv4Addresses.FirstOrDefault()
                       ?? server.TargetHost;
        var serverMac = server.Adapters.FirstOrDefault(a => a.IsUp && !string.IsNullOrWhiteSpace(a.MacAddress))?.MacAddress;
        var serverGw = server.Adapters.FirstOrDefault(a => a.IsUp)?.DefaultGateway;

        // Require non-empty probe sets before using .All() — empty.All() is true in LINQ and caused false CMP-001.
        static bool AllFailIcmpTo(DiagnosticSnapshot c, string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var probes = c.Probes.Where(p => p.Protocol == ProbeProtocol.Icmp
                                             && string.Equals(p.Target, ip, StringComparison.OrdinalIgnoreCase)
                                             && p.Outcome is ProbeOutcome.Pass or ProbeOutcome.Fail).ToList();
            return probes.Count > 0 && probes.All(p => p.Outcome == ProbeOutcome.Fail);
        }

        static bool AllFailTcpTo(DiagnosticSnapshot c, string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var probes = c.Probes.Where(p => p.Protocol == ProbeProtocol.Tcp
                                             && string.Equals(p.Target, ip, StringComparison.OrdinalIgnoreCase)
                                             && p.Outcome is ProbeOutcome.Pass or ProbeOutcome.Fail).ToList();
            return probes.Count > 0 && probes.All(p => p.Outcome == ProbeOutcome.Fail);
        }

        var clientsWithValidIcmp = clients.Where(c => AllFailIcmpTo(c, serverIp) ||
            c.Probes.Any(p => p.Protocol == ProbeProtocol.Icmp && string.Equals(p.Target, serverIp, StringComparison.OrdinalIgnoreCase) && p.Outcome == ProbeOutcome.Pass)).ToList();
        var clientsWithValidTcp = clients.Where(c => AllFailTcpTo(c, serverIp) ||
            c.Probes.Any(p => p.Protocol == ProbeProtocol.Tcp && string.Equals(p.Target, serverIp, StringComparison.OrdinalIgnoreCase) && p.Outcome == ProbeOutcome.Pass)).ToList();

        var allClientsFailIcmp = clients.Count > 0
                                 && clients.All(c => AllFailIcmpTo(c, serverIp))
                                 && clients.All(c => c.Probes.Any(p => p.Protocol == ProbeProtocol.Icmp && string.Equals(p.Target, serverIp, StringComparison.OrdinalIgnoreCase)));
        var allClientsFailTcp = clients.Count > 0
                                && clients.All(c => AllFailTcpTo(c, serverIp))
                                && clients.All(c => c.Probes.Any(p => p.Protocol == ProbeProtocol.Tcp && string.Equals(p.Target, serverIp, StringComparison.OrdinalIgnoreCase)));

        if (!allClientsFailIcmp && !clients.Any(c => AllFailIcmpTo(c, serverIp)))
            insufficient.Add("Insufficient ICMP probes targeting server IP for common-outage analysis.");
        if (!allClientsFailTcp && !clients.Any(c => AllFailTcpTo(c, serverIp)))
            insufficient.Add("Insufficient TCP probes targeting server IP for common-outage analysis.");

        if (allClientsFailIcmp && allClientsFailTcp)
        {
            serverIssues.Add("All clients fail ICMP and TCP to server — likely server-side, L2 path, or infrastructure isolation.");
            findings.Add(new Finding
            {
                Id = "CMP-001",
                Title = "Common outage across clients",
                Severity = Severity.Critical,
                Status = DiagnosticStatus.Fail,
                Evidence = $"Clients={clients.Count}; server IP={serverIp}; MAC={serverMac}; validIcmpSets={clientsWithValidIcmp.Count}; validTcpSets={clientsWithValidTcp.Count}",
                Confidence = 0.8,
                Category = "Correlation",
                PossibleCauses = new[] { "Server NIC/firewall", "Switch ACL / AP isolation", "Wrong VLAN", "Server IP not actually bound" },
                RecommendedActions = new[] { "Validate server adapter on console", "Check switch/AP client isolation", "Avoid blanket network reset" },
                VerificationMethod = "Server local loopback + peer from known-good host"
            });
        }

        foreach (var client in clients)
        {
            var clientGw = client.Adapters.FirstOrDefault(a => a.IsUp)?.DefaultGateway;
            if (serverGw is not null && clientGw is not null && !string.Equals(serverGw, clientGw, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "CMP-002",
                    Title = $"Gateway mismatch: {client.MachineName}",
                    Severity = Severity.High,
                    Status = DiagnosticStatus.Warning,
                    Evidence = $"Server GW={serverGw}, Client GW={clientGw}",
                    Confidence = 0.75,
                    Category = "Correlation",
                    PossibleCauses = new[] { "Different subnet/VLAN", "Wrong static config" },
                    RecommendedActions = new[] { "Align IP plan", "Check DHCP scopes" },
                    VerificationMethod = "Adapter comparison"
                });
                clientIssues.Add($"{client.MachineName}: gateway differs from server");
            }

            var observed = client.Neighbors.Where(n => string.Equals(n.IpAddress, serverIp, StringComparison.OrdinalIgnoreCase)).ToList();
            if (observed.Count > 1)
            {
                insufficient.Add($"{client.MachineName}: multiple neighbor MACs for server IP — do not conclude conflict from a single sample; correlate across time/clients.");
            }

            var observedOne = observed.FirstOrDefault();
            if (serverMac is not null && observedOne?.MacAddress is not null &&
                !string.Equals(NormalizeMac(serverMac), NormalizeMac(observedOne.MacAddress), StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "CMP-003",
                    Title = $"Server MAC mismatch observed by {client.MachineName}",
                    Severity = Severity.Critical,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"Server MAC={serverMac}, observed={observedOne.MacAddress}; neighborCount={observed.Count}",
                    Confidence = observed.Count == 1 ? 0.55 : 0.7,
                    Category = "Correlation",
                    PossibleCauses = new[] { "IP conflict", "Stale ARP" },
                    RecommendedActions = new[] { "Refresh ARP on multiple clients", "Confirm DHCP leases", "Do not conclude from one ARP entry alone" },
                    VerificationMethod = "Multi-client MAC correlation"
                });
            }
            else if (serverMac is null || observedOne?.MacAddress is null)
            {
                insufficient.Add($"{client.MachineName}: insufficient MAC evidence for conflict analysis");
            }
        }

        var serverSpoolerDown = server.Services.Any(s => s.Name.Equals("Spooler", StringComparison.OrdinalIgnoreCase) &&
                                                         s.Status.Equals("Stopped", StringComparison.OrdinalIgnoreCase));
        if (serverSpoolerDown)
            serverIssues.Add("Server Spooler not running");

        var serverProfilePublic = server.Adapters.Any(a => a.IsUp && a.Category == NetworkCategory.Public);
        if (serverProfilePublic)
            serverIssues.Add("Server network profile Public");

        if (allClientsFailIcmp && server.Adapters.Any(a => a.IsUp) &&
            server.Services.Any(s => s.Name.Equals("LanmanServer", StringComparison.OrdinalIgnoreCase) && s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase)))
        {
            infra.Add("Server services look up while all clients unreachable — suspect switch/AP isolation or L2 path (not repairable from Windows alone).");
        }

        var hasValid = findings.Count > 0 || serverIssues.Count > 0 || infra.Count > 0 || clientIssues.Count > 0;
        return new CompareResult
        {
            Findings = findings,
            ServerSideIssues = serverIssues,
            ClientSpecificIssues = clientIssues,
            InfrastructureHints = infra,
            InsufficientEvidence = insufficient,
            HasValidEvidence = hasValid || (allClientsFailIcmp && allClientsFailTcp)
        };
    }

    private static string NormalizeMac(string mac)
        => new string(mac.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
}
