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

        var serverIp = server.Adapters.FirstOrDefault(a => a.IsUp && a.IPv4Addresses.Count > 0)?.IPv4Addresses.FirstOrDefault();
        var serverMac = server.Adapters.FirstOrDefault(a => a.IsUp && !string.IsNullOrWhiteSpace(a.MacAddress))?.MacAddress;
        var serverGw = server.Adapters.FirstOrDefault(a => a.IsUp)?.DefaultGateway;

        var allClientsFailIcmp = clients.Count > 0 && clients.All(c =>
            c.Probes.Where(p => p.Protocol == ProbeProtocol.Icmp && p.Target == serverIp).All(p => !p.Success));
        var allClientsFailTcp = clients.Count > 0 && clients.All(c =>
            c.Probes.Where(p => p.Protocol == ProbeProtocol.Tcp).All(p => !p.Success));

        if (allClientsFailIcmp && allClientsFailTcp)
        {
            serverIssues.Add("All clients fail ICMP and TCP to server — likely server-side, L2 path, or infrastructure isolation.");
            findings.Add(new Finding
            {
                Id = "CMP-001",
                Title = "Common outage across clients",
                Severity = Severity.Critical,
                Status = DiagnosticStatus.Fail,
                Evidence = $"Clients={clients.Count}; server IP={serverIp}; MAC={serverMac}",
                Confidence = 0.8,
                Category = "Correlation",
                PossibleCauses = new[] { "Server NIC/firewall", "Switch ACL / AP isolation", "Wrong VLAN", "Server IP not actually bound" },
                RecommendedActions = new[] { "Validate server adapter on console", "Check switch/AP client isolation", "Avoid blanket network reset" },
                VerificationMethod = "Server local loopback + peer from known-good host"
            });
        }

        foreach (var client in clients)
        {
            var clientIp = client.Adapters.FirstOrDefault(a => a.IsUp && a.IPv4Addresses.Count > 0)?.IPv4Addresses.FirstOrDefault();
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

            var observed = client.Neighbors.FirstOrDefault(n => string.Equals(n.IpAddress, serverIp, StringComparison.OrdinalIgnoreCase));
            if (serverMac is not null && observed?.MacAddress is not null &&
                !string.Equals(NormalizeMac(serverMac), NormalizeMac(observed.MacAddress), StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "CMP-003",
                    Title = $"Server MAC mismatch observed by {client.MachineName}",
                    Severity = Severity.Critical,
                    Status = DiagnosticStatus.Fail,
                    Evidence = $"Server MAC={serverMac}, observed={observed.MacAddress}",
                    Confidence = 0.7,
                    Category = "Correlation",
                    PossibleCauses = new[] { "IP conflict", "Stale ARP", "Man-in-the-middle unlikely on LAN misconfig" },
                    RecommendedActions = new[] { "Refresh ARP on multiple clients", "Confirm DHCP leases" },
                    VerificationMethod = "Multi-client MAC correlation"
                });
            }
            else if (serverMac is null || observed?.MacAddress is null)
            {
                insufficient.Add($"{client.MachineName}: insufficient MAC evidence for conflict analysis");
            }
        }

        var serverSpoolerDown = server.Services.Any(s => s.Name.Equals("Spooler", StringComparison.OrdinalIgnoreCase) &&
                                                         !s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
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

        return new CompareResult
        {
            Findings = findings,
            ServerSideIssues = serverIssues,
            ClientSpecificIssues = clientIssues,
            InfrastructureHints = infra,
            InsufficientEvidence = insufficient
        };
    }

    private static string NormalizeMac(string mac)
        => new string(mac.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
}
