using MyPC.LanPrintDoctor.Abstractions.Firewall;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeNetworkProfileService : INetworkProfileService
{
    public List<NetworkConnectionProfile> Profiles { get; set; } = new();
    public int SetPrivateCalls { get; private set; }

    public Task<IReadOnlyList<NetworkConnectionProfile>> GetConnectionProfilesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<NetworkConnectionProfile>)Profiles);

    public Task<bool> SetPrivateAsync(int interfaceIndex, CancellationToken ct = default)
        => SetCategoryAsync(interfaceIndex, "Private", ct);

    public Task<bool> SetCategoryAsync(int interfaceIndex, string category, CancellationToken ct = default)
    {
        SetPrivateCalls++;
        var idx = Profiles.FindIndex(p => p.InterfaceIndex == interfaceIndex);
        if (idx < 0) return Task.FromResult(false);
        var old = Profiles[idx];
        Profiles[idx] = new NetworkConnectionProfile
        {
            InterfaceIndex = old.InterfaceIndex,
            Name = old.Name,
            InterfaceAlias = old.InterfaceAlias,
            NetworkCategory = category,
            IsDomainManaged = category.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase)
        };
        return Task.FromResult(true);
    }
}
