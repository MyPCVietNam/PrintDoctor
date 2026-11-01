using MyPC.LanPrintDoctor.Core.Engine;

namespace MyPC.LanPrintDoctor.UnitTests;

public class IpMathTests
{
    [Fact]
    public void SameSubnet_DetectsMismatch()
    {
        Assert.True(IpMath.SameSubnetPrefix("192.168.1.10", 24, "192.168.1.50"));
        Assert.False(IpMath.SameSubnetPrefix("192.168.1.10", 24, "192.168.2.50"));
    }
}
