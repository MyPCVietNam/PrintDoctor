using System.Net;

namespace MyPC.LanPrintDoctor.Core.Engine;

public static class IpMath
{
    public static bool TryGetNetwork(string ip, string maskOrPrefix, out uint network, out uint mask)
    {
        network = 0;
        mask = 0;
        if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = addr.GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        var ipVal = BitConverter.ToUInt32(bytes, 0);

        if (int.TryParse(maskOrPrefix, out var prefix) && prefix is >= 0 and <= 32)
        {
            mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        }
        else if (IPAddress.TryParse(maskOrPrefix, out var maskAddr))
        {
            var mb = maskAddr.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(mb);
            mask = BitConverter.ToUInt32(mb, 0);
        }
        else return false;

        network = ipVal & mask;
        return true;
    }

    public static bool SameSubnet(string ipA, string maskA, string ipB)
    {
        if (!TryGetNetwork(ipA, maskA, out var netA, out var mask))
            return false;
        if (!TryGetNetwork(ipB, mask.ToString(), out var netB, out _))
        {
            // mask as dotted from uint
            var mb = BitConverter.GetBytes(mask);
            if (BitConverter.IsLittleEndian) Array.Reverse(mb);
            if (!TryGetNetwork(ipB, new IPAddress(mb).ToString(), out netB, out _))
            {
                // recompute with same mask bits
                if (!IPAddress.TryParse(ipB, out var addrB) || addrB.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return false;
                var bb = addrB.GetAddressBytes();
                if (BitConverter.IsLittleEndian) Array.Reverse(bb);
                netB = BitConverter.ToUInt32(bb, 0) & mask;
            }
        }
        return netA == netB;
    }

    public static bool SameSubnetPrefix(string ipA, int prefixLength, string ipB)
    {
        if (!IPAddress.TryParse(ipA, out var a) || !IPAddress.TryParse(ipB, out var b))
            return false;
        if (a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;
        var ab = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(ab);
            Array.Reverse(bb);
        }
        var av = BitConverter.ToUInt32(ab, 0);
        var bv = BitConverter.ToUInt32(bb, 0);
        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        return (av & mask) == (bv & mask);
    }

    public static string PrefixToMask(int prefix)
    {
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var bytes = BitConverter.GetBytes(mask);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return new IPAddress(bytes).ToString();
    }
}
