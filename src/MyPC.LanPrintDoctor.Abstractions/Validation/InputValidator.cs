using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace MyPC.LanPrintDoctor.Abstractions.Validation;

public static partial class InputValidator
{
    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")]
    private static partial Regex HostnameRegex();

    public static bool TryParseHost(string? input, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var value = input.Trim();
        if (value.Length > 253)
            return false;

        if (IPAddress.TryParse(value, out var ip))
        {
            if (ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            {
                normalized = ip.ToString();
                return true;
            }
            return false;
        }

        if (!HostnameRegex().IsMatch(value))
            return false;

        normalized = value;
        return true;
    }

    public static bool IsSafePathSegment(string? segment)
        => !string.IsNullOrWhiteSpace(segment)
           && segment.IndexOfAny(Path.GetInvalidFileNameChars()) < 0
           && !segment.Contains("..", StringComparison.Ordinal);
}
