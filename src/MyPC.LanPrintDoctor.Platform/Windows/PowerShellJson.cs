using System.Globalization;
using System.Text.Json;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public static class PowerShellJson
{
    public static IEnumerable<JsonElement> Enumerate(JsonElement root)
        => root.ValueKind == JsonValueKind.Array ? root.EnumerateArray() : new[] { root };

    public static string? GetString(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var p)) return null;
        return p.ValueKind switch
        {
            JsonValueKind.String => p.GetString(),
            JsonValueKind.Number => p.ToString(),
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            JsonValueKind.Null => null,
            _ => p.ToString()
        };
    }

    public static bool IsTruthy(JsonElement el)
        => TryParseEnabled(el, out var b) && b;

    /// <summary>
    /// Strict Enabled parsing — never treat "False"/GPOBoolean False as true.
    /// Returns false when value cannot be interpreted (caller may treat as UNKNOWN).
    /// </summary>
    public static bool TryParseEnabled(JsonElement el, out bool enabled)
    {
        enabled = false;
        switch (el.ValueKind)
        {
            case JsonValueKind.True:
                enabled = true;
                return true;
            case JsonValueKind.False:
                enabled = false;
                return true;
            case JsonValueKind.Number:
                if (el.TryGetInt32(out var n))
                {
                    if (n == 0) { enabled = false; return true; }
                    if (n == 1) { enabled = true; return true; }
                    return false;
                }
                return false;
            case JsonValueKind.String:
            {
                var s = (el.GetString() ?? "").Trim();
                if (s is "True" or "true" or "1" or "Enabled" or "Bật" or "Yes")
                {
                    enabled = true;
                    return true;
                }
                if (s is "False" or "false" or "0" or "Disabled" or "Tắt" or "No" or "")
                {
                    enabled = false;
                    return true;
                }
                // Unknown GPOBoolean / localized — not truthy
                return false;
            }
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                return false;
            default:
                return false;
        }
    }

    public static bool TryGetTruthy(JsonElement parent, string name, out bool value)
    {
        value = false;
        if (!parent.TryGetProperty(name, out var p)) return false;
        value = IsTruthy(p);
        return true;
    }

    public static string NormalizeServiceStatus(JsonElement el)
    {
        var raw = GetString(el, "Status") ?? "Unknown";
        return ServiceStatusParser.Normalize(raw);
    }

    public static string NormalizeStartType(JsonElement el)
    {
        var raw = GetString(el, "StartType") ?? "Unknown";
        return raw switch
        {
            "0" => "Boot",
            "1" => "System",
            "2" => "Automatic",
            "3" => "Manual",
            "4" => "Disabled",
            _ => raw
        };
    }

    public static bool IsPrinterOffline(string? statusText)
    {
        if (string.IsNullOrWhiteSpace(statusText)) return false;
        // PrinterStatus enum: Normal=0, Other=1, ... Offline=7 (varies); also localized strings
        if (statusText.Equals("7", StringComparison.Ordinal)) return true;
        if (statusText.Contains("Offline", StringComparison.OrdinalIgnoreCase)) return true;
        if (statusText.Contains("Ngoại tuyến", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public static int? GetInt(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var p)) return null;
        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var n)) return n;
        if (p.ValueKind == JsonValueKind.String && int.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s))
            return s;
        return null;
    }
}
