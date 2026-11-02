namespace MyPC.LanPrintDoctor.Core.Ui;

/// <summary>Permanent scan lifecycle shown in the status strip (Gate B/C).</summary>
public enum ScanUiPhase
{
    Ready = 0,
    Validating = 1,
    Scanning = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5
}

/// <summary>Shared HF2 theme tokens for UI + unit contract tests (Gate A/H).</summary>
public static class ThemePalette
{
    public const string BgDeep = "#0B0F16";
    public const string BgPanel = "#171D28";
    public const string BgElevated = "#202838";
    public const string TextPrimary = "#F2F4F8";
    public const string TextMuted = "#BBC5D3";
    public const string AccentGold = "#E0B84A";
    public const string PassGreen = "#3DDC97";
    public const string WarnAmber = "#F1C453";
    public const string FailRed = "#FF7474";
    public const string OnAccent = "#0B0F16";

    /// <summary>Relative luminance for WCAG contrast (sRGB).</summary>
    public static double RelativeLuminance(string hex)
    {
        var (r, g, b) = ParseRgb(hex);
        static double Lin(double c)
        {
            c /= 255.0;
            return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * Lin(r) + 0.7152 * Lin(g) + 0.0722 * Lin(b);
    }

    public static double ContrastRatio(string fgHex, string bgHex)
    {
        var l1 = RelativeLuminance(fgHex);
        var l2 = RelativeLuminance(bgHex);
        var lighter = Math.Max(l1, l2);
        var darker = Math.Min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
    }

    public static (byte R, byte G, byte B) ParseRgb(string hex)
    {
        var h = hex.Trim().TrimStart('#');
        if (h.Length == 8) h = h[^6..];
        if (h.Length != 6) throw new ArgumentException("Expected #RRGGBB", nameof(hex));
        return (
            Convert.ToByte(h[..2], 16),
            Convert.ToByte(h[2..4], 16),
            Convert.ToByte(h[4..6], 16));
    }
}

/// <summary>Server/Client + Quick/Deep mode rules (Gate D/E).</summary>
public static class ScanModeRules
{
    public const string EmptyFindingsVi = "Chưa kiểm tra — nhấn KIỂM TRA để bắt đầu.";
    public const string EmptyFindingsEn = "Not scanned yet — press SCAN to begin.";

    public static bool RequiresTargetHost(bool isClientRole) => isClientRole;

    public static string? ResolveScanTarget(bool isServerRole, string? targetHost)
        => isServerRole ? null : (string.IsNullOrWhiteSpace(targetHost) ? null : targetHost.Trim());

    public static string ModeIndicatorVi(bool isServerRole, bool deepScan)
        => isServerRole
            ? (deepScan ? "Chế độ: MÁY CHỦ · Quét SÂU (local)" : "Chế độ: MÁY CHỦ · Quét NHANH (local)")
            : (deepScan ? "Chế độ: MÁY TRẠM · Quét SÂU → IP máy chủ" : "Chế độ: MÁY TRẠM · Quét NHANH → IP máy chủ");

    public static string PhaseLabelVi(ScanUiPhase phase) => phase switch
    {
        ScanUiPhase.Ready => "READY",
        ScanUiPhase.Validating => "VALIDATING",
        ScanUiPhase.Scanning => "SCANNING",
        ScanUiPhase.Completed => "COMPLETED",
        ScanUiPhase.Failed => "FAILED",
        ScanUiPhase.Cancelled => "CANCELLED",
        _ => phase.ToString().ToUpperInvariant()
    };

    /// <summary>Display status must keep UNKNOWN distinct from FAIL (Gate D).</summary>
    public static string NormalizeFindingStatus(string status)
    {
        if (string.IsNullOrWhiteSpace(status)) return "UNKNOWN";
        var s = status.Trim().ToUpperInvariant();
        return s switch
        {
            "FAIL" or "FAILED" or "ERROR" => "FAIL",
            "PASS" or "OK" or "SUCCESS" => "PASS",
            "WARN" or "WARNING" => "WARN",
            "UNKNOWN" or "NOTTESTED" or "NOT_TESTED" or "N/A" or "NOTAPPLICABLE" => "UNKNOWN",
            _ => s
        };
    }
}
