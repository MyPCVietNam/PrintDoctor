namespace MyPC.LanPrintDoctor.Abstractions.Diagnostics;

/// <summary>
/// Collector outcome that distinguishes Pass/Fail from NotTested/Unknown.
/// Never treat NotTested or Unknown as Pass or Fail.
/// </summary>
public enum ProbeOutcome
{
    Pass,
    Fail,
    NotTested,
    Unknown,
    AuthDenied,
    AccessDenied,
    NotApplicable
}
