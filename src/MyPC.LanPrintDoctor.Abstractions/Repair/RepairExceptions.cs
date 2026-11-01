namespace MyPC.LanPrintDoctor.Abstractions.Repair;

/// <summary>Rule already matches desired config — Apply is a no-op (not a mutation failure).</summary>
public sealed class RepairNoChangeException : Exception
{
    public RepairNoChangeException(string message) : base(message) { }
}

/// <summary>Cannot proceed without destructive overwrite — fail closed, no mutation.</summary>
public sealed class RepairBlockedException : Exception
{
    public RepairBlockedException(string message) : base(message) { }
}
