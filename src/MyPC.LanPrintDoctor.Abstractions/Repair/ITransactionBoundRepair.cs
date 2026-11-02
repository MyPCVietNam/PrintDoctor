namespace MyPC.LanPrintDoctor.Abstractions.Repair;

/// <summary>
/// Repair operations that must share the executor-generated TransactionId
/// (never mint a separate ID for provenance / journal correlation).
/// </summary>
public interface ITransactionBoundRepair
{
    void BindTransaction(string transactionId);
    string? BoundTransactionId { get; }
}
