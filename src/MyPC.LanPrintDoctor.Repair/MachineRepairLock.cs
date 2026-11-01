namespace MyPC.LanPrintDoctor.Repair;

/// <summary>
/// Cross-process machine-level lock preventing concurrent repairs.
/// Fail-closed: if lock cannot be acquired, Apply must not proceed.
/// </summary>
public sealed class MachineRepairLock : IDisposable
{
    private readonly string _path;
    private FileStream? _stream;
    public bool Acquired { get; private set; }

    public MachineRepairLock(string? directory = null)
    {
        var dir = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MyPC", "LanPrintDoctor", "locks");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "repair.lock");
    }

    public bool TryAcquire(TimeSpan? wait = null)
    {
        var deadline = DateTime.UtcNow + (wait ?? TimeSpan.Zero);
        while (true)
        {
            try
            {
                _stream = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                using var sw = new StreamWriter(_stream, leaveOpen: true);
                sw.WriteLine(DateTimeOffset.UtcNow.ToString("O"));
                sw.WriteLine(Environment.ProcessId);
                sw.Flush();
                _stream.Flush(true);
                Acquired = true;
                return true;
            }
            catch (IOException)
            {
                if (DateTime.UtcNow >= deadline) return false;
                Thread.Sleep(50);
            }
        }
    }

    public void Dispose()
    {
        try { _stream?.Dispose(); } catch { /* ignore */ }
        _stream = null;
        Acquired = false;
    }
}
