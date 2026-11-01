namespace MyPC.LanPrintDoctor.Repair;

/// <summary>
/// Machine-wide exclusive lock preventing concurrent PrintDoctor repairs across
/// processes and diagnostic sessions. Identity is independent of SessionId.
/// Prefer named mutex on Windows; always also hold an ACL-friendly file lock
/// under ProgramData (or an explicit test directory).
/// Fail-closed: if lock cannot be acquired, Apply must not proceed.
/// </summary>
public sealed class MachineRepairLock : IDisposable
{
    public const string MutexName = @"Global\MyPC.LanPrintDoctor.MachineRepair";

    /// <summary>
    /// Prefer ProgramData (machine-wide). Fall back to LocalAppData when ProgramData
    /// is not writable (Linux CI / non-elevated). Named mutex remains the primary
    /// cross-process exclusion on Windows.
    /// </summary>
    public static string MachineWideDirectory { get; } = ResolveMachineWideDirectory();

    private readonly string _path;
    private readonly bool _useNamedMutex;
    private FileStream? _stream;
    private Mutex? _mutex;
    private bool _mutexOwned;

    public bool Acquired { get; private set; }
    public string LockPath => _path;

    /// <param name="directory">
    /// Optional override for unit tests. Production callers must pass null so the
    /// machine-wide path is used (never a per-session journal folder).
    /// Named mutex is used only for the machine-wide path so parallel unit tests
    /// with isolated lock directories do not contend on Global\…
    /// </param>
    public MachineRepairLock(string? directory = null)
    {
        _useNamedMutex = string.IsNullOrWhiteSpace(directory);
        var dir = _useNamedMutex ? MachineWideDirectory : directory!;
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "repair.lock");
    }

    private static string ResolveMachineWideDirectory()
    {
        foreach (var root in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     Path.GetTempPath()
                 })
        {
            if (string.IsNullOrWhiteSpace(root)) continue;
            try
            {
                var dir = Path.Combine(root, "MyPC", "LanPrintDoctor", "locks");
                Directory.CreateDirectory(dir);
                var probe = Path.Combine(dir, ".write-probe");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return dir;
            }
            catch
            {
                /* try next root */
            }
        }

        // Last resort — still prefer a stable name under temp.
        var fallback = Path.Combine(Path.GetTempPath(), "MyPC.LanPrintDoctor.locks");
        Directory.CreateDirectory(fallback);
        return fallback;
    }

    public bool TryAcquire(TimeSpan? wait = null)
    {
        var deadline = DateTime.UtcNow + (wait ?? TimeSpan.Zero);
        while (true)
        {
            if (TryAcquireOnce())
            {
                Acquired = true;
                return true;
            }

            if (DateTime.UtcNow >= deadline)
                return false;
            Thread.Sleep(50);
        }
    }

    private bool TryAcquireOnce()
    {
        // Named mutex only for production machine-wide locks (Windows Global\).
        if (_useNamedMutex)
        {
            try
            {
                _mutex = new Mutex(initiallyOwned: false, name: MutexName, createdNew: out _);
                try
                {
                    _mutexOwned = _mutex.WaitOne(0);
                }
                catch (AbandonedMutexException)
                {
                    // Prior process crashed while holding the mutex — we now own it.
                    _mutexOwned = true;
                }

                if (!_mutexOwned)
                {
                    _mutex.Dispose();
                    _mutex = null;
                    return false;
                }
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                _mutex = null;
                _mutexOwned = false;
            }
            catch (UnauthorizedAccessException)
            {
                _mutex = null;
                _mutexOwned = false;
            }
            catch (IOException)
            {
                _mutex = null;
                _mutexOwned = false;
            }
        }

        try
        {
            _stream = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            using var sw = new StreamWriter(_stream, leaveOpen: true);
            sw.WriteLine(DateTimeOffset.UtcNow.ToString("O"));
            sw.WriteLine(Environment.ProcessId);
            sw.WriteLine(_useNamedMutex ? MutexName : "file-only");
            sw.Flush();
            _stream.Flush(true);
            return true;
        }
        catch (IOException)
        {
            ReleaseMutexOnly();
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            ReleaseMutexOnly();
            return false;
        }
    }

    private void ReleaseMutexOnly()
    {
        if (_mutex is not null)
        {
            try
            {
                if (_mutexOwned) _mutex.ReleaseMutex();
            }
            catch
            {
                /* ignore */
            }

            try { _mutex.Dispose(); } catch { /* ignore */ }
            _mutex = null;
            _mutexOwned = false;
        }
    }

    public void Dispose()
    {
        try { _stream?.Dispose(); } catch { /* ignore */ }
        _stream = null;
        ReleaseMutexOnly();
        Acquired = false;
    }
}
