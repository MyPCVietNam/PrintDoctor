namespace MyPC.LanPrintDoctor.Repair;

/// <summary>
/// Machine-wide exclusive lock. Production (directory=null) requires the Global named
/// mutex on Windows and a ProgramData file lock — fail closed if either cannot be owned.
/// Test overrides pass an isolated directory (file lock only, no Global mutex).
/// </summary>
public sealed class MachineRepairLock : IDisposable
{
    public const string MutexName = @"Global\MyPC.LanPrintDoctor.MachineRepair";

    public static string MachineWideDirectory { get; } = ResolveMachineWideDirectory();

    private readonly string _path;
    private readonly bool _productionMachineWide;
    private FileStream? _stream;
    private Mutex? _mutex;
    private bool _mutexOwned;

    public bool Acquired { get; private set; }
    public string LockPath => _path;
    public bool UsedNamedMutex => _productionMachineWide && _mutexOwned;

    /// <param name="directory">
    /// Null = production machine-wide path + Global mutex (fail closed).
    /// Non-null = isolated test lock (file only).
    /// </param>
    public MachineRepairLock(string? directory = null)
    {
        _productionMachineWide = string.IsNullOrWhiteSpace(directory);
        var dir = _productionMachineWide ? MachineWideDirectory : directory!;
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "repair.lock");
    }

    private static string ResolveMachineWideDirectory()
    {
        // Prefer ProgramData. Do not silently substitute a per-user path for production
        // identity — if ProgramData is unusable, TryAcquire will fail closed on Windows
        // when the mutex/file cannot be taken. LocalAppData is only used when ProgramData
        // is missing entirely (non-Windows CI scaffolding).
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(programData))
        {
            var dir = Path.Combine(programData, "MyPC", "LanPrintDoctor", "locks");
            try
            {
                Directory.CreateDirectory(dir);
                return dir;
            }
            catch
            {
                /* TryAcquire will fail closed if unwritable */
                return dir;
            }
        }

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
        if (_productionMachineWide && OperatingSystem.IsWindows())
        {
            // HF1 GATE E: Global mutex is mandatory on Windows production — fail closed.
            try
            {
                _mutex = new Mutex(initiallyOwned: false, name: MutexName, createdNew: out _);
                try
                {
                    _mutexOwned = _mutex.WaitOne(0);
                }
                catch (AbandonedMutexException)
                {
                    _mutexOwned = true; // prior crash — recover ownership
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
                ReleaseMutexOnly();
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                ReleaseMutexOnly();
                return false;
            }
            catch (IOException)
            {
                ReleaseMutexOnly();
                return false;
            }
        }

        try
        {
            _stream = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            using var sw = new StreamWriter(_stream, leaveOpen: true);
            sw.WriteLine(DateTimeOffset.UtcNow.ToString("O"));
            sw.WriteLine(Environment.ProcessId);
            sw.WriteLine(_productionMachineWide ? MutexName : "test-file-lock");
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
