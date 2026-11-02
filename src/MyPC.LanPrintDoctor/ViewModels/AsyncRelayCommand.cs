using System.Windows.Input;

namespace MyPC.LanPrintDoctor.ViewModels;

/// <summary>
/// Lightweight async ICommand (Gate C). Avoids CommunityToolkit dependency;
/// raises CanExecuteChanged explicitly when IsBusy flips.
/// </summary>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _can;
    private int _running;

    public AsyncRelayCommand(Func<Task> execute, Func<bool>? can = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _can = can;
    }

    public event EventHandler? CanExecuteChanged;

    public void RaiseCanExecuteChanged()
        => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    public bool CanExecute(object? parameter)
        => Interlocked.CompareExchange(ref _running, 0, 0) == 0 && (_can?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        if (Interlocked.Exchange(ref _running, 1) != 0) return;
        RaiseCanExecuteChanged();
        try
        {
            await _execute();
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
            RaiseCanExecuteChanged();
        }
    }
}

public sealed class RelayCommand : ICommand
{
    private readonly Func<Task>? _async;
    private readonly Action? _sync;
    private readonly Func<bool>? _can;

    public RelayCommand(Func<Task> asyncExecute, Func<bool>? can = null)
    {
        _async = asyncExecute;
        _can = can;
    }

    public RelayCommand(Action execute, Func<bool>? can = null)
    {
        _sync = execute;
        _can = can;
    }

    public event EventHandler? CanExecuteChanged;

    public void RaiseCanExecuteChanged()
        => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    public bool CanExecute(object? parameter) => _can?.Invoke() ?? true;

    public async void Execute(object? parameter)
    {
        if (_sync is not null) { _sync(); return; }
        if (_async is not null) await _async();
    }
}
