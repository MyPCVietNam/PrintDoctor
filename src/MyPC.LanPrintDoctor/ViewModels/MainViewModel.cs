using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Validation;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ReportExporter _exporter = new();
    private DiagnosticSnapshot? _lastSnapshot;
    private string _targetHost = "";
    private string _statusText = "";
    private string _sessionText = "";
    private string _detailHint = "";
    private bool _isServerRole = true;
    private int _languageIndex;
    private UiLabels _labels = UiLabels.Vietnamese;

    public MainViewModel()
    {
        ScanCommand = new RelayCommand(async () => await ScanAsync(), () => !IsBusy);
        ShowCausesCommand = new RelayCommand(() => ShowCauses(), () => _lastSnapshot is not null);
        SafeRepairCommand = new RelayCommand(async () => await SafeRepairAsync(), () => _lastSnapshot is not null && !IsBusy);
        ExportCommand = new RelayCommand(async () => await ExportAsync(), () => _lastSnapshot is not null && !IsBusy);
        CompareCommand = new RelayCommand(() =>
        {
            StatusText = Labels.CompareHint;
            OnPropertyChanged(nameof(StatusText));
        });
        StatusText = Labels.Ready;
        DetailHint = Labels.DetailHint;
        Subtitle = Labels.Subtitle;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Subtitle { get; private set; } = "";
    public UiLabels Labels
    {
        get => _labels;
        private set { _labels = value; OnPropertyChanged(); }
    }

    public int LanguageIndex
    {
        get => _languageIndex;
        set
        {
            if (_languageIndex == value) return;
            _languageIndex = value;
            Labels = value == 0 ? UiLabels.Vietnamese : UiLabels.English;
            Subtitle = Labels.Subtitle;
            StatusText = Labels.Ready;
            DetailHint = Labels.DetailHint;
            OnPropertyChanged();
            OnPropertyChanged(nameof(Subtitle));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(DetailHint));
            OnPropertyChanged(nameof(Labels));
        }
    }

    public bool IsServerRole
    {
        get => _isServerRole;
        set { _isServerRole = value; if (value) IsClientRole = false; OnPropertyChanged(); }
    }

    public bool IsClientRole
    {
        get => !_isServerRole;
        set { if (value) { _isServerRole = false; OnPropertyChanged(nameof(IsServerRole)); } OnPropertyChanged(); }
    }

    public string TargetHost
    {
        get => _targetHost;
        set { _targetHost = value; OnPropertyChanged(); }
    }

    public string StatusText
    {
        get => _statusText;
        set { _statusText = value; OnPropertyChanged(); }
    }

    public string SessionText
    {
        get => _sessionText;
        set { _sessionText = value; OnPropertyChanged(); }
    }

    public string DetailHint
    {
        get => _detailHint;
        set { _detailHint = value; OnPropertyChanged(); }
    }

    public bool IsBusy { get; private set; }

    public ObservableCollection<FindingRow> Findings { get; } = new();

    public ICommand ScanCommand { get; }
    public ICommand ShowCausesCommand { get; }
    public ICommand SafeRepairCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand CompareCommand { get; }

    private async Task ScanAsync()
    {
        if (IsClientRole)
        {
            if (!InputValidator.TryParseHost(TargetHost, out var host))
            {
                StatusText = Labels.InvalidHost;
                return;
            }
            TargetHost = host;
        }

        IsBusy = true;
        StatusText = Labels.Scanning;
        Findings.Clear();
        try
        {
            var (net, fw, svc, smb, prn, sha, _) = PlatformComposition.CreateWindowsStack();
            var orch = new DiagnosticOrchestrator(net, fw, svc, smb, prn, sha);
            var snap = await orch.RunAsync(new DiagnosticRequest
            {
                Role = IsServerRole ? MachineRole.Server : MachineRole.Client,
                TargetHost = string.IsNullOrWhiteSpace(TargetHost) ? null : TargetHost,
                DeepScan = true
            });
            _lastSnapshot = snap;
            SessionText = $"Session: {snap.SessionId}";
            foreach (var f in snap.Findings.OrderByDescending(x => x.Severity))
            {
                Findings.Add(new FindingRow
                {
                    Status = f.Status.ToString().ToUpperInvariant(),
                    Title = $"{f.Id} — {f.Title}",
                    Evidence = f.Evidence
                });
            }

            if (Findings.Count == 0)
            {
                Findings.Add(new FindingRow
                {
                    Status = "PASS",
                    Title = Labels.NoCritical,
                    Evidence = Labels.NoCriticalEvidence
                });
            }

            StatusText = string.Format(Labels.ScanDone, snap.Findings.Count);
        }
        catch (Exception ex)
        {
            StatusText = Labels.ScanFailed + ": " + ex.Message;
        }
        finally
        {
            IsBusy = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private void ShowCauses()
    {
        if (_lastSnapshot is null) return;
        var text = string.Join(Environment.NewLine + Environment.NewLine,
            _lastSnapshot.Findings.Select(f =>
                $"{f.Id} [{f.Status}]\n{f.Title}\n{Labels.Evidence}: {f.Evidence}\n{Labels.Causes}: {string.Join("; ", f.PossibleCauses)}\n{Labels.Actions}: {string.Join("; ", f.RecommendedActions)}"));
        MessageBox.Show(string.IsNullOrWhiteSpace(text) ? Labels.NoCritical : text, Labels.Causes, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task SafeRepairAsync()
    {
        if (_lastSnapshot is null) return;
        var repairable = _lastSnapshot.Findings.Where(f => !string.IsNullOrWhiteSpace(f.RepairId)).ToList();
        if (repairable.Count == 0)
        {
            StatusText = Labels.NoRepair;
            return;
        }

        var pick = repairable[0];
        var confirm = MessageBox.Show(
            string.Format(Labels.ConfirmRepair, pick.RepairId, pick.Title),
            Labels.SafeRepair,
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            StatusText = Labels.RepairCancelled;
            return;
        }

        IsBusy = true;
        try
        {
            var (net, fw, svc, smb, prn, sha, elev) = PlatformComposition.CreateWindowsStack();
            _ = (net, smb, prn, sha);
            var journalDir = Path.Combine(_exporter.DefaultRoot, "Journals", _lastSnapshot.SessionId);
            var executor = new RepairExecutor(new RepairJournal(journalDir));
            Abstractions.Repair.IRepairOperation op = pick.RepairId switch
            {
                "FW-ICMP-ECHO" => new FirewallIcmpEchoRepair(fw, elev),
                "NET-PROFILE-PRIVATE" => new NetworkProfilePrivateRepair(elev),
                "SVC-SPOOLER-START" => new ServiceStartRepair("Spooler", "SVC-SPOOLER-START", "Start Print Spooler", svc, elev),
                "SVC-LANMANSERVER-START" => new ServiceStartRepair("LanmanServer", "SVC-LANMANSERVER-START", "Start LanmanServer", svc, elev),
                "SVC-LANMANWORKSTATION-START" => new ServiceStartRepair("LanmanWorkstation", "SVC-LANMANWORKSTATION-START", "Start LanmanWorkstation", svc, elev),
                "FW-FILE-PRINT-SHARE" => new FirewallIcmpEchoRepair(fw, elev),
                _ => throw new InvalidOperationException("Repair not available for " + pick.RepairId)
            };

            // Preview-only apply path for FW ops until Windows script hooks attached; service start is live.
            if (op is FirewallIcmpEchoRepair or NetworkProfilePrivateRepair)
            {
                var preview = await op.PreviewChangesAsync();
                MessageBox.Show(preview.Description + "\n\n" + string.Join("\n", preview.Changes), Labels.SafeRepair);
                if (!elev.IsAdministrator())
                {
                    StatusText = Labels.NeedAdmin;
                    return;
                }
            }

            var result = await executor.ExecuteAsync(op, userConfirmed: true);
            StatusText = result.Message ?? result.Status.ToString();
            if (result.Verified)
                await ScanAsync();
            else if (result.Status == DiagnosticStatus.Pass)
                StatusText = Labels.UnverifiedSuccess;
        }
        catch (Exception ex)
        {
            StatusText = Labels.RepairFailed + ": " + ex.Message;
        }
        finally
        {
            IsBusy = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private async Task ExportAsync()
    {
        if (_lastSnapshot is null) return;
        try
        {
            var path = await _exporter.ExportZipAsync(_lastSnapshot, redact: false);
            StatusText = Labels.Exported + ": " + path;
        }
        catch (Exception ex)
        {
            StatusText = Labels.ExportFailed + ": " + ex.Message;
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class FindingRow
{
    public string Status { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
}

public sealed class UiLabels
{
    public string Subtitle { get; init; } = "";
    public string Role { get; init; } = "";
    public string Server { get; init; } = "";
    public string Client { get; init; } = "";
    public string TargetIp { get; init; } = "";
    public string Scan { get; init; } = "";
    public string Causes { get; init; } = "";
    public string SafeRepair { get; init; } = "";
    public string Export { get; init; } = "";
    public string Compare { get; init; } = "";
    public string Findings { get; init; } = "";
    public string Ready { get; init; } = "";
    public string Scanning { get; init; } = "";
    public string ScanDone { get; init; } = "";
    public string ScanFailed { get; init; } = "";
    public string InvalidHost { get; init; } = "";
    public string NoCritical { get; init; } = "";
    public string NoCriticalEvidence { get; init; } = "";
    public string DetailHint { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Actions { get; init; } = "";
    public string NoRepair { get; init; } = "";
    public string ConfirmRepair { get; init; } = "";
    public string RepairCancelled { get; init; } = "";
    public string NeedAdmin { get; init; } = "";
    public string UnverifiedSuccess { get; init; } = "";
    public string RepairFailed { get; init; } = "";
    public string Exported { get; init; } = "";
    public string ExportFailed { get; init; } = "";
    public string CompareHint { get; init; } = "";

    public static UiLabels Vietnamese { get; } = new()
    {
        Subtitle = "Chẩn đoán LAN & chia sẻ máy in — mặc định chỉ đọc, sửa có kiểm soát.",
        Role = "Vai trò máy",
        Server = "Máy chủ",
        Client = "Máy trạm",
        TargetIp = "IP đối tượng (máy chủ)",
        Scan = "KIỂM TRA",
        Causes = "XEM NGUYÊN NHÂN",
        SafeRepair = "SỬA AN TOÀN",
        Export = "XUẤT BÁO CÁO",
        Compare = "SO SÁNH BÁO CÁO",
        Findings = "Kết quả",
        Ready = "Sẵn sàng. Chưa thay đổi hệ thống.",
        Scanning = "Đang chẩn đoán (read-only)...",
        ScanDone = "Hoàn tất. {0} phát hiện.",
        ScanFailed = "Quét thất bại",
        InvalidHost = "IP/hostname không hợp lệ.",
        NoCritical = "Không có phát hiện nghiêm trọng từ rule engine",
        NoCriticalEvidence = "Vẫn xuất báo cáo để đối chiếu server/client.",
        DetailHint = "Chi tiết kỹ thuật đầy đủ nằm trong báo cáo ZIP (Details).",
        Evidence = "Bằng chứng",
        Actions = "Đề xuất",
        NoRepair = "Không có repair hợp lệ cho các phát hiện hiện tại.",
        ConfirmRepair = "Xác nhận sửa '{0}' — {1}?\nBackup trước, verify sau, rollback nếu thất bại.",
        RepairCancelled = "Đã hủy sửa chữa.",
        NeedAdmin = "Cần quyền Administrator (UAC) để sửa.",
        UnverifiedSuccess = "Không tuyên bố SUCCESS khi chưa verify.",
        RepairFailed = "Sửa thất bại",
        Exported = "Đã xuất",
        ExportFailed = "Xuất báo cáo thất bại",
        CompareHint = "Nhập báo cáo server + client (Export ZIP/JSON) để so sánh trong phiên bản chi tiết. Engine CompareEngine đã sẵn trong Core."
    };

    public static UiLabels English { get; } = new()
    {
        Subtitle = "LAN & printer-share diagnostics — read-only by default, controlled repair.",
        Role = "Machine role",
        Server = "Server",
        Client = "Client",
        TargetIp = "Target host/IP (server)",
        Scan = "SCAN",
        Causes = "VIEW CAUSES",
        SafeRepair = "SAFE REPAIR",
        Export = "EXPORT REPORT",
        Compare = "COMPARE REPORTS",
        Findings = "Findings",
        Ready = "Ready. No system changes yet.",
        Scanning = "Running diagnostics (read-only)...",
        ScanDone = "Done. {0} finding(s).",
        ScanFailed = "Scan failed",
        InvalidHost = "Invalid IP/hostname.",
        NoCritical = "No critical rule-engine findings",
        NoCriticalEvidence = "Still export a report for server/client correlation.",
        DetailHint = "Full technical details are in the evidence ZIP.",
        Evidence = "Evidence",
        Actions = "Actions",
        NoRepair = "No eligible repair for current findings.",
        ConfirmRepair = "Confirm repair '{0}' — {1}?\nBackup first, verify after, rollback on failure.",
        RepairCancelled = "Repair cancelled.",
        NeedAdmin = "Administrator (UAC) required for repair.",
        UnverifiedSuccess = "Never claim SUCCESS without verification.",
        RepairFailed = "Repair failed",
        Exported = "Exported",
        ExportFailed = "Export failed",
        CompareHint = "Import server + client reports to compare. CompareEngine is available in Core."
    };
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

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _can?.Invoke() ?? true;

    public async void Execute(object? parameter)
    {
        if (_sync is not null) { _sync(); return; }
        if (_async is not null) await _async();
    }
}
