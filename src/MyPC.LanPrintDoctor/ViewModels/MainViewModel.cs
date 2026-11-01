using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Validation;
using MyPC.LanPrintDoctor.Core.Compare;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ReportExporter _exporter = new() { ProcessRunner = new ProcessRunner() };
    private readonly ReportCompareService _compare = new();
    private DiagnosticSnapshot? _lastSnapshot;
    private RepairJournal? _lastJournal;
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
        CompareCommand = new RelayCommand(() => CompareReports(), () => !IsBusy);
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
    public ObservableCollection<RepairChoiceRow> AvailableRepairs { get; } = new();
    private RepairChoiceRow? _selectedRepair;
    public RepairChoiceRow? SelectedRepair
    {
        get => _selectedRepair;
        set { _selectedRepair = value; OnPropertyChanged(); }
    }

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
            var (net, fw, svc, smb, prn, sha, _, _) = PlatformComposition.CreateWindowsStack();
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

            // P2 network root-cause cases (A/B/C) — evidence-based, no single-cause default
            foreach (var rc in new NetworkRootCauseEngine().Analyze(snap))
            {
                Findings.Add(new FindingRow
                {
                    Status = rc.Status.ToString().ToUpperInvariant(),
                    Title = $"{rc.CaseId} — {rc.Title}",
                    Evidence = (rc.Evidence ?? "") + " | " + (rc.RecommendedAction ?? "")
                        + $" | evidence={rc.EvidenceLevel}"
                        + (rc.InfrastructureActionRequired ? " | INFRASTRUCTURE_ACTION_REQUIRED" : "")
                        + (rc.InfrastructureInvestigationRecommended ? " | INFRASTRUCTURE_INVESTIGATION_RECOMMENDED" : "")
                });
            }

            AvailableRepairs.Clear();
            SelectedRepair = null;
            foreach (var f in snap.Findings
                         .Where(x => !string.IsNullOrWhiteSpace(x.RepairId)
                                     && x.RepairOwner is not RepairOwnerRole.ServerActionRequired and not RepairOwnerRole.None)
                         .GroupBy(x => x.RepairId!, StringComparer.OrdinalIgnoreCase)
                         .Select(g => g.First()))
            {
                AvailableRepairs.Add(new RepairChoiceRow
                {
                    RepairId = f.RepairId!,
                    Title = f.Title,
                    Evidence = f.Evidence,
                    Owner = f.RepairOwner.ToString()
                });
            }
            if (AvailableRepairs.Count == 1)
                SelectedRepair = AvailableRepairs[0];

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
        var findings = _lastSnapshot.Findings.Select(f =>
            $"{f.Id} [{f.Status}]\n{f.Title}\n{Labels.Evidence}: {f.Evidence}\n{Labels.Causes}: {string.Join("; ", f.PossibleCauses)}\n{Labels.Actions}: {string.Join("; ", f.RecommendedActions)}");
        var root = new NetworkRootCauseEngine().Analyze(_lastSnapshot).Select(rc =>
            $"{rc.CaseId} [{rc.Confidence}/{rc.Status}]\n{rc.Title}\n{Labels.Evidence}: {rc.Evidence}\n{Labels.Actions}: {rc.RecommendedAction}"
            + (rc.InfrastructureActionRequired ? "\nINFRASTRUCTURE_ACTION_REQUIRED" : ""));
        var text = string.Join(Environment.NewLine + Environment.NewLine, findings.Concat(root));
        MessageBox.Show(string.IsNullOrWhiteSpace(text) ? Labels.NoCritical : text, Labels.Causes, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task SafeRepairAsync()
    {
        if (_lastSnapshot is null) return;
        if (AvailableRepairs.Count == 0)
        {
            var serverOnly = _lastSnapshot.Findings.Any(f => f.RepairOwner == RepairOwnerRole.ServerActionRequired);
            StatusText = serverOnly
                ? "SERVER_ACTION_REQUIRED: run PrintDoctor on the server — local client firewall will not be modified for a remote inbound issue."
                : Labels.NoRepair;
            if (serverOnly)
                MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Explicit list selection — never auto-pick first when multiple repairs exist.
        if (SelectedRepair is null || string.IsNullOrWhiteSpace(SelectedRepair.RepairId))
        {
            StatusText = "Chọn một repair trong danh sách trước khi Apply (không tự chọn).";
            MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var pick = _lastSnapshot.Findings.FirstOrDefault(f =>
                       string.Equals(f.RepairId, SelectedRepair.RepairId, StringComparison.OrdinalIgnoreCase)
                       && f.RepairOwner is not RepairOwnerRole.ServerActionRequired and not RepairOwnerRole.None)
                   ?? _lastSnapshot.Findings.FirstOrDefault(f =>
                       string.Equals(f.RepairId, SelectedRepair.RepairId, StringComparison.OrdinalIgnoreCase));
        if (pick is null || pick.RepairOwner == RepairOwnerRole.ServerActionRequired || string.IsNullOrWhiteSpace(pick.RepairId))
        {
            StatusText = "SERVER_ACTION_REQUIRED / invalid selection.";
            MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var (net, fw, svc, smb, prn, sha, elev, profiles) = PlatformComposition.CreateWindowsStack();
        _ = (net, smb, prn, sha);

        int? selectedIf = null;
        string? previewDetail = null;
        if (pick.RepairId == "NET-PROFILE-PRIVATE")
        {
            var candidates = _lastSnapshot.Adapters
                .Where(a => a.IsUp && a.Category == NetworkCategory.Public)
                .OrderBy(a => a.InterfaceMetric ?? int.MaxValue)
                .ThenBy(a => a.InterfaceIndex)
                .ToList();
            if (candidates.Count == 0)
            {
                StatusText = "No Public adapters available for profile repair.";
                return;
            }
            // Explicit selection required — never silently pick first NIC when multiple/VPN present
            var lines = candidates.Select((a, i) =>
                $"{i + 1}) IfIndex={a.InterfaceIndex} Alias={a.Name} IP={string.Join(",", a.IPv4Addresses)} GW={a.DefaultGateway} Cat={a.Category} Metric={a.InterfaceMetric}").ToList();
            var prompt = "Chọn interface (nhập số 1.." + candidates.Count + ") — multi-NIC/VPN bắt buộc chọn đúng:\n\n"
                         + string.Join("\n", lines)
                         + "\n\nCancel = hủy. OK sau khi ghi nhớ số; hộp nhập phía sau.";
            MessageBox.Show(prompt, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            // Use single candidate only when exactly one Public NIC; otherwise require index via InputBox substitute
            if (candidates.Count == 1)
            {
                selectedIf = candidates[0].InterfaceIndex;
                previewDetail = lines[0];
            }
            else
            {
                // WPF has no InputBox — present Yes/No per candidate until one chosen
                selectedIf = null;
                foreach (var (a, idx) in candidates.Select((a, i) => (a, i)))
                {
                    var ans = MessageBox.Show(
                        $"Sửa profile cho interface này?\n\n{lines[idx]}",
                        Labels.SafeRepair,
                        MessageBoxButton.YesNoCancel,
                        MessageBoxImage.Question);
                    if (ans == MessageBoxResult.Cancel) { StatusText = Labels.RepairCancelled; return; }
                    if (ans == MessageBoxResult.Yes)
                    {
                        selectedIf = a.InterfaceIndex;
                        previewDetail = lines[idx];
                        break;
                    }
                }
                if (selectedIf is null)
                {
                    StatusText = "Không chọn interface — repair bị từ chối (InterfaceIndex=?).";
                    return;
                }
            }
        }

        var runner = new ProcessRunner();
        var op = CreateRepair(pick.RepairId!, fw, svc, elev, profiles, runner, selectedIf, previewDetail);

        if (!op.IsImplemented)
        {
            StatusText = $"NOT_IMPLEMENTED: {op.OperationId} — repair disabled (no fake success).";
            MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (op.OwnerRole == RepairOwnerRole.LocalServer && _lastSnapshot.Role != MachineRole.Server)
        {
            StatusText = "SERVER_ACTION_REQUIRED: this repair owns server-local firewall state.";
            MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var preview = await op.PreviewChangesAsync();
        var confirm = MessageBox.Show(
            string.Format(Labels.ConfirmRepair, pick.RepairId, pick.Title) + "\n\n" + preview.Description + "\n" + string.Join("\n", preview.Changes)
            + (preview.Reversible ? "" : "\n\n⚠ " + Labels.Irreversible),
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
            if (!elev.IsAdministrator())
            {
                StatusText = Labels.NeedAdmin;
                return;
            }

            var journalsRoot = Path.Combine(_exporter.DefaultRoot, "Journals");
            var crossSession = RepairJournal.ScanAllSessions(journalsRoot);
            if (crossSession is RepairRecoveryState.UncertainState
                or RepairRecoveryState.Incomplete
                or RepairRecoveryState.CorruptJournal)
            {
                var details = RepairJournal.ListUncertain(journalsRoot);
                StatusText = crossSession == RepairRecoveryState.CorruptJournal
                    ? "CORRUPT_JOURNAL: unreadable repair journal — further repairs blocked."
                    : "UNCERTAIN_STATE: unfinished repair transaction(s) across sessions — review journal; no auto-rollback; further repairs blocked.";
                MessageBox.Show(
                    StatusText + "\n\n" + string.Join("\n", details.Take(8).Select(d => $"{d.SessionPath}: {d.OperationId}/{d.TransactionId} {d.Detail}")),
                    Labels.SafeRepair,
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var journalDir = Path.Combine(journalsRoot, _lastSnapshot.SessionId);
            _lastJournal = new RepairJournal(journalDir);
            if (_lastJournal.GetRecoveryState() is RepairRecoveryState.UncertainState
                or RepairRecoveryState.Incomplete
                or RepairRecoveryState.CorruptJournal)
            {
                StatusText = _lastJournal.IsCorrupt
                    ? "CORRUPT_JOURNAL: prior journal unreadable — review before another repair."
                    : "UNCERTAIN_STATE: prior repair Applied/ApplyStarted without successful Verify — review journal before another repair.";
                MessageBox.Show(StatusText, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var executor = new RepairExecutor(_lastJournal);
            var before = await op.PreviewChangesAsync();
            var result = await executor.ExecuteAsync(op, userConfirmed: true, ct: default, localRole: _lastSnapshot.Role, findingOwner: pick.RepairOwner);

            _lastSnapshot.RepairsJson = _lastJournal.ToJson();
            _lastSnapshot.BeforeAfterJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                before = before,
                result,
                rolledBackClaimedOnlyIfVerified = result.RolledBack
            });

            if (result.NotImplemented)
                StatusText = result.Message ?? "NOT_IMPLEMENTED";
            else if (result.Verified && result.Status == DiagnosticStatus.Pass)
            {
                StatusText = result.Message ?? Labels.ScanDone;
                await ScanAsync();
            }
            else if (result.Status == DiagnosticStatus.Pass && !result.Verified)
                StatusText = Labels.UnverifiedSuccess;
            else
                StatusText = result.Message ?? Labels.RepairFailed;
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

    private static IRepairOperation CreateRepair(
        string repairId,
        Abstractions.Firewall.IFirewallInspector fw,
        Abstractions.Services.IWindowsServiceInspector svc,
        Abstractions.Security.IElevationService elev,
        Abstractions.Firewall.INetworkProfileService profiles,
        Abstractions.Platform.IProcessRunner runner,
        int? preferredInterfaceIndex = null,
        string? previewDetail = null)
        => repairId switch
        {
            "FW-ICMP-ECHO" => new FirewallIcmpEchoRepair(fw, elev),
            "FW-FILE-PRINT-SHARE" => new FilePrintShareRepair(fw, elev),
            "FW-OWNED-ICMP4" => new OwnedFirewallRuleRepair(runner, elev, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet()),
            "FW-OWNED-SMB445" => new OwnedFirewallRuleRepair(runner, elev, OwnedFirewallSpec.Smb445PrivateLocalSubnet()),
            "FW-OWNED-SHA48631" => new OwnedFirewallRuleRepair(runner, elev, OwnedFirewallSpec.ShaPrint48631()),
            "FW-OWNED-SHA48633" => new OwnedFirewallRuleRepair(runner, elev, OwnedFirewallSpec.ShaPrint48633Udp()),
            "NET-PROFILE-PRIVATE" => new NetworkProfilePrivateRepair(profiles, elev, preferredInterfaceIndex, previewDetail),
            "SVC-SPOOLER-START" => new ServiceStartRepair("Spooler", "SVC-SPOOLER-START", "Start Print Spooler", svc, elev),
            "SVC-LANMANSERVER-START" => new ServiceStartRepair("LanmanServer", "SVC-LANMANSERVER-START", "Start LanmanServer", svc, elev),
            "SVC-LANMANWORKSTATION-START" => new ServiceStartRepair("LanmanWorkstation", "SVC-LANMANWORKSTATION-START", "Start LanmanWorkstation", svc, elev),
            "SHA-START-PROCESS" => new NotImplementedRepair("SHA-START-PROCESS", "ShaPrint process start — verify executable path before enabling (NOT_IMPLEMENTED)"),
            _ => new NotImplementedRepair(repairId, "Unknown repair")
        };

    private void CompareReports()
    {
        var serverDlg = new OpenFileDialog
        {
            Title = Labels.CompareServerFile,
            Filter = "Report (*.zip;*.json)|*.zip;*.json|All|*.*"
        };
        if (serverDlg.ShowDialog() != true) return;

        var clientDlg = new OpenFileDialog
        {
            Title = Labels.CompareClientFiles,
            Filter = "Report (*.zip;*.json)|*.zip;*.json|All|*.*",
            Multiselect = true
        };
        if (clientDlg.ShowDialog() != true || clientDlg.FileNames.Length == 0) return;

        try
        {
            var result = _compare.CompareFiles(serverDlg.FileName, clientDlg.FileNames);
            Findings.Clear();
            foreach (var f in result.Findings)
            {
                Findings.Add(new FindingRow
                {
                    Status = f.Status.ToString().ToUpperInvariant(),
                    Title = $"{f.Id} — {f.Title}",
                    Evidence = f.Evidence
                });
            }

            var sb = new StringBuilder();
            sb.AppendLine($"HasValidEvidence={result.HasValidEvidence}");
            if (result.ServerSideIssues.Count > 0) sb.AppendLine("SERVER: " + string.Join("; ", result.ServerSideIssues));
            if (result.ClientSpecificIssues.Count > 0) sb.AppendLine("CLIENT: " + string.Join("; ", result.ClientSpecificIssues));
            if (result.InfrastructureHints.Count > 0) sb.AppendLine("INFRA: " + string.Join("; ", result.InfrastructureHints));
            if (result.InsufficientEvidence.Count > 0) sb.AppendLine("INSUFFICIENT: " + string.Join("; ", result.InsufficientEvidence));
            if (Findings.Count == 0 && !result.HasValidEvidence)
                Findings.Add(new FindingRow { Status = "UNKNOWN", Title = "Insufficient evidence", Evidence = sb.ToString() });
            StatusText = sb.ToString();
            MessageBox.Show(sb.ToString(), Labels.Compare, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusText = Labels.CompareFailed + ": " + ex.Message;
            MessageBox.Show(StatusText, Labels.Compare, MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task ExportAsync()
    {
        if (_lastSnapshot is null) return;
        try
        {
            var redact = MessageBox.Show(Labels.RedactPrompt, Labels.Export, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
            if (_lastJournal is not null)
                _lastSnapshot.RepairsJson = _lastJournal.ToJson();
            var path = await _exporter.ExportZipAsync(_lastSnapshot, redact);
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

public sealed class RepairChoiceRow
{
    public string RepairId { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Owner { get; init; } = "";
    public override string ToString() => $"{RepairId} — {Title}";
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
    public string CompareServerFile { get; init; } = "";
    public string CompareClientFiles { get; init; } = "";
    public string CompareFailed { get; init; } = "";
    public string Irreversible { get; init; } = "";
    public string RedactPrompt { get; init; } = "";

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
        CompareHint = "Chọn báo cáo server và client (ZIP/JSON) để so sánh thật.",
        CompareServerFile = "Chọn báo cáo MÁY CHỦ",
        CompareClientFiles = "Chọn báo cáo MÁY TRẠM (tối đa nhiều file)",
        CompareFailed = "So sánh thất bại",
        Irreversible = "Thao tác này không thể rollback tự động.",
        RedactPrompt = "Ẩn IP/MAC/tên máy trong báo cáo?"
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
        CompareHint = "Pick server and client report ZIP/JSON files for a real comparison.",
        CompareServerFile = "Select SERVER report",
        CompareClientFiles = "Select CLIENT reports (multi-select)",
        CompareFailed = "Compare failed",
        Irreversible = "This operation cannot be automatically rolled back.",
        RedactPrompt = "Redact IP/MAC/machine name in the report?"
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
