using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Validation;
using MyPC.LanPrintDoctor.Core.Compare;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Core.Ui;
using MyPC.LanPrintDoctor.Platform.Logging;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ReportExporter _exporter = new() { ProcessRunner = new ProcessRunner() };
    private readonly ReportCompareService _compare = new();
    private readonly AppLogWriter _log;
    private readonly DispatcherTimer _elapsedTimer;
    private readonly Stopwatch _scanWatch = new();
    private CancellationTokenSource? _scanCts;
    private DiagnosticSnapshot? _lastSnapshot;
    private RepairJournal? _lastJournal;
    private Exception? _lastError;
    private string _lastErrorContext = "";
    private string _targetHost = "";
    private string _statusText = "";
    private string _stageText = "";
    private string _sessionText = "";
    private string _detailHint = "";
    private string _elapsedText = "";
    private string _logPathText = "";
    private bool _isServerRole = true;
    private bool _isDeepScan;
    private bool _isBusy;
    private int _languageIndex;
    private ScanUiPhase _phase = ScanUiPhase.Ready;
    private UiLabels _labels = UiLabels.Vietnamese;
    private RepairChoiceRow? _selectedRepair;

    public MainViewModel()
    {
        _log = new AppLogWriter(processRunner: new ProcessRunner());
        LogPathText = "Logs: " + _log.LogDirectory;

        ScanCommand = new AsyncRelayCommand(ScanAsync, () => !IsBusy);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsBusy && _scanCts is not null);
        ShowCausesCommand = new RelayCommand(ShowCauses, () => _lastSnapshot is not null);
        SafeRepairCommand = new AsyncRelayCommand(SafeRepairAsync, () => _lastSnapshot is not null && !IsBusy);
        ExportCommand = new AsyncRelayCommand(ExportAsync, () => _lastSnapshot is not null && !IsBusy);
        CompareCommand = new RelayCommand(CompareReports, () => !IsBusy);
        CopyErrorCommand = new RelayCommand(CopyErrorDetails, () => _lastError is not null || Phase == ScanUiPhase.Failed);

        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _elapsedTimer.Tick += (_, _) => RefreshElapsed();

        VersionText = "v" + (Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "1.2.2-HF2");

        StatusText = Labels.Ready;
        StageText = "";
        DetailHint = Labels.DetailHint;
        Subtitle = Labels.Subtitle;
        ModeIndicator = ScanModeRules.ModeIndicatorVi(true, false);
        Phase = ScanUiPhase.Ready;
        ShowEmptyFindings();
        _log.WriteInfo("UI started " + VersionText);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string VersionText { get; }
    public string Subtitle { get; private set; } = "";
    public string ModeIndicator { get; private set; } = "";

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
            if (Phase is ScanUiPhase.Ready)
                StatusText = Labels.Ready;
            DetailHint = Labels.DetailHint;
            RefreshModeIndicator();
            if (Findings.Count == 1 && Findings[0].Status == "—")
                ShowEmptyFindings();
            OnPropertyChanged();
            OnPropertyChanged(nameof(Subtitle));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(DetailHint));
            OnPropertyChanged(nameof(Labels));
            RaiseCommands();
        }
    }

    public bool IsServerRole
    {
        get => _isServerRole;
        set
        {
            if (_isServerRole == value) return;
            _isServerRole = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsClientRole));
            OnPropertyChanged(nameof(TargetHostVisibility));
            OnPropertyChanged(nameof(ServerLocalHintVisibility));
            RefreshModeIndicator();
        }
    }

    public bool IsClientRole
    {
        get => !_isServerRole;
        set
        {
            if (value == !_isServerRole) return;
            _isServerRole = !value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsServerRole));
            OnPropertyChanged(nameof(TargetHostVisibility));
            OnPropertyChanged(nameof(ServerLocalHintVisibility));
            RefreshModeIndicator();
        }
    }

    public bool IsQuickScan
    {
        get => !_isDeepScan;
        set
        {
            if (value == !_isDeepScan) return;
            _isDeepScan = !value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsDeepScan));
            RefreshModeIndicator();
        }
    }

    public bool IsDeepScan
    {
        get => _isDeepScan;
        set
        {
            if (_isDeepScan == value) return;
            _isDeepScan = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsQuickScan));
            RefreshModeIndicator();
        }
    }

    public Visibility TargetHostVisibility
        => IsClientRole ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ServerLocalHintVisibility
        => IsServerRole ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ProgressVisibility
        => IsBusy ? Visibility.Visible : Visibility.Collapsed;

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

    public string StageText
    {
        get => _stageText;
        set { _stageText = value; OnPropertyChanged(); }
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

    public string ElapsedText
    {
        get => _elapsedText;
        set { _elapsedText = value; OnPropertyChanged(); }
    }

    public string LogPathText
    {
        get => _logPathText;
        set { _logPathText = value; OnPropertyChanged(); }
    }

    public ScanUiPhase Phase
    {
        get => _phase;
        private set
        {
            _phase = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PhaseCode));
            OnPropertyChanged(nameof(PhaseBrush));
            OnPropertyChanged(nameof(StatusBrush));
            RaiseCommands();
        }
    }

    public string PhaseCode => ScanModeRules.PhaseLabelVi(Phase);

    public Brush PhaseBrush => Phase switch
    {
        ScanUiPhase.Ready => BrushFrom(ThemePalette.TextMuted),
        ScanUiPhase.Validating or ScanUiPhase.Scanning => BrushFrom(ThemePalette.WarnAmber),
        ScanUiPhase.Completed => BrushFrom(ThemePalette.PassGreen),
        ScanUiPhase.Failed => BrushFrom(ThemePalette.FailRed),
        ScanUiPhase.Cancelled => BrushFrom(ThemePalette.AccentGold),
        _ => BrushFrom(ThemePalette.TextMuted)
    };

    public Brush StatusBrush => Phase switch
    {
        ScanUiPhase.Failed => BrushFrom(ThemePalette.FailRed),
        ScanUiPhase.Completed => BrushFrom(ThemePalette.PassGreen),
        ScanUiPhase.Scanning or ScanUiPhase.Validating => BrushFrom(ThemePalette.WarnAmber),
        ScanUiPhase.Cancelled => BrushFrom(ThemePalette.AccentGold),
        _ => BrushFrom(ThemePalette.TextMuted)
    };

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (_isBusy == value) return;
            _isBusy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ProgressVisibility));
            RaiseCommands();
        }
    }

    public ObservableCollection<FindingRow> Findings { get; } = new();
    public ObservableCollection<RepairChoiceRow> AvailableRepairs { get; } = new();

    public RepairChoiceRow? SelectedRepair
    {
        get => _selectedRepair;
        set { _selectedRepair = value; OnPropertyChanged(); }
    }

    public AsyncRelayCommand ScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand ShowCausesCommand { get; }
    public AsyncRelayCommand SafeRepairCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public RelayCommand CompareCommand { get; }
    public RelayCommand CopyErrorCommand { get; }

    private async Task ScanAsync()
    {
        _lastError = null;
        _lastErrorContext = "Scan";
        Phase = ScanUiPhase.Validating;
        StageText = Labels.Role + "...";

        string? target = null;
        if (IsClientRole)
        {
            if (string.IsNullOrWhiteSpace(TargetHost))
            {
                Phase = ScanUiPhase.Failed;
                StatusText = Labels.TargetRequired;
                StageText = "";
                _lastError = new InvalidOperationException(Labels.TargetRequired);
                _log.WriteError("Scan validation: target required in client mode");
                return;
            }
            if (!InputValidator.TryParseHost(TargetHost, out var host))
            {
                Phase = ScanUiPhase.Failed;
                StatusText = Labels.InvalidHost;
                StageText = "";
                _lastError = new ArgumentException(Labels.InvalidHost);
                _log.WriteError("Scan validation: invalid host " + TargetHost);
                return;
            }
            TargetHost = host;
            target = host;
        }
        else
        {
            // Server mode = local only (Gate E)
            target = null;
            TargetHost = "";
        }

        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        IsBusy = true;
        Phase = ScanUiPhase.Scanning;
        StatusText = Labels.Scanning;
        Findings.Clear();
        AvailableRepairs.Clear();
        SelectedRepair = null;
        _scanWatch.Restart();
        _elapsedTimer.Start();
        RefreshElapsed();
        _log.WriteInfo($"Scan start role={(IsServerRole ? "Server" : "Client")} deep={IsDeepScan} target={target ?? "(local)"}");

        var progress = new Progress<string>(stage =>
        {
            StageText = stage;
            StatusText = Labels.Scanning + " " + stage;
        });

        try
        {
            var (net, fw, svc, smb, prn, sha, _, _) = PlatformComposition.CreateWindowsStack();
            var orch = new DiagnosticOrchestrator(net, fw, svc, smb, prn, sha);
            var snap = await orch.RunAsync(new DiagnosticRequest
            {
                Role = IsServerRole ? MachineRole.Server : MachineRole.Client,
                TargetHost = target,
                DeepScan = IsDeepScan
            }, progress, ct);

            ct.ThrowIfCancellationRequested();

            _lastSnapshot = snap;
            SessionText = $"Session: {snap.SessionId}";
            foreach (var f in snap.Findings.OrderByDescending(x => x.Severity))
            {
                Findings.Add(FindingRow.From(f.Status.ToString(), $"{f.Id} — {f.Title}", f.Evidence));
            }

            foreach (var rc in new NetworkRootCauseEngine().Analyze(snap))
            {
                Findings.Add(FindingRow.From(
                    rc.Status.ToString(),
                    $"{rc.CaseId} — {rc.Title}",
                    (rc.Evidence ?? "") + " | " + (rc.RecommendedAction ?? "")
                        + $" | evidence={rc.EvidenceLevel}"
                        + (rc.InfrastructureActionRequired ? " | INFRASTRUCTURE_ACTION_REQUIRED" : "")
                        + (rc.InfrastructureInvestigationRecommended ? " | INFRASTRUCTURE_INVESTIGATION_RECOMMENDED" : "")));
            }

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
                Findings.Add(FindingRow.From("PASS", Labels.NoCritical, Labels.NoCriticalEvidence));
            }

            _scanWatch.Stop();
            Phase = ScanUiPhase.Completed;
            StageText = IsDeepScan ? "DeepScan COMPLETED" : "QuickScan COMPLETED";
            StatusText = string.Format(Labels.ScanDone, snap.Findings.Count, _scanWatch.Elapsed.TotalSeconds);
            _log.WriteInfo($"Scan completed findings={snap.Findings.Count} elapsed={_scanWatch.Elapsed.TotalSeconds:0.0}s");
        }
        catch (OperationCanceledException)
        {
            Phase = ScanUiPhase.Cancelled;
            StatusText = Labels.ScanCancelled;
            StageText = "CANCELLED";
            _log.WriteInfo("Scan cancelled by user");
            if (Findings.Count == 0)
                ShowEmptyFindings();
        }
        catch (Exception ex)
        {
            // Never swallow — surface + log (Gate C/F). Do NOT auto-repair.
            _lastError = ex;
            _lastErrorContext = "Scan";
            Phase = ScanUiPhase.Failed;
            StatusText = Labels.ScanFailed + ": " + ex.Message;
            StageText = "FAILED — " + ex.GetType().Name;
            var path = _log.WriteError("Scan failed", ex);
            LogPathText = "Logs: " + path;
            if (Findings.Count == 0)
            {
                Findings.Add(FindingRow.From("FAIL", Labels.ScanFailed, ex.Message));
            }
        }
        finally
        {
            _elapsedTimer.Stop();
            RefreshElapsed();
            IsBusy = false;
            _scanCts?.Dispose();
            _scanCts = null;
            RaiseCommands();
        }
    }

    private void CancelScan()
    {
        try { _scanCts?.Cancel(); }
        catch (ObjectDisposedException) { /* ignore */ }
        StageText = "Cancelling...";
    }

    private void ShowEmptyFindings()
    {
        Findings.Clear();
        Findings.Add(FindingRow.From("—", Labels.EmptyFindings, ""));
    }

    private void CopyErrorDetails()
    {
        var details = _log.FormatErrorDetails(
            _lastErrorContext,
            _lastError,
            extra: $"Phase={PhaseCode}\nStatus={StatusText}\nStage={StageText}\nSession={SessionText}");
        try
        {
            Clipboard.SetText(details);
            StatusText = Labels.ErrorCopied;
            _log.WriteInfo("Copied error details to clipboard");
        }
        catch (Exception ex)
        {
            StatusText = "Clipboard failed: " + ex.Message;
            _log.WriteError("Clipboard copy failed", ex);
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
            var lines = candidates.Select((a, i) =>
                $"{i + 1}) IfIndex={a.InterfaceIndex} Alias={a.Name} IP={string.Join(",", a.IPv4Addresses)} GW={a.DefaultGateway} Cat={a.Category} Metric={a.InterfaceMetric}").ToList();
            var prompt = "Chọn interface (nhập số 1.." + candidates.Count + ") — multi-NIC/VPN bắt buộc chọn đúng:\n\n"
                         + string.Join("\n", lines)
                         + "\n\nCancel = hủy. OK sau khi ghi nhớ số; hộp nhập phía sau.";
            MessageBox.Show(prompt, Labels.SafeRepair, MessageBoxButton.OK, MessageBoxImage.Information);
            if (candidates.Count == 1)
            {
                selectedIf = candidates[0].InterfaceIndex;
                previewDetail = lines[0];
            }
            else
            {
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
            var executor = new RepairExecutor(_lastJournal, lockDirectory: null, journalsRoot: journalsRoot);
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
            else if (result.NoChange && result.Verified)
                StatusText = result.Message ?? Labels.AlreadyConfigured;
            else if (result.Verified && result.Status == DiagnosticStatus.Pass)
            {
                StatusText = Labels.LocalConfigVerified;
                await ScanAsync();
            }
            else if (result.Status == DiagnosticStatus.Pass && !result.Verified)
                StatusText = Labels.UnverifiedSuccess;
            else
                StatusText = result.Message ?? Labels.RepairFailed;
        }
        catch (Exception ex)
        {
            _lastError = ex;
            _lastErrorContext = "SafeRepair";
            StatusText = Labels.RepairFailed + ": " + ex.Message;
            _log.WriteError("SafeRepair failed", ex);
        }
        finally
        {
            IsBusy = false;
            RaiseCommands();
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
            "SHA-START-PROCESS" => new ShaPrintStartRepair(
                new WindowsShaPrintInspector(new WindowsNetworkProbe(runner), runner),
                runner, elev),
            "NET-MS-SERVER-BINDING" => new NotImplementedRepair("NET-MS-SERVER-BINDING",
                "File and Printer Sharing (SMB) binding repair — detect-only in RC3; enable after exact adapter selection is field-validated (NOT_IMPLEMENTED)"),
            "PRN-RESTORE-MAPPING" => new NotImplementedRepair("PRN-RESTORE-MAPPING",
                "Printer mapping restore — requires confirmed target share; disabled until secure UNC prerequisites are field-validated (NOT_IMPLEMENTED)"),
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
                Findings.Add(FindingRow.From(f.Status.ToString(), $"{f.Id} — {f.Title}", f.Evidence));

            var sb = new StringBuilder();
            sb.AppendLine($"HasValidEvidence={result.HasValidEvidence}");
            if (result.ServerSideIssues.Count > 0) sb.AppendLine("SERVER: " + string.Join("; ", result.ServerSideIssues));
            if (result.ClientSpecificIssues.Count > 0) sb.AppendLine("CLIENT: " + string.Join("; ", result.ClientSpecificIssues));
            if (result.InfrastructureHints.Count > 0) sb.AppendLine("INFRA: " + string.Join("; ", result.InfrastructureHints));
            if (result.InsufficientEvidence.Count > 0) sb.AppendLine("INSUFFICIENT: " + string.Join("; ", result.InsufficientEvidence));
            if (Findings.Count == 0 && !result.HasValidEvidence)
                Findings.Add(FindingRow.From("UNKNOWN", "Insufficient evidence", sb.ToString()));
            StatusText = sb.ToString();
            MessageBox.Show(sb.ToString(), Labels.Compare, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _lastError = ex;
            _lastErrorContext = "Compare";
            StatusText = Labels.CompareFailed + ": " + ex.Message;
            _log.WriteError("Compare failed", ex);
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
            _lastError = ex;
            _lastErrorContext = "Export";
            StatusText = Labels.ExportFailed + ": " + ex.Message;
            _log.WriteError("Export failed", ex);
        }
    }

    private void RefreshModeIndicator()
    {
        ModeIndicator = LanguageIndex == 0
            ? ScanModeRules.ModeIndicatorVi(IsServerRole, IsDeepScan)
            : (IsServerRole
                ? (IsDeepScan ? "Mode: SERVER · DEEP (local)" : "Mode: SERVER · QUICK (local)")
                : (IsDeepScan ? "Mode: CLIENT · DEEP → server IP" : "Mode: CLIENT · QUICK → server IP"));
        OnPropertyChanged(nameof(ModeIndicator));
    }

    private void RefreshElapsed()
    {
        if (_scanWatch.IsRunning || _scanWatch.ElapsedMilliseconds > 0)
            ElapsedText = $"{_scanWatch.Elapsed.TotalSeconds:0.0}s";
        else
            ElapsedText = "";
    }

    private void RaiseCommands()
    {
        ScanCommand.RaiseCanExecuteChanged();
        CancelScanCommand.RaiseCanExecuteChanged();
        ShowCausesCommand.RaiseCanExecuteChanged();
        SafeRepairCommand.RaiseCanExecuteChanged();
        ExportCommand.RaiseCanExecuteChanged();
        CompareCommand.RaiseCanExecuteChanged();
        CopyErrorCommand.RaiseCanExecuteChanged();
    }

    private static SolidColorBrush BrushFrom(string hex)
    {
        var (r, g, b) = ThemePalette.ParseRgb(hex);
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class FindingRow
{
    public string Status { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public Brush StatusBrush { get; init; } = Brushes.White;

    public static FindingRow From(string status, string title, string evidence)
    {
        var normalized = ScanModeRules.NormalizeFindingStatus(status);
        if (status == "—") normalized = "—";
        var brush = normalized switch
        {
            "PASS" => Brush("#3DDC97"),
            "FAIL" => Brush("#FF7474"),
            "WARN" => Brush("#F1C453"),
            "UNKNOWN" => Brush("#BBC5D3"),
            _ => Brush("#BBC5D3")
        };
        return new FindingRow
        {
            Status = normalized == "—" ? "—" : normalized,
            Title = title,
            Evidence = evidence,
            StatusBrush = brush
        };
    }

    private static SolidColorBrush Brush(string hex)
    {
        var (r, g, b) = ThemePalette.ParseRgb(hex);
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

public sealed class RepairChoiceRow
{
    public string RepairId { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Owner { get; init; } = "";
    public override string ToString() => $"{RepairId} — {Title}";
}
