using System.Diagnostics;
using System.Windows;
using System.Windows.Navigation;
using MyPC.LanPrintDoctor.ViewModels;

namespace MyPC.LanPrintDoctor;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }

    private void BrandLink_OnRequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
