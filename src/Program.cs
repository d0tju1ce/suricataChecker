using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    static class Program
    {
        public const string AppName = "suricataChecker";

        /// <summary>Error log of this Windows user on this computer – not in the application folder (it is not copied with it).</summary>
        public static string ErrorLogPath =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName, "error.log");

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            // errors in the UI thread: short message, details only in the log
            Application.ThreadException += (s, e) =>
            {
                LogError("UI", e.Exception);
                MessageBox.Show(e.Exception.GetBaseException().Message + "\n\nDetails were written to " + ErrorLogPath,
                    AppName + " – unexpected error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            // errors outside the UI thread would end the application without a word – at least log them
            AppDomain.CurrentDomain.UnhandledException += (s, e) => LogError("background thread (application ends)", e.ExceptionObject as Exception);
            TaskScheduler.UnobservedTaskException += (s, e) => { LogError("task", e.Exception); e.SetObserved(); };

            // a console tool started by the application (suricata.exe -V / -T) that misses a DLL must not stop with a
            // Windows "System Error" box – the mode is inherited, the process exits with 0xC0000135 and that is reported
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

            Theme.LoadFonts();
            if (args.Length == 2 && args[0] == "--export-logo") { Logo.Export(args[1], Theme.LogoFamily); return; }
            Marks.Load();

            // Suricata check at start: when something is missing (Npcap, Suricata, configuration, rules, service) the setup
            // window opens first; "--setup" = started again as administrator from that window
            bool setupArg = Array.IndexOf(args, "--setup") >= 0;
            if (setupArg || SetupForm.CheckAtStart)
            {
                var settings = AppSettings.Load();
                SetupState state = null;
                try { state = SetupState.Check(settings); } catch (Exception ex) { LogError("setup check", ex); }
                if (setupArg || (state != null && !state.AllOk))
                    using (var setup = new SetupForm(settings, state, startup: true))
                    {
                        Application.Run(setup);
                        if (setup.ExitApplication) return;
                    }
            }
            Application.Run(new MainForm());
        }

        const uint SEM_FAILCRITICALERRORS = 0x0001, SEM_NOOPENFILEERRORBOX = 0x8000;
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern uint SetErrorMode(uint mode);

        static readonly object logLock = new object();

        public static void LogError(string where, Exception ex)
        {
            try
            {
                lock (logLock)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ErrorLogPath));
                    var fi = new FileInfo(ErrorLogPath);
                    if (fi.Exists && fi.Length > 1024 * 1024) File.Delete(ErrorLogPath + ".old");
                    if (fi.Exists && fi.Length > 1024 * 1024) File.Move(ErrorLogPath, ErrorLogPath + ".old");   // keep it small
                    File.AppendAllText(ErrorLogPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{where}] {ex}\r\n\r\n");
                }
            }
            catch { }
        }
    }
}
