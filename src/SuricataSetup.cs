using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SuricataChecker
{
    /// <summary>
    /// State of Suricata on this computer – everything the application needs: Npcap in the WinPcap API-compatible Mode,
    /// Suricata, the configuration of the application (config\suricata) deployed, the ET Open rules, the service running.
    /// Reads only (works as a standard user, no network).
    /// </summary>
    class SetupState
    {
        public bool NpcapInstalled, Wpcap;
        public Version NpcapVersion, SuricataVersion;
        public string SuricataExe, ServiceName, ConfigNote, RuleDir;
        public bool ConfigDeployed;
        /// <summary>suricata.exe or its folder can be changed by standard users – the service (LocalSystem) and every
        /// elevated start of it would run their code; the setup does not start it then.</summary>
        public bool SuricataWritable;
        public int RulesListed, RulesMissing;
        public DateTime? RulesDate;
        public ServiceControllerStatus? ServiceStatus;
        public ServiceStartMode? StartMode;

        public string Dir => SuricataExe == null ? null : Path.GetDirectoryName(SuricataExe);
        public string DeployedYaml => Dir == null ? null : Path.Combine(Dir, "suricata.yaml");

        public bool NpcapOk => NpcapInstalled && Wpcap;
        public bool SuricataOk => SuricataExe != null;
        public bool RulesOk => RulesListed > 0 && RulesMissing == 0;
        public bool ServiceRegistered => ServiceName != null;
        public bool ServiceOk => ServiceStatus == ServiceControllerStatus.Running;
        public bool AllOk => NpcapOk && SuricataOk && ConfigDeployed && RulesOk && ServiceOk;
        public bool RulesOld => RulesDate.HasValue && DateTime.Now - RulesDate.Value > TimeSpan.FromDays(7);

        public static string AppConfigDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "suricata");
        public static string Script => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "Install-SuricataConfig.ps1");

        public static SetupState Check(AppSettings s)
        {
            var st = new SetupState
            {
                NpcapInstalled = SystemChecks.NpcapInstalled(),
                Wpcap = SystemChecks.WpcapPresent(),
                NpcapVersion = SuricataInstaller.InstalledVersion("Npcap"),
                ServiceName = SystemChecks.FindSuricataServiceName(),
            };
            st.SuricataExe = SystemChecks.FindSuricataExe(s, st.ServiceName);
            st.SuricataVersion = SuricataInstaller.InstalledVersion("Suricata");
            if (st.SuricataVersion == null && st.SuricataExe != null)
                try { st.SuricataVersion = SuricataInstaller.ParseVersion(FileVersionInfo.GetVersionInfo(st.SuricataExe).ProductVersion); } catch { }
            if (st.ServiceName != null)
                try { using (var sc = new ServiceController(st.ServiceName)) { st.ServiceStatus = sc.Status; st.StartMode = sc.StartType; } } catch { }

            if (st.SuricataExe != null) st.SuricataWritable = SystemChecks.WritableByStandardUsers(st.SuricataExe);
            if (st.SuricataExe != null)
            {
                // the deployed files must be the ones of the application (config\suricata) – the same SHA-256
                var notes = new List<string>();
                foreach (var f in new[] { "suricata.yaml", "threshold.config" })
                {
                    string src = Path.Combine(AppConfigDir, f), dst = Path.Combine(st.Dir, f);
                    if (!File.Exists(src)) continue;
                    if (!File.Exists(dst)) notes.Add(f + " is missing");
                    else if (Hash(src) != Hash(dst)) notes.Add(f + " differs from config\\suricata of the application");
                }
                st.ConfigDeployed = notes.Count == 0;
                st.ConfigNote = string.Join(", ", notes);
                if (File.Exists(st.DeployedYaml))
                {
                    st.RulesMissing = SystemChecks.MissingRuleFiles(st.DeployedYaml, out st.RuleDir, out st.RulesListed).Count;
                    try
                    {
                        var dates = Directory.GetFiles(st.RuleDir, "emerging-*.rules").Select(File.GetLastWriteTime).ToList();
                        if (dates.Count > 0) st.RulesDate = dates.Max();
                    }
                    catch { }
                }
            }
            return st;
        }

        static string Hash(string file)
        {
            try { using (var sha = SHA256.Create()) using (var fs = File.OpenRead(file)) return BitConverter.ToString(sha.ComputeHash(fs)); }
            catch { return "?" + file; }
        }
    }

    /// <summary>
    /// One window for getting Suricata running on this computer: shows the state of every part and does whatever is
    /// missing in one go – Npcap (WinPcap API-compatible Mode), Suricata (official installers, signature and hash checked),
    /// the configuration and the ET Open rules from the application folder and the Windows service
    /// (config\Install-SuricataConfig.ps1). Opened at start when something is missing, and from Settings.
    /// </summary>
    class SetupForm : Form
    {
        const string RegKey = @"Software\suricataChecker";

        /// <summary>Check Suricata when the application starts (this Windows user on this computer).</summary>
        public static bool CheckAtStart
        {
            get { try { using (var k = Registry.CurrentUser.OpenSubKey(RegKey)) return !(k?.GetValue("CheckSetupAtStart") is int v) || v != 0; } catch { return true; } }
            set { try { using (var k = Registry.CurrentUser.CreateSubKey(RegKey)) k.SetValue("CheckSetupAtStart", value ? 1 : 0, RegistryValueKind.DWord); } catch { } }
        }

        /// <summary>Start: the application should end (closed with "Exit", or started again as administrator).</summary>
        public bool ExitApplication { get; private set; }
        /// <summary>A new instance runs as administrator – the caller closes this one.</summary>
        public bool RestartedElevated { get; private set; }

        readonly AppSettings s;
        readonly bool startup, admin = SystemChecks.IsAdmin();
        SetupState st;
        SuricataInstaller.Release latestSuricata, latestNpcap;
        bool running;

        readonly StatusIcon[] icons = new StatusIcon[5];
        readonly Label[] details = new Label[5];
        readonly Toggle chkNpcap = new Toggle("x"), chkSuricata = new Toggle("x"), chkDeploy = new Toggle("x"), chkRules = new Toggle("x"), chkStart = new Toggle("x");
        readonly DarkCombo cmbAdapter = new DarkCombo(560);
        readonly Label lblAdapter = new Label { Text = "Capture adapter", AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(Ui.S(10), Ui.S(10), Ui.S(4), 0) };
        readonly Label lblNothing = new Label { AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(Ui.S(3), Ui.S(6), 0, Ui.S(6)) };
        readonly FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        readonly TextBox log = Ui.DetailBox().Also(t => { t.WordWrap = true; t.ScrollBars = ScrollBars.Vertical; });
        readonly Button btnRun, btnCheck, btnContinue;
        readonly Toggle chkAtStart = new Toggle("Check Suricata when the application starts");
        readonly Label lblResult = new Label { AutoSize = true, Font = Theme.F(11f, Weight.Bold), Margin = new Padding(0, Ui.S(4), 0, Ui.S(8)) };

        public SetupForm(AppSettings settings, SetupState state, bool startup)
        {
            s = settings;
            st = state;
            this.startup = startup;
            Text = Program.AppName + " – Suricata setup";
            Size = new Size(Ui.S(1000), Ui.S(860));
            MinimumSize = new Size(Ui.S(820), Ui.S(640));
            StartPosition = startup ? FormStartPosition.CenterScreen : FormStartPosition.CenterParent;
            ShowInTaskbar = startup;
            MinimizeBox = startup;
            Font = Theme.F(9.5f);
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Padding = new Padding(Ui.S(20), Ui.S(14), Ui.S(20), Ui.S(14));
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            HandleCreated += (o, e) => Theme.DarkTitleBar(this);

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1 };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var title = new Label { Text = "Suricata on this computer", AutoSize = true, Font = Theme.F(16f, Weight.Bold), Margin = new Padding(0, 0, 0, Ui.S(2)) };
            var note = new Label
            {
                AutoSize = true, ForeColor = Theme.SubText, MaximumSize = new Size(Ui.S(930), 0), Margin = new Padding(Ui.S(1), 0, 0, Ui.S(10)),
                Text = "suricataChecker needs Npcap, Suricata, its configuration and the ET Open rules from the application folder (config\\suricata) " +
                       "and the running Suricata service. What is missing is installed and set up here in one go (administrator rights). " +
                       "Installers come only from the official sources and are checked (signature of the publisher, SHA-256) before they run."
            };
            root.Controls.Add(title);
            root.Controls.Add(note);
            root.Controls.Add(lblResult);

            // --- state
            var checks = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3 };
            checks.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            checks.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.S(150)));
            checks.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            string[] names = { "Npcap", "Suricata", "Configuration", "ET Open rules", "Service" };
            for (int i = 0; i < names.Length; i++)
            {
                icons[i] = new StatusIcon { Size = new Size(Ui.S(28), Ui.S(28)), Margin = new Padding(0, Ui.S(3), Ui.S(10), Ui.S(3)) };
                details[i] = new Label { AutoSize = true, ForeColor = Theme.SubText, Anchor = AnchorStyles.Left, MaximumSize = new Size(Ui.S(720), 0) };
                checks.Controls.Add(icons[i], 0, i);
                checks.Controls.Add(new Label { Text = names[i], AutoSize = true, Font = Theme.F(10f, Weight.SemiBold), Anchor = AnchorStyles.Left }, 1, i);
                checks.Controls.Add(details[i], 2, i);
            }
            root.Controls.Add(Wrap(checks));

            // --- what will be done
            var act = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1 };
            act.Controls.Add(new Label { Text = "What will be done", AutoSize = true, Font = Theme.F(11f, Weight.Bold), Margin = new Padding(0, 0, 0, Ui.S(4)) });
            act.Controls.Add(actions);
            var adapterRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            adapterRow.Controls.Add(lblAdapter);
            adapterRow.Controls.Add(cmbAdapter);
            act.Controls.Add(adapterRow);
            root.Controls.Add(Wrap(act));

            // --- log
            var logCard = new Card { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, Ui.S(10)) };
            logCard.Controls.Add(log);
            root.Controls.Add(logCard);
            // rows: title, note, result, state, actions (auto) – log (fills the rest) – buttons (auto)
            for (int i = 0; i < 5; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            // --- buttons
            btnRun = Ui.B(admin ? "Install and set up" : "Install and set up as administrator", async (o, e) => await RunAsync(), ButtonKind.Primary);
            btnCheck = Ui.B("Check again", async (o, e) => await RecheckAsync());
            btnContinue = Ui.B(startup ? "Continue to the application" : "Close", (o, e) => Close());
            var bottom = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            bottom.Controls.AddRange(new Control[] { btnRun, btnCheck, btnContinue, chkAtStart });
            if (startup)
                bottom.Controls.Add(Ui.B("Exit", (o, e) => { ExitApplication = true; Close(); }));
            root.Controls.Add(bottom);
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            chkAtStart.Checked = CheckAtStart;
            chkAtStart.CheckedChanged += (o, e) => CheckAtStart = chkAtStart.Checked;
            var tips = new ToolTip { AutoPopDelay = 20000 };
            tips.SetToolTip(chkAtStart, "When something is missing at start (Npcap, Suricata, configuration, rules, service), this window opens first.\n" +
                                        "Turn it off on a computer that only reads an eve.json of another one.");
            if (!admin) tips.SetToolTip(btnRun, "Starts the application again as administrator (UAC) and opens this window there.");
            foreach (var t in new[] { chkNpcap, chkSuricata, chkDeploy, chkRules, chkStart }) t.CheckedChanged += (o, e) => UpdateButtons();

            log.Text = "The progress is shown here. The installers of Npcap and Suricata open their own windows; the configuration, " +
                       "the ET Open rules (downloaded from rules.emergingthreats.net, checksum verified) and the service are set up by " +
                       "config\\Install-SuricataConfig.ps1 – its output appears here.\r\n";
            FillAdapters();
            Shown += async (o, e) =>
            {
                if (st == null) await RecheckAsync(); else ShowState();
                await LoadLatestAsync();
            };
            FormClosing += (o, e) => { if (running) e.Cancel = true; };
        }

        static Card Wrap(Control c)
        {
            var card = new Card { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, Ui.S(10)) };
            card.Controls.Add(c);
            return card;
        }

        static void SetText(Toggle t, string text)
        {
            t.Text = text;
            t.Size = new Size(Ui.S(46) + TextRenderer.MeasureText(text, t.Font).Width, Ui.S(30));
        }

        void Log(string line)
        {
            if (IsDisposed) return;
            if (InvokeRequired) { BeginInvoke((Action)(() => Log(line))); return; }
            log.AppendText((line ?? "") + "\r\n");
        }

        async Task RecheckAsync()
        {
            Cursor = Cursors.WaitCursor;
            try { st = await Task.Run(() => SetupState.Check(s)); }
            finally { Cursor = Cursors.Default; }
            ShowState();
        }

        async Task LoadLatestAsync()
        {
            try
            {
                var sur = SuricataInstaller.LatestSuricataAsync(CancellationToken.None);
                var np = SuricataInstaller.LatestNpcapAsync(CancellationToken.None);
                await Task.WhenAll(sur, np);
                latestSuricata = sur.Result;
                latestNpcap = np.Result;
                ShowState();
            }
            catch (Exception ex)
            {
                var inner = ex is AggregateException ae ? ae.Flatten().InnerException : ex;
                Log("Version check on the official download pages failed: " + (inner?.InnerException?.Message ?? inner?.Message));
            }
        }

        static string V(Version v) => v == null ? "?" : v.ToString(Math.Min(3, v.Build >= 0 ? 3 : 2));

        bool Newer(SuricataInstaller.Release rel, Version inst) => rel != null && inst != null && SuricataInstaller.Compare(inst, rel.Version) < 0;

        /// <summary>Shows the state and preselects the actions that are needed.</summary>
        void ShowState()
        {
            if (st == null) return;
            void Set(int i, CheckState state, string text) { icons[i].State = state; details[i].Text = text; }

            bool npUpd = Newer(latestNpcap, st.NpcapVersion), surUpd = Newer(latestSuricata, st.SuricataVersion);
            Set(0, st.NpcapOk ? (npUpd ? CheckState.Warning : CheckState.Ok) : CheckState.Error,
                !st.NpcapInstalled ? "not installed – Suricata captures traffic with Npcap"
                : !st.Wpcap ? $"installed {V(st.NpcapVersion)} WITHOUT the WinPcap API-compatible Mode – wpcap.dll is missing, Suricata cannot start"
                : $"installed {V(st.NpcapVersion)} (WinPcap API-compatible Mode)" + (npUpd ? $" – update {latestNpcap.VersionText} available" : latestNpcap != null ? " – up to date" : ""));
            Set(1, st.SuricataOk ? (st.SuricataWritable ? CheckState.Error : surUpd ? CheckState.Warning : CheckState.Ok) : CheckState.Error,
                !st.SuricataOk ? "not installed" + (latestSuricata != null ? $" – newest {latestSuricata.VersionText}" : "")
                : $"installed {V(st.SuricataVersion)} ({st.Dir})" + (surUpd ? $" – update {latestSuricata.VersionText} available" : latestSuricata != null ? " – up to date" : "") +
                  (st.SuricataWritable ? "\nWARNING: standard users can change suricata.exe or its folder – the service runs it as LocalSystem. Allow writing " +
                                         "there to administrators only (or install Suricata to C:\\Program Files); the setup does not run it until then." : ""));
            Set(2, !st.SuricataOk ? CheckState.Error : st.ConfigDeployed ? CheckState.Ok : CheckState.Error,
                !st.SuricataOk ? "needs Suricata" : st.ConfigDeployed ? "suricata.yaml and threshold.config = config\\suricata of the application" : st.ConfigNote);
            Set(3, !st.SuricataOk || !st.RulesOk ? CheckState.Error : st.RulesOld ? CheckState.Warning : CheckState.Ok,
                !st.SuricataOk ? "needs Suricata"
                : st.RulesListed == 0 ? "no rule files found in the configuration"
                : st.RulesMissing > 0 ? $"{st.RulesMissing} of {st.RulesListed} rule files missing in {st.RuleDir} – the Suricata installer does not include them"
                : $"{st.RulesListed} rule files" + (st.RulesDate.HasValue ? $", ET Open from {st.RulesDate:yyyy-MM-dd}" + (st.RulesOld ? " – older than 7 days" : "") : ""));
            Set(4, st.ServiceOk ? (st.StartMode == ServiceStartMode.Automatic ? CheckState.Ok : CheckState.Warning) : CheckState.Error,
                !st.ServiceRegistered ? "not registered – the Suricata installer does not create the service"
                : $"{st.ServiceName} – {(st.ServiceOk ? "running" : (st.ServiceStatus?.ToString() ?? "unknown").ToLowerInvariant())}" +
                  (st.StartMode == ServiceStartMode.Automatic ? " (automatic start)" : st.StartMode != null ? $" (start: {st.StartMode})" : ""));

            lblResult.Text = st.AllOk ? "✔ Suricata is set up and running." : "Suricata is not ready yet – the steps below are needed.";
            lblResult.ForeColor = st.AllOk ? Theme.Ok : Theme.Attention;

            // actions: needed ones preselected, updates offered unticked
            actions.SuspendLayout();
            actions.Controls.Clear();
            void Add(Toggle t, string text, bool check) { SetText(t, text); t.Checked = check; actions.Controls.Add(t); }
            if (!st.NpcapOk)
                Add(chkNpcap, (st.NpcapInstalled ? "Reinstall" : "Install") + $" Npcap {latestNpcap?.VersionText} in the WinPcap API-compatible Mode (its installer opens – keep that option ticked)", true);
            else if (npUpd) Add(chkNpcap, $"Update Npcap {V(st.NpcapVersion)} → {latestNpcap.VersionText}", false);
            if (!st.SuricataOk) Add(chkSuricata, $"Install Suricata {latestSuricata?.VersionText}", true);
            else if (surUpd) Add(chkSuricata, $"Update Suricata {V(st.SuricataVersion)} → {latestSuricata.VersionText} (the service is stopped meanwhile)", false);
            bool deployNeeded = !st.SuricataOk || !st.ConfigDeployed || !st.RulesOk || !st.ServiceRegistered;
            if (deployNeeded)
                Add(chkDeploy, "Deploy the configuration and the ET Open rules from the application folder" +
                               (st.ServiceRegistered ? " and restart the service" : ", register the Suricata service and start it"), true);
            else
            {
                Add(chkRules, "Update the ET Open rules" + (st.RulesDate.HasValue ? $" (now from {st.RulesDate:yyyy-MM-dd})" : "") + " and restart the service", false);
                if (!st.ServiceOk) Add(chkStart, "Start the Suricata service", true);
            }
            if (actions.Controls.Count == 0) { lblNothing.Text = "Nothing to do."; actions.Controls.Add(lblNothing); }
            actions.ResumeLayout(true);

            bool askAdapter = !st.ServiceRegistered;
            lblAdapter.Visible = cmbAdapter.Visible = askAdapter;
            UpdateButtons();
        }

        void UpdateButtons()
        {
            bool any = new[] { chkNpcap, chkSuricata, chkDeploy, chkRules, chkStart }.Any(t => t.Parent == actions && t.Checked);
            btnRun.Enabled = !running && any;
            btnCheck.Enabled = btnContinue.Enabled = !running;
            if (startup && st != null) btnContinue.Text = st.AllOk ? "Continue to the application" : "Continue without setup";
        }

        // ------------------------------------------------------------------ capture adapter

        class Adapter { public string Text, Device; public int Score; public override string ToString() => Text; }

        /// <summary>Network adapters for the capture (\Device\NPF_{GUID}); the one with the default route first, physical before
        /// virtual / VPN.</summary>
        void FillAdapters()
        {
            var list = new List<Adapter>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    var p = ni.GetIPProperties();
                    var ip = p.UnicastAddresses.Select(a => a.Address).FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    bool gw = p.GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any));
                    bool virt = System.Text.RegularExpressions.Regex.IsMatch(ni.Description + " " + ni.Name, "virtual|hyper-v|vpn|tap-|wireguard|vethernet|loopback|bluetooth", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    list.Add(new Adapter
                    {
                        Text = $"{ni.Name} – {ni.Description}" + (ip != null ? $" ({ip})" : "") + (gw ? "" : " – no default route"),
                        Device = @"\Device\NPF_" + ni.Id,
                        Score = (gw ? 0 : 10) + (virt ? 5 : 0)
                    });
                }
            }
            catch { }
            cmbAdapter.Items.Clear();
            foreach (var a in list.OrderBy(a => a.Score)) cmbAdapter.Items.Add(a);
            if (cmbAdapter.Items.Count > 0) cmbAdapter.SelectedIndex = 0;
        }

        // ------------------------------------------------------------------ run

        async Task RunAsync()
        {
            if (!admin) { RestartAsAdmin(); return; }
            var adapter = cmbAdapter.SelectedItem as Adapter;
            if (chkDeploy.Parent == actions && chkDeploy.Checked && !st.ServiceRegistered && adapter == null)
            { Ui.Warn(this, "No network adapter to capture on was found."); return; }

            // the configuration is loaded by the service running as LocalSystem – warn when standard users can change it
            bool deploy = chkDeploy.Parent == actions && chkDeploy.Checked, rulesOnly = chkRules.Parent == actions && chkRules.Checked;
            bool allowWritable = false;
            if (deploy || rulesOnly)
            {
                var writable = new[] { SetupState.Script, Path.Combine(SetupState.AppConfigDir, "suricata.yaml"), Path.Combine(SetupState.AppConfigDir, "threshold.config") }
                    .Where(f => File.Exists(f) && SystemChecks.WritableByStandardUsers(f)).ToList();
                if (writable.Count > 0)
                {
                    if (MessageBox.Show(this, "Standard users can change these files or their folder – they are run / loaded with administrator rights:\n\n" +
                            string.Join("\n", writable) + "\n\nKeep the application in a folder only administrators can change (e.g. C:\\Program Files\\suricataChecker). Continue anyway?",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                    allowWritable = true;
                }
            }

            running = true;
            UpdateButtons();
            log.Clear();
            bool ok = true;
            try
            {
                if (chkNpcap.Parent == actions && chkNpcap.Checked)
                {
                    ok = await InstallAsync(npcap: true);
                    if (ok && !SystemChecks.WpcapPresent())
                    {
                        Log("ERROR: wpcap.dll is still missing – Npcap was installed without the WinPcap API-compatible Mode. Run it again and keep the option ticked.");
                        ok = false;
                    }
                }
                if (ok && chkSuricata.Parent == actions && chkSuricata.Checked)
                {
                    ok = await InstallAsync(npcap: false);
                    if (ok && !deploy)
                    {
                        // an update may have replaced suricata.yaml / the rules (or the service): check again
                        var after = await Task.Run(() => SetupState.Check(s));
                        if (!after.ConfigDeployed || !after.RulesOk || !after.ServiceRegistered)
                        {
                            Log("The installer changed the configuration, the rules or the service – they are deployed again.");
                            deploy = true;
                            rulesOnly = false;
                        }
                    }
                }
                if (ok && (deploy || rulesOnly))
                {
                    st = await Task.Run(() => SetupState.Check(s));
                    if (!st.SuricataOk) { Log("ERROR: Suricata is not installed."); ok = false; }
                    else if (st.SuricataWritable)
                    {
                        Log("ERROR: standard users can change " + st.SuricataExe + " or its folder – it is not run with administrator rights. " +
                            "Allow writing there to administrators only, then run the setup again.");
                        ok = false;
                    }
                    else if (!SystemChecks.WpcapPresent()) { Log("ERROR: " + SystemChecks.WpcapMissingText); ok = false; }
                    else
                    {
                        var args = new StringBuilder("-Yes");
                        if (rulesOnly) args.Append(" -RulesOnly");
                        if (allowWritable) args.Append(" -AllowWritableSource");
                        if (st.Dir != null) args.Append($" -SuricataDir \"{st.Dir}\"");
                        if (!st.ServiceRegistered && adapter != null && cmbAdapter.Visible) args.Append($" -Interface \"{adapter.Device}\"");
                        Log($"== Deploying the configuration and the ET Open rules ({Path.GetFileName(SetupState.Script)})");
                        int code = await RunScriptAsync(args.ToString());
                        if (code != 0) { Log($"ERROR: the script ended with exit code {code} – see the messages above."); ok = false; }
                    }
                }
                else if (ok && chkStart.Parent == actions && chkStart.Checked && st.ServiceName != null)
                {
                    Log($"== Starting the service {st.ServiceName}");
                    try
                    {
                        await Task.Run(() =>
                        {
                            using (var sc = new ServiceController(st.ServiceName))
                            {
                                sc.Start();
                                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
                            }
                        });
                        Log("The service is running.");
                    }
                    catch (Exception ex) { Log("ERROR: the service could not be started: " + ex.Message); ok = false; }
                }
            }
            catch (Exception ex) { Log("ERROR: " + ex.Message); ok = false; }
            finally { running = false; }

            st = await Task.Run(() => SetupState.Check(s));
            UsePaths();
            ShowState();
            if (st.AllOk)
            {
                Log("");
                Log("All checks passed – Suricata is set up and running.");
                if (startup)
                {
                    MessageBox.Show(this, "Suricata is set up and running. The application opens now.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    Close();
                }
            }
            else if (ok) Log("Done – some checks still fail, see above.");
        }

        /// <summary>Downloads, verifies and runs the official installer (interactive window of the installer).</summary>
        async Task<bool> InstallAsync(bool npcap)
        {
            if ((npcap ? latestNpcap : latestSuricata) == null) await LoadLatestAsync();
            var rel = npcap ? latestNpcap : latestSuricata;
            if (rel == null) { Log("ERROR: the official download page could not be read – check the internet connection."); return false; }
            Log($"== {rel.Product} {rel.VersionText}: downloading {rel.Url}");
            SuricataInstaller.Download d;
            try { d = await SuricataInstaller.DownloadAsync(rel, new Progress<string>(Log), CancellationToken.None); }
            catch (Exception ex)
            {
                Log("ERROR: download / verification failed: " + (ex.InnerException?.Message ?? ex.Message));
                return false;
            }
            using (d)
            {
                Log($"Verified: signature valid, signer {d.Signer}, SHA-256 {d.Sha256}" +
                    (d.KnownHashMatch == true ? " (matches the known hash of this version)" : " (newer than this application knows – verified by the signature)"));
                string svc = npcap ? null : SystemChecks.FindSuricataServiceName();
                bool wasRunning = false;
                int code;
                try
                {
                    if (svc != null)
                        await Task.Run(() =>
                        {
                            using (var sc = new ServiceController(svc))
                                if (sc.Status != ServiceControllerStatus.Stopped)
                                {
                                    wasRunning = true;
                                    sc.Stop();
                                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
                                }
                        });
                    Log(npcap ? "The Npcap installer opens – keep \"Install Npcap in WinPcap API-compatible Mode\" TICKED (preselected)."
                              : "The Suricata installer opens – finish it.");
                    code = await SuricataInstaller.RunInstallerAsync(d, npcap ? "/winpcap_mode=yes" : null);
                }
                catch (Exception ex) { Log("ERROR: the installer could not be started: " + ex.Message); code = -1; }
                finally
                {
                    if (wasRunning)
                        try
                        {
                            await Task.Run(() =>
                            {
                                using (var sc = new ServiceController(svc))
                                {
                                    sc.Start();
                                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
                                }
                            });
                        }
                        catch (Exception ex) { Log($"WARNING: the service {svc} could not be started again: {ex.Message}"); }
                }
                Log($"{rel.Product}: installation {SuricataInstaller.ExitCodeText(code)}.");
                if (code == 1641)
                {
                    // the installer has already started the restart of Windows – nothing more can be done now
                    Log("Windows is being restarted by the installer – open \"Set up Suricata\" again after the restart.");
                    return false;
                }
                if (code == 3010) Log("Windows needs a restart to finish the installation – the setup continues; restart Windows afterwards.");
                return code == 0 || code == 3010;
            }
        }

        /// <summary>Runs config\Install-SuricataConfig.ps1 unattended and shows its output here.</summary>
        Task<int> RunScriptAsync(string args) => Task.Run(() =>
        {
            if (!File.Exists(SetupState.Script)) { Log("ERROR: the script is missing: " + SetupState.Script); return -1; }
            var oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{SetupState.Script}\" {args}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = oem, StandardErrorEncoding = oem,
                WorkingDirectory = Path.GetDirectoryName(SetupState.Script)
            };
            using (var p = new Process { StartInfo = psi })
            {
                p.OutputDataReceived += (o, e) => { if (e.Data != null) Log(e.Data); };
                p.ErrorDataReceived += (o, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) Log(e.Data); };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit();
                return p.ExitCode;
            }
        });

        /// <summary>After the setup the application reads the deployed configuration and its eve.json.</summary>
        void UsePaths()
        {
            if (st?.DeployedYaml == null || !File.Exists(st.DeployedYaml)) return;
            bool changed = false;
            string appDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            bool inApp(string p) { try { return Path.GetFullPath(p).StartsWith(appDir, StringComparison.OrdinalIgnoreCase); } catch { return false; } }
            if (string.IsNullOrWhiteSpace(s.SuricataConfigPath) || !File.Exists(s.SuricataConfigPath) || inApp(s.SuricataConfigPath))
            { s.SuricataConfigPath = st.DeployedYaml; changed = true; }
            string eve = SystemChecks.EvePathFromYaml(s.SuricataConfigPath);
            if (eve != null && !string.Equals(eve, s.SuricataEvePath, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(s.SuricataEvePath) || !File.Exists(s.SuricataEvePath)))
            { s.SuricataEvePath = eve; changed = true; }
            // at start nothing else is pending – save; from Settings the page shows the paths and "Save settings" saves them
            if (changed && startup) try { s.Save(); } catch { }
        }

        void RestartAsAdmin()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--setup") { Verb = "runas", UseShellExecute = true });
                RestartedElevated = true;
                ExitApplication = true;
                Close();
            }
            catch (Win32Exception) { }   // UAC prompt cancelled
            catch (Exception ex) { Ui.Warn(this, "The application could not be started as administrator:\n" + ex.Message); }
        }
    }
}
