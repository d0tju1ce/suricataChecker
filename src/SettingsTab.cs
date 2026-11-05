using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>
    /// "Settings" page: settings of the application (saved per computer) and actions on Suricata on this computer.
    /// Options that need administrator rights are greyed out for a standard user (eve.json itself is readable by every user).
    /// </summary>
    partial class SettingsTab : UserControl
    {
        readonly AppSettings s;
        readonly StatusTab status;
        readonly bool admin = SystemChecks.IsAdmin();
        readonly Field txtSurCfg = new Field(400) { Anchor = AnchorStyles.Left | AnchorStyles.Right };
        readonly Field txtEve = new Field(400) { Anchor = AnchorStyles.Left | AnchorStyles.Right };
        readonly NumberField numMax = new NumberField(10, 100000, 100), numRefresh = new NumberField(2, 3600, 5), numMb = new NumberField(1, 4096, 10);
        readonly Toggle chkAuto = new Toggle("Auto-refresh");
        readonly ToolTip tips = new ToolTip { AutoPopDelay = 20000 };
        readonly Label lblMarks = new Label { AutoSize = true, Font = Theme.F(10f, Weight.SemiBold), Margin = new Padding(Ui.S(3), 0, 0, Ui.S(4)) };
        readonly DataGridView sigGrid = Ui.CreateGrid();
        readonly DataGridView ruleGrid = Ui.CreateGrid();
        /// <summary>Labels that wrap with the window width (width = card width minus the given reserve).</summary>
        readonly List<(Label Label, int Reserve)> wrapLabels = new List<(Label, int)>();

        public event EventHandler SettingsSaved;

        public SettingsTab(AppSettings settings, StatusTab statusTab)
        {
            s = settings;
            status = statusTab;
            Dock = DockStyle.Fill;

            var root = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));   // cards as wide as the page, not as their content
            if (!admin) root.Controls.Add(AdminCard());
            root.Controls.Add(AppCard());
            root.Controls.Add(AiCard());
            root.Controls.Add(SuricataCard());
            root.Controls.Add(MarksCard());
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true }.Also(Theme.DarkScrollBars);
            scroll.Controls.Add(root);
            Controls.Add(scroll);
            // the cards never get wider than the window (otherwise the right part is cut off when the window is
            // made smaller); long texts wrap
            scroll.ClientSizeChanged += (o, e) => FitWidth(root, scroll.ClientSize.Width);
            FitWidth(root, scroll.ClientSize.Width);
            LoadToUi();
        }

        // ------------------------------------------------------------------ layout

        void FitWidth(Control root, int width)
        {
            if (width <= 0) return;
            root.MaximumSize = new Size(width - Ui.S(4), 0);   // small reserve for the right border of the cards
            foreach (var (label, reserve) in wrapLabels)
                label.MaximumSize = new Size(Math.Max(Ui.S(200), width - reserve), 0);
        }

        static Card NewCard() => new Card { Dock = DockStyle.Fill, AutoSize = true };

        static TableLayoutPanel Grid(int columns)
        {
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = columns };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 1; i < columns; i++) t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            return t;
        }

        void Title(TableLayoutPanel t, string title, string note)
        {
            var l = new Label { Text = title, AutoSize = true, Font = Theme.F(12.5f, Weight.Bold), Margin = new Padding(0, 0, 0, Ui.S(2)) };
            var n = new Label { Text = note, AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(Ui.S(1), 0, 0, Ui.S(10)) };
            wrapLabels.Add((n, Ui.S(60)));
            t.Controls.Add(l); t.SetColumnSpan(l, t.ColumnCount);
            t.Controls.Add(n); t.SetColumnSpan(n, t.ColumnCount);
        }

        static void Row(TableLayoutPanel t, params Control[] controls)
        {
            var f = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, Ui.S(6)) };
            f.Controls.AddRange(controls);
            t.Controls.Add(f); t.SetColumnSpan(f, t.ColumnCount);
        }

        static Label FieldLabel(string text) =>
            new Label { Text = text, AutoSize = true, ForeColor = Theme.SubText, Font = Theme.F(9f, Weight.SemiBold), Margin = new Padding(Ui.S(3), 0, 0, Ui.S(2)) };

        /// <summary>Button that needs administrator rights – greyed out for a standard user.</summary>
        Button AdminButton(string text, Func<Task> action, string tip)
        {
            var b = Ui.B(text, async (o, e) => await action());
            b.Enabled = admin;
            tips.SetToolTip(b, tip + (admin ? "" : "\n\nRequires administrator rights – use \"Restart as administrator\"."));
            return b;
        }

        Control AdminCard()
        {
            var card = NewCard();
            var t = Grid(2);
            var l = new Label
            {
                Text = "Running as a standard user – the greyed-out options require administrator rights.",
                AutoSize = true, Font = Theme.F(10f, Weight.SemiBold), Anchor = AnchorStyles.Left, Margin = new Padding(Ui.S(3), 0, 0, 0)
            };
            wrapLabels.Add((l, Ui.S(320)));
            t.Controls.Add(l, 0, 0);
            t.Controls.Add(Ui.B("Restart as administrator", (o, e) => RestartElevated()), 1, 0);
            card.Controls.Add(t);
            return card;
        }

        Control AppCard()
        {
            var card = NewCard();
            var t = Grid(4);
            Title(t, "Application", "Saved to suricataChecker.settings.xml next to the application, separately for this computer (" + AppSettings.Computer + ").");

            var cfg = FieldLabel("Suricata configuration (suricata.yaml)");
            t.Controls.Add(cfg); t.SetColumnSpan(cfg, 4);
            t.Controls.Add(txtSurCfg);
            t.Controls.Add(Ui.B("Browse", (o, e) => Browse(txtSurCfg, "Suricata configuration (*.yaml;*.yml)|*.yaml;*.yml|All files (*.*)|*.*")));
            t.Controls.Add(Ui.B("Open", (o, e) => OpenInEditor(txtSurCfg.Value)));
            t.Controls.Add(new Label { AutoSize = true, Margin = new Padding(0) });   // empty 4th cell

            var eve = FieldLabel("Suricata event log (eve.json)");
            eve.Margin = new Padding(Ui.S(3), Ui.S(8), 0, Ui.S(2));
            t.Controls.Add(eve); t.SetColumnSpan(eve, 4);
            t.Controls.Add(txtEve);
            t.Controls.Add(Ui.B("Browse", (o, e) => Browse(txtEve, "EVE JSON (*.json)|*.json|All files (*.*)|*.*")));
            t.Controls.Add(Ui.B("Open folder", (o, e) => OpenFolder(txtEve.Value)));
            var fromYaml = Ui.B("From yaml", (o, e) =>
            {
                var path = SystemChecks.EvePathFromYaml(txtSurCfg.Value.Trim().Trim('"'));
                if (path != null) txtEve.Value = path;
                else Ui.Warn(this, "The path to eve.json could not be determined from the Suricata configuration.");
            });
            tips.SetToolTip(fromYaml, "Reads the path of eve.json from default-log-dir / outputs in suricata.yaml.");
            t.Controls.Add(fromYaml);

            var l1 = Ui.L("Max. events shown"); l1.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            var nums = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Fill, Margin = new Padding(0, Ui.S(8), 0, 0) };
            nums.Controls.AddRange(new Control[] { l1, numMax, Ui.L("Max. MB read from the end of eve.json"), numMb });
            t.Controls.Add(nums); t.SetColumnSpan(nums, 4);
            tips.SetToolTip(numMb.Box, "eve.json grows quickly (tens to hundreds of MB a day) – only its end is read.");

            var l2 = Ui.L("Auto-refresh interval (s)"); l2.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            var refresh = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, Ui.S(8)) };
            refresh.Controls.AddRange(new Control[] { l2, numRefresh, chkAuto });
            t.Controls.Add(refresh); t.SetColumnSpan(refresh, 4);
            tips.SetToolTip(chkAuto, "Reloads the events periodically (interval on the left) while the EDR – Events page is shown.");
            // takes effect immediately; saved with the other settings
            chkAuto.CheckedChanged += (o, e) => { if (loadingUi) return; ApplyFromUi(); SettingsSaved?.Invoke(this, EventArgs.Empty); };

            var save = Ui.B("Save settings", async (o, e) => await SaveAsync(), ButtonKind.Primary);
            tips.SetToolTip(save, "Saves only the settings of this application (paths, max. events, auto-refresh)\nto suricataChecker.settings.xml. Does not change Suricata.");
            var detect = Ui.B("Auto-detect Suricata paths", async (o, e) => await AutoDetectAsync());
            tips.SetToolTip(detect, "Finds suricata.yaml and eve.json of the installed Suricata (service / Program Files).");
            Row(t, save, detect);

            card.Controls.Add(t);
            return card;
        }

        Control SuricataCard()
        {
            var card = NewCard();
            var t = Grid(1);
            Title(t, "Suricata on this computer",
                "Npcap, Suricata, the configuration and the ET Open rules from the application folder and the Suricata service are installed, " +
                "updated and checked in one window – \"Set up Suricata\" (it also opens at start when something is missing).");
            var setup = Ui.B("Set up Suricata", (o, e) => OpenSetup());
            tips.SetToolTip(setup, "Shows the state of Npcap, Suricata, the configuration, the rules and the service and installs / sets up\n" +
                                   "what is missing or outdated (administrator rights; as a standard user it offers a restart with UAC).");
            Row(t, setup,
                AdminButton("Test configuration", TestSuricataConfigAsync,
                    "Runs suricata -T with the configuration above – checks the YAML and loads all rules without capturing traffic."),
                AdminButton("Restart Suricata service", RestartServiceAsync,
                    "Restarts the Suricata Windows service – needed after a change of suricata.yaml, the rules or threshold.config."));
            card.Controls.Add(t);
            return card;
        }

        /// <summary>Opens the setup window; afterwards the page shows the paths of the deployed configuration.</summary>
        void OpenSetup()
        {
            ApplyFromUi();
            using (var f = new SetupForm(s, null, startup: false))
            {
                f.ShowDialog(this);
                if (f.RestartedElevated) { FindForm()?.Close(); return; }   // the elevated instance continues
            }
            LoadToUi();
            SettingsSaved?.Invoke(this, EventArgs.Empty);
            _ = status.RunChecksAsync();
        }

        Control MarksCard()
        {
            var card = NewCard();
            var t = Grid(1);
            Title(t, "False positives",
                "Marks are saved to marks.json next to the application, separately for this computer. A marked alert stays in the list " +
                "greyed out; the alerts of a hidden signature are left out (\"Show hidden false positives\" on the EDR – Events page). " +
                "The knowledge base holds false positives confirmed from verdicts of the AI analyzer (\"Apply verdicts\"): matching alerts " +
                "are greyed out and the next AI analysis gets the assessment and its reason.");
            wrapLabels.Add((lblMarks, Ui.S(60)));
            t.Controls.Add(lblMarks);

            var table = new System.Data.DataTable();
            Ui.AddColumn(sigGrid, table, "SID", "SID", typeof(long), 90);
            Ui.AddColumn(sigGrid, table, "Signature", "Hidden signature", typeof(string), 400, fill: true);
            sigGrid.DataSource = table;
            sigGrid.Height = Ui.S(190);
            sigGrid.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            sigGrid.Margin = new Padding(0, Ui.S(4), 0, Ui.S(8));
            t.Controls.Add(sigGrid);

            var rt = new System.Data.DataTable();
            rt.Columns.Add("_rule", typeof(object));
            Ui.AddColumn(ruleGrid, rt, "SID", "SID", typeof(long), 90);
            Ui.AddColumn(ruleGrid, rt, "Signature", "Knowledge base: signature", typeof(string), 260);
            Ui.AddColumn(ruleGrid, rt, "Scope", "Source → destination", typeof(string), 220);
            Ui.AddColumn(ruleGrid, rt, "Reason", "Reason", typeof(string), 260, fill: true);
            Ui.AddColumn(ruleGrid, rt, "By", "Assessed by", typeof(string), 150);
            Ui.AddColumn(ruleGrid, rt, "Date", "Confirmed", typeof(DateTime), 95, format: "yyyy-MM-dd");
            ruleGrid.DataSource = rt;
            ruleGrid.Height = Ui.S(190);
            ruleGrid.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            ruleGrid.Margin = new Padding(0, Ui.S(4), 0, Ui.S(8));
            t.Controls.Add(ruleGrid);

            Row(t,
                Ui.B("Remove selected assessments", (o, e) =>
                    Marks.RemoveRules(ruleGrid.SelectedRows.Cast<DataGridViewRow>()
                        .Select(r => (r.DataBoundItem as System.Data.DataRowView)?["_rule"] as FpRule).Where(x => x != null))),
                Ui.B("Show selected signatures again", (o, e) =>
                    Marks.Unhide(sigGrid.SelectedRows.Cast<DataGridViewRow>()
                        .Select(r => r.DataBoundItem is System.Data.DataRowView rv ? (long)rv["SID"] : 0L).Where(x => x != 0))),
                Ui.B("Clear all marks", (o, e) =>
                {
                    if (MessageBox.Show(this, "Remove all false positive marks and knowledge base assessments and show all hidden signatures again (this computer)?",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                        Marks.ClearAll();
                }));

            Marks.Changed += (o, e) => RefreshMarks();
            RefreshMarks();
            card.Controls.Add(t);
            return card;
        }

        void RefreshMarks()
        {
            int hidden = Marks.HiddenSignatures.Count, marked = Marks.MarkedEvents;
            lblMarks.Text = $"{marked} alert(s) marked as false positive · {hidden} signature(s) hidden · {Marks.Rules.Count} assessment(s) in the knowledge base";
            var table = (System.Data.DataTable)sigGrid.DataSource;
            table.Rows.Clear();
            foreach (var kv in Marks.HiddenSignatures) table.Rows.Add(kv.Key, kv.Value);
            var rt = (System.Data.DataTable)ruleGrid.DataSource;
            rt.Rows.Clear();
            foreach (var r in Marks.Rules)
                rt.Rows.Add(r, r.Sid, r.Signature, r.Scope, r.Reason, r.By, r.Date == default ? (object)DBNull.Value : r.Date);
        }

        // ------------------------------------------------------------------ settings

        bool loadingUi, uiLoaded;

        public void LoadToUi()
        {
            loadingUi = true;   // the toggles fire CheckedChanged -> ApplyFromUi would read half-filled fields
            try
            {
                txtSurCfg.Value = s.SuricataConfigPath;
                txtEve.Value = s.SuricataEvePath;
                numMax.Value = s.MaxEvents;
                numRefresh.Value = s.RefreshSeconds;
                numMb.Value = s.EveMaxMegabytes;
                chkAuto.Checked = s.AutoRefresh;
                LoadAiToUi();
            }
            finally { loadingUi = false; uiLoaded = true; }
        }

        public void ApplyFromUi()
        {
            if (!uiLoaded) return;   // the fields are still empty (start of the application)
            s.SuricataConfigPath = txtSurCfg.Value.Trim().Trim('"');
            s.SuricataEvePath = txtEve.Value.Trim().Trim('"');
            s.MaxEvents = numMax.Value;
            s.RefreshSeconds = numRefresh.Value;
            s.EveMaxMegabytes = numMb.Value;
            s.AutoRefresh = chkAuto.Checked;
            ApplyAiFromUi();
        }

        async Task SaveAsync()
        {
            ApplyFromUi();
            try { s.Save(); }
            catch (Exception ex) { Ui.Warn(this, "The settings could not be saved:\n" + ex.Message); }
            SettingsSaved?.Invoke(this, EventArgs.Empty);
            await status.RunChecksAsync();
        }

        async Task AutoDetectAsync()
        {
            ApplyFromUi();
            await Task.Run(() => SystemChecks.AutoDetect(s, true));
            LoadToUi();
            SettingsSaved?.Invoke(this, EventArgs.Empty);
            await status.RunChecksAsync();
        }

        void Browse(Field target, string filter)
        {
            using (var dlg = new OpenFileDialog { Filter = filter, CheckFileExists = true })
            {
                try
                {
                    string cur = target.Value.Trim();
                    if (cur.Length > 0)
                    {
                        string dir = Directory.Exists(cur) ? cur : Path.GetDirectoryName(cur);
                        if (Directory.Exists(dir)) dlg.InitialDirectory = dir;
                        if (File.Exists(cur)) dlg.FileName = Path.GetFileName(cur);
                    }
                }
                catch { }
                if (dlg.ShowDialog(this) == DialogResult.OK) target.Value = dlg.FileName;
            }
        }

        void OpenInEditor(string path)
        {
            path = path.Trim().Trim('"');
            if (!File.Exists(path)) { Ui.Warn(this, "The file does not exist:\n" + path); return; }
            Process.Start("notepad.exe", "\"" + path + "\"");
        }

        void OpenFolder(string path)
        {
            path = path.Trim().Trim('"');
            if (File.Exists(path)) { Process.Start("explorer.exe", "/select,\"" + path + "\""); return; }
            string dir = null;
            try { dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path); } catch { }
            if (dir != null && Directory.Exists(dir)) Process.Start("explorer.exe", "\"" + dir + "\"");
            else Ui.Warn(this, "The folder does not exist:\n" + path);
        }

        // ------------------------------------------------------------------ actions (administrator)

        async Task TestSuricataConfigAsync()
        {
            ApplyFromUi();
            if (status.SuricataExe == null) await status.RunChecksAsync();
            string cfg = s.SuricataConfigPath, exe = status.SuricataExe;
            if (!File.Exists(cfg)) { Ui.Warn(this, "The Suricata configuration file does not exist:\n" + cfg); return; }
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) { Ui.Warn(this, "suricata.exe was not found – is Suricata installed?"); return; }
            if (!SystemChecks.WpcapPresent()) { Ui.Warn(this, SystemChecks.WpcapMissingText); return; }
            // this runs as administrator: a suricata.exe a standard user can replace is never started, and a configuration
            // a standard user can edit (it can load plugins and Lua scripts) only after a confirmation
            if (SystemChecks.WritableByStandardUsers(exe))
            {
                Ui.Warn(this, "suricata.exe or its folder can be changed by standard users:\n" + exe +
                              "\n\nIt is not started with administrator rights. Fix the permissions of the Suricata folder (only administrators may write).");
                return;
            }
            if (SystemChecks.WritableByStandardUsers(cfg) && MessageBox.Show(this,
                    "The configuration file or its folder can be changed by standard users:\n" + cfg +
                    "\n\nSuricata loads plugins and scripts named in the configuration – it will run with administrator rights. Test it anyway?",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            // the ET Open rules come with Install-SuricataConfig.ps1, not with the Suricata installer
            var missing = SystemChecks.MissingRuleFiles(cfg, out string ruleDir, out int listed);
            if (missing.Count > 0)
            {
                if (MessageBox.Show(this,
                        $"{missing.Count} of {listed} rule files named in the configuration are missing in\n{ruleDir}\n\n" +
                        string.Join(", ", missing.Take(6)) + (missing.Count > 6 ? ", …" : "") + "\n\n" +
                        "The ET Open rules are not part of the Suricata installer – \"Set up Suricata\" downloads, checks and deploys them " +
                        "(with the configuration and the service). Without them suricata -T stops at the first missing file.\n\nOpen \"Set up Suricata\"?",
                        Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    OpenSetup();
                return;
            }

            Cursor = Cursors.WaitCursor;
            try
            {
                var r = await Task.Run(() => SystemChecks.RunProcess(exe, $"-T -c \"{cfg}\" -v", 180000));
                Ui.ShowText(this, $"Suricata -T  (exit code {r.ExitCode}{(r.ExitCode == 0 ? " – configuration OK" : SystemChecks.ExitCodeNote(r.ExitCode))})", r.Output);
            }
            catch (Exception ex) { Ui.Warn(this, "suricata -T could not be started:\n" + ex.Message); }
            finally { Cursor = Cursors.Default; }
        }

        async Task RestartServiceAsync()
        {
            if (status.SuricataExe == null) await status.RunChecksAsync();
            string name = status.ServiceName;
            if (string.IsNullOrEmpty(name))
            {
                // not installed, or installed by the MSI without the service (the installer does not create it)
                if (MessageBox.Show(this, (string.IsNullOrEmpty(status.SuricataExe) ? "Suricata is not installed on this computer."
                        : "The Suricata service is not registered – the Suricata installer does not create it.") + "\n\nOpen \"Set up Suricata\"?",
                        Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    OpenSetup();
                return;
            }
            if (MessageBox.Show(this, $"Restart the service \"{name}\"?\nSuricata does not capture traffic for a few seconds.",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Cursor = Cursors.WaitCursor;
            try
            {
                await Task.Run(() =>
                {
                    using (var sc = new ServiceController(name))
                    {
                        if (sc.Status != ServiceControllerStatus.Stopped)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
                        }
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
                    }
                });
            }
            catch (Exception ex) { Ui.Warn(this, "The service could not be restarted:\n" + ex.Message); }
            finally { Cursor = Cursors.Default; }
            await status.RunChecksAsync();
        }

        void RestartElevated()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { Verb = "runas", UseShellExecute = true });
                FindForm()?.Close();
            }
            catch (Win32Exception) { }   // UAC prompt cancelled
        }
    }
}
