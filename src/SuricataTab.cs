using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>"EDR – Events" page: reads and filters events from eve.json.</summary>
    class SuricataTab : UserControl, ILazyTab
    {
        // alert severity colours: 1 (and drop) = the attention beige, 2 = darker beige, 3+ = dark row with beige text
        static readonly Color Sev2Bg = Color.FromArgb(0xC2, 0xB0, 0xA5), Sev2Selected = Color.FromArgb(0xD2, 0xC2, 0xB8);
        static readonly Color Sev3Bg = Color.FromArgb(0x3D, 0x37, 0x33), Sev3Selected = Color.FromArgb(0x4D, 0x46, 0x41);

        readonly AppSettings s;
        readonly DarkCombo cboType = new DarkCombo(130, editable: true);
        readonly DarkCombo cboSev = new DarkCombo(170);
        readonly TimeRangeSelector time = new TimeRangeSelector(2);
        readonly Field txtIp = new Field(130), txtText = new Field(200);
        readonly NumberField numMax = new NumberField(10, 100000, 100, 75);
        readonly Toggle chkHidden = new Toggle("Show hidden false positives");
        readonly Button btnLoad;
        readonly DataGridView grid = Ui.CreateGrid();
        readonly EventDetailView txtDetail = new EventDetailView();
        readonly SplitContainer split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = Theme.Bg, SplitterWidth = Ui.S(12) };
        readonly Label lblStatus = new Label { Dock = DockStyle.Bottom, Height = Ui.S(28), TextAlign = ContentAlignment.BottomLeft, ForeColor = Theme.SubText };
        readonly DataTable table = new DataTable();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Card filters = new Card { Dock = DockStyle.Top, Padding = new Padding(Ui.S(10), Ui.S(8), Ui.S(10), Ui.S(8)) };
        readonly TableLayoutPanel filterGrid = new TableLayoutPanel { Dock = DockStyle.Top, Margin = new Padding(0) };
        readonly List<Label> filterLabels = new List<Label>();
        readonly (string Label, Control Control)[] filterFields;
        readonly FlowLayoutPanel filterActions;
        int filterPairs;
        List<SuricataEvent> events = new List<SuricataEvent>();
        CancellationTokenSource cts;
        bool loading, loadedOnce, reloadPending, restartPending;
        // last complete read – auto-refresh with the same filters then reads only the lines added since
        SuricataResult lastResult;
        string lastKey;

        public SuricataTab(AppSettings settings)
        {
            s = settings;
            Dock = DockStyle.Fill;

            cboType.Items.AddRange(new object[] { "All", "alert", "anomaly", "drop", "dns", "http", "tls", "fileinfo", "flow", "netflow", "ssh", "smb", "smtp", "ftp", "dhcp", "krb5", "rdp", "quic", "stats" });
            cboType.SelectedIndex = 1;
            cboSev.Items.AddRange(new object[] { "All", "1 – high", "≤ 2 – high and medium", "≤ 3" });
            cboSev.SelectedIndex = 0;

            btnLoad = Ui.B("Load", async (o, e) => await LoadAsync(false), ButtonKind.Primary);
            // applies the event type filter right away
            var btnFilter = Ui.B("Filter", async (o, e) => await ReloadAsync());
            var tip = new ToolTip();
            tip.SetToolTip(btnFilter, "Shows the events of the selected / typed event type.");
            tip.SetToolTip(cboType, "Event type from eve.json (event_type). A custom value can also be typed.");
            tip.SetToolTip(cboSev, "Alert severity (1 = highest). With this filter only alerts are shown.");
            tip.SetToolTip(txtIp.Box, "Source or destination IP: an address (exact match, e.g. 10.0.0.1), a range (10.0.0.0/24)" + Environment.NewLine + "or a part of the address (e.g. 192.168.)");
            tip.SetToolTip(txtText.Box, "Full-text search in the whole JSON event (signature, domain, URL…). Prefix ! = exclude.");

            // event type box + Filter button share one grid cell
            var typeCell = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, Height = Ui.S(38), Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0) };
            typeCell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            typeCell.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            cboType.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            typeCell.Controls.Add(cboType, 0, 0);
            typeCell.Controls.Add(btnFilter, 1, 0);

            filterFields = new[]
            {
                ("Type", (Control)typeCell), ("Time", time.Preset), ("From", time.From), ("To", time.To),
                ("Severity", cboSev), ("IP", txtIp), ("Text", txtText), ("Max. events", numMax)
            };
            foreach (var (label, ctl) in filterFields)
            {
                filterLabels.Add(new Label { Text = label, AutoSize = true, ForeColor = Theme.SubText, Anchor = AnchorStyles.Left, Margin = new Padding(Ui.S(4), 0, Ui.S(8), 0) });
                if (ctl != numMax) ctl.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            }
            filterActions = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, Ui.S(4), 0, 0) };
            filterActions.Controls.AddRange(new Control[]
            {
                btnLoad,
                Ui.B("Clear filters", (o, e) => ClearFilters()),
                Ui.B("Export CSV", (o, e) => Ui.ExportCsv(this, grid, "suricata")),
                Ui.B("AI analyzer", (o, e) => OpenAiAnalyzer()),
                chkHidden
            });
            tip.SetToolTip(chkHidden, "Shows also the alerts of signatures hidden as false positives (Settings page lists them).");
            chkHidden.CheckedChanged += async (o, e) => await ReloadAsync();
            time.PresetChanged += async (o, e) => await ReloadAsync();   // a different time window: load it now
            // layout and height follow the width of the card (computed – AutoSize does not grow the card reliably)
            filters.SizeChanged += (o, e) => ArrangeFilters();
            ArrangeFilters();
            foreach (Control c in new Control[] { cboType, txtIp.Box, txtText.Box })
                c.KeyDown += async (o, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ReloadAsync(); } };

            table.Columns.Add("_idx", typeof(int));
            Ui.AddColumn(grid, table, "Time", "Time", typeof(DateTime), 150, format: Ui.DateFormatMs);
            Ui.AddColumn(grid, table, "Type", "Type", typeof(string), 70);
            Ui.AddColumn(grid, table, "Sev", "Severity", typeof(int), 75);
            Ui.AddColumn(grid, table, "Detail", "Signature / detail", typeof(string), 380, fill: true);
            Ui.AddColumn(grid, table, "Category", "Category", typeof(string), 200);
            Ui.AddColumn(grid, table, "Source", "Source", typeof(string), 150);
            Ui.AddColumn(grid, table, "Dest", "Destination", typeof(string), 150);
            Ui.AddColumn(grid, table, "Proto", "Proto", typeof(string), 55);
            Ui.AddColumn(grid, table, "App", "App", typeof(string), 60);
            Ui.AddColumn(grid, table, "Action", "Action", typeof(string), 70);
            Ui.AddColumn(grid, table, "Mark", "Mark", typeof(string), 120);
            Ui.AddColumn(grid, table, "SID", "SID", typeof(long), 85);
            grid.DataSource = table;
            grid.SelectionChanged += (o, e) => ShowDetail();
            grid.CellFormatting += Grid_CellFormatting;
            AttachMarkMenu(Ui.AttachCellMenu(grid, async v => { txtText.Value = v; await ReloadAsync(); }));
            // a changed mark reloads the list – after the running load, if one is in progress
            Marks.Changed += async (o, e) =>
            {
                if (!loadedOnce) return;
                if (loading) reloadPending = true;
                else await LoadAsync(true);
            };

            filters.Controls.Add(filterGrid);
            var detailCard = new Card { Dock = DockStyle.Fill, Margin = new Padding(0) };
            detailCard.Controls.Add(txtDetail);
            split.Panel1.Controls.Add(grid);
            split.Panel2.Controls.Add(detailCard);
            split.FixedPanel = FixedPanel.Panel2;
            var gap = new Panel { Dock = DockStyle.Top, Height = Ui.S(10) };

            Controls.Add(split);
            Controls.Add(gap);
            Controls.Add(filters);
            Controls.Add(lblStatus);

            // initial detail panel height, once the page has its real size
            bool splitSet = false;
            split.SizeChanged += (o, e) =>
            {
                if (splitSet || split.Height < Ui.S(400)) return;
                try { split.SplitterDistance = split.Height - Ui.S(260); splitSet = true; } catch { }
            };
            // auto-refresh (on/off and interval) is set on the Settings page; it runs while this page is shown
            timer.Tick += async (o, e) => { if (s.AutoRefresh && !loading && Visible) await LoadAsync(true); };
            lblStatus.Text = "Press \"Load\" to load Suricata events.";
            ApplySettings();
        }

        /// <summary>
        /// Filters as a grid of "label | field" pairs with aligned columns: 4 pairs per row in a wide window,
        /// 2 pairs in a narrow one; the buttons on the last row.
        /// </summary>
        void ArrangeFilters()
        {
            int width = filters.ClientSize.Width - filters.Padding.Horizontal;
            if (width <= 0) return;
            int pairs = width >= Ui.S(1050) ? 4 : 2;
            if (pairs != filterPairs) BuildFilterGrid(pairs);
            int height = filterGrid.GetPreferredSize(new Size(width, 0)).Height;
            if (filterGrid.Height != height) filterGrid.Height = height;
            if (filters.Height != height + filters.Padding.Vertical) filters.Height = height + filters.Padding.Vertical;
        }

        void BuildFilterGrid(int pairs)
        {
            filterPairs = pairs;
            filterGrid.SuspendLayout();
            filterGrid.Controls.Clear();
            filterGrid.ColumnStyles.Clear();
            filterGrid.RowStyles.Clear();
            filterGrid.ColumnCount = pairs * 2;
            filterGrid.RowCount = (filterFields.Length + pairs - 1) / pairs + 1;
            // the first field (type + Filter) gets more room in the wide layout
            float[] weights = pairs == 4 ? new[] { 31f, 23f, 23f, 23f } : new[] { 50f, 50f };
            foreach (float w in weights)
            {
                filterGrid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                filterGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, w));
            }
            for (int i = 0; i < filterFields.Length; i++)
            {
                int col = (i % pairs) * 2, row = i / pairs;
                filterGrid.Controls.Add(filterLabels[i], col, row);
                filterGrid.Controls.Add(filterFields[i].Control, col + 1, row);
            }
            filterGrid.Controls.Add(filterActions, 0, filterGrid.RowCount - 1);
            filterGrid.SetColumnSpan(filterActions, pairs * 2);
            filterGrid.ResumeLayout(true);
        }

        public void ApplySettings()
        {
            numMax.Value = s.MaxEvents;
            timer.Interval = Math.Max(2, s.RefreshSeconds) * 1000;
            timer.Enabled = s.AutoRefresh;
        }

        public async Task EnsureLoadedAsync()
        {
            if (!loadedOnce) await LoadAsync(true);
        }

        void ClearFilters()
        {
            cboType.SelectedIndex = 0;
            cboSev.SelectedIndex = 0;
            txtIp.Value = txtText.Value = "";
        }

        SuricataQuery BuildQuery()
        {
            string type = cboType.Text.Trim();
            var q = new SuricataQuery
            {
                EventType = type == "All" ? "" : type,
                Ip = txtIp.Value.Trim(),
                Text = txtText.Value.Trim(),
                Max = numMax.Value,
                MaxBytes = Math.Max(1, s.EveMaxMegabytes) * 1024L * 1024L,
                MaxSeverity = cboSev.SelectedIndex == 0 ? (int?)null : cboSev.SelectedIndex,
                HiddenSids = chkHidden.Checked ? null : Marks.HiddenSidsSnapshot()
            };
            time.GetRange(out q.From, out q.To);
            return q;
        }

        /// <summary>Filter, Enter, a cell menu item: a running load is stopped and started again with the new filters.</summary>
        Task ReloadAsync()
        {
            if (!loading) return LoadAsync(false);
            restartPending = true;
            cts?.Cancel();
            return Task.CompletedTask;
        }

        public async Task LoadAsync(bool auto)
        {
            if (loading) { if (!auto) { restartPending = false; cts?.Cancel(); } return; }   // the Stop button
            SuricataQuery q;
            try { q = BuildQuery(); }
            catch (Exception ex) { Ui.Warn(this, ex.Message); return; }

            string path = s.SuricataEvePath;
            loading = true;
            loadedOnce = true;
            btnLoad.Text = "Stop";
            lblStatus.Text = "Loading Suricata events…";
            cts = new CancellationTokenSource();
            var token = cts.Token;
            var sw = Stopwatch.StartNew();
            string key = QueryKey(path, q) + "|" + time.Key;   // another time window = full read, not only the new lines
            var previous = auto && key == lastKey ? lastResult : null;
            lastResult = null; lastKey = null;
            try
            {
                var res = await Task.Run(() => ReadOrUpdate(path, q, previous, token));
                bool incremental = res.Incremental;
                if (!token.IsCancellationRequested) { lastResult = res; lastKey = key; }   // a stopped read is incomplete
                Bind(res.Events);
                var alerts = res.Events.Where(e => e.Severity.HasValue).ToList();
                lblStatus.ForeColor = Theme.SubText;
                lblStatus.Text = $"Showing {res.Events.Count} events"
                                 + (alerts.Count > 0 ? $" (alerts – sev 1: {alerts.Count(a => a.Severity == 1)}, sev 2: {alerts.Count(a => a.Severity == 2)}, sev 3+: {alerts.Count(a => a.Severity >= 3)})" : "")
                                 + $" · {path} ({SystemChecks.FormatSize(res.FileSize)}"
                                 + (res.Partial ? $", last {SystemChecks.FormatSize(res.BytesRead)} read" : "") + ")"
                                 + (res.ParseErrors > 0 ? $" · invalid lines: {res.ParseErrors}" : "")
                                 + (res.Hidden > 0 ? $" · {res.Hidden} hidden false positives" : "")
                                 + (token.IsCancellationRequested ? " · stopped" : "")
                                 + (incremental ? " · new lines only" : "")
                                 + $" · {sw.Elapsed.TotalSeconds:0.00} s · updated {DateTime.Now:HH:mm:ss}";
            }
            catch (Exception ex)
            {
                lblStatus.ForeColor = Theme.Error;
                lblStatus.Text = "Error: " + ex.Message;
                if (!auto) Ui.Warn(this, ex.Message);
            }
            finally
            {
                loading = false;
                btnLoad.Text = "Load";
            }
            if (restartPending || reloadPending)
            {
                bool manual = restartPending;
                restartPending = reloadPending = false;
                await LoadAsync(!manual);
            }
        }

        static string QueryKey(string path, SuricataQuery q) =>
            string.Join("|", path, q.EventType, q.Ip, q.Text, q.Max, q.MaxBytes, q.MaxSeverity,
                q.HiddenSids == null ? "all" : string.Join(",", q.HiddenSids.OrderBy(x => x)),
                q.To?.ToString("o") ?? "");   // the moving "from" of a preset is in TimeRangeSelector.Key (the preset, not the time)

        /// <summary>
        /// Full read, or – when the previous complete read had the same filters and the file only grew – just the lines added
        /// since, merged with the previous events (those that fell out of the time window are dropped).
        /// </summary>
        static SuricataResult ReadOrUpdate(string path, SuricataQuery q, SuricataResult previous, CancellationToken ct)
        {
            if (previous != null)
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (!fi.Exists || fi.Length < previous.CompleteEnd || fi.CreationTimeUtc != previous.FileCreatedUtc) previous = null;   // rotated / replaced
                }
                catch { previous = null; }
            }
            if (previous == null) return SuricataReader.Read(path, q, ct);

            var added = SuricataReader.Read(path, q, ct, previous.CompleteEnd);
            if (ct.IsCancellationRequested) return added;
            var merged = added.Events.Concat(previous.Events
                    .Where(e => (!q.From.HasValue || e.Time >= q.From.Value) && (!q.To.HasValue || e.Time <= q.To.Value)))
                .Take(q.Max).ToList();
            return new SuricataResult
            {
                Events = merged,
                FileSize = added.FileSize,
                CompleteEnd = added.CompleteEnd,
                FileCreatedUtc = added.FileCreatedUtc,
                BytesRead = previous.BytesRead + (added.FileSize - previous.FileSize),
                Partial = previous.Partial,
                LinesScanned = previous.LinesScanned + added.LinesScanned,
                ParseErrors = previous.ParseErrors + added.ParseErrors,
                Hidden = previous.Hidden + added.Hidden,
                Incremental = true,
            };
        }

        void Bind(List<SuricataEvent> list)
        {
            string selected = Selected()?.Raw;
            events = list;
            table.BeginLoadData();
            table.Rows.Clear();
            for (int i = 0; i < list.Count; i++)
            {
                var e = list[i];
                table.Rows.Add(i, e.Time, e.EventType, (object)e.Severity ?? DBNull.Value, e.Summary, e.Category, e.Src, e.Dest,
                    e.Proto, e.AppProto, e.Action, MarkText(e), (object)e.Sid ?? DBNull.Value);
            }
            table.EndLoadData();

            if (selected != null)
                foreach (DataGridViewRow r in grid.Rows)
                    if (r.DataBoundItem is DataRowView rv && events[(int)rv["_idx"]].Raw == selected)
                    {
                        grid.CurrentCell = r.Cells["Time"];
                        break;
                    }
            ShowDetail();
        }

        SuricataEvent Selected()
        {
            if (grid.CurrentRow?.DataBoundItem is DataRowView rv)
            {
                int i = (int)rv["_idx"];
                if (i >= 0 && i < events.Count) return events[i];
            }
            return null;
        }

        static KeyValuePair<string, string> Row(string k, string v) => new KeyValuePair<string, string>(k, v ?? "");

        void ShowDetail()
        {
            var e = Selected();
            if (e == null) { txtDetail.Display(null, null); return; }
            var summary = new List<KeyValuePair<string, string>>
            {
                Row("Time", e.Time.ToString(Ui.DateFormatMs)),
                Row("Type", e.EventType),
                Row("Connection", $"{e.Proto} {e.Src} → {e.Dest}  {e.AppProto}".Trim()),
            };
            if (e.Severity.HasValue)
            {
                summary.Add(Row("Alert", $"[{e.Sid}] {e.Signature}"));
                summary.Add(Row("Category", e.Category));
                summary.Add(Row("Severity", $"{e.Severity}   action: {e.Action}"));
            }
            string mark = MarkText(e);
            if (mark.Length > 0) summary.Add(Row("Marked", mark));
            var rule = Marks.RuleFor(e);
            if (rule != null)
                summary.Add(Row("Assessment", $"{rule.Reason}  ({rule.By}, {rule.Confidence} confidence, confirmed {rule.Date:yyyy-MM-dd}, scope {rule.Scope})"));
            txtDetail.Display(summary, SuricataReader.Flatten(e.Raw));
        }

        /// <summary>AI analyzer over the shown / selected events (a snapshot – later reloads do not change it).</summary>
        void OpenAiAnalyzer()
        {
            if (events.Count == 0) { Ui.Warn(this, "Load events first – the AI analyzer works with the events shown in the table."); return; }
            var selected = grid.SelectedRows.Cast<DataGridViewRow>()
                .Select(r => r.DataBoundItem as DataRowView).Where(rv => rv != null)
                .Select(rv => events[(int)rv["_idx"]]).OrderByDescending(e => e.Time).ToList();
            var parts = new List<string> { "event type " + cboType.Text, "time " + time.Preset.Text, "severity " + cboSev.Text };
            if (txtIp.Value.Trim().Length > 0) parts.Add("IP contains \"" + txtIp.Value.Trim() + "\"");
            if (txtText.Value.Trim().Length > 0) parts.Add("text \"" + txtText.Value.Trim() + "\" (prefix ! = excluded)");
            parts.Add(chkHidden.Checked ? "hidden false positives shown" : "signatures hidden as false positives left out");
            parts.Add("max. " + numMax.Value + " events");
            new AiAnalyzerForm(s, SuricataAi.Source(events, selected, string.Join("; ", parts))).Show(FindForm());
        }

        static string MarkText(SuricataEvent e) =>
            Marks.IsHidden(e) ? "false positive (signature hidden)" : Marks.IsMarked(e) ? "false positive"
            : Marks.RuleFor(e) != null ? "false positive (knowledge base)" : "";

        /// <summary>Event of the row under the mouse (the menu is opened by a right click on a row).</summary>
        SuricataEvent EventAtCursor()
        {
            var hit = grid.HitTest(grid.PointToClient(Cursor.Position).X, grid.PointToClient(Cursor.Position).Y);
            if (hit.RowIndex >= 0 && grid.Rows[hit.RowIndex].DataBoundItem is DataRowView rv)
            {
                int i = (int)rv["_idx"];
                if (i >= 0 && i < events.Count) return events[i];
            }
            return null;
        }

        /// <summary>False positive items in the right-click menu of the table.</summary>
        void AttachMarkMenu(ContextMenuStrip menu)
        {
            SuricataEvent target = null;
            var sep = new ToolStripSeparator();
            var miMark = new ToolStripMenuItem("", null, (o, e) => ToggleMark(target));
            var miHide = new ToolStripMenuItem("", null, (o, e) => ToggleHide(target));
            var miRule = new ToolStripMenuItem("Remove the false positive assessment (knowledge base)", null, (o, e) =>
            {
                var rule = target == null ? null : Marks.RuleFor(target);
                if (rule != null && MessageBox.Show(this, $"Remove this assessment from the knowledge base?\n\n[{rule.Sid}] {rule.Signature}\n" +
                        $"{rule.Scope}\n{rule.Reason}", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    Marks.RemoveRules(new[] { rule });
            });
            menu.Items.AddRange(new ToolStripItem[] { sep, miMark, miHide, miRule });
            menu.Opening += (o, e) =>
            {
                target = EventAtCursor() ?? Selected();
                bool any = target != null, alert = any && target.Sid.HasValue;
                miMark.Visible = any;
                miMark.Text = any && Marks.IsMarked(target) ? "Unmark false positive" : "Mark as false positive";
                miHide.Visible = alert;
                miRule.Visible = alert && Marks.RuleFor(target) != null;
                sep.Visible = any;
                if (alert)
                    miHide.Text = Marks.IsHidden(target)
                        ? $"Show the alerts of this signature again (SID {target.Sid})"
                        : $"Mark all alerts of this signature as false positive and hide them (SID {target.Sid})";
            };
        }

        void ToggleMark(SuricataEvent ev)
        {
            if (ev == null) return;
            bool mark = !Marks.IsMarked(ev);
            Marks.SetMarked(ev, mark);
            if (!mark || !ev.Sid.HasValue || Marks.IsHidden(ev)) return;
            // a severity 1–2 alert is not offered to be hidden as a whole – one false positive does not make every future
            // alert of the signature harmless (it can still be hidden on purpose from the menu, with a warning)
            if (ev.Severity <= 2) return;
            // offer to mark and hide the same alerts (same signature) as well
            int same = events.Count(x => x.Sid == ev.Sid && x != ev);
            if (MessageBox.Show(this,
                    $"Mark all alerts with the same signature as false positive and hide them?\n\n[{ev.Sid}] {ev.Signature}\n\n" +
                    $"{same} more such alert(s) in the current list; future alerts of this signature are hidden too.\n" +
                    "They can be shown again with \"Show hidden false positives\" or on the Settings page.",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                Marks.Hide(ev.Sid.Value, ev.Signature);
        }

        void ToggleHide(SuricataEvent ev)
        {
            if (ev?.Sid == null) return;
            if (Marks.IsHidden(ev)) { Marks.Unhide(new[] { ev.Sid.Value }); return; }
            if (ev.Severity <= 2 && MessageBox.Show(this,
                    $"This is a severity {ev.Severity} alert:\n\n[{ev.Sid}] {ev.Signature}\n\n" +
                    "Hiding the signature hides ALL its future alerts – from every source and to every destination, also real attacks. " +
                    "Consider marking only this alert as false positive, or suppressing the signature for one host in threshold.config.\n\n" +
                    "Hide all alerts of this signature anyway?",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            Marks.Hide(ev.Sid.Value, ev.Signature);
        }

        void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || !(grid.Rows[e.RowIndex].DataBoundItem is DataRowView rv)) return;
            if ((rv["Mark"] as string)?.Length > 0)
            {
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.Muted;
                return;
            }
            int? sev = rv["Sev"] is int v ? v : (int?)null;
            if ((rv["Type"] as string) == "drop") sev = 1;
            if (!sev.HasValue) return;
            if (sev <= 1)
            {
                e.CellStyle.BackColor = Theme.SuspiciousBg;
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.SuspiciousText;
                e.CellStyle.SelectionBackColor = Theme.SuspiciousSelected;
            }
            else if (sev == 2)
            {
                e.CellStyle.BackColor = Sev2Bg;
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.SuspiciousText;
                e.CellStyle.SelectionBackColor = Sev2Selected;
            }
            else
            {
                e.CellStyle.BackColor = Sev3Bg;
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.Attention;
                e.CellStyle.SelectionBackColor = Sev3Selected;
            }
        }
    }
}
