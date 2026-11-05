using System;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    interface ILazyTab
    {
        Task EnsureLoadedAsync();
        void ApplySettings();
    }

    static class Ui
    {
        public const string DateFormat = "yyyy-MM-dd HH:mm:ss";
        public const string DateFormatMs = "yyyy-MM-dd HH:mm:ss.fff";

        static float? dpiScale;

        /// <summary>Converts pixels from 96 DPI to the current DPI (column widths etc.).</summary>
        public static int S(int px)
        {
            if (!dpiScale.HasValue)
                using (var g = Graphics.FromHwnd(IntPtr.Zero)) dpiScale = g.DpiX / 96f;
            return (int)Math.Round(px * dpiScale.Value);
        }

        public static Label L(string text) => new Label { Text = text, AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(S(10), S(10), S(2), 0) };

        /// <summary>Label + control that wrap together in a FlowLayoutPanel.</summary>
        public static Control Pair(string label, Control control)
        {
            var p = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Margin = new Padding(0) };
            p.Controls.Add(L(label));
            p.Controls.Add(control);
            return p;
        }

        public static Button B(string text, EventHandler click, ButtonKind kind = ButtonKind.Secondary)
        {
            var b = new FlatButton(text, kind);
            if (click != null) b.Click += click;
            return b;
        }

        public static TextBox DetailBox() => new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Dock = DockStyle.Fill,
            Font = Theme.Mono,
            BackColor = Theme.Surface,
            ForeColor = Color.FromArgb(0xE6, 0xE6, 0xE6),
            BorderStyle = BorderStyle.None
        }.Also(Theme.DarkScrollBars);

        public static T Also<T>(this T c, Action<T> a) { a(c); return c; }

        public static DataGridView CreateGrid()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AutoGenerateColumns = false,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = true,
                RowHeadersVisible = false,
                BackgroundColor = Theme.Bg,
                BorderStyle = BorderStyle.None,
                ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableWithAutoHeaderText,
                EnableHeadersVisualStyles = false,
                CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None,
                GridColor = Theme.Line,
            };
            g.RowTemplate.Height = S(30);
            g.DefaultCellStyle.BackColor = Theme.Bg;
            g.DefaultCellStyle.ForeColor = Theme.Text;
            g.DefaultCellStyle.SelectionBackColor = Theme.Hover;
            g.DefaultCellStyle.SelectionForeColor = Theme.Text;
            g.DefaultCellStyle.Font = Theme.F(9.5f);
            g.DefaultCellStyle.Padding = new Padding(S(6), 0, S(4), 0);
            g.ColumnHeadersDefaultCellStyle.BackColor = Theme.Bg;
            g.ColumnHeadersDefaultCellStyle.ForeColor = Theme.SubText;
            g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Bg;
            g.ColumnHeadersDefaultCellStyle.Font = Theme.F(9.5f, Weight.Bold);
            g.ColumnHeadersDefaultCellStyle.Padding = new Padding(S(6), S(8), S(4), S(8));
            // dark scroll bars (the grid hosts them as child controls)
            g.HandleCreated += (s, e) => { foreach (Control c in g.Controls) Theme.DarkScrollBars(c); };
            g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            g.DefaultCellStyle.WrapMode = DataGridViewTriState.False;
            typeof(DataGridView).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)?.SetValue(g, true, null);
            return g;
        }

        public static void AddColumn(DataGridView grid, DataTable table, string name, string header, Type type, int width, bool fill = false, string format = null)
        {
            table.Columns.Add(name, type);
            var c = new DataGridViewTextBoxColumn
            {
                Name = name,
                DataPropertyName = name,
                HeaderText = header,
                Width = S(width),
                SortMode = DataGridViewColumnSortMode.Automatic
            };
            if (fill) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; c.MinimumWidth = S(200); }
            if (format != null) c.DefaultCellStyle.Format = format;
            grid.Columns.Add(c);
        }

        /// <summary>Right click on a cell: copy / search the value.</summary>
        public static ContextMenuStrip AttachCellMenu(DataGridView grid, Action<string> searchValue)
        {
            var menu = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), Font = Theme.F(9.5f) };
            string cellValue = "";
            menu.Items.Add("Copy value", null, (s, e) => { if (cellValue.Length > 0) CopyToClipboard(grid, cellValue); });
            menu.Items.Add("Search for this value", null, (s, e) => searchValue(cellValue));
            menu.Items.Add("Copy selected rows", null, (s, e) =>
            {
                var data = grid.GetClipboardContent();
                if (data != null) CopyToClipboard(grid, data);
            });
            grid.CellMouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.ColumnIndex < 0) return;
                if (!grid.Rows[e.RowIndex].Selected) grid.CurrentCell = grid[e.ColumnIndex, e.RowIndex];
                cellValue = grid[e.ColumnIndex, e.RowIndex].FormattedValue?.ToString() ?? "";
                menu.Show(Cursor.Position);
            };
            return menu;
        }

        /// <summary>
        /// Clipboard write that does not end in an error dialog: another process (a clipboard manager, a remote session)
        /// may hold the clipboard for a moment – a few retries, then a short message.
        /// </summary>
        public static void CopyToClipboard(Control owner, object data)
        {
            try
            {
                if (data is string text) Clipboard.SetDataObject(text, true, 5, 100);
                else Clipboard.SetDataObject(data, true, 5, 100);
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.ExternalException || ex is System.Threading.ThreadStateException)
            {
                Warn(owner, "The clipboard is used by another program – try again.");
            }
        }

        /// <summary>Writes an export / report; an error (folder read-only, file open in Excel…) is reported, not thrown.</summary>
        public static bool TryWriteFile(IWin32Window owner, string path, string content, Encoding encoding)
        {
            try { File.WriteAllText(path, content, encoding); return true; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException)
            {
                MessageBox.Show(owner, "The file could not be saved:\n" + path + "\n\n" + ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }

        /// <summary>An export / report holds the event data of this computer – inside the application folder it would be copied
        /// to other computers with the folder. Asks before saving there.</summary>
        public static bool OutsideAppFolder(IWin32Window owner, string file)
        {
            try
            {
                string dir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!Path.GetFullPath(file).StartsWith(dir, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { return true; }
            return MessageBox.Show(owner, "The file contains events of this computer. Saved in the application folder it would be copied " +
                "to other computers together with the application." + Environment.NewLine + Environment.NewLine + "Save it there anyway?", Program.AppName,
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        public static void ExportCsv(IWin32Window owner, DataGridView grid, string baseName)
        {
            using (var dlg = new SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                FileName = baseName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv"
            })
            {
                if (dlg.ShowDialog(owner) != DialogResult.OK || !OutsideAppFolder(owner, dlg.FileName)) return;
                string sep = CultureInfo.CurrentCulture.TextInfo.ListSeparator;
                var cols = grid.Columns.Cast<DataGridViewColumn>().Where(c => c.Visible).OrderBy(c => c.DisplayIndex).ToList();
                var sb = new StringBuilder();
                sb.AppendLine(string.Join(sep, cols.Select(c => Csv(c.HeaderText, sep))));
                foreach (DataGridViewRow r in grid.Rows)
                    sb.AppendLine(string.Join(sep, cols.Select(c => Csv(r.Cells[c.Index].FormattedValue?.ToString() ?? "", sep))));
                if (!TryWriteFile(owner, dlg.FileName, sb.ToString(), new UTF8Encoding(true))) return;
                MessageBox.Show(owner, $"Exported {grid.Rows.Count} rows to\n{dlg.FileName}", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        static string Csv(string v, string sep)
        {
            // Excel runs a cell starting with = + - @ as a formula – event data (command lines, URLs, DNS names) may come
            // from an attacker, so such a value gets a leading apostrophe (shown as text). Plain numbers (-1) stay.
            if (v.Length > 0 && ("=+-@".IndexOf(v[0]) >= 0 || v[0] == (char)9 || v[0] == (char)13)
                && !double.TryParse(v, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _))
                v = "'" + v;
            if (v.Contains(sep) || v.Contains("\"") || v.Contains("\n") || v.Contains("\r"))
                return "\"" + v.Replace("\"", "\"\"") + "\"";
            return v;
        }

        public static void ShowText(IWin32Window owner, string title, string text)
        {
            using (var f = new Form
            {
                Text = title,
                Size = new Size(S(950), S(620)),
                StartPosition = FormStartPosition.CenterParent,
                ShowIcon = false,
                MinimizeBox = false,
                Font = Theme.F(9.5f),
                BackColor = Theme.Bg,
                ForeColor = Theme.Text
            })
            {
                var t = DetailBox();
                t.Text = (text ?? "").Replace("\r\n", "\n").Replace("\n", "\r\n");
                var card = new Card { Dock = DockStyle.Fill };
                card.Controls.Add(t);
                var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(16)) };
                host.Controls.Add(card);
                f.Controls.Add(host);
                f.HandleCreated += (s, e) => Theme.DarkTitleBar(f);
                f.ShowDialog(owner);
            }
        }

        public static void Warn(IWin32Window owner, string msg) =>
            MessageBox.Show(owner, msg, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);

    }

    /// <summary>
    /// Time window: presets or a custom from–to range. The three controls (Preset, From, To) are placed by the caller,
    /// so they can sit in the columns of a filter grid.
    /// </summary>
    class TimeRangeSelector
    {
        readonly DarkCombo cbo = new DarkCombo(140);
        readonly Field dtFrom = new Field(150), dtTo = new Field(150);

        public Control Preset => cbo;
        public Control From => dtFrom;
        public Control To => dtTo;

        public TimeRangeSelector(int defaultIndex)
        {
            cbo.Items.AddRange(new object[] { "Last 15 minutes", "Last hour", "Last 24 hours", "Last 7 days", "Last 30 days", "All", "Custom range" });
            cbo.SelectedIndex = defaultIndex;
            cbo.SelectedIndexChanged += (s, e) => { UpdateEnabled(); PresetChanged?.Invoke(this, EventArgs.Empty); };
            dtFrom.Value = DateTime.Now.AddDays(-1).ToString(Ui.DateFormat);
            dtTo.Value = DateTime.Now.Date.AddDays(1).AddSeconds(-1).ToString(Ui.DateFormat);
            UpdateEnabled();
        }

        /// <summary>Another preset was chosen (the caller loads again – the time window is different).</summary>
        public event EventHandler PresetChanged;

        /// <summary>Identifies the chosen range (preset, and the From / To texts of a custom range) – part of the key that decides
        /// whether a refresh may only add new lines to the previous result.</summary>
        public string Key => cbo.SelectedIndex == 6 ? "custom|" + dtFrom.Value.Trim() + "|" + dtTo.Value.Trim() : "preset|" + cbo.SelectedIndex;

        void UpdateEnabled() => dtFrom.Box.Enabled = dtTo.Box.Enabled = cbo.SelectedIndex == 6;

        static DateTime Parse(Field f, string name)
        {
            if (DateTime.TryParseExact(f.Value.Trim(), new[] { Ui.DateFormat, "yyyy-MM-dd HH:mm", "yyyy-MM-dd" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                return d;
            throw new FormatException($"Invalid \"{name}\" time: \"{f.Value}\". Use the format {Ui.DateFormat}.");
        }

        public void GetRange(out DateTime? from, out DateTime? to)
        {
            from = null; to = null;
            var now = DateTime.Now;
            switch (cbo.SelectedIndex)
            {
                case 0: from = now.AddMinutes(-15); break;
                case 1: from = now.AddHours(-1); break;
                case 2: from = now.AddHours(-24); break;
                case 3: from = now.AddDays(-7); break;
                case 4: from = now.AddDays(-30); break;
                case 6:
                    from = Parse(dtFrom, "from"); to = Parse(dtTo, "to");
                    if (from > to) throw new FormatException("The start of the time range is after its end.");
                    break;
            }
        }
    }
}
