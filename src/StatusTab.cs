using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>"Overview" page: state of Suricata on this computer (the settings are on the Settings page).</summary>
    class StatusTab : UserControl
    {
        readonly AppSettings s;
        readonly StatusIcon icon = new StatusIcon();
        readonly Label lblHeadline = new Label { AutoSize = true, Font = Theme.F(15f, Weight.Bold), ForeColor = Theme.Text, Margin = new Padding(0, Ui.S(2), 0, 0), Text = "Checking…" };
        readonly Label lblChecked = new Label { AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(Ui.S(1), Ui.S(2), 0, 0) };
        readonly TableLayoutPanel details = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, Padding = new Padding(0, Ui.S(4), 0, 0) };
        bool checking;

        /// <summary>suricata.exe found by the last check (null = not checked yet, "" = not found).</summary>
        public string SuricataExe { get; private set; }

        /// <summary>Name of the Suricata Windows service (null = not registered).</summary>
        public string ServiceName { get; private set; }

        /// <summary>Raised after every check (the Settings page refreshes the log size).</summary>
        public event EventHandler Checked;

        public StatusTab(AppSettings settings)
        {
            s = settings;
            Dock = DockStyle.Fill;

            var card = new Card { Dock = DockStyle.Fill, Margin = new Padding(0) };

            var head = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Padding = new Padding(0, 0, 0, Ui.S(14)) };
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var texts = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0) };
            texts.Controls.Add(lblHeadline);
            texts.Controls.Add(lblChecked);
            head.Controls.Add(icon, 0, 0);
            head.Controls.Add(texts, 1, 0);
            var again = Ui.B("Check Suricata", async (o, e) => await RunChecksAsync());
            again.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            head.Controls.Add(again, 2, 0);

            var line = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = Theme.Line };
            details.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.S(150)));
            details.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(0, Ui.S(10), 0, 0) };
            scroll.Controls.Add(details);

            card.Controls.Add(scroll);
            card.Controls.Add(line);
            card.Controls.Add(head);
            Controls.Add(card);
        }

        public async Task RunChecksAsync()
        {
            if (checking) return;
            checking = true;
            try
            {
                icon.State = null;
                lblHeadline.Text = "Checking…";
                var r = await Task.Run(() => SystemChecks.CheckSuricata(s));
                icon.State = r.State;
                lblHeadline.Text = r.Headline;
                lblChecked.Text = "Checked " + DateTime.Now.ToString(Ui.DateFormat);
                ShowDetails(r);
                SuricataExe = r.ExePath ?? "";
                ServiceName = r.ServiceName;
            }
            finally { checking = false; }
            Checked?.Invoke(this, EventArgs.Empty);
        }

        static readonly Regex KeyValue = new Regex(@"^([A-Za-z][A-Za-z .]*):\s+(.*)$");

        /// <summary>Lines "Key:   value" from the check as a two-column list.</summary>
        void ShowDetails(CheckResult r)
        {
            details.SuspendLayout();
            details.Controls.Clear();
            details.RowStyles.Clear();
            int row = 0;
            foreach (var line in r.Lines)
            {
                if (line.Trim().Length == 0) continue;
                var m = KeyValue.Match(line);
                string key = m.Success ? m.Groups[1].Value : "", value = m.Success ? m.Groups[2].Value : line.Trim();
                bool bad = Regex.IsMatch(value, "not found|not running|not registered|cannot start|missing|DISABLED|does not exist|DOES NOT EXIST|denied|stopped|not set", RegexOptions.IgnoreCase);
                details.Controls.Add(new Label { Text = key, AutoSize = true, ForeColor = Theme.SubText, Font = Theme.F(9.5f, Weight.SemiBold), Margin = new Padding(0, Ui.S(5), 0, Ui.S(5)) }, 0, row);
                details.Controls.Add(new Label { Text = value, AutoSize = true, ForeColor = bad ? Theme.Attention : Theme.Text, Font = Theme.F(10f), Margin = new Padding(0, Ui.S(5), 0, Ui.S(5)) }, 1, row);
                row++;
            }
            details.ResumeLayout(true);
        }
    }
}
