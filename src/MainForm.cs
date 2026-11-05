using System;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    class MainForm : Form
    {
        readonly AppSettings settings = AppSettings.Load();
        readonly StatusTab statusTab;
        readonly SuricataTab suricataTab;
        readonly SettingsTab settingsTab;
        readonly NavButton navOverview = new NavButton("Overview", NavIcon.Overview);
        readonly NavButton navEvents = new NavButton("EDR – Events", NavIcon.Events);
        readonly NavButton navSettings = new NavButton("Settings", NavIcon.Settings);
        readonly Label lblTitle = new Label { AutoSize = true, Font = Theme.F(20f, Weight.Bold), ForeColor = Theme.Text, Margin = new Padding(0) };
        readonly Label lblSubtitle = new Label { AutoSize = true, Font = Theme.F(10f), ForeColor = Theme.SubText, Margin = new Padding(Ui.S(2), Ui.S(2), 0, 0) };
        readonly Panel pages = new Panel { Dock = DockStyle.Fill };
        readonly CaptionBar captionBar;
        readonly Control sidebar;
        Control current;

        public MainForm()
        {
            SuspendLayout();
            Text = Program.AppName + " – Suricata EDR monitor";
            Font = Theme.F(9.5f);
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Size = new Size(Ui.S(1450), Ui.S(880));
            MinimumSize = new Size(Ui.S(1050), Ui.S(620));
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { Icon = SystemIcons.Shield; }

            statusTab = new StatusTab(settings) { Visible = false };
            suricataTab = new SuricataTab(settings) { Visible = false };
            settingsTab = new SettingsTab(settings, statusTab) { Visible = false };
            pages.Controls.Add(statusTab);
            pages.Controls.Add(suricataTab);
            pages.Controls.Add(settingsTab);

            var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(0, 0, 0, Ui.S(16)) };
            header.Controls.Add(lblTitle);
            header.Controls.Add(lblSubtitle);

            var content = new Panel { Dock = DockStyle.Fill, Padding = new Padding(Ui.S(32), Ui.S(22), Ui.S(28), Ui.S(14)) };
            content.Controls.Add(pages);
            content.Controls.Add(header);

            captionBar = new CaptionBar(this);
            sidebar = BuildSidebar();
            Controls.Add(content);
            Controls.Add(captionBar);
            Controls.Add(sidebar);
            ResumeLayout(true);

            // until the paths are detected at start a click only remembers the page (the fields are still empty – applying them
            // would clear the detected paths, and the Events page would load without eve.json)
            navOverview.Click += async (o, e) => await NavigateAsync(statusTab);
            navEvents.Click += async (o, e) => await NavigateAsync(suricataTab);
            navSettings.Click += async (o, e) => await NavigateAsync(settingsTab);
            settingsTab.SettingsSaved += (o, e) => suricataTab.ApplySettings();

            HandleCreated += (o, e) => Theme.DarkTitleBar(this);
            Load += (o, e) =>
            {
                // the window must not be larger than the screen
                var wa = Screen.FromControl(this).WorkingArea;
                if (Width > wa.Width || Height > wa.Height)
                {
                    Size = new Size(Math.Min(Width, wa.Width), Math.Min(Height, wa.Height));
                    Location = new Point(wa.Left + (wa.Width - Width) / 2, wa.Top + (wa.Height - Height) / 2);
                }
            };
            Shown += async (o, e) =>
            {
                // paths first (eve.json is needed by the Events page), then the Events page and the Suricata check
                await Task.Run(() => SystemChecks.AutoDetect(settings, false));
                // paths found at the first start are saved right away (nothing the user typed)
                if (settings.Snapshot() != settings.SavedSnapshot) try { settings.Save(); } catch { }
                settingsTab.LoadToUi();
                ready = true;
                var events = ShowPageAsync(requested ?? suricataTab);
                await statusTab.RunChecksAsync();
                await events;
            };
            FormClosing += (o, e) =>
            {
                if (!ready) return;   // closed during the start – nothing was changed
                // changes on the Settings page not saved with "Save settings" are saved now, without asking
                settingsTab.ApplyFromUi();
                if (settings.Snapshot() == settings.SavedSnapshot) return;
                try { settings.Save(); }
                catch (Exception ex)
                {
                    // e.g. a read-only folder – say what would be lost, but do not keep the application from closing
                    var changes = settings.Changes();
                    if (MessageBox.Show(this, "The changed settings could not be saved:\n" + ex.Message + "\n\n" +
                            string.Join("\n", changes.Take(10).Select(c => "• " + c)) + "\n\nClose the application anyway (the changes are lost)?",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                        e.Cancel = true;
                }
            };
        }

        Control BuildSidebar()
        {
            var side = new SidebarPanel { Dock = DockStyle.Left, Width = Ui.S(250), Padding = new Padding(Ui.S(16), Ui.S(96), Ui.S(16), Ui.S(16)) };

            var nav = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new Padding(0, Ui.S(4), 0, 0) };
            foreach (var n in new[] { navOverview, navEvents, navSettings })
            {
                n.Dock = DockStyle.Top;
                n.Margin = new Padding(0, 0, 0, Ui.S(6));
                nav.Controls.Add(n);
            }

            bool admin = SystemChecks.IsAdmin();
            var adminLbl = new Label
            {
                Dock = DockStyle.Bottom,
                Height = Ui.S(52),
                ForeColor = Theme.SidebarSubText,
                Font = Theme.F(9f),
                TextAlign = ContentAlignment.BottomLeft,
                Text = (admin ? "Running as administrator" : "Running as a standard user")
                       + "\nversion " + Application.ProductVersion
            };

            side.Controls.Add(nav);
            side.Controls.Add(adminLbl);
            return side;
        }

        bool ready;
        Control requested;

        Task NavigateAsync(Control page)
        {
            if (ready) return ShowPageAsync(page);
            requested = page;
            navOverview.Selected = page == statusTab;
            navEvents.Selected = page == suricataTab;
            navSettings.Selected = page == settingsTab;
            return Task.CompletedTask;
        }

        async Task ShowPageAsync(Control page)
        {
            settingsTab.ApplyFromUi();
            navOverview.Selected = page == statusTab;
            navEvents.Selected = page == suricataTab;
            navSettings.Selected = page == settingsTab;
            lblTitle.Text = page == statusTab ? "Overview" : page == settingsTab ? "Settings" : "EDR – Events";
            lblSubtitle.Text = page == statusTab ? "State of Suricata on this computer"
                             : page == settingsTab ? "Application settings and Suricata on this computer"
                             : "Suricata events from eve.json";
            if (current != page)
            {
                page.Dock = DockStyle.Fill;
                page.Visible = true;
                if (current != null) current.Visible = false;
                current = page;
            }
            if (page is ILazyTab t)
            {
                t.ApplySettings();
                await t.EnsureLoadedAsync();
            }
        }

        // ---- window without the system title bar: the native frame stays (resizing, snapping, shadow),
        //      the caption area is the logo part of the side bar and the strip above the content
        const int WM_NCCALCSIZE = 0x83, WM_NCHITTEST = 0x84;
        const int HTTRANSPARENT = -1, HTCLIENT = 1, HTCAPTION = 2, HTTOP = 12, HTTOPLEFT = 13, HTTOPRIGHT = 14;
        static readonly int SidebarCaptionHeight = Ui.S(84);

        [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
        [DllImport("user32.dll")] static extern bool IsZoomed(IntPtr hwnd);
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            SetWindowPos(Handle, IntPtr.Zero, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020);   // NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            captionBar?.Invalidate(true);   // maximize / restore glyph
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_NCCALCSIZE && m.WParam != IntPtr.Zero)
            {
                // keep the side and bottom frame, drop the title bar; maximized, the top would be off-screen by the frame width
                var before = (RECT)Marshal.PtrToStructure(m.LParam, typeof(RECT));
                base.WndProc(ref m);
                var after = (RECT)Marshal.PtrToStructure(m.LParam, typeof(RECT));
                after.Top = before.Top + (IsZoomed(Handle) ? after.Left - before.Left : 0);
                Marshal.StructureToPtr(after, m.LParam, false);
                m.Result = IntPtr.Zero;
                return;
            }
            base.WndProc(ref m);
            if (m.Msg == WM_NCHITTEST && m.Result.ToInt32() == HTCLIENT)
            {
                long lp = m.LParam.ToInt64();
                var pt = PointToClient(new Point((short)(lp & 0xFFFF), (short)((lp >> 16) & 0xFFFF)));
                int edge = Ui.S(6);
                if (WindowState == FormWindowState.Normal && pt.Y < edge)
                    m.Result = (IntPtr)(pt.X < edge * 2 ? HTTOPLEFT : pt.X >= ClientSize.Width - edge * 2 ? HTTOPRIGHT : HTTOP);
                else if (pt.Y < captionBar.Bottom || (pt.X < sidebar.Width && pt.Y < SidebarCaptionHeight))
                    m.Result = (IntPtr)HTCAPTION;
            }
        }

        /// <summary>Strip above the content with the minimize / maximize / close buttons; the rest of it drags the window.</summary>
        class CaptionBar : Panel
        {
            public CaptionBar(Form form)
            {
                Dock = DockStyle.Top;
                Height = Ui.S(32);
                BackColor = Theme.Bg;
                Controls.Add(new CaptionButton(CaptionGlyph.Minimize, () => form.WindowState = FormWindowState.Minimized));
                Controls.Add(new CaptionButton(CaptionGlyph.Maximize, () =>
                    form.WindowState = form.WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized));
                Controls.Add(new CaptionButton(CaptionGlyph.Close, form.Close));
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == WM_NCHITTEST) { m.Result = (IntPtr)HTTRANSPARENT; return; }   // handled by the form
                base.WndProc(ref m);
            }
        }

        enum CaptionGlyph { Minimize, Maximize, Close }

        class CaptionButton : Control
        {
            static readonly Color CloseHover = Theme.NavSelectedHover;
            readonly CaptionGlyph glyph;
            readonly Action action;
            bool hover, down;

            public CaptionButton(CaptionGlyph glyph, Action action)
            {
                this.glyph = glyph;
                this.action = action;
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
                SetStyle(ControlStyles.Selectable, false);
                Dock = DockStyle.Right;
                Width = Ui.S(46);
            }

            protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
            protected override void OnMouseLeave(EventArgs e) { hover = down = false; Invalidate(); base.OnMouseLeave(e); }
            protected override void OnMouseDown(MouseEventArgs e) { if (e.Button == MouseButtons.Left) { down = true; Invalidate(); } base.OnMouseDown(e); }
            protected override void OnMouseUp(MouseEventArgs e)
            {
                bool click = down && ClientRectangle.Contains(e.Location);
                down = false; Invalidate();
                base.OnMouseUp(e);
                if (click) action();
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                bool close = glyph == CaptionGlyph.Close;
                // close: the beige of the buttons with a dark cross instead of the usual red
                Color fill = !hover ? Theme.Bg : close ? (down ? Theme.NavSelected : CloseHover) : (down ? Theme.Border : Theme.Hover);
                g.Clear(fill);
                Color fore = close && hover ? Theme.AccentText : hover || down ? Theme.Text : Theme.SubText;
                int s = Ui.S(10), x = (Width - s) / 2, y = (Height - s) / 2;
                using (var p = new Pen(fore, Math.Max(1f, Ui.S(1))))
                {
                    if (glyph == CaptionGlyph.Minimize) g.DrawLine(p, x, y + s / 2, x + s, y + s / 2);
                    else if (glyph == CaptionGlyph.Close)
                    {
                        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                        g.DrawLine(p, x, y, x + s, y + s);
                        g.DrawLine(p, x + s, y, x, y + s);
                    }
                    else if (FindForm()?.WindowState == FormWindowState.Maximized)
                    {
                        int d = Ui.S(2);
                        g.DrawRectangle(p, x, y + d, s - d, s - d);
                        g.DrawLines(p, new[] { new Point(x + d, y + d), new Point(x + d, y), new Point(x + s, y), new Point(x + s, y + s - d), new Point(x + s - d, y + s - d) });
                    }
                    else g.DrawRectangle(p, x, y, s, s);
                }
            }
        }

        /// <summary>Side bar: brand colour, logo and application name at the top.</summary>
        class SidebarPanel : Panel
        {
            public SidebarPanel()
            {
                DoubleBuffered = true;
                ResizeRedraw = true;
                BackColor = Theme.Sidebar;
            }

            protected override void WndProc(ref Message m)
            {
                base.WndProc(ref m);
                // the logo part drags the window (the form answers HTCAPTION)
                if (m.Msg == WM_NCHITTEST)
                {
                    long lp = m.LParam.ToInt64();
                    var pt = PointToClient(new Point((short)(lp & 0xFFFF), (short)((lp >> 16) & 0xFFFF)));
                    if (pt.Y < SidebarCaptionHeight) m.Result = (IntPtr)HTTRANSPARENT;
                }
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                var g = e.Graphics;
                int x = Ui.S(18), y = Ui.S(22), size = Ui.S(48);
                Logo.Draw(g, new RectangleF(x, y, size, size), Theme.LogoFamily);
                TextRenderer.DrawText(g, Program.AppName, Theme.F(14f, Weight.ExtraBold), new Point(x + size + Ui.S(12), y + Ui.S(1)), Theme.SidebarText, TextFormatFlags.NoPrefix);
                TextRenderer.DrawText(g, "EDR monitor", Theme.F(9.5f), new Point(x + size + Ui.S(13), y + Ui.S(27)), Theme.SidebarSubText, TextFormatFlags.NoPrefix);
                using (var p = new Pen(Theme.SidebarLine))
                {
                    g.DrawLine(p, Ui.S(18), Ui.S(84), Width - Ui.S(18), Ui.S(84));
                    int by = Height - Ui.S(80);
                    g.DrawLine(p, Ui.S(18), by, Width - Ui.S(18), by);
                }
            }
        }
    }
}
