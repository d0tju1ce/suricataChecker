using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>Panel with rounded corners (cards on the dark background).</summary>
    class Card : Panel
    {
        public Card()
        {
            DoubleBuffered = true;
            ResizeRedraw = true;
            BackColor = Theme.Surface;
            Padding = new Padding(Ui.S(18), Ui.S(14), Ui.S(18), Ui.S(14));
            Margin = new Padding(0, 0, 0, Ui.S(14));
        }

        protected override void OnPaintBackground(PaintEventArgs e) =>
            Theme.PaintBox(e.Graphics, this, BackColor, Theme.Line, Ui.S(8));
    }

    enum ButtonKind { Primary, Secondary }

    /// <summary>Flat button: yellow (primary) or dark grey with a border (secondary).</summary>
    class FlatButton : Button
    {
        readonly ButtonKind kind;
        bool hover, down;

        public FlatButton(string text, ButtonKind kind = ButtonKind.Secondary)
        {
            this.kind = kind;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            Font = Theme.F(9.5f, Weight.Bold);
            Cursor = Cursors.Hand;
            Margin = new Padding(Ui.S(3), Ui.S(3), Ui.S(3), Ui.S(3));
            Text = text;
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            var sz = TextRenderer.MeasureText(Text, Font);
            Size = new Size(Math.Max(sz.Width + Ui.S(30), Width), Ui.S(32));
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { down = false; Invalidate(); base.OnMouseUp(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            // all buttons share one look (light beige like "Load"); the kind is kept for the callers
            Color fill = !Enabled ? Theme.Hover : down ? Theme.NavSelected : hover ? Theme.NavSelectedHover : Theme.NavSelected;
            Color fore = Enabled ? Theme.AccentText : Theme.Muted;
            Color border = Focused && ShowFocusCues ? Theme.Sidebar : Color.Empty;
            Theme.PaintBox(e.Graphics, this, fill, border, Ui.S(6));
            TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, fore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>Text input in a rounded box; the border turns green (sidebar colour) when focused.</summary>
    class Field : Panel
    {
        public readonly TextBox Box = new TextBox { BorderStyle = BorderStyle.None, BackColor = Theme.Input, ForeColor = Theme.Text };

        public Field(int width)
        {
            DoubleBuffered = true;
            ResizeRedraw = true;
            BackColor = Theme.Input;
            Box.Font = Theme.F(9.5f);
            Size = new Size(Ui.S(width), Ui.S(32));
            Margin = new Padding(Ui.S(3), Ui.S(3), Ui.S(3), Ui.S(3));
            Cursor = Cursors.IBeam;
            Controls.Add(Box);
            Box.GotFocus += (s, e) => Invalidate();
            Box.LostFocus += (s, e) => Invalidate();
            Box.EnabledChanged += (s, e) =>
            {
                // disabled = same fill as the box around it (greyed out like the disabled buttons)
                Box.BackColor = Box.Enabled ? Theme.Input : Theme.Surface;
                Invalidate();
            };
            Click += (s, e) => Box.Focus();
        }

        public string Value { get => Box.Text; set => Box.Text = value; }

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            int pad = Ui.S(10);
            Box.SetBounds(pad, (Height - Box.Height) / 2, Math.Max(10, Width - 2 * pad), Box.Height);
        }

        protected override void OnPaintBackground(PaintEventArgs e) =>
            Theme.PaintBox(e.Graphics, this, Box.Enabled ? Theme.Input : Theme.Surface, Box.Focused ? Theme.Sidebar : Theme.Border, Ui.S(6));
    }

    /// <summary>Whole-number input (replaces NumericUpDown, which cannot be themed). Arrow keys / wheel change the value.</summary>
    class NumberField : Field
    {
        readonly int min, max, step;

        public NumberField(int min, int max, int step, int width = 80) : base(width)
        {
            this.min = min; this.max = max; this.step = step;
            Box.TextAlign = HorizontalAlignment.Right;
            Box.KeyPress += (s, e) => { if (!char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar)) e.Handled = true; };
            Box.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Up) { Value = Value + step; e.Handled = true; }
                else if (e.KeyCode == Keys.Down) { Value = Value - step; e.Handled = true; }
            };
            Box.MouseWheel += (s, e) => Value = Value + Math.Sign(e.Delta) * step;
            Box.Leave += (s, e) => Value = Value;
            Value = min;
        }

        public new int Value
        {
            get => int.TryParse(Box.Text, out var v) ? Math.Max(min, Math.Min(max, v)) : min;
            set => Box.Text = Math.Max(min, Math.Min(max, value)).ToString();
        }
    }

    /// <summary>ComboBox in the dark theme: owner-drawn items, rounded border and a chevron.</summary>
    class DarkCombo : ComboBox
    {
        public DarkCombo(int width, bool editable = false)
        {
            DropDownStyle = editable ? ComboBoxStyle.DropDown : ComboBoxStyle.DropDownList;
            FlatStyle = FlatStyle.Flat;
            DrawMode = DrawMode.OwnerDrawFixed;
            BackColor = Theme.Input;
            ForeColor = Theme.Text;
            Font = Theme.F(9.5f);
            ItemHeight = Ui.S(24);
            Width = Ui.S(width);
            Margin = new Padding(Ui.S(3), Ui.S(3), Ui.S(3), Ui.S(3));   // same as the buttons
            DropDown += (s, e) =>
            {
                var info = new COMBOBOXINFO { cbSize = Marshal.SizeOf(typeof(COMBOBOXINFO)) };
                if (GetComboBoxInfo(Handle, ref info)) Theme.DarkScrollBars(info.hwndList);
            };
            GotFocus += (s, e) => Invalidate();
            LostFocus += (s, e) => Invalidate();
        }

        /// <summary>Same height as the buttons and text fields (32 px at 100 %): the height of the selection field
        /// is set through ItemHeight (owner-drawn combo), the border is what the combo adds around it.</summary>
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            int border = Height - ItemHeight;
            int item = Ui.S(32) - border;
            if (item > 0 && item != ItemHeight) ItemHeight = item;
            CenterEdit();
            ClearSelectionLater();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            if (IsHandleCreated) CenterEdit();
            ClearSelectionLater();
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            ClearSelectionLater();
        }

        /// <summary>An editable combo selects (highlights) its whole text after a resize or a programmatic change –
        /// without focus the highlight only looks like a selection, so it is removed.</summary>
        void ClearSelectionLater()
        {
            if (DropDownStyle != ComboBoxStyle.DropDown || !IsHandleCreated || ContainsFocus) return;
            BeginInvoke((Action)(() => { if (!IsDisposed && !ContainsFocus) SelectionLength = 0; }));
        }

        /// <summary>Editable combo: the text box inside sits at the top by default – centre it vertically.</summary>
        void CenterEdit()
        {
            if (DropDownStyle != ComboBoxStyle.DropDown) return;
            var info = new COMBOBOXINFO { cbSize = Marshal.SizeOf(typeof(COMBOBOXINFO)) };
            if (!GetComboBoxInfo(Handle, ref info) || info.hwndEdit == IntPtr.Zero) return;
            int h = Font.Height, x = info.rcItem.Left, w = info.rcItem.Right - info.rcItem.Left;
            SetWindowPos(info.hwndEdit, IntPtr.Zero, x, (Height - h) / 2, w, h, 0x0004 | 0x0010);   // NOZORDER | NOACTIVATE
        }

        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            bool edit = (e.State & DrawItemState.ComboBoxEdit) != 0;
            bool selected = !edit && (e.State & DrawItemState.Selected) != 0;
            using (var b = new SolidBrush(selected ? Theme.Hover : BackColor)) e.Graphics.FillRectangle(b, e.Bounds);
            var r = new Rectangle(e.Bounds.X + Ui.S(edit ? 4 : 8), e.Bounds.Y, e.Bounds.Width - Ui.S(10), e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, GetItemText(Items[e.Index]), Font, r, Enabled ? Theme.Text : Theme.Muted,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == 0x000F /* WM_PAINT */) using (var g = Graphics.FromHwnd(Handle)) PaintChrome(g);
        }

        void PaintChrome(Graphics g)
        {
            var r = ClientRectangle;
            int bw = SystemInformation.VerticalScrollBarWidth + 2;
            var arrow = new Rectangle(r.Right - bw - 1, 1, bw, r.Height - 2);
            using (var b = new SolidBrush(BackColor)) g.FillRectangle(b, arrow);
            using (var p = new Pen(BackColor, 2)) g.DrawRectangle(p, 1, 1, r.Width - 3, r.Height - 3);

            // editable combo: the strips above and below the (centred) text box are not painted by the combo
            var info = new COMBOBOXINFO { cbSize = Marshal.SizeOf(typeof(COMBOBOXINFO)) };
            if (DropDownStyle == ComboBoxStyle.DropDown && GetComboBoxInfo(Handle, ref info) && info.hwndEdit != IntPtr.Zero
                && GetWindowRect(info.hwndEdit, out var er))
            {
                var edit = RectangleToClient(Rectangle.FromLTRB(er.Left, er.Top, er.Right, er.Bottom));
                using (var region = new Region(new Rectangle(2, 2, arrow.X - 2, r.Height - 4)))
                using (var b = new SolidBrush(BackColor))
                {
                    region.Exclude(edit);
                    g.FillRegion(b, region);
                }
            }

            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, r.Width - 1.5f, r.Height - 1.5f), Ui.S(6)))
            using (var outside = new Region(r))
            {
                outside.Exclude(path);
                using (var b = new SolidBrush(Parent?.BackColor ?? Theme.Bg)) g.FillRegion(b, outside);
                using (var p = new Pen(ContainsFocus || DroppedDown ? Theme.Sidebar : Theme.Border)) g.DrawPath(p, path);
            }
            float cx = arrow.X + arrow.Width / 2f, cy = r.Height / 2f, d = Ui.S(4);
            using (var p = new Pen(Enabled ? Theme.SubText : Theme.Muted, Ui.S(2)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                g.DrawLines(p, new[] { new PointF(cx - d, cy - d / 2), new PointF(cx, cy + d / 2), new PointF(cx + d, cy - d / 2) });
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        struct COMBOBOXINFO
        {
            public int cbSize;
            public RECT rcItem, rcButton;
            public int stateButton;
            public IntPtr hwndCombo, hwndEdit, hwndList;
        }

        [DllImport("user32.dll")] static extern bool GetComboBoxInfo(IntPtr hwnd, ref COMBOBOXINFO info);
    }

    /// <summary>On/off switch (replaces CheckBox).</summary>
    class Toggle : CheckBox
    {
        public Toggle(string text)
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Font = Theme.F(9.5f);
            Cursor = Cursors.Hand;
            AutoSize = false;
            Margin = new Padding(Ui.S(10), Ui.S(3), Ui.S(3), Ui.S(3));
            Text = text;
            Size = new Size(Ui.S(46) + TextRenderer.MeasureText(text, Font).Width, Ui.S(32));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent?.BackColor ?? Theme.Bg);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var track = new RectangleF(0.5f, (Height - Ui.S(20)) / 2f, Ui.S(36), Ui.S(20));
            using (var path = Theme.Round(track, Ui.S(5)))
            {
                using (var b = new SolidBrush(Checked ? Theme.Sidebar : Theme.Input)) g.FillPath(b, path);
                using (var p = new Pen(Checked ? Theme.Sidebar : Theme.Border)) g.DrawPath(p, path);
            }
            float k = Ui.S(14);
            var knob = new RectangleF(Checked ? track.Right - k - Ui.S(3) : track.X + Ui.S(3), track.Y + (track.Height - k) / 2, k, k);
            using (var path = Theme.Round(knob, Ui.S(3)))
            using (var b = new SolidBrush(Checked ? Theme.SidebarText : Theme.SubText)) g.FillPath(b, path);
            var tr = new Rectangle(Ui.S(44), 0, Width - Ui.S(44), Height);
            TextRenderer.DrawText(g, Text, Font, tr, Theme.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }

    enum NavIcon { Overview, Events, Ids, Settings }

    /// <summary>Navigation item in the side bar.</summary>
    class NavButton : Control
    {
        readonly NavIcon icon;
        bool selected, hover;

        public NavButton(string text, NavIcon icon)
        {
            this.icon = icon;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            Text = text;
            Font = Theme.F(11f, Weight.SemiBold);
            Cursor = Cursors.Hand;
            Height = Ui.S(46);
        }

        public bool Selected { get => selected; set { selected = value; Invalidate(); } }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            Color fill = selected ? Theme.NavSelected : hover ? Theme.SidebarHover : Theme.Sidebar;
            Color fore = Theme.SidebarText;
            Theme.PaintBox(g, this, fill, Color.Empty, Ui.S(8));

            var ir = new RectangleF(Ui.S(16), (Height - Ui.S(20)) / 2f, Ui.S(20), Ui.S(20));
            using (var b = new SolidBrush(fore))
            using (var p = new Pen(fore, Ui.S(2)) { LineJoin = LineJoin.Round, StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                // every icon fills the same 20 x 20 box including the line width: draw inside the box shrunk by half a line
                var r = RectangleF.Inflate(ir, -p.Width / 2, -p.Width / 2);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                if (icon == NavIcon.Overview) DrawShield(g, p, b, r);
                else if (icon == NavIcon.Ids) DrawInfo(g, p, b, r);
                else if (icon == NavIcon.Settings) DrawGear(g, p, b, r);
                else DrawList(g, p, b, r);
            }
            var tr = new Rectangle(Ui.S(48), 0, Width - Ui.S(52), Height);
            TextRenderer.DrawText(g, Text, Font, tr, fore, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }

        static void DrawShield(Graphics g, Pen p, Brush b, RectangleF r)
        {
            float x = r.X, y = r.Y, w = r.Width, h = r.Height;
            using (var path = new GraphicsPath())
            {
                path.AddLine(x + w / 2, y, x + w, y + h * 0.18f);
                path.AddBezier(x + w, y + h * 0.18f, x + w, y + h * 0.65f, x + w * 0.75f, y + h * 0.86f, x + w / 2, y + h);
                path.AddBezier(x + w / 2, y + h, x + w * 0.25f, y + h * 0.86f, x, y + h * 0.65f, x, y + h * 0.18f);
                path.CloseFigure();
                g.DrawPath(p, path);
            }
            g.DrawLines(p, new[] { new PointF(x + w * 0.32f, y + h * 0.5f), new PointF(x + w * 0.46f, y + h * 0.64f), new PointF(x + w * 0.7f, y + h * 0.38f) });
        }

        static void DrawInfo(Graphics g, Pen p, Brush b, RectangleF r)
        {
            g.DrawEllipse(p, r.X, r.Y, r.Width, r.Height);
            float cx = r.X + r.Width / 2, d = p.Width * 1.3f;
            g.FillEllipse(b, cx - d / 2, r.Y + r.Height * 0.27f - d / 2, d, d);
            g.DrawLine(p, cx, r.Y + r.Height * 0.47f, cx, r.Y + r.Height * 0.74f);
        }

        /// <summary>Settings: cog wheel with 6 wide teeth (rounded corners) and a large hole in the middle.</summary>
        static void DrawGear(Graphics g, Pen p, Brush b, RectangleF r)
        {
            float cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2;
            float ro = r.Width / 2, ri = ro * 0.74f, hole = ro * 0.36f;
            var pts = new List<PointF>();
            PointF At(float radius, double deg) =>
                new PointF(cx + radius * (float)Math.Cos(deg * Math.PI / 180), cy + radius * (float)Math.Sin(deg * Math.PI / 180));
            for (int i = 0; i < 6; i++)
            {
                double a = i * 60 - 90;
                pts.Add(At(ri, a - 19));   // tooth: root – tip – tip – root
                pts.Add(At(ro, a - 12));
                pts.Add(At(ro, a + 12));
                pts.Add(At(ri, a + 19));
            }
            g.DrawPolygon(p, pts.ToArray());   // the pen has round joins -> rounded tooth corners
            g.DrawEllipse(p, cx - hole, cy - hole, hole * 2, hole * 2);
        }

        static void DrawList(Graphics g, Pen p, Brush b, RectangleF r)
        {
            // three rows over (almost) the full height, like the outline of the other icons
            float d = p.Width * 1.4f;
            for (int i = 0; i < 3; i++)
            {
                float y = r.Y + r.Height * (0.03f + 0.47f * i);
                g.FillRectangle(b, r.X - p.Width / 2, y - d / 2, d, d);
                g.DrawLine(p, r.X + r.Width * 0.36f, y, r.Right, y);
            }
        }
    }

    /// <summary>Status symbol (OK / warning / error) in a rounded square.</summary>
    class StatusIcon : Control
    {
        CheckState? state;

        public StatusIcon()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Size = new Size(Ui.S(48), Ui.S(48));
            Margin = new Padding(0, Ui.S(2), Ui.S(14), 0);
        }

        public CheckState? State { get => state; set { state = value; Invalidate(); } }

        public static Color ColorOf(CheckState? s) =>
            s == CheckState.Ok ? Theme.Ok : s == CheckState.Warning ? Theme.Warn : s == CheckState.Error ? Theme.Error : Theme.SubText;

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            Theme.PaintBox(g, this, Theme.Bg, Theme.Border, Ui.S(10));
            float w = Width, h = Height;
            using (var p = new Pen(ColorOf(state), Ui.S(3)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                switch (state)
                {
                    case CheckState.Ok:
                        g.DrawLines(p, new[] { new PointF(w * 0.3f, h * 0.52f), new PointF(w * 0.44f, h * 0.66f), new PointF(w * 0.71f, h * 0.36f) });
                        break;
                    case CheckState.Warning:
                        g.DrawLine(p, w / 2, h * 0.3f, w / 2, h * 0.56f);
                        g.DrawLine(p, w / 2, h * 0.7f, w / 2, h * 0.7f + 0.1f);
                        break;
                    case CheckState.Error:
                        g.DrawLine(p, w * 0.36f, h * 0.36f, w * 0.64f, h * 0.64f);
                        g.DrawLine(p, w * 0.64f, h * 0.36f, w * 0.36f, h * 0.64f);
                        break;
                    default:
                        for (int i = -1; i <= 1; i++) g.DrawLine(p, w / 2 + i * w * 0.15f, h / 2, w / 2 + i * w * 0.15f + 0.1f, h / 2);
                        break;
                }
            }
        }
    }
}
