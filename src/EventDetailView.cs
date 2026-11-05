using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>
    /// Detail of one Suricata event: "name  value" rows, names grey, values white. Long values wrap under the value
    /// column (no horizontal scrolling); multi-line values (e.g. the printable payload) keep their lines.
    /// </summary>
    class EventDetailView : RichTextBox
    {
        public EventDetailView()
        {
            Dock = DockStyle.Fill;
            BorderStyle = BorderStyle.None;
            ReadOnly = true;
            WordWrap = true;
            ScrollBars = RichTextBoxScrollBars.Vertical;
            DetectUrls = false;
            Font = Theme.Mono;
            BackColor = Theme.Surface;   // after ReadOnly – otherwise the control turns grey
            ForeColor = Theme.Text;
            Theme.DarkScrollBars(this);
        }

        /// <summary>Summary rows, a separator and the fields of the event (e.g. the flattened JSON).</summary>
        public void Display(IList<KeyValuePair<string, string>> summary, IList<KeyValuePair<string, string>> fields)
        {
            SuspendDrawing();
            try
            {
                Clear();
                if (summary == null) return;
                // value column after the longest name – capped, very long JSON paths just push their value further
                int keyChars = Math.Min(32, summary.Concat(fields).Select(r => r.Key.Length).DefaultIfEmpty(8).Max() + 2);
                int indent = TextRenderer.MeasureText(new string('0', keyChars), Font, Size.Empty, TextFormatFlags.NoPadding).Width;

                foreach (var r in summary) AppendRow(r.Key, Split(r.Value), indent);
                AppendSeparator();
                foreach (var f in fields) AppendRow(f.Key, Split(f.Value), indent);
                // tab stop at the value column for all rows
                SelectAll();
                SelectionTabs = new[] { indent };
                Select(0, 0);
            }
            finally { ResumeDrawing(); }
        }

        /// <summary>Multi-line values – one line per row (wrapped further if too long).</summary>
        static IEnumerable<string> Split(string value)
        {
            if (string.IsNullOrEmpty(value)) return new[] { "" };
            return value.Replace("\r\n", "\n").TrimEnd('\n').Split('\n');
        }

        /// <summary>First line: name + value; wrapped and further lines start under the value (hanging indent).</summary>
        void AppendRow(string key, IEnumerable<string> lines, int indent)
        {
            bool first = true;
            foreach (var line in lines)
            {
                SelectionStart = TextLength;
                SelectionIndent = 0;
                SelectionHangingIndent = indent;
                SelectionColor = Theme.SubText;
                AppendText(first ? key + ":\t" : "\t");
                SelectionColor = Theme.Text;
                AppendText(line + "\n");
                first = false;
            }
        }

        void AppendSeparator()
        {
            SelectionStart = TextLength;
            SelectionIndent = SelectionHangingIndent = 0;
            SelectionColor = Theme.Line;
            AppendText(new string('─', 60) + "\n");
        }

        // ---- no flicker while the text is rebuilt
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr w, IntPtr l);
        const int WM_SETREDRAW = 0x000B;

        void SuspendDrawing() { if (IsHandleCreated) SendMessage(Handle, WM_SETREDRAW, IntPtr.Zero, IntPtr.Zero); }

        void ResumeDrawing()
        {
            if (!IsHandleCreated) return;
            SendMessage(Handle, WM_SETREDRAW, (IntPtr)1, IntPtr.Zero);
            Invalidate();
        }
    }
}
