using System;
using System.Drawing;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>
    /// Read-only view of the AI answers: renders the Markdown subset the models use (headings, bullet and numbered
    /// lists with hanging indent, **bold**, `code`, code blocks, quotes, rules, tables as monospace text).
    /// </summary>
    class MarkdownView : RichTextBox
    {
        static readonly Regex InlineRx = new Regex(@"(\*\*[^*\n]+\*\*|__[^_\n]+__|`[^`\n]+`)", RegexOptions.Compiled);
        static readonly Regex ListRx = new Regex(@"^(\s*)([-*+•]|\d{1,3}[.)])\s+(.*)$", RegexOptions.Compiled);
        static readonly Regex TableRuleRx = new Regex(@"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$", RegexOptions.Compiled);
        static readonly Color CodeColor = Color.FromArgb(0xE0, 0xD4, 0xC4);

        readonly Font body = Theme.F(10f), bold = Theme.F(10f, Weight.Bold), h1 = Theme.F(14f, Weight.ExtraBold),
                      h2 = Theme.F(12.5f, Weight.Bold), h3 = Theme.F(11f, Weight.Bold), mono = Theme.Mono;

        public MarkdownView()
        {
            Dock = DockStyle.Fill;
            BorderStyle = BorderStyle.None;
            ReadOnly = true;
            WordWrap = true;
            ScrollBars = RichTextBoxScrollBars.Vertical;
            DetectUrls = true;
            Font = body;
            BackColor = Theme.Surface;   // after ReadOnly – otherwise the control turns grey
            ForeColor = Theme.Text;
            LinkClicked += (s, e) => OpenLink(e.LinkText);
            Theme.DarkScrollBars(this);
        }

        /// <summary>
        /// A link in the AI answer can come from attacker-controlled event data (URL, user agent, DNS name). Only http(s)
        /// is opened – never file:, UNC paths or other protocol handlers – and only after the full URL is confirmed.
        /// </summary>
        void OpenLink(string text)
        {
            if (!Uri.TryCreate((text ?? "").Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                MessageBox.Show(FindForm(), "Only http:// and https:// links can be opened from the answer:\n\n" + text, Program.AppName,
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            // indicators of compromise should rather be copied than opened – "No" copies the address
            var answer = MessageBox.Show(FindForm(), uri.AbsoluteUri +
                    "\n\nThe link comes from the AI answer and may originate from the analyzed (possibly malicious) data.\n\n" +
                    "Yes = open it in the browser     No = only copy the address     Cancel = nothing",
                    Program.AppName, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer == DialogResult.No) Ui.CopyToClipboard(this, uri.AbsoluteUri);
            else if (answer == DialogResult.Yes)
                try { System.Diagnostics.Process.Start(uri.AbsoluteUri); } catch { }
        }

        /// <summary>Grey note (status, what was sent).</summary>
        public void AppendNote(string text, Color? color = null)
        {
            Start(0, 0);
            Put(text + "\n", Theme.F(9.5f), color ?? Theme.SubText);
            Put("\n", body, Theme.Text);
            ScrollToEnd();
        }

        /// <summary>A question of the user in the conversation – beige bar in front of it.</summary>
        public void AppendQuestion(string text)
        {
            Start(0, Ui.S(14));
            Put("\n» ", bold, Theme.Attention);
            Put(text.Trim() + "\n\n", bold, Theme.Attention);
            ScrollToEnd();
        }

        public void AppendMarkdown(string md)
        {
            answerStart = TextLength;
            bool code = false;
            foreach (var raw in (md ?? "").Replace("\r\n", "\n").Split('\n'))
            {
                string line = raw.TrimEnd();
                if (line.TrimStart().StartsWith("```")) { code = !code; continue; }
                if (code)
                {
                    Start(Ui.S(16), 0);
                    Put(line + "\n", mono, CodeColor);
                    continue;
                }
                string t = line.Trim();
                if (t.Length == 0) { Start(0, 0); Put("\n", body, Theme.Text); continue; }

                if (t.StartsWith("#"))
                {
                    int level = 0;
                    while (level < t.Length && t[level] == '#') level++;
                    string title = t.Substring(level).Trim().Replace("**", "");
                    Start(0, 0);
                    Put(title + "\n", level <= 1 ? h1 : level == 2 ? h2 : h3, level <= 2 ? Theme.Text : Theme.Attention);
                    continue;
                }
                if (Regex.IsMatch(t, @"^(-{3,}|\*{3,}|_{3,})$"))
                {
                    Start(0, 0);
                    Put(new string('─', 48) + "\n", body, Theme.Line);
                    continue;
                }
                if (t.StartsWith("|"))
                {
                    if (TableRuleRx.IsMatch(t)) continue;
                    Start(Ui.S(4), 0);
                    Put(t.Replace("**", "") + "\n", mono, Theme.Text);
                    continue;
                }
                if (t.StartsWith(">"))
                {
                    Start(Ui.S(14), 0);
                    Inline(t.TrimStart('>', ' ') + "\n", Theme.SubText);
                    continue;
                }
                var m = ListRx.Match(line);
                if (m.Success)
                {
                    int depth = Math.Min(4, m.Groups[1].Value.Replace("\t", "  ").Length / 2);
                    string marker = char.IsDigit(m.Groups[2].Value[0]) ? m.Groups[2].Value : depth == 0 ? "•" : "–";
                    int indent = Ui.S(10 + depth * 20);
                    Start(indent, Ui.S(18));
                    Put(marker + "\t", body, depth == 0 ? Theme.Attention : Theme.SubText);
                    SelectionTabs = new[] { indent + Ui.S(18) };
                    Inline(m.Groups[3].Value + "\n", Theme.Text);
                    continue;
                }
                Start(0, 0);
                Inline(t + "\n", Theme.Text);
            }
            // show the beginning of the answer (it is usually longer than the view)
            SelectionStart = Math.Min(answerStart, TextLength);
            ScrollToCaret();
        }

        int answerStart;

        void Inline(string text, Color color)
        {
            foreach (var part in InlineRx.Split(text))
            {
                if (part.Length == 0) continue;
                if ((part.StartsWith("**") && part.EndsWith("**") || part.StartsWith("__") && part.EndsWith("__")) && part.Length > 4)
                    Put(part.Substring(2, part.Length - 4), bold, color);
                else if (part.StartsWith("`") && part.EndsWith("`") && part.Length > 2)
                    Put(part.Substring(1, part.Length - 2), mono, CodeColor);
                else
                    Put(part, body, color);
            }
        }

        void Start(int indent, int hanging)
        {
            SelectionStart = TextLength;
            SelectionLength = 0;
            SelectionIndent = indent;
            SelectionHangingIndent = hanging;
        }

        void Put(string text, Font font, Color color)
        {
            SelectionStart = TextLength;
            SelectionFont = font;
            SelectionColor = color;
            SelectedText = text;
        }

        void ScrollToEnd()
        {
            SelectionStart = TextLength;
            ScrollToCaret();
        }
    }
}
