using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>
    /// The alerts the AI considers false positives – the analyst checks which ones are saved to the false positive
    /// knowledge base (Marks rules). Nothing is saved without this confirmation: the verdict of the AI can be wrong and
    /// the analyzed traffic may even try to talk the AI into it.
    /// </summary>
    static class AiVerdictsDialog
    {
        enum Scope { SameHosts, AnySource, AnyHost }

        public static void Show(IWin32Window owner, List<AiVerdict> verdicts)
        {
            var rows = verdicts.Where(v => v.Item is SuricataAi.Group g && g.First.Sid.HasValue).ToList();
            int skipped = verdicts.Count - rows.Count;
            if (rows.Count == 0)
            {
                Ui.Warn(owner, "The verdicts of the AI concern only events that are not alerts (DNS, flow, HTTP…) – " +
                               "the knowledge base keeps false positives of alert signatures only.");
                return;
            }

            using (var f = new Form
            {
                Text = Program.AppName + " – false positives proposed by the AI",
                Size = new Size(Ui.S(1150), Ui.S(560)),
                MinimumSize = new Size(Ui.S(700), Ui.S(380)),
                StartPosition = FormStartPosition.CenterParent,
                ShowIcon = false,
                MinimizeBox = false,
                Font = Theme.F(9.5f),
                BackColor = Theme.Bg,
                ForeColor = Theme.Text,
                Padding = new Padding(Ui.S(16)),
            })
            {
                f.HandleCreated += (o, e) => Theme.DarkTitleBar(f);

                var info = new Label
                {
                    Dock = DockStyle.Top,
                    AutoSize = false,
                    Height = Ui.S(66),
                    ForeColor = Theme.SubText,
                    Text = "Check the alerts that really are false positives. They are saved to the knowledge base (marks.json, this computer): " +
                           "matching alerts – also future ones – are greyed out and the next AI analysis gets the assessment with its reason. " +
                           "The AI can be wrong: severity 1 alerts and low confidence verdicts are not checked in advance. " +
                           "Remove an assessment on the Settings page." +
                           (skipped > 0 ? $"\n{skipped} verdict(s) for events that are not alerts are left out." : ""),
                };

                var grid = Ui.CreateGrid();
                grid.ReadOnly = false;
                grid.MultiSelect = false;
                grid.EditMode = DataGridViewEditMode.EditOnEnter;
                var chk = new DataGridViewCheckBoxColumn { Name = "Save", HeaderText = "Save", Width = Ui.S(50) };
                grid.Columns.Add(chk);
                void Col(string name, string header, int width, bool fill = false)
                {
                    var c = new DataGridViewTextBoxColumn { Name = name, HeaderText = header, Width = Ui.S(width), ReadOnly = true, SortMode = DataGridViewColumnSortMode.NotSortable };
                    if (fill) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; c.MinimumWidth = Ui.S(200); }
                    grid.Columns.Add(c);
                }
                Col("Ref", "Ref", 50);
                Col("Sev", "Sev", 40);
                Col("Signature", "Signature", 300);
                Col("Hosts", "Source → destination", 230);
                Col("Count", "Count", 60);
                Col("Conf", "Confidence", 85);
                Col("Reason", "Reason (AI)", 300, fill: true);
                grid.Columns["Reason"].DefaultCellStyle.WrapMode = DataGridViewTriState.True;
                grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;

                foreach (var v in rows)
                {
                    var g = (SuricataAi.Group)v.Item;
                    var e = g.First;
                    bool check = e.Severity != 1 && e.EventType != "drop" && v.Confidence != "low";
                    int i = grid.Rows.Add(check, "#" + v.Ref, e.Severity?.ToString() ?? "", $"[{e.Sid}] {e.Signature}",
                                          $"{e.SrcIp} → {e.Dest}", g.Count, v.Confidence, v.Reason);
                    grid.Rows[i].Tag = v;
                    if (e.Severity == 1) grid.Rows[i].Cells["Sev"].Style.ForeColor = Theme.Attention;
                    var existing = Marks.RuleFor(e);
                    if (existing != null) grid.Rows[i].Cells["Reason"].ToolTipText = "Already in the knowledge base: " + existing.Reason;
                }
                grid.CurrentCellDirtyStateChanged += (o, e) => { if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };

                var card = new Card { Dock = DockStyle.Fill };
                card.Controls.Add(grid);

                var cboScope = new DarkCombo(380);
                cboScope.Items.AddRange(new object[]
                {
                    "Same source and destination (recommended)",
                    "Same destination, any source",
                    "Whole signature – any host",
                });
                cboScope.SelectedIndex = 0;
                var tips = new ToolTip { AutoPopDelay = 20000 };
                tips.SetToolTip(cboScope, "Which future alerts the assessment covers. The narrower, the smaller the risk of hiding a real attack " +
                                          "that triggers the same signature.");

                var btnSave = Ui.B("Save checked", null, ButtonKind.Primary);
                var btnCancel = Ui.B("Cancel", (o, e) => f.Close());
                var lblScope = new Label { Text = "Scope", AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(0, Ui.S(9), Ui.S(8), 0) };
                var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, WrapContents = false, Padding = new Padding(0, Ui.S(10), 0, 0) };
                bottom.Controls.AddRange(new Control[] { lblScope, cboScope, btnSave, btnCancel });

                btnSave.Click += (o, e) =>
                {
                    grid.EndEdit();
                    var chosen = grid.Rows.Cast<DataGridViewRow>().Where(r => r.Cells["Save"].Value is bool b && b).Select(r => (AiVerdict)r.Tag).ToList();
                    if (chosen.Count == 0) { Ui.Warn(f, "Check at least one alert, or Cancel."); return; }
                    var scope = (Scope)cboScope.SelectedIndex;
                    var severe = chosen.Select(v => ((SuricataAi.Group)v.Item).First).Where(x => x.Severity <= 2 || x.EventType == "drop").ToList();
                    if (severe.Count > 0 && MessageBox.Show(f,
                            $"{severe.Count} of the checked alerts have severity 1–2 – they are greyed out from now on" +
                            (scope == Scope.SameHosts ? " for these hosts" : scope == Scope.AnySource ? " for these destinations from ANY source" : " for ANY host") +
                            ".\n\nAn attack that triggers the same signature would look like a known false positive. Save them anyway?",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

                    var today = DateTime.Today;
                    var added = new List<FpRule>();
                    foreach (var v in chosen)
                    {
                        var ev = ((SuricataAi.Group)v.Item).First;
                        var rule = new FpRule
                        {
                            Sid = ev.Sid.Value,
                            Signature = ev.Signature,
                            SrcIp = scope == Scope.SameHosts ? ev.SrcIp : "",
                            DestIp = scope == Scope.AnyHost ? "" : ev.DestIp,
                            Reason = v.Reason,
                            By = "AI " + v.Model,
                            Confidence = v.Confidence,
                            Date = today,
                        };
                        if (!added.Any(x => x.SameScope(rule))) added.Add(rule);
                    }
                    Marks.AddRules(added);
                    MessageBox.Show(f, $"{added.Count} assessment(s) saved to the false positive knowledge base.", Program.AppName,
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    f.Close();
                };

                f.Controls.Add(card);
                f.Controls.Add(new Panel { Dock = DockStyle.Top, Height = Ui.S(8) });
                f.Controls.Add(info);
                f.Controls.Add(bottom);
                f.AcceptButton = null;
                f.CancelButton = btnCancel;
                f.ShowDialog(owner);
            }
        }
    }
}
