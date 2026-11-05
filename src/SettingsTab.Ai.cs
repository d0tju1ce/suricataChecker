using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>"AI analyzer" card of the Settings page: provider, API key, model and what is sent.</summary>
    partial class SettingsTab
    {
        readonly DarkCombo cboAiProvider = new DarkCombo(200);
        readonly DarkCombo cboAiModel = new DarkCombo(260, editable: true);
        readonly Field txtAiKey = new Field(380);
        readonly NumberField numAiMax = new NumberField(10, 2000, 50);
        readonly DarkCombo cboAiLang = new DarkCombo(130, editable: true);
        readonly Toggle chkAiMask = new Toggle("Mask computer, user names and internal IPs");
        readonly Label lblAiKey = new Label { AutoSize = true, Margin = new Padding(Ui.S(3), Ui.S(2), 0, Ui.S(8)) };
        readonly string[] aiModels = new string[2];   // model typed for each provider (Claude, OpenAI)
        int aiShown = -1;                              // provider currently shown in the card

        AiProvider AiSelected => cboAiProvider.SelectedIndex == 1 ? AiProvider.OpenAI : AiProvider.Claude;

        Control AiCard()
        {
            var card = NewCard();
            var t = Grid(1);
            Title(t, "AI analyzer",
                "The \"AI analyzer\" button on the Events page sends the chosen events to Claude (Anthropic) or ChatGPT (OpenAI) and shows " +
                "the analysis. The connection uses an API key from the developer platform of the provider (billed per use) – a ChatGPT Plus or " +
                "Claude Pro subscription cannot be used by other applications. The key is stored only on this computer in the Windows " +
                "Credential Manager of your Windows account (not in the application folder) – another computer needs its own key.");

            cboAiProvider.Items.AddRange(new object[] { AiClient.ProviderName(AiProvider.Claude), AiClient.ProviderName(AiProvider.OpenAI) });
            cboAiProvider.SelectedIndexChanged += (o, e) => ShowAiProvider();
            cboAiLang.Items.AddRange(new object[] { "English", "Czech", "Slovak", "German", "Polish" });
            txtAiKey.Box.UseSystemPasswordChar = true;
            txtAiKey.Box.KeyDown += async (o, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await SaveAiKeyAsync(); } };
            tips.SetToolTip(cboAiModel, "Model used for the analysis. \"Test connection\" loads the models available for your key.");
            tips.SetToolTip(numAiMax, "Identical events are sent as one group with a count. Above this number of groups the suspicious\nand newest events are kept. More groups = more tokens (cost) and a longer answer time.");
            tips.SetToolTip(chkAiMask, "Default of the switch in the AI analyzer: computer name, domain, user names and internal IP addresses\nare replaced with pseudonyms before sending and restored in the answer.");

            var lp = Ui.L("Provider"); lp.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            Row(t, lp, cboAiProvider, Ui.L("Model"), cboAiModel);
            t.Controls.Add(FieldLabel("API key"));
            var test = Ui.B("Test connection", async (o, e) => await TestAiAsync());
            tips.SetToolTip(test, "Checks the key (typed or saved) and loads the list of available models.");
            var getKey = Ui.B("Get a key", (o, e) => { try { Process.Start(AiClient.KeyUrl(AiSelected)); } catch { } });
            Row(t, txtAiKey, Ui.B("Save key", async (o, e) => await SaveAiKeyAsync()), Ui.B("Remove key", (o, e) => RemoveAiKey()), test, getKey);
            wrapLabels.Add((lblAiKey, Ui.S(60)));
            t.Controls.Add(lblAiKey);

            var lm = Ui.L("Max. event groups sent"); lm.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            Row(t, lm, numAiMax, Ui.L("Answer language"), cboAiLang, chkAiMask);
            var save = Ui.B("Save settings", async (o, e) => await SaveAsync(), ButtonKind.Primary);
            tips.SetToolTip(save, "Saves the provider, model and the other options (the key is saved with \"Save key\").");
            Row(t, save);
            card.Controls.Add(t);
            return card;
        }

        void LoadAiToUi()
        {
            aiModels[0] = s.Ai.ClaudeModel;
            aiModels[1] = s.Ai.OpenAiModel;
            aiShown = -1;
            cboAiProvider.SelectedIndex = s.Ai.Provider == AiProvider.OpenAI ? 1 : 0;
            ShowAiProvider();
            numAiMax.Value = s.Ai.MaxEvents;
            cboAiLang.Text = s.Ai.Language;
            chkAiMask.Checked = s.Ai.Mask;
        }

        void ApplyAiFromUi()
        {
            if (aiShown >= 0) aiModels[aiShown] = cboAiModel.Text.Trim();
            s.Ai.Provider = AiSelected;
            s.Ai.ClaudeModel = string.IsNullOrWhiteSpace(aiModels[0]) ? AiSettings.DefaultClaudeModel : aiModels[0];
            s.Ai.OpenAiModel = string.IsNullOrWhiteSpace(aiModels[1]) ? AiSettings.DefaultOpenAiModel : aiModels[1];
            s.Ai.MaxEvents = numAiMax.Value;
            s.Ai.Language = string.IsNullOrWhiteSpace(cboAiLang.Text) ? "English" : cboAiLang.Text.Trim();
            s.Ai.Mask = chkAiMask.Checked;
        }

        /// <summary>Provider changed in the combo: its model list, model and key state.</summary>
        void ShowAiProvider()
        {
            int idx = cboAiProvider.SelectedIndex;
            if (idx < 0) return;
            if (aiShown >= 0 && aiShown != idx) aiModels[aiShown] = cboAiModel.Text.Trim();
            aiShown = idx;
            var p = AiSelected;
            cboAiModel.Items.Clear();
            cboAiModel.Items.AddRange(AiClient.SuggestedModels(p));
            cboAiModel.Text = aiModels[idx] ?? "";
            txtAiKey.Value = "";
            ShowAiKeyState();
        }

        void ShowAiKeyState(string extra = null)
        {
            var p = AiSelected;
            bool has = s.Ai.HasKey(p);
            lblAiKey.Text = (has ? "API key saved" : "No key saved for " + AiClient.ProviderName(p) + " – paste it above and press \"Save key\".")
                            + (extra != null ? "\n" + extra : "");
            lblAiKey.ForeColor = has ? Theme.Ok : Theme.SubText;
        }

        async Task SaveAiKeyAsync()
        {
            string key = txtAiKey.Value.Trim();
            if (key.Length == 0) { Ui.Warn(this, "Paste the API key into the field first."); return; }
            var p = AiSelected;
            bool looksRight = p == AiProvider.Claude ? key.StartsWith("sk-ant-") : key.StartsWith("sk-") && !key.StartsWith("sk-ant-");
            if (!looksRight && MessageBox.Show(this, $"The key does not look like a {AiClient.ProviderName(p)} API key.\nSave it anyway?",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try { s.Ai.SetKey(p, key); }
            catch (Exception ex) { Ui.Warn(this, ex.Message); return; }
            txtAiKey.Value = "";
            ShowAiKeyState("Saved to the Windows Credential Manager of this computer (" + AiSettings.CredentialName(p) + "). Use \"Test connection\" to check it.");
            await Task.CompletedTask;
        }

        void RemoveAiKey()
        {
            var p = AiSelected;
            if (!s.Ai.HasKey(p)) { ShowAiKeyState(); return; }
            if (MessageBox.Show(this, $"Remove the saved {AiClient.ProviderName(p)} API key from this computer?", Program.AppName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try { s.Ai.SetKey(p, ""); }
            catch (Exception ex) { Ui.Warn(this, ex.Message); return; }
            ShowAiKeyState("The key was removed.");
        }

        async Task TestAiAsync()
        {
            var p = AiSelected;
            string key = txtAiKey.Value.Trim();
            if (key.Length == 0) key = s.Ai.GetKey(p);
            if (key.Length == 0) { Ui.Warn(this, "Paste the API key into the field (or save it) first."); return; }
            lblAiKey.Text = "Connecting to " + AiClient.ProviderName(p) + "…";
            lblAiKey.ForeColor = Theme.SubText;
            try
            {
                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
                {
                    var models = await AiClient.ListModelsAsync(p, key, cts.Token);
                    string current = cboAiModel.Text.Trim();
                    cboAiModel.Items.Clear();
                    cboAiModel.Items.AddRange(models.Cast<object>().ToArray());
                    cboAiModel.Text = current;
                    string note = models.Count == 0 ? "" : models.Contains(current, StringComparer.OrdinalIgnoreCase)
                        ? " The model " + current + " is available."
                        : " The model \"" + current + "\" is not in the list – choose one from the list and press \"Save settings\".";
                    ShowAiKeyState("Connection OK – " + models.Count + " models available for this key." + note
                                   + (txtAiKey.Value.Trim().Length > 0 ? " The typed key is not saved yet." : ""));
                    lblAiKey.ForeColor = Theme.Ok;
                }
            }
            catch (Exception ex)
            {
                ShowAiKeyState("Connection failed: " + (ex is OperationCanceledException ? "timed out." : ex.Message.Replace("\n\n", " ")));
                lblAiKey.ForeColor = Theme.Attention;
            }
        }
    }
}
