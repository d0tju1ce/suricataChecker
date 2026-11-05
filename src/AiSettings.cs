using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace SuricataChecker
{
    public enum AiProvider { Claude, OpenAI }

    /// <summary>
    /// Settings of the AI analyzer – part of the per-computer settings (&lt;Ai&gt; element, provider, models, limits).
    /// The API keys are NOT in the settings file: they are in the Windows Credential Manager of the current user on
    /// this computer (<see cref="CredentialStore"/>), so they never travel with the application folder.
    /// </summary>
    public class AiSettings
    {
        public const string DefaultClaudeModel = "claude-sonnet-5-5", DefaultOpenAiModel = "gpt-5";

        public AiProvider Provider = AiProvider.Claude;
        public string ClaudeModel = DefaultClaudeModel, OpenAiModel = DefaultOpenAiModel;
        public int MaxEvents = 300;
        public bool Mask = true;
        string language = "English";

        /// <summary>Answer language – goes into the system prompt, so only a language name is accepted (letters, spaces,
        /// hyphen, max. 30 characters); anything else (an edited settings file) falls back to English.</summary>
        public string Language
        {
            get => language;
            set => language = IsLanguageName(value) ? value.Trim() : "English";
        }

        public static bool IsLanguageName(string v) =>
            !string.IsNullOrWhiteSpace(v) && v.Trim().Length <= 30 && v.Trim().All(c => char.IsLetter(c) || c == ' ' || c == '-');

        /// <summary>Old DPAPI key blobs that could not be moved to the Credential Manager (the write failed) – they are written
        /// back to the settings file so the key is not lost, and moved at the next start.</summary>
        readonly Dictionary<AiProvider, string> unmigrated = new Dictionary<AiProvider, string>();

        /// <summary>A key from the older format (DPAPI blob in the settings file) was moved to the Credential Manager –
        /// the settings file should be saved to drop it.</summary>
        public bool Migrated { get; private set; }

        public string Model
        {
            get => Provider == AiProvider.Claude ? ClaudeModel : OpenAiModel;
            set { if (Provider == AiProvider.Claude) ClaudeModel = value; else OpenAiModel = value; }
        }

        /// <summary>Name of the entry in Credential Manager → Windows Credentials, e.g. "suricataChecker/AI/Claude".</summary>
        public static string CredentialName(AiProvider p) => Program.AppName + "/AI/" + p;

        public string GetKey(AiProvider p)
        {
            try { return CredentialStore.Read(CredentialName(p)); }
            catch { return ""; }
        }

        public bool HasKey(AiProvider p) => GetKey(p).Length > 0;

        /// <summary>Saves the key (empty = removes it).</summary>
        public void SetKey(AiProvider p, string key)
        {
            key = (key ?? "").Trim();
            if (key.Length == 0) CredentialStore.Delete(CredentialName(p));
            else CredentialStore.Write(CredentialName(p), AiClient.ProviderName(p) + " API key", key,
                Program.AppName + " AI analyzer – stored only on this computer");
        }

        public static AiSettings FromXml(XElement e)
        {
            var a = new AiSettings();
            if (e == null) return a;
            if (Enum.TryParse((string)e.Element("Provider"), out AiProvider p)) a.Provider = p;
            a.ClaudeModel = NonEmpty((string)e.Element("ClaudeModel"), DefaultClaudeModel);
            a.OpenAiModel = NonEmpty((string)e.Element("OpenAiModel"), DefaultOpenAiModel);
            if (int.TryParse((string)e.Element("MaxEvents"), out var max)) a.MaxEvents = max;
            if (bool.TryParse((string)e.Element("Mask"), out var mask)) a.Mask = mask;
            a.Language = NonEmpty((string)e.Element("Language"), "English");
            a.MigrateOldKey(AiProvider.Claude, (string)e.Element("ClaudeKey"));
            a.MigrateOldKey(AiProvider.OpenAI, (string)e.Element("OpenAiKey"));
            return a;
        }

        /// <summary>Older versions kept the key as a DPAPI blob in the settings file – move it to the Credential Manager.</summary>
        void MigrateOldKey(AiProvider p, string blob)
        {
            if (string.IsNullOrWhiteSpace(blob)) return;
            string key;
            try
            {
                key = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob),
                    Encoding.UTF8.GetBytes(Program.AppName + ".ai-key"), DataProtectionScope.CurrentUser));
            }
            catch { Migrated = true; return; }   // another user / computer – cannot be decrypted, nothing to move: dropped
            try
            {
                if (key.Length > 0 && !HasKey(p)) SetKey(p, key);
                Migrated = true;                 // moved – the blob is dropped from the file
            }
            catch { unmigrated[p] = blob; }      // the Credential Manager refused it – keep the blob, try again next start
        }

        public XElement ToXml() => new XElement("Ai",
            new XComment(" API keys are not stored here – they are in the Windows Credential Manager of each computer "),
            new XElement("Provider", Provider),
            new XElement("ClaudeModel", ClaudeModel),
            new XElement("OpenAiModel", OpenAiModel),
            new XElement("MaxEvents", MaxEvents),
            new XElement("Mask", Mask ? "true" : "false"),
            new XElement("Language", Language),
            unmigrated.TryGetValue(AiProvider.Claude, out var c) ? new XElement("ClaudeKey", c) : null,
            unmigrated.TryGetValue(AiProvider.OpenAI, out var o) ? new XElement("OpenAiKey", o) : null);

        static string NonEmpty(string v, string fallback) => string.IsNullOrWhiteSpace(v) ? fallback : v.Trim();
    }
}
