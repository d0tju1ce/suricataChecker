using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace SuricataChecker
{
    /// <summary>
    /// Settings stored next to the exe (portable) in suricataChecker.settings.xml, separately for each computer:
    /// &lt;suricataChecker&gt;&lt;Computer name="PC1"&gt;…&lt;/Computer&gt;&lt;/suricataChecker&gt;. A computer without its own
    /// entry starts with the defaults. Paths inside the application folder are stored relative, so the folder can be moved.
    /// The older flat format (&lt;AppSettings&gt;) is taken over as the settings of the current computer.
    /// </summary>
    public class AppSettings
    {
        public string SuricataConfigPath { get; set; } = "";
        public string SuricataEvePath { get; set; } = "";
        public int MaxEvents { get; set; } = 2000;
        public int RefreshSeconds { get; set; } = 15;
        public bool AutoRefresh { get; set; }
        public int EveMaxMegabytes { get; set; } = 50;
        public AiSettings Ai { get; set; } = new AiSettings();

        public static string FilePath => Path.Combine(BaseDir, "suricataChecker.settings.xml");
        static string BaseDir => AppDomain.CurrentDomain.BaseDirectory;
        public static string Computer => Environment.MachineName;

        public static AppSettings Load()
        {
            var s = new AppSettings();
            try
            {
                if (!File.Exists(FilePath)) return s;
                var root = XDocument.Load(FilePath).Root;
                XElement e = root.Name.LocalName == "AppSettings"
                    ? root
                    : root.Elements("Computer").FirstOrDefault(c => string.Equals((string)c.Attribute("name"), Computer, StringComparison.OrdinalIgnoreCase));
                if (e == null) return s;
                s.SuricataConfigPath = FromStored((string)e.Element("SuricataConfigPath") ?? "");
                s.SuricataEvePath = FromStored((string)e.Element("SuricataEvePath") ?? "");
                if (int.TryParse((string)e.Element("MaxEvents"), out var max)) s.MaxEvents = max;
                if (int.TryParse((string)e.Element("RefreshSeconds"), out var refresh)) s.RefreshSeconds = refresh;
                if (bool.TryParse((string)e.Element("AutoRefresh"), out var auto)) s.AutoRefresh = auto;
                if (int.TryParse((string)e.Element("EveMaxMegabytes"), out var mb)) s.EveMaxMegabytes = mb;
                s.Ai = AiSettings.FromXml(e.Element("Ai"));
            }
            catch { }
            s.SavedSnapshot = s.Snapshot();
            // a key of an older version was moved to the Credential Manager – remove it from the file right away
            if (s.Ai.Migrated) try { s.Save(); } catch { }
            return s;
        }

        /// <summary>Writes the entry of this computer and keeps the entries of the other computers.</summary>
        public void Save()
        {
            using (FileLock.Acquire(FilePath))   // another instance (the folder is shared between computers) must not write meanwhile
                SaveLocked();
            SavedSnapshot = Snapshot();
        }

        /// <summary>The settings as they are in the file (after Load / Save) – compared with <see cref="Snapshot"/> to find
        /// unsaved changes.</summary>
        public string SavedSnapshot { get; private set; } = "";

        public string Snapshot() => ComputerElement().ToString(SaveOptions.DisableFormatting);

        static readonly System.Collections.Generic.Dictionary<string, string> Names = new System.Collections.Generic.Dictionary<string, string>
        {
            ["SuricataConfigPath"] = "Suricata configuration (suricata.yaml)", ["SuricataEvePath"] = "eve.json",
            ["MaxEvents"] = "Max. events", ["RefreshSeconds"] = "Auto-refresh interval (s)", ["AutoRefresh"] = "Auto-refresh",
            ["EveMaxMegabytes"] = "Max. MB read from eve.json", ["Ai/Provider"] = "AI provider", ["Ai/ClaudeModel"] = "Claude model",
            ["Ai/OpenAiModel"] = "ChatGPT model", ["Ai/MaxEvents"] = "Max. event groups sent", ["Ai/Mask"] = "Mask computer, user names and internal IPs",
            ["Ai/Language"] = "Answer language",
        };

        /// <summary>Unsaved changes as "name: saved → current" (keys are never listed).</summary>
        public System.Collections.Generic.List<string> Changes()
        {
            var list = new System.Collections.Generic.List<string>();
            try
            {
                System.Collections.Generic.Dictionary<string, string> Leaves(string xml) =>
                    string.IsNullOrEmpty(xml) ? new System.Collections.Generic.Dictionary<string, string>()
                    : XElement.Parse(xml).Descendants().Where(x => !x.HasElements && !x.Name.LocalName.EndsWith("Key"))
                        .ToDictionary(x => string.Join("/", x.AncestorsAndSelf().Reverse().Skip(1).Select(a => a.Name.LocalName)), x => x.Value);
                var saved = Leaves(SavedSnapshot);
                foreach (var kv in Leaves(Snapshot()))
                {
                    saved.TryGetValue(kv.Key, out var old);
                    if (old == kv.Value) continue;
                    string Show(string v) => string.IsNullOrEmpty(v) ? "(empty)" : v == "true" ? "on" : v == "false" ? "off" : v;
                    list.Add($"{(Names.TryGetValue(kv.Key, out var n) ? n : kv.Key)}: {Show(old)} → {Show(kv.Value)}");
                }
            }
            catch { }
            return list;
        }

        XElement ComputerElement() => new XElement("Computer", new XAttribute("name", Computer),
            new XElement("SuricataConfigPath", ToStored(SuricataConfigPath)),
            new XElement("SuricataEvePath", ToStored(SuricataEvePath)),
            new XElement("MaxEvents", MaxEvents),
            new XElement("RefreshSeconds", RefreshSeconds),
            new XElement("AutoRefresh", AutoRefresh ? "true" : "false"),
            new XElement("EveMaxMegabytes", EveMaxMegabytes),
            Ai.ToXml());

        void SaveLocked()
        {
            XElement root = null;
            if (File.Exists(FilePath))
            {
                try
                {
                    var old = XDocument.Load(FilePath).Root;
                    if (old.Name.LocalName == "suricataChecker") root = old;
                    else if (old.Name.LocalName != "AppSettings") KeepUnreadable();   // the old flat format = this computer
                }
                catch { KeepUnreadable(); }
            }
            if (root == null) root = new XElement("suricataChecker");

            root.Elements("Computer").Where(c => string.Equals((string)c.Attribute("name"), Computer, StringComparison.OrdinalIgnoreCase)).Remove();
            root.Add(ComputerElement());
            // no API keys in the portable file – also not the ones older versions wrote for other computers
            // (this computer keeps a blob only when moving it to the Credential Manager failed – see AiSettings)
            root.Elements("Computer").Where(c => !string.Equals((string)c.Attribute("name"), Computer, StringComparison.OrdinalIgnoreCase))
                .Descendants().Where(x => x.Name.LocalName == "ClaudeKey" || x.Name.LocalName == "OpenAiKey").Remove();
            var sorted = root.Elements("Computer").OrderBy(c => (string)c.Attribute("name"), StringComparer.OrdinalIgnoreCase).ToList();
            root.Elements("Computer").Remove();
            root.Add(sorted);

            // temp file first: an interrupted write must not destroy the settings of the other computers
            string tmp = FilePath + ".tmp";
            new XDocument(new XDeclaration("1.0", "utf-8", null), root).Save(tmp);
            if (File.Exists(FilePath)) File.Replace(tmp, FilePath, null);
            else File.Move(tmp, FilePath);
        }

        /// <summary>The file cannot be read (damaged, edited by hand) – keep a copy before it is overwritten, it may hold the
        /// settings of other computers.</summary>
        static void KeepUnreadable()
        {
            try { File.Copy(FilePath, FilePath + ".unreadable-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), true); } catch { }
        }

        /// <summary>Path inside the application folder -> relative (config\suricata\…), otherwise unchanged.</summary>
        static string ToStored(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) return path ?? "";
                string full = Path.GetFullPath(path), dir = Path.GetFullPath(BaseDir).TrimEnd('\\') + "\\";
                return full.StartsWith(dir, StringComparison.OrdinalIgnoreCase) ? full.Substring(dir.Length) : full;
            }
            catch { return path; }
        }

        static string FromStored(string path)
        {
            try { return string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(BaseDir, path)); }
            catch { return path; }
        }
    }

    /// <summary>
    /// Exclusive lock for a read-modify-write of a file shared by several computers / instances (settings, marks): a
    /// "&lt;file&gt;.lock" file opened without sharing. Waits up to 5 s for another writer; after that it continues without the
    /// lock (a stale lock of a crashed instance must not block saving for ever).
    /// </summary>
    static class FileLock
    {
        public static IDisposable Acquire(string path)
        {
            string lockPath = path + ".lock";
            for (int i = 0; i < 50; i++)
            {
                try { return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose); }
                catch (IOException) { System.Threading.Thread.Sleep(100); }
                catch (UnauthorizedAccessException) { break; }   // read-only folder – the write itself will report it
            }
            return new MemoryStream();
        }
    }
}
