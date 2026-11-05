using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace SuricataChecker
{
    /// <summary>
    /// Analyst marks kept between runs in marks.json next to the exe, separately for each computer (same idea as in
    /// ransomwareChecker). Two kinds of false positive:
    /// - one event marked as false positive – stays in the list, greyed out and without the severity colour;
    /// - a whole signature (SID) marked as false positive – all its alerts (also future ones) are hidden
    ///   ("Show hidden false positives" on the EDR – Events page, unhide on the Settings page).
    /// - a false positive assessment (knowledge base): a signature between given hosts with the reason, confirmed by the
    ///   analyst from a verdict of the AI analyzer – matching alerts (also future ones) are greyed out like marked ones
    ///   and the next AI analysis gets the assessment as context.
    /// Format: {"PC": {"events": ["timestamp|flow_id|event_type|sid", …], "signatures": {"2027766": "ET INFO …"},
    ///          "rules": [{"sid": 2027766, "signature": "…", "src": "10.0.0.5", "dest": "", "reason": "…", "by": "…", "confidence": "high", "date": "2026-11-04"}]}}
    /// </summary>
    class FpRule
    {
        public long Sid;
        public string Signature = "", SrcIp = "", DestIp = "", Reason = "", By = "", Confidence = "";
        public DateTime Date;

        /// <summary>An empty address matches any host.</summary>
        public bool Matches(SuricataEvent e) =>
            e.Sid == Sid && (SrcIp.Length == 0 || SrcIp == e.SrcIp) && (DestIp.Length == 0 || DestIp == e.DestIp);

        public bool SameScope(FpRule o) => o.Sid == Sid && o.SrcIp == SrcIp && o.DestIp == DestIp;

        public string Scope => (SrcIp.Length == 0 ? "any" : SrcIp) + " → " + (DestIp.Length == 0 ? "any" : DestIp);
    }

    static class Marks
    {
        // all three are replaced as a whole on every change (copy-on-write, never changed in place): the AI payload is
        // built on a worker thread (the AI analyzer is not modal) and reads them while the main window marks / hides
        static HashSet<string> events = new HashSet<string>(StringComparer.Ordinal);
        static SortedDictionary<long, string> signatures = new SortedDictionary<long, string>();
        static List<FpRule> rules = new List<FpRule>();

        static string FilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "marks.json");
        static string Computer => Environment.MachineName;

        /// <summary>Raised after every change (the Events page reloads, the Settings page refreshes its list).</summary>
        public static event EventHandler Changed;

        /// <summary>Hidden signatures: SID → signature name.</summary>
        public static IReadOnlyDictionary<long, string> HiddenSignatures => signatures;
        public static int MarkedEvents => events.Count;
        public static IReadOnlyList<FpRule> Rules => rules;

        public static bool IsMarked(SuricataEvent e) => events.Contains(e.Key);
        public static bool IsHidden(SuricataEvent e) => e.Sid.HasValue && signatures.ContainsKey(e.Sid.Value);
        public static FpRule RuleFor(SuricataEvent e) => e.Sid.HasValue ? rules.FirstOrDefault(r => r.Matches(e)) : null;
        public static bool IsFalsePositive(SuricataEvent e) => IsMarked(e) || IsHidden(e) || RuleFor(e) != null;
        // (each of them reads the field once – a change meanwhile replaces the whole collection, the old one stays intact)

        /// <summary>Copy of the hidden SIDs for the reader thread.</summary>
        public static HashSet<long> HiddenSidsSnapshot() => new HashSet<long>(signatures.Keys);

        public static void Load()
        {
            var ev2 = new HashSet<string>(StringComparer.Ordinal);
            var sg2 = new SortedDictionary<long, string>();
            events = ev2;
            signatures = sg2;
            rules = new List<FpRule>();
            try
            {
                if (!File.Exists(FilePath)) return;
                var root = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(FilePath)) as Dictionary<string, object>;
                var pc = root?.FirstOrDefault(kv => string.Equals(kv.Key, Computer, StringComparison.OrdinalIgnoreCase)).Value as Dictionary<string, object>;
                if (pc == null) return;
                if (pc.TryGetValue("events", out var ev) && ev is object[] list)
                    foreach (var k in list.OfType<string>()) ev2.Add(k);   // filled before anyone else reads (start)
                if (pc.TryGetValue("signatures", out var sg) && sg is Dictionary<string, object> map)
                    foreach (var kv in map)
                        if (long.TryParse(kv.Key, out var sid)) sg2[sid] = kv.Value as string ?? "";
                if (pc.TryGetValue("rules", out var ru) && ru is object[] items)
                {
                    var loaded = new List<FpRule>();
                    foreach (var d in items.OfType<Dictionary<string, object>>())
                    {
                        string S(string k) => d.TryGetValue(k, out var v) && v != null ? Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) : "";
                        if (!long.TryParse(S("sid"), out var sid)) continue;
                        DateTime.TryParse(S("date"), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var date);
                        loaded.Add(new FpRule { Sid = sid, Signature = S("signature"), SrcIp = S("src"), DestIp = S("dest"),
                                                Reason = S("reason"), By = S("by"), Confidence = S("confidence"), Date = date });
                    }
                    rules = loaded;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("The false positive marks could not be read from " + FilePath + ":\r\n" + ex.Message,
                    Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        public static void SetMarked(SuricataEvent e, bool marked)
        {
            var copy = new HashSet<string>(events, StringComparer.Ordinal);
            if (marked ? copy.Add(e.Key) : copy.Remove(e.Key)) { events = copy; Save(); }
        }

        public static void Hide(long sid, string signature)
        {
            signatures = new SortedDictionary<long, string>(signatures) { [sid] = signature ?? "" };
            Save();
        }

        public static void Unhide(IEnumerable<long> sids)
        {
            var copy = new SortedDictionary<long, string>(signatures);
            bool changed = false;
            foreach (var sid in sids.ToList()) changed |= copy.Remove(sid);
            if (changed) { signatures = copy; Save(); }
        }

        /// <summary>Adds assessments; one with the same signature and hosts is replaced.</summary>
        public static void AddRules(IEnumerable<FpRule> added)
        {
            var list = new List<FpRule>(rules);
            foreach (var r in added)
            {
                list.RemoveAll(x => x.SameScope(r));
                list.Add(r);
            }
            rules = list.OrderBy(r => r.Sid).ThenBy(r => r.SrcIp).ThenBy(r => r.DestIp).ToList();
            Save();
        }

        public static void RemoveRules(IEnumerable<FpRule> removed)
        {
            var set = new HashSet<FpRule>(removed);
            if (set.Count == 0) return;
            rules = rules.Where(r => !set.Contains(r)).ToList();
            Save();
        }

        public static void ClearAll()
        {
            events = new HashSet<string>(StringComparer.Ordinal);
            signatures = new SortedDictionary<long, string>();
            rules = new List<FpRule>();
            Save();
        }

        /// <summary>Writes the entry of this computer and keeps the entries of the other computers.</summary>
        static void Save()
        {
            try
            {
                using (FileLock.Acquire(FilePath)) SaveLocked();   // the folder may be shared – another instance must not write meanwhile
            }
            catch (Exception ex)
            {
                MessageBox.Show("The mark could not be saved to " + FilePath + ":\r\n" + ex.Message,
                    Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            Changed?.Invoke(null, EventArgs.Empty);
        }

        static void SaveLocked()
        {
            {
                var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                Dictionary<string, object> root = null;
                if (File.Exists(FilePath))
                {
                    try { root = ser.DeserializeObject(File.ReadAllText(FilePath)) as Dictionary<string, object>; }
                    catch (ArgumentException) { }   // invalid JSON
                    // damaged / hand-edited file: keep a copy, it may hold the marks of other computers
                    if (root == null)
                        try { File.Copy(FilePath, FilePath + ".unreadable-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), true); } catch { }
                }
                root = root ?? new Dictionary<string, object>();
                foreach (var k in root.Keys.Where(k => string.Equals(k, Computer, StringComparison.OrdinalIgnoreCase)).ToList()) root.Remove(k);
                if (events.Count > 0 || signatures.Count > 0 || rules.Count > 0)
                    root[Computer] = new Dictionary<string, object>
                    {
                        ["events"] = events.OrderBy(k => k, StringComparer.Ordinal).ToArray(),
                        ["signatures"] = signatures.ToDictionary(kv => kv.Key.ToString(), kv => (object)kv.Value),
                        ["rules"] = rules.Select(r => (object)new Dictionary<string, object>
                        {
                            ["sid"] = r.Sid, ["signature"] = r.Signature, ["src"] = r.SrcIp, ["dest"] = r.DestIp,
                            ["reason"] = r.Reason, ["by"] = r.By, ["confidence"] = r.Confidence,
                            ["date"] = r.Date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                        }).ToArray(),
                    };
                // temp file first: an interrupted write must not destroy the marks of the other computers
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, ser.Serialize(root));
                if (File.Exists(FilePath)) File.Replace(tmp, FilePath, null);
                else File.Move(tmp, FilePath);
            }
        }
    }
}
