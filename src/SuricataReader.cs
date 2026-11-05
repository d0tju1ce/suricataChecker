using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace SuricataChecker
{
    public class SuricataEvent
    {
        public DateTime Time;
        public string EventType = "", SrcIp = "", DestIp = "", Proto = "", AppProto = "";
        public string Signature = "", Category = "", Action = "", Summary = "", FlowId = "", Raw = "";
        public string Timestamp = "";   // as written in eve.json (Time is parsed to local time)
        public int? SrcPort, DestPort, Severity;
        public long? Sid;

        public string Src => SrcPort.HasValue ? $"{SrcIp}:{SrcPort}" : SrcIp;
        public string Dest => DestPort.HasValue ? $"{DestIp}:{DestPort}" : DestIp;

        /// <summary>Identifies one event for the false positive marks (marks.json).</summary>
        public string Key => Timestamp + "|" + FlowId + "|" + EventType + "|" + Sid;
    }

    public class SuricataQuery
    {
        public string EventType = "";
        public int? MaxSeverity;
        public string Ip = "", Text = "";
        public DateTime? From, To;
        public int Max = 2000;
        public long MaxBytes = 50L * 1024 * 1024;
        /// <summary>Alerts of these SIDs are skipped (signatures hidden as false positives); null = none.</summary>
        public HashSet<long> HiddenSids;
    }

    public class SuricataResult
    {
        public List<SuricataEvent> Events = new List<SuricataEvent>();
        public long FileSize, BytesRead;
        /// <summary>Offset just after the last complete line (a line Suricata is still writing is left for the next read).</summary>
        public long CompleteEnd;
        public DateTime FileCreatedUtc;
        /// <summary>Only the added lines were read (auto-refresh), merged with the previous result.</summary>
        public bool Incremental;
        public int LinesScanned, ParseErrors, Hidden;
        public bool Partial;
    }

    /// <summary>
    /// IP filter of the Events page: an address matches exactly (10.0.0.1 does not match 10.0.0.15), a CIDR range
    /// (10.0.0.0/24, fd00::/8) matches the addresses in it, any other text (e.g. "192.168.") is a part of the address.
    /// </summary>
    public class IpFilter
    {
        IPAddress exact, network;
        int prefix;
        string text;

        public static IpFilter Parse(string value)
        {
            value = (value ?? "").Trim();
            if (value.Length == 0) return null;
            var f = new IpFilter { text = value };
            int slash = value.IndexOf('/');
            if (slash > 0 && IPAddress.TryParse(value.Substring(0, slash), out var net) && int.TryParse(value.Substring(slash + 1), out var bits)
                && bits >= 0 && bits <= (net.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
            {
                f.network = net;
                f.prefix = bits;
            }
            else if (IPAddress.TryParse(value, out var ip) && (value.Contains(":") || value.Count(c => c == '.') == 3)) f.exact = ip;
            return f;
        }

        /// <summary>Quick test on the raw line before it is parsed (false = the line certainly does not match).</summary>
        public bool MayMatchLine(string line) =>
            network != null                                                       // a range cannot be tested as text
            || line.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0
            || (exact != null && line.IndexOf(exact.ToString(), StringComparison.OrdinalIgnoreCase) >= 0);   // other IPv6 notation

        public bool Matches(string address)
        {
            if (string.IsNullOrEmpty(address)) return false;
            if (exact == null && network == null) return address.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0;
            if (!IPAddress.TryParse(address, out var ip)) return false;
            if (exact != null) return ip.Equals(exact);
            if (ip.AddressFamily != network.AddressFamily) return false;
            byte[] a = ip.GetAddressBytes(), n = network.GetAddressBytes();
            for (int i = 0, bits = prefix; bits > 0; i++, bits -= 8)
            {
                int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
                if ((a[i] & mask) != (n[i] & mask)) return false;
            }
            return true;
        }
    }

    /// <summary>Reads eve.json (JSON lines) from the end of the file – newest events first.</summary>
    public static class SuricataReader
    {
        static readonly Regex EventTypeRx = new Regex("\"event_type\"\\s*:\\s*\"([^\"]*)\"", RegexOptions.Compiled);
        static readonly Regex TzRx = new Regex(@"([+-]\d{2})(\d{2})$", RegexOptions.Compiled);

        /// <param name="fromOffset">-1 = the last MaxBytes of the file; otherwise only the lines that start at or after this offset
        /// (the CompleteEnd of a previous read – auto-refresh reads only what was added).</param>
        public static SuricataResult Read(string path, SuricataQuery q, CancellationToken ct, long fromOffset = -1)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException("The path to eve.json is not set (Settings page).");
            if (!File.Exists(path))
                throw new InvalidOperationException("eve.json file not found: " + path);

            var res = new SuricataResult();
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };
            bool negateText = q.Text.StartsWith("!");
            string text = negateText ? q.Text.Substring(1) : q.Text;
            string textEscaped = text.Replace("\\", "\\\\");
            int olderThanFrom = 0;
            var ip = IpFilter.Parse(q.Ip);

            // newest line first, read in blocks from the end: stops as soon as there are enough events (no need to hold
            // the whole window in memory) and a Stop keeps the newest events
            foreach (string line in LinesFromEnd(path, q.MaxBytes, res, fromOffset))
            {
                if (res.Events.Count >= q.Max) break;
                if ((res.LinesScanned & 1023) == 0 && ct.IsCancellationRequested) break;
                res.LinesScanned++;

                if (q.EventType.Length > 0)
                {
                    var m = EventTypeRx.Match(line);
                    if (!m.Success || !string.Equals(m.Groups[1].Value, q.EventType, StringComparison.OrdinalIgnoreCase)) continue;
                }
                if (text.Length > 0)
                {
                    bool contains = line.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0
                                    || line.IndexOf(textEscaped, StringComparison.OrdinalIgnoreCase) >= 0;
                    if (contains == negateText) continue;
                }
                if (ip != null && !ip.MayMatchLine(line)) continue;

                Dictionary<string, object> d;
                try { d = ser.DeserializeObject(line) as Dictionary<string, object>; }
                catch { res.ParseErrors++; continue; }
                if (d == null) { res.ParseErrors++; continue; }

                var ev = Build(d, line);
                if (q.To.HasValue && ev.Time > q.To.Value) continue;
                if (q.From.HasValue && ev.Time < q.From.Value)
                {
                    // eve.json is roughly chronological – after 1000 older records in a row we can stop. Flow / netflow records
                    // are written when the flow ends but carry its start time (minutes or hours earlier) – they do not count.
                    if (ev.EventType != "flow" && ev.EventType != "netflow" && ++olderThanFrom > 1000) break;
                    continue;
                }
                if (q.From.HasValue) olderThanFrom = 0;
                if (q.MaxSeverity.HasValue && (!ev.Severity.HasValue || ev.Severity.Value > q.MaxSeverity.Value)) continue;
                if (ip != null && !ip.Matches(ev.SrcIp) && !ip.Matches(ev.DestIp)) continue;
                if (q.HiddenSids != null && ev.Sid.HasValue && q.HiddenSids.Contains(ev.Sid.Value)) { res.Hidden++; continue; }

                res.Events.Add(ev);
            }
            res.Partial = res.BytesRead < res.FileSize;
            return res;
        }

        /// <summary>
        /// Lines of the file from the last one backwards, at most <paramref name="maxBytes"/> from the end (a line cut by
        /// that limit is skipped). Updates FileSize and BytesRead of the result while reading.
        /// </summary>
        static IEnumerable<string> LinesFromEnd(string path, long maxBytes, SuricataResult res, long fromOffset)
        {
            const int Block = 1 << 20;
            var utf8 = new UTF8Encoding(false);
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.RandomAccess))
            {
                long length = fs.Length, stop = fromOffset >= 0 ? Math.Min(fromOffset, length) : Math.Max(0, length - maxBytes), pos = length;
                res.FileSize = length;
                res.CompleteEnd = length;
                try { res.FileCreatedUtc = File.GetCreationTimeUtc(path); } catch { }
                bool firstBlock = true, tailIncomplete = false;   // the last line has no line end yet (being written)
                byte[] pending = new byte[0];   // start of the line that continues into the block read before
                var buf = new byte[Block];
                while (pos > stop)
                {
                    int n = (int)Math.Min(Block, pos - stop);
                    pos -= n;
                    fs.Seek(pos, SeekOrigin.Begin);
                    int got = 0;
                    while (got < n)
                    {
                        int r = fs.Read(buf, got, n - got);
                        if (r <= 0) break;
                        got += r;
                    }
                    if (got < n) yield break;   // the file was truncated (rotation) meanwhile
                    res.BytesRead = length - pos;

                    var data = new byte[n + pending.Length];
                    Buffer.BlockCopy(buf, 0, data, 0, n);
                    Buffer.BlockCopy(pending, 0, data, n, pending.Length);
                    if (firstBlock)
                    {
                        firstBlock = false;
                        if (data.Length > 0 && data[data.Length - 1] != (byte)'\n') { tailIncomplete = true; res.CompleteEnd = stop; }
                    }
                    int end = data.Length;
                    for (int i = data.Length - 1; i >= 0; i--)
                    {
                        if (data[i] != (byte)'\n') continue;
                        if (tailIncomplete)
                        {
                            tailIncomplete = false;     // skip the unfinished line, it is read complete next time
                            res.CompleteEnd = pos + i + 1;
                        }
                        else
                        {
                            string line = Decode(utf8, data, i + 1, end);
                            if (line.Length > 0) yield return line;
                        }
                        end = i;
                    }
                    pending = new byte[end];
                    Buffer.BlockCopy(data, 0, pending, 0, end);
                }
                // first line of the file / of the added part (otherwise cut by the size limit)
                if ((stop == 0 || fromOffset >= 0) && pending.Length > 0 && !tailIncomplete)
                {
                    string first = Decode(utf8, pending, 0, pending.Length);
                    if (first.Length > 0) yield return first;
                }
            }
        }

        static string Decode(Encoding enc, byte[] data, int from, int to)
        {
            if (to > from && data[to - 1] == (byte)'\r') to--;
            return to > from ? enc.GetString(data, from, to - from) : "";
        }

        static SuricataEvent Build(Dictionary<string, object> d, string raw)
        {
            var e = new SuricataEvent
            {
                Raw = raw,
                Timestamp = P(d, "timestamp"),
                Time = ParseTime(P(d, "timestamp")),
                EventType = P(d, "event_type"),
                SrcIp = P(d, "src_ip"),
                DestIp = P(d, "dest_ip"),
                Proto = P(d, "proto"),
                AppProto = P(d, "app_proto"),
                FlowId = P(d, "flow_id"),
                SrcPort = Int(P(d, "src_port")),
                DestPort = Int(P(d, "dest_port")),
            };
            if (d.TryGetValue("alert", out var ao) && ao is Dictionary<string, object> a)
            {
                e.Signature = P(a, "signature");
                e.Category = P(a, "category");
                e.Severity = Int(P(a, "severity"));
                e.Action = P(a, "action");
                if (long.TryParse(P(a, "signature_id"), out var sid)) e.Sid = sid;
            }
            e.Summary = Summarize(e, d);
            return e;
        }

        static string Summarize(SuricataEvent e, Dictionary<string, object> d)
        {
            switch (e.EventType)
            {
                case "alert":
                    return e.Signature;
                case "drop":
                    return Join("DROP", e.Signature, P(d, "drop", "reason"));
                case "dns":
                {
                    string rr = First(P(d, "dns", "rrname"), P(d, "dns", "queries", "0", "rrname"));
                    string rrtype = First(P(d, "dns", "rrtype"), P(d, "dns", "queries", "0", "rrtype"));
                    string rcode = P(d, "dns", "rcode");
                    return Join(P(d, "dns", "type"), rrtype, rr, rcode.Length > 0 ? "[" + rcode + "]" : "");
                }
                case "http":
                {
                    string status = P(d, "http", "status");
                    return Join(P(d, "http", "http_method"), P(d, "http", "hostname") + P(d, "http", "url"), status.Length > 0 ? "→ " + status : "");
                }
                case "tls":
                {
                    string sni = P(d, "tls", "sni");
                    return Join(sni.Length > 0 ? "SNI: " + sni : "", P(d, "tls", "version"), P(d, "tls", "subject"));
                }
                case "fileinfo":
                {
                    string size = P(d, "fileinfo", "size");
                    return Join(P(d, "fileinfo", "filename"), size.Length > 0 ? "(" + size + " B)" : "", P(d, "fileinfo", "magic"));
                }
                case "flow":
                case "netflow":
                {
                    string k = e.EventType;
                    return Join(P(d, k, "state"),
                        $"pkts {P(d, k, "pkts_toserver")}/{P(d, k, "pkts_toclient")}",
                        $"bytes {P(d, k, "bytes_toserver")}/{P(d, k, "bytes_toclient")}",
                        P(d, k, "reason"));
                }
                case "anomaly":
                    return Join(P(d, "anomaly", "type"), P(d, "anomaly", "event"), P(d, "anomaly", "layer"));
                case "ssh":
                    return Join(P(d, "ssh", "client", "software_version"), "→", P(d, "ssh", "server", "software_version"));
                case "smb":
                    return Join(P(d, "smb", "command"), P(d, "smb", "filename"), P(d, "smb", "share"));
                case "stats":
                    return "engine statistics (uptime " + P(d, "stats", "uptime") + " s)";
                default:
                    return e.AppProto;
            }
        }

        /// <summary>Navigation in nested JSON, a numeric key = array index.</summary>
        static string P(Dictionary<string, object> d, params string[] path)
        {
            object cur = d;
            foreach (var key in path)
            {
                if (cur is Dictionary<string, object> dict)
                {
                    if (!dict.TryGetValue(key, out cur)) return "";
                }
                else if (cur is object[] arr && int.TryParse(key, out var idx))
                {
                    if (idx < 0 || idx >= arr.Length) return "";
                    cur = arr[idx];
                }
                else return "";
            }
            if (cur == null || cur is Dictionary<string, object> || cur is object[]) return "";
            return Convert.ToString(cur, CultureInfo.InvariantCulture) ?? "";
        }

        static int? Int(string s) => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : (int?)null;
        static string First(params string[] v) { foreach (var x in v) if (!string.IsNullOrEmpty(x)) return x; return ""; }
        static string Join(params string[] parts)
        {
            var sb = new StringBuilder();
            foreach (var p in parts)
                if (!string.IsNullOrWhiteSpace(p)) { if (sb.Length > 0) sb.Append("  "); sb.Append(p); }
            return sb.ToString();
        }

        /// <summary>
        /// Suricata writes the local time of the sensor + offset. The Windows build computes the offset wrongly
        /// (in winter time it reports +0200 instead of +0100), so only the local time is used and the offset is ignored.
        /// </summary>
        static DateTime ParseTime(string s)
        {
            if (string.IsNullOrEmpty(s)) return DateTime.MinValue;
            var m = TzRx.Match(s);
            if (m.Success) s = s.Substring(0, m.Index);
            return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t) ? t : DateTime.MinValue;
        }

        /// <summary>
        /// JSON event as "path  value" rows for the detail view: nested objects as dotted paths (alert.signature),
        /// arrays with an index (metadata.tag[0]). Invalid JSON is returned as one "raw" row.
        /// </summary>
        public static List<KeyValuePair<string, string>> Flatten(string json)
        {
            var rows = new List<KeyValuePair<string, string>>();
            try
            {
                var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };
                FlattenValue(ser.DeserializeObject(json), "", rows);
            }
            catch { rows.Add(new KeyValuePair<string, string>("raw", json)); }
            return rows;
        }

        static void FlattenValue(object v, string path, List<KeyValuePair<string, string>> rows)
        {
            switch (v)
            {
                case Dictionary<string, object> obj:
                    if (obj.Count == 0) rows.Add(new KeyValuePair<string, string>(path, "{}"));
                    foreach (var kv in obj) FlattenValue(kv.Value, path.Length == 0 ? kv.Key : path + "." + kv.Key, rows);
                    break;
                case object[] arr:
                    if (arr.Length == 0) rows.Add(new KeyValuePair<string, string>(path, "[]"));
                    for (int i = 0; i < arr.Length; i++) FlattenValue(arr[i], path + "[" + i + "]", rows);
                    break;
                case null:
                    rows.Add(new KeyValuePair<string, string>(path, "null"));
                    break;
                case bool b:
                    rows.Add(new KeyValuePair<string, string>(path, b ? "true" : "false"));
                    break;
                case IFormattable f:
                    rows.Add(new KeyValuePair<string, string>(path, f.ToString(null, CultureInfo.InvariantCulture)));
                    break;
                default:
                    rows.Add(new KeyValuePair<string, string>(path, v.ToString()));
                    break;
            }
        }

        public static string PrettyJson(string json)
        {
            var sb = new StringBuilder(json.Length * 2);
            int indent = 0;
            bool inStr = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < json.Length) sb.Append(json[++i]);
                    else if (c == '"') inStr = false;
                    continue;
                }
                switch (c)
                {
                    case '"': inStr = true; sb.Append(c); break;
                    case '{':
                    case '[':
                        sb.Append(c);
                        int j = i + 1;
                        while (j < json.Length && char.IsWhiteSpace(json[j])) j++;
                        if (j < json.Length && (json[j] == '}' || json[j] == ']')) { sb.Append(json[j]); i = j; break; }
                        NewLine(sb, ++indent);
                        break;
                    case '}':
                    case ']':
                        NewLine(sb, --indent);
                        sb.Append(c);
                        break;
                    case ',': sb.Append(c); NewLine(sb, indent); break;
                    case ':': sb.Append(": "); break;
                    default: if (!char.IsWhiteSpace(c)) sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        static void NewLine(StringBuilder sb, int indent)
        {
            sb.AppendLine();
            sb.Append(' ', Math.Max(0, indent) * 2);
        }
    }
}
