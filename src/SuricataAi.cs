using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SuricataChecker
{
    /// <summary>
    /// Suricata events for the AI analyzer: alerts of the same signature between the same hosts/port and other
    /// identical events are grouped with a count; engine noise (flow IDs, interface, packet dumps, rule metadata
    /// dates) is left out and long values are shortened. Over the limit, alerts by severity and the newest events
    /// are kept. The groups are sent oldest first (timeline).
    /// </summary>
    static class SuricataAi
    {
        const int MaxValue = 600, MaxChars = 180000;

        static readonly HashSet<string> Skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "timestamp", "flow_id", "parent_id", "in_iface", "community_id", "pcap_cnt", "tx_id", "packet", "payload", "stream",
            "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto", "host", "capture_file",
            "alert.gid", "alert.rev", "alert.signature", "alert.signature_id", "alert.category", "alert.severity", "alert.action",
            // packet / body content may hold passwords, cookies and other data of the users – never sent
            "payload_printable", "payload_length", "alert.rule"
        };
        static readonly string[] SkipPrefixes =
        {
            "packet_info.", "ether.", "vlan", "flow.start", "flow.end", "stats.",
            // content of packets, HTTP bodies and all headers (Cookie, Authorization…), WebSocket / frame payloads
            "http.http_request_body", "http.http_response_body", "http.request_headers", "http.response_headers",
            "websocket.payload", "frame.payload"
        };
        static readonly string[] KeepMetadata = { "mitre", "signature_severity", "attack_target", "confidence", "malware_family", "deployment" };

        public static AiSource Source(List<SuricataEvent> shown, List<SuricataEvent> selected, string filters)
        {
            var src = new AiSource
            {
                Product = "Suricata IDS events (eve.json)",
                Filters = filters,
                TuningHint = "suggested Suricata changes (suppress / threshold entries in threshold.config, disabled rules)",
                Tasks = new[]
                {
                    ("Triage – find threats and suspicious activity",
                     "Triage these network events: identify malicious or suspicious traffic (C2, scanning, exploitation, data exfiltration, " +
                     "policy violations), rate the overall severity and list what needs attention first."),
                    ("Explain what happened (timeline)",
                     "Reconstruct what happened as a timeline: group related events by host pair and flow (alerts, DNS queries, HTTP/TLS " +
                     "sessions, file transfers), note the direction of each connection (internal → external or inbound) and the protocols, " +
                     "and explain them in plain language. Point out anything unusual."),
                    ("Find false positives and suggest tuning",
                     "Identify alerts that are most likely benign or false positives (e.g. normal update, cloud or local network traffic) and " +
                     "propose concrete threshold.config entries (suppress / threshold, by SID and if possible by source or destination) that " +
                     "reduce noise without losing the detection of real attacks. List the false positive groups in the fp-verdicts block."),
                    ("Answer my question only",
                     "Answer the analyst's question below using the events."),
                }
            };
            if (selected.Count > 0) src.Scopes.Add(Scope(selected.Count == 1 ? "Selected event" : "Selected rows", selected));
            src.Scopes.Add(Scope("All shown events", shown));
            var alerts = shown.Where(e => e.Severity.HasValue || e.EventType == "drop").ToList();
            if (alerts.Count > 0 && alerts.Count < shown.Count) src.Scopes.Add(Scope("Alerts only", alerts));
            var high = shown.Where(e => e.Severity <= 2 || e.EventType == "drop").ToList();
            if (high.Count > 0 && high.Count < alerts.Count) src.Scopes.Add(Scope("Alerts of severity 1–2 only", high));
            src.DefaultScope = selected.Count > 1 ? 0 : selected.Count == 1 ? 1 : 0;
            src.ApplyVerdicts = AiVerdictsDialog.Show;
            return src;
        }

        static AiScope Scope(string name, List<SuricataEvent> list) =>
            new AiScope { Name = name, Count = list.Count, Build = (r, max) => Build(list, r, max) };

        /// <summary>One sent group – the target of a [#n] reference of the AI.</summary>
        internal class Group
        {
            public SuricataEvent First;
            public DateTime Oldest, Newest;
            public int Count;
            public readonly HashSet<string> SrcPorts = new HashSet<string>();
        }

        static AiPayload Build(List<SuricataEvent> list, Redactor r, int maxGroups)
        {
            var groups = new Dictionary<string, Group>();
            var order = new List<Group>();
            foreach (var e in list)
            {
                // alerts: same signature between the same hosts and destination port; other events: same summary
                string key = e.Sid.HasValue
                    ? $"{e.EventType}|{e.Sid}|{e.SrcIp}|{e.DestIp}|{e.DestPort}|{Marks.IsFalsePositive(e)}"
                    : $"{e.EventType}|{e.SrcIp}|{e.DestIp}|{e.DestPort}|{e.Summary}";
                if (!groups.TryGetValue(key, out var g))
                {
                    g = new Group { First = e, Oldest = e.Time, Newest = e.Time };
                    groups[key] = g;
                    order.Add(g);
                }
                g.Count++;
                if (e.SrcPort.HasValue && g.SrcPorts.Count < 50) g.SrcPorts.Add(e.SrcPort.Value.ToString());
                if (e.Time < g.Oldest) g.Oldest = e.Time;
                if (e.Time > g.Newest) g.Newest = e.Time;
            }

            var chosen = order.Count <= maxGroups ? order
                : order.OrderBy(g => g.First.EventType == "drop" ? 0 : g.First.Severity ?? 9).ThenByDescending(g => g.Newest).Take(maxGroups).ToList();

            var p = new AiPayload();
            var sb = new StringBuilder();
            sb.AppendLine("Counts by event type in this selection: " + string.Join(", ",
                list.GroupBy(e => e.EventType).OrderByDescending(g => g.Count()).Select(g => $"{g.Key}: {g.Count()}")));
            var sev = list.Where(e => e.Severity.HasValue).GroupBy(e => e.Severity.Value).OrderBy(g => g.Key).Select(g => $"severity {g.Key}: {g.Count()}").ToList();
            if (sev.Count > 0) sb.AppendLine("Alerts by severity (1 = highest): " + string.Join(", ", sev));
            if (list.Count > 0) sb.AppendLine($"Time span: {list.Min(e => e.Time):yyyy-MM-dd HH:mm:ss} – {list.Max(e => e.Time):yyyy-MM-dd HH:mm:ss} (sensor local time)");
            sb.AppendLine();

            int n = 0;
            foreach (var g in chosen.OrderBy(g => g.Oldest))
            {
                var e = g.First;
                var block = new StringBuilder();
                block.Append($"[#{++n}] {g.Oldest:yyyy-MM-dd HH:mm:ss} | {e.EventType}");
                if (g.Count > 1) block.Append($" | ×{g.Count}, last {g.Newest:yyyy-MM-dd HH:mm:ss}");
                block.AppendLine();
                // IP and port masked separately (an IPv6 address with ":port" would otherwise be read as one address)
                string src = r.Mask(e.SrcIp) + (g.SrcPorts.Count > 1 ? $" ({g.SrcPorts.Count} source ports)" : e.SrcPort.HasValue ? ":" + e.SrcPort : "");
                string dest = r.Mask(e.DestIp) + (e.DestPort.HasValue ? ":" + e.DestPort : "");
                block.AppendLine($"  connection: {e.Proto} {src} -> {dest}"
                                 + (e.AppProto.Length > 0 ? $" app={e.AppProto}" : ""));
                if (e.Sid.HasValue)
                    block.AppendLine($"  alert: [{e.Sid}] {e.Signature} | category: {e.Category} | severity {e.Severity} | action {e.Action}");
                var rule = Marks.RuleFor(e);
                if (rule != null)
                    block.AppendLine($"  note: earlier assessed as a false positive ({rule.By}, confirmed by the analyst{(rule.Date == default ? "" : " " + rule.Date.ToString("yyyy-MM-dd"))}, " +
                                     $"scope {r.Mask(rule.SrcIp.Length == 0 ? "any" : rule.SrcIp)} -> {r.Mask(rule.DestIp.Length == 0 ? "any" : rule.DestIp)}): {r.Mask(rule.Reason)}");
                else if (Marks.IsFalsePositive(e)) block.AppendLine("  note: marked as false positive by the analyst");
                // FTP: the argument of PASS is the password (the command itself stays)
                bool ftpPass = e.Raw.IndexOf("\"command\":\"PASS\"", StringComparison.OrdinalIgnoreCase) >= 0;
                bool ftpUser = e.Raw.IndexOf("\"command\":\"USER\"", StringComparison.OrdinalIgnoreCase) >= 0;
                foreach (var f in SuricataReader.Flatten(e.Raw))
                {
                    if (ftpPass && f.Key.StartsWith("ftp.command_data", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!Keep(f.Key) ||string.IsNullOrWhiteSpace(f.Value) || f.Value == "null" || f.Value == "[]" || f.Value == "{}") continue;
                    string v = MaskField(f.Key, f.Value, r, ftpUser).Replace("\r", "\\r").Replace("\n", "\\n");
                    if (v.Length > MaxValue) v = v.Substring(0, MaxValue) + "…(shortened)";
                    block.AppendLine($"  {f.Key}: {v}");
                }
                if (sb.Length + block.Length > MaxChars) { p.OmittedGroups += chosen.Count - n + 1; n--; break; }
                sb.Append(block);
                p.Refs.Add(g);
                p.Events += g.Count;
            }
            p.Groups = n;
            p.OmittedGroups += order.Count - chosen.Count;
            p.Text = sb.ToString();
            return p;
        }

        // identities carried by the protocols themselves – not known in advance, so the general masking would not catch them
        static readonly string[] UserFields = { "ntlmssp.user", "krb5.cname", "rdp.cookie", "ldap.request.bind_request.name", "ssh.client.user" };
        static readonly string[] HostFields = { "ntlmssp.host", "dhcp.hostname", "dhcp.client_id", "smtp.helo", "nbss.name", "krb5.sname" };
        static readonly string[] DomainFields = { "ntlmssp.domain", "krb5.realm" };
        static readonly string[] EmailFields = { "smtp.mail_from", "smtp.rcpt_to", "email.from", "email.to", "email.cc", "email.bcc", "email.reply_to" };

        static bool FieldIs(string key, string[] names) =>
            names.Any(n => key.EndsWith(n, StringComparison.OrdinalIgnoreCase) || key.IndexOf(n + "[", StringComparison.OrdinalIgnoreCase) >= 0);

        static string MaskField(string key, string value, Redactor r, bool ftpUser)
        {
            if (!r.Enabled) return value;
            if (FieldIs(key, UserFields) || (ftpUser && key.StartsWith("ftp.command_data", StringComparison.OrdinalIgnoreCase)))
                return r.MaskUser(value);
            if (FieldIs(key, DomainFields)) return r.MaskDomain(value);
            if (FieldIs(key, HostFields)) return r.MaskHost(value);
            if (FieldIs(key, EmailFields)) return r.MaskEmails(value);
            return r.Mask(value);
        }

        static bool Keep(string key)
        {
            if (Skip.Contains(key)) return false;
            foreach (var pre in SkipPrefixes) if (key.StartsWith(pre, StringComparison.OrdinalIgnoreCase)) return false;
            if (key.StartsWith("alert.metadata.", StringComparison.OrdinalIgnoreCase))
                return KeepMetadata.Any(k => key.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0);
            return true;
        }
    }
}
