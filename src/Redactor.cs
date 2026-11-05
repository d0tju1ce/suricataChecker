using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SuricataChecker
{
    /// <summary>
    /// Masks identifying values before events are sent to an AI service: computer and domain names, user names
    /// (in C:\Users\&lt;name&gt; paths and account contexts), account SIDs, e-mail addresses, UNC servers, internal IPv4
    /// and IPv6 addresses. Every value gets a stable
    /// pseudonym (HOST-1, USER-2, IP-3…) so relations between events stay visible; the AI answer is translated back
    /// locally with <see cref="Unmask"/>. Public IPv4 addresses, domains, paths and hashes stay – they are what the
    /// analysis needs.
    /// </summary>
    class Redactor
    {
        public readonly bool Enabled;
        readonly Dictionary<string, string> toToken = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> toValue = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> counters = new Dictionary<string, int>();
        readonly HashSet<string> userNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Regex known, knownUsers;
        bool dirty = true;

        static readonly HashSet<string> WellKnownDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "NT AUTHORITY", "NT SERVICE", "BUILTIN", "Window Manager", "Font Driver Host", "NT VIRTUAL MACHINE", "IIS APPPOOL" };
        static readonly HashSet<string> CommonProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "Public", "Default", "Default User", "All Users", "defaultuser0", "Administrator", "SYSTEM", "LocalService", "NetworkService" };
        static readonly Regex ProfileRx = new Regex(@"(\\Users\\)([^\\/:*?""<>|\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex Ipv4Rx = new Regex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", RegexOptions.Compiled);
        static readonly Regex Ipv6Rx = new Regex(@"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![0-9A-Za-z:])", RegexOptions.Compiled);
        // case-insensitive: the model may write "User-1"
        static readonly Regex TokenRx = new Regex(@"\b(?:HOST|DOMAIN|DNSDOMAIN|USER|IP|IPV6|MAC|SID|ORG)-\d+\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        // account SIDs (domain / local accounts S-1-5-21-…, Entra ID S-1-12-1-…) – well-known SIDs (S-1-5-18, S-1-5-32-544…) stay
        static readonly Regex SidRx = new Regex(@"\bS-1-(?:5-21(?:-\d+){3}|12-1(?:-\d+){4})(?:-\d+)?(?!\d)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        // \server\share – the server of a UNC path (not the \?\ and \.\ prefixes; an IP address is masked as an IP)
        static readonly Regex UncRx = new Regex(@"(?<![\\\w])\\\\([A-Za-z0-9][A-Za-z0-9_-]{0,62}(?:\.[A-Za-z0-9-]+)*)(?=\\|\s|$|""|')", RegexOptions.Compiled);
        // "OneDrive - Company name" folders reveal the organisation
        static readonly Regex OneDriveOrgRx = new Regex(@"(OneDrive - )([^\\/\r\n""<>|:*?]+?)(?=\\|/|$|""|\s{2})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex EmailRx = new Regex(@"(?<![\w.%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w-])", RegexOptions.Compiled);
        // reverse DNS of an address: 5.1.168.192.in-addr.arpa, b.a.9.8. … .ip6.arpa
        static readonly Regex ReverseV4Rx = new Regex(@"(?<![\w.-])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex ReverseV6Rx = new Regex(@"(?<![\w.-])((?:[0-9a-f]\.){32})ip6\.arpa\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        // names in private DNS zones (devices and servers of the local network, mDNS)
        static readonly Regex PrivateNameRx = new Regex(@"(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})\.)+(?:local|lan|home\.arpa|internal|intranet|localdomain|home|corp|private)(?![\w-])\.?",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex MacRx = new Regex(@"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])", RegexOptions.Compiled);

        public Redactor(bool enabled)
        {
            Enabled = enabled;
            if (!enabled) return;
            Token(Environment.MachineName, "HOST");
            try
            {
                var g = IPGlobalProperties.GetIPGlobalProperties();
                Token(g.HostName, "HOST");
                Token(g.DomainName, "DNSDOMAIN");
            }
            catch { }
            Token(Environment.UserDomainName, "DOMAIN");
            Token(Environment.UserName, "USER");
        }

        /// <summary>Number of distinct masked values.</summary>
        public int Count => toValue.Count;

        public string Summary => Count == 0 ? "nothing to mask"
            : string.Join(", ", toValue.Keys.GroupBy(t => t.Substring(0, t.LastIndexOf('-'))).Select(g => $"{g.Count()}× {g.Key}"));

        string Token(string value, string kind)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;
            value = value.Trim();
            if (value.Length < 2) return value;
            if (toToken.TryGetValue(value, out var t)) return t;
            if (kind == "USER") userNames.Add(value);
            counters.TryGetValue(kind, out var n);
            counters[kind] = ++n;
            t = kind + "-" + n;
            toToken[value] = t;
            toValue[t] = value;
            dirty = true;
            return t;
        }

        /// <summary>Account (DOMAIN\user, user@domain or user) – well-known system accounts stay.</summary>
        public string MaskUser(string account)
        {
            if (!Enabled || string.IsNullOrWhiteSpace(account) || account == "-") return account;
            int bs = account.IndexOf('\\');
            if (bs > 0)
            {
                string domain = account.Substring(0, bs), user = account.Substring(bs + 1);
                if (WellKnownDomains.Contains(domain)) return account;
                string d = toToken.TryGetValue(domain, out var known) ? known : Token(domain, "DOMAIN");
                return d + "\\" + (CommonProfiles.Contains(user) ? user : Token(user, "USER"));
            }
            int at = account.IndexOf('@');
            if (at > 0) return Token(account.Substring(0, at), "USER") + "@" + Mask(account.Substring(at + 1));
            return CommonProfiles.Contains(account) ? account : Token(account, "USER");
        }

        /// <summary>Name of a computer from a protocol field (NetBIOS / DHCP / NTLM host name, SMTP HELO) – an IP address is
        /// masked as an IP, a well-known value stays.</summary>
        public string MaskHost(string name)
        {
            if (!Enabled || string.IsNullOrWhiteSpace(name) || name == "-") return name;
            if (IPAddress.TryParse(name.Trim(), out _)) return Mask(name);
            return Token(name.Trim(), "HOST");
        }

        /// <summary>Domain / realm from a protocol field (NTLM domain, Kerberos realm).</summary>
        public string MaskDomain(string name)
        {
            if (!Enabled || string.IsNullOrWhiteSpace(name) || name == "-" || WellKnownDomains.Contains(name.Trim())) return name;
            return toToken.TryGetValue(name.Trim(), out var t) ? t : Token(name.Trim(), "DOMAIN");
        }

        /// <summary>E-mail addresses in a header value ("Name &lt;user@domain&gt;"): the local part becomes USER-n.</summary>
        public string MaskEmails(string text)
        {
            if (!Enabled || string.IsNullOrEmpty(text)) return text;
            return Mask(text);   // e-mail addresses are part of the general masking
        }

        /// <summary>Second pass over the finished payload: names learned only later (from a profile path or a user field
        /// of a later event) are masked also where they appeared earlier, e.g. in a command line.</summary>
        public string MaskNames(string text)
        {
            if (!Enabled || string.IsNullOrEmpty(text)) return text;
            return NamePass(text);
        }

        /// <summary>Free text: profile paths, internal IPs, IPv6 addresses and all names masked so far.</summary>
        public string Mask(string text)
        {
            if (!Enabled || string.IsNullOrEmpty(text)) return text;
            text = SidRx.Replace(text, m => Token(m.Value.ToUpperInvariant(), "SID"));
            text = EmailRx.Replace(text, m => Token(m.Groups[1].Value, "USER") + "@" + m.Groups[2].Value);
            text = OneDriveOrgRx.Replace(text, m => m.Groups[1].Value + Token(m.Groups[2].Value.Trim(), "ORG"));
            text = UncRx.Replace(text, m =>
            {
                string host = m.Groups[1].Value;
                if (IPAddress.TryParse(host, out _) || host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return m.Value;
                return @"\\" + Token(host, "HOST");
            });
            text = ProfileRx.Replace(text, m => CommonProfiles.Contains(m.Groups[2].Value) ? m.Value : m.Groups[1].Value + Token(m.Groups[2].Value, "USER"));
            text = ReverseV4Rx.Replace(text, m =>
            {
                string ip = m.Groups[4].Value + "." + m.Groups[3].Value + "." + m.Groups[2].Value + "." + m.Groups[1].Value;
                return IPAddress.TryParse(ip, out var a) && IsInternal(a) ? Token(ip, "IP") + ".in-addr.arpa" : m.Value;
            });
            text = ReverseV6Rx.Replace(text, m =>
            {
                var nibbles = m.Groups[1].Value.Replace(".", "").ToCharArray();
                Array.Reverse(nibbles);
                var hex = new string(nibbles);
                string addr = string.Join(":", Enumerable.Range(0, 8).Select(i => hex.Substring(i * 4, 4)));
                if (!IPAddress.TryParse(addr, out var ip) || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast) return m.Value;
                return Token(ip.ToString(), "IPV6") + ".ip6.arpa";
            });
            text = PrivateNameRx.Replace(text, m => Token(m.Value.TrimEnd('.'), "HOST") + (m.Value.EndsWith(".") ? "." : ""));
            text = MacRx.Replace(text, m => m.Value == "00:00:00:00:00:00" || m.Value.Equals("ff:ff:ff:ff:ff:ff", StringComparison.OrdinalIgnoreCase)
                ? m.Value : Token(m.Value.ToLowerInvariant(), "MAC"));
            text = Ipv4Rx.Replace(text, m => IPAddress.TryParse(m.Value, out var ip) && IsInternal(ip) ? Token(m.Value, "IP") : m.Value);
            text = Ipv6Rx.Replace(text, m =>
            {
                string addr = m.Value.Split('%')[0];
                if (addr.Count(c => c == ':') < 2 || !IPAddress.TryParse(addr, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) return m.Value;
                if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast) return m.Value;
                return Token(addr, "IPV6");
            });
            return NamePass(text);
        }

        string NamePass(string text)
        {
            if (dirty)
            {
                // computer and domain names anywhere in the text – longest first, whole words, not a part of a
                // PowerShell Verb-Noun name
                var names = toToken.Keys.Where(k => !userNames.Contains(k) && !char.IsDigit(k[0]) && k.IndexOf(':') < 0)
                    .OrderByDescending(k => k.Length).Select(Regex.Escape).ToList();
                known = names.Count == 0 ? null
                    : new Regex(@"(?<![A-Za-z0-9])(?:" + string.Join("|", names) + @")(?![A-Za-z0-9])(?!-\d)", RegexOptions.IgnoreCase);
                // user names are often ordinary words (test, admin, backup): only where the text says it is an account –
                // a profile path, DOMAIN\user, user@…, "net user x", /user:x, -u x, user: x
                var users = userNames.Where(k => k.IndexOf(':') < 0).OrderByDescending(k => k.Length).Select(Regex.Escape).ToList();
                string alt = string.Join("|", users);
                knownUsers = users.Count == 0 ? null : new Regex(
                    @"(?:(?<=\\Users\\)|(?<=\b(?:HOST|DOMAIN|DNSDOMAIN)-\d+\\)|(?<=(?:\buser(?:name)?|/u(?:ser)?|(?<![\w-])-u|\bnet1?(?:\.exe)?""?\s+user)[\s:=]+""?))"
                    + @"(?:" + alt + @")(?![A-Za-z0-9_-])|(?<![\w.%+-])(?:" + alt + @")(?=@)",
                    RegexOptions.IgnoreCase);
                dirty = false;
            }
            if (known != null)
            {
                string s = text;
                text = known.Replace(s, m =>
                {
                    // a name of letters only joined by "-" to another word is a part of a PowerShell Verb-Noun name
                    // (Test-Path) – "WIN11-TEST" style names with digits or dashes are masked also inside longer names
                    if (m.Value.All(char.IsLetter))
                    {
                        int a = m.Index, b = m.Index + m.Length;
                        if ((b + 1 < s.Length && s[b] == '-' && char.IsLetter(s[b + 1])) || (a >= 2 && s[a - 1] == '-' && char.IsLetter(s[a - 2])))
                            return m.Value;
                    }
                    return toToken.TryGetValue(m.Value, out var t) ? t : m.Value;
                });
            }
            if (knownUsers != null) text = knownUsers.Replace(text, m => toToken.TryGetValue(m.Value, out var t) ? t : m.Value);
            return text;
        }

        /// <summary>Pseudonyms in the AI answer back to the real values (shown only locally).</summary>
        public string Unmask(string text)
        {
            if (!Enabled || string.IsNullOrEmpty(text) || Count == 0) return text;
            return TokenRx.Replace(text, m => toValue.TryGetValue(m.Value, out var v) ? v : m.Value);
        }

        /// <summary>Address of the local network: private IPv4 ranges, IPv6 link-local / unique local, loopback.</summary>
        public static bool IsInternalAddress(string address)
        {
            if (!IPAddress.TryParse((address ?? "").Trim(), out var ip)) return false;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;
            return IsInternal(ip);
        }

        static bool IsInternal(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            if (b.Length != 4) return false;
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);   // CGNAT
        }
    }

    /// <summary>
    /// Removes secrets from the data sent to an AI service – always, also with masking off: passwords and tokens in
    /// command lines, URLs and connection strings, Authorization values, API keys and private keys. The name of the
    /// parameter stays (the analysis may need to know that a password was passed), only the value becomes [REDACTED].
    /// The secrets are not restored in the answer.
    /// </summary>
    static class SecretScrubber
    {
        public const string Redacted = "[REDACTED]";
        const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant;
        const string Value = @"(?:""[^""]*""|'[^']*'|[^\s""'&;,]+)";
        const string SecretWord = @"(?:password|passwd|pwd|passphrase|secret|client_secret|api[_-]?key|access[_-]?key|secret[_-]?key|"
                                  + @"access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|token|sas|sig|credential)";

        static readonly Regex[] Rules =
        {
            // -----BEGIN … PRIVATE KEY----- blocks (also cut off)
            new Regex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", O),
            // well-known token formats: OpenAI / Anthropic, AWS, GitHub, Slack, Google API, JWT
            new Regex(@"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", O),
            new Regex(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", RegexOptions.Compiled),
            new Regex(@"\bgh[pousr]_[A-Za-z0-9]{30,}", O),
            new Regex(@"\bxox[abprs]-[A-Za-z0-9-]{10,}", O),
            new Regex(@"\bAIza[0-9A-Za-z_-]{35}", RegexOptions.Compiled),
            new Regex(@"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", RegexOptions.Compiled),
        };

        // name=value / name: value (connection strings, URL parameters, JSON, config lines)
        static readonly Regex KeyValue = new Regex(@"(?<![A-Za-z0-9])(" + SecretWord + @")(""?\s*[=:]\s*)(" + Value + ")", O);
        // Authorization: Bearer / Basic …
        static readonly Regex AuthHeader = new Regex(@"\b(Bearer|Basic|Digest|NTLM|Negotiate)\s+[A-Za-z0-9._~+/=-]{8,}", O);
        // command-line options: -p x, -password x, --password=x, /password:x, -Password "x"
        //   (/p only with a space – schtasks /P x; /p:x is an msbuild property). A value that looks like a path or a port
        //   stays (mkdir -p C:\dir, ssh -p 22).
        static readonly Regex CmdOption = new Regex(
            @"((?:^|\s)(?:(?:-p|--?(?:pw|pwd|pass|passwd|password|passphrase|secret|token|apikey|api-key|key)|/(?:pw|pwd|pass|passwd|password|token|rp))(?:[:=]|\s+)|/p\s+))"
            + @"(?!\d{1,5}(?:\s|$))(?![-/])(?![A-Za-z]:[\\/]|\\|\.{1,2}[\\/]|~[\\/]|""[A-Za-z]:[\\/])(" + Value + ")", O);
        // mysql -pPassword (value attached to -p; lower-case p only – -P is the port)
        static readonly Regex MySqlPassword = new Regex(@"((?i:\bmysql(?:dump|admin|sh)?(?:\.exe)?)""?\s(?:[^\r\n]*?\s)?-p)(?=[^\s-])(\S+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        // net use [Z:] \server\share <password> [/user:…]
        static readonly Regex NetUse = new Regex(@"(\bnet1?(?:\.exe)?""?\s+use\s+(?:[A-Za-z]:\s+|\*\s+)?""?\\\\[^\s""]+""?\s+)(?![/*])(""[^""]*""|\S+)", O);
        // Password=… up to the ";" of a connection string (the password may contain spaces)
        static readonly Regex ConnStringPassword = new Regex(@"((?<![A-Za-z0-9])(?:password|pwd)\s*=\s*)([^;\r\n""]+)(?=;)", O);
        // net user <name> <password> [/add …]
        static readonly Regex NetUser = new Regex(@"(\bnet1?(?:\.exe)?""?\s+user\s+(?:""[^""]+""|[^\s/]+)\s+)(?![/*])(""[^""]*""|\S+)", O);
        // ConvertTo-SecureString "x" -AsPlainText
        static readonly Regex SecureString = new Regex(@"(ConvertTo-SecureString\s+(?:-String\s+)?)(""[^""]*""|'[^']*'|[^\s""']+)", O);
        // user:password@host in URLs
        static readonly Regex UrlCredentials = new Regex(@"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)", O);

        public static string Scrub(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            foreach (var rx in Rules) text = rx.Replace(text, Redacted);
            text = AuthHeader.Replace(text, m => m.Groups[1].Value + " " + Redacted);
            text = UrlCredentials.Replace(text, m => m.Groups[1].Value + Redacted + m.Groups[3].Value);
            text = NetUser.Replace(text, m => m.Groups[1].Value + Redacted);
            text = NetUse.Replace(text, m => m.Groups[1].Value + Redacted);
            text = MySqlPassword.Replace(text, m => m.Groups[1].Value + Redacted);
            text = ConnStringPassword.Replace(text, m => m.Groups[1].Value + Redacted);
            text = SecureString.Replace(text, m => m.Groups[1].Value + Redacted);
            text = CmdOption.Replace(text, m => m.Groups[1].Value + Redacted);
            text = KeyValue.Replace(text, m => m.Groups[3].Value.Contains(Redacted) ? m.Value : m.Groups[1].Value + m.Groups[2].Value + Redacted);
            return text;
        }
    }
}
