using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SuricataChecker
{
    public enum CheckState { Ok, Warning, Error }

    public class CheckResult
    {
        public CheckState State = CheckState.Error;
        public string Headline = "";
        public string ExePath;
        public string ServiceName;
        public readonly List<string> Lines = new List<string>();
    }

    public class ProcessOutput
    {
        public int ExitCode;
        public bool TimedOut;
        public string Output = "";
    }

    /// <summary>Detection of Suricata on Windows.</summary>
    public static class SystemChecks
    {
        const StringComparison OIC = StringComparison.OrdinalIgnoreCase;

        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static CheckResult CheckSuricata(AppSettings s)
        {
            var r = new CheckResult();
            string svcName = FindSuricataServiceName();
            ServiceControllerStatus? svcStatus = null;
            if (svcName != null)
                try { using (var sc = new ServiceController(svcName)) svcStatus = sc.Status; } catch { }

            r.ServiceName = svcName;
            r.ExePath = FindSuricataExe(s, svcName);
            var procs = Process.GetProcessesByName("suricata");
            var pids = procs.Select(p => p.Id).ToList();
            foreach (var p in procs) p.Dispose();

            if (r.ExePath != null)
            {
                r.Lines.Add("Installation:   " + r.ExePath);
                string ver = SuricataVersion(r.ExePath);
                if (ver != null) r.Lines.Add("Version:        " + ver);
            }
            else r.Lines.Add("Installation:   suricata.exe not found");

            r.Lines.Add(svcName != null
                ? $"Service:        {svcName} – {StatusText(svcStatus ?? ServiceControllerStatus.Stopped)}"
                : r.ExePath != null
                    ? "Service:        not registered – the installer does not create it: Settings → \"Set up Suricata\""
                    : "Service:        not registered");
            r.Lines.Add("Process:        " + (pids.Count > 0 ? "running (PID " + string.Join(", ", pids) + ")" : "not running"));
            bool npcap = NpcapInstalled(), wpcap = WpcapPresent();
            r.Lines.Add("Npcap:          " + (!npcap ? "not found (Suricata on Windows requires Npcap)"
                : wpcap ? "installed (WinPcap API-compatible Mode – wpcap.dll in System32)"
                : "installed WITHOUT the WinPcap API-compatible Mode – wpcap.dll missing, Suricata cannot start"));
            r.Lines.Add("");
            r.Lines.Add(DescribeFile("Configuration:  ", s.SuricataConfigPath));
            if (!string.IsNullOrEmpty(s.SuricataConfigPath) && File.Exists(s.SuricataConfigPath))
            {
                var missingRules = MissingRuleFiles(s.SuricataConfigPath, out string ruleDir, out int listed);
                if (listed > 0)
                    r.Lines.Add("Rules:          " + (missingRules.Count == 0 ? $"{listed} files in {ruleDir}"
                        : $"{missingRules.Count} of {listed} files missing in {ruleDir} – deploy the ET Open rules: Settings → \"Set up Suricata\""));
            }
            r.Lines.Add(DescribeFile("eve.json:       ", s.SuricataEvePath));

            bool installed = r.ExePath != null || svcName != null;
            bool running = pids.Count > 0 || svcStatus == ServiceControllerStatus.Running;
            if (!installed) { r.State = CheckState.Error; r.Headline = "Suricata is not installed"; }
            else if (!running && !wpcap)
            {
                r.State = CheckState.Error;
                r.Headline = npcap ? "Suricata cannot start – Npcap is not in the WinPcap API-compatible Mode (wpcap.dll missing)"
                                   : "Suricata cannot start – Npcap is not installed";
                r.Lines.Add("");
                r.Lines.Add(npcap ? WpcapMissingText : "Install Npcap: Settings → \"Set up Suricata\".");
            }
            else if (!running && svcName == null) { r.State = CheckState.Warning; r.Headline = "Suricata is installed, but its service is not registered"; }
            else if (!running) { r.State = CheckState.Warning; r.Headline = "Suricata is installed but not running"; }
            else { r.State = CheckState.Ok; r.Headline = "Suricata is installed and running"; }
            return r;
        }

        public static string FindSuricataServiceName()
        {
            var services = ServiceController.GetServices();
            try
            {
                var hit = services.FirstOrDefault(x => x.ServiceName.IndexOf("suricata", OIC) >= 0 || x.DisplayName.IndexOf("suricata", OIC) >= 0);
                return hit?.ServiceName;
            }
            finally { foreach (var sc in services) sc.Dispose(); }
        }

        public static string FindSuricataExe(AppSettings s, string svcName)
        {
            // only places an administrator controls: the registered service, Program Files and the installer record in HKLM.
            // Not the folder of the configuration (it comes from the portable settings file) and not PATH – a suricata.exe
            // planted there would be started by the checks, also in an elevated process.
            var candidates = new List<string>();
            if (svcName != null) candidates.Add(GetServiceBinary(svcName));
            foreach (var pf in new[] { Environment.GetEnvironmentVariable("ProgramW6432"), Environment.GetEnvironmentVariable("ProgramFiles"), Environment.GetEnvironmentVariable("ProgramFiles(x86)") })
                if (!string.IsNullOrEmpty(pf)) candidates.Add(Path.Combine(pf, "Suricata", "suricata.exe"));
            candidates.AddRange(UninstallLocations("Suricata").Select(d => Path.Combine(d, "suricata.exe")));

            return candidates.FirstOrDefault(c => !string.IsNullOrEmpty(c) && File.Exists(c));
        }

        static IEnumerable<string> UninstallLocations(string productName)
        {
            var result = new List<string>();
            foreach (var root in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(root))
                    {
                        if (k == null) continue;
                        foreach (var name in k.GetSubKeyNames())
                            using (var sub = k.OpenSubKey(name))
                            {
                                var dn = sub?.GetValue("DisplayName") as string;
                                var loc = sub?.GetValue("InstallLocation") as string;
                                if (dn != null && dn.IndexOf(productName, OIC) >= 0 && !string.IsNullOrWhiteSpace(loc))
                                    result.Add(loc.Trim('"'));
                            }
                    }
                }
                catch { }
            }
            return result;
        }

        static readonly SecurityIdentifier[] NonAdminSids =
        {
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),                 // Everyone
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),          // Users
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),     // Authenticated Users
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),           // INTERACTIVE
        };

        const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.DeleteSubdirectoriesAndFiles;
        const FileSystemRights AncestorRights = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

        /// <summary>
        /// True if a standard user can change the file or its folder (replace the exe, edit the yaml): Everyone, Users,
        /// Authenticated Users, INTERACTIVE or – in an elevated process – the signed-in user's own account have write access.
        /// Such a file must not be run / loaded with administrator rights without the user knowing. Unknown = true.
        /// </summary>
        public static bool WritableByStandardUsers(string file)
        {
            try
            {
                var sids = NonAdminSids.ToList();
                var me = WindowsIdentity.GetCurrent().User;
                if (me != null) sids.Add(me);
                var rules = new List<AuthorizationRuleCollection>
                {
                    File.GetAccessControl(file).GetAccessRules(true, true, typeof(SecurityIdentifier)),
                    Directory.GetAccessControl(Path.GetDirectoryName(Path.GetFullPath(file))).GetAccessRules(true, true, typeof(SecurityIdentifier)),
                };
                bool Grants(AuthorizationRuleCollection coll, FileSystemRights rights)
                {
                    foreach (FileSystemAccessRule r in coll)
                        if (r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & rights) != 0
                            && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0   // applies to children only, not to this object
                            && sids.Contains((SecurityIdentifier)r.IdentityReference))
                            return true;
                    return false;
                }
                // on the folder also "create files" counts: a DLL placed next to the exe is loaded by it
                if (rules.Any(c => Grants(c, WriteRights))) return true;
                // every folder above up to the root of the drive: whoever can delete / rename a subfolder there (or take
                // the folder over) can put a folder of his own in place of ours. "Create folders" alone (C:\ grants it to
                // all users) is not enough – the existing folder cannot be replaced without a delete right.
                for (var d = Directory.GetParent(Path.GetDirectoryName(Path.GetFullPath(file))); d != null; d = d.Parent)
                    if (Grants(Directory.GetAccessControl(d.FullName).GetAccessRules(true, true, typeof(SecurityIdentifier)), AncestorRights))
                        return true;
                return false;
            }
            catch { return true; }
        }

        static string SuricataVersion(string exe)
        {
            // the check runs on every refresh of the Overview page – never start an exe a standard user could have replaced
            // from an elevated process (the version is then read from the file properties)
            if (IsAdmin() && WritableByStandardUsers(exe)) return FileVersion(exe);
            // without wpcap.dll suricata.exe does not even start (Windows would show "wpcap.dll was not found")
            if (!WpcapPresent()) return FileVersion(exe);
            try
            {
                var o = RunProcess(exe, "-V", 8000);
                var line = o.Output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.IndexOf("version", OIC) >= 0);
                if (!string.IsNullOrEmpty(line)) return line;
            }
            catch { }
            return FileVersion(exe);
        }

        /// <summary>suricata.exe (Windows build) is linked against wpcap.dll, which Npcap puts into System32 only in the
        /// "WinPcap API-compatible Mode" (default on, but it can be unticked). Otherwise the DLL is only in System32\Npcap,
        /// where the loader does not look, and Suricata – also the service – cannot start.</summary>
        public static bool WpcapPresent() => File.Exists(Path.Combine(Environment.SystemDirectory, "wpcap.dll"));

        /// <summary>Rule files listed under "rule-files:" of a suricata.yaml that do not exist (relative names are looked up
        /// in "default-rule-path"). The ET Open rules are not part of the Suricata installer – Install-SuricataConfig.ps1
        /// downloads them; until then suricata -T stops at the first missing file.</summary>
        public static List<string> MissingRuleFiles(string yamlPath, out string ruleDir, out int listed)
        {
            var missing = new List<string>();
            ruleDir = null; listed = 0;
            string[] lines;
            try { lines = File.ReadAllLines(yamlPath); } catch { return missing; }
            string Clean(string v)
            {
                int hash = v.IndexOf(" #", StringComparison.Ordinal);
                if (hash >= 0) v = v.Substring(0, hash);
                v = v.Trim().Trim('"', '\'');
                // the Windows configuration writes "C:\\Program Files\\..." (a plain YAML scalar keeps both backslashes)
                return v.Length > 2 ? v.Substring(0, 2) + Regex.Replace(v.Substring(2), @"\\{2,}", @"\") : v;
            }
            var files = new List<string>();
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith("default-rule-path:", StringComparison.Ordinal))
                    ruleDir = Clean(lines[i].Substring("default-rule-path:".Length));
                else if (Regex.IsMatch(lines[i], @"^rule-files:\s*(#.*)?$"))
                {
                    for (i++; i < lines.Length; i++)
                    {
                        string l = lines[i];
                        if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                        var m = Regex.Match(l, @"^\s*-\s*(.+)$");
                        if (!m.Success) { i--; break; }
                        files.Add(Clean(m.Groups[1].Value));
                    }
                }
            }
            if (string.IsNullOrEmpty(ruleDir)) ruleDir = Path.GetDirectoryName(yamlPath);
            listed = files.Count;
            foreach (var f in files)
            {
                try { if (!File.Exists(Path.IsPathRooted(f) ? f : Path.Combine(ruleDir, f))) missing.Add(f); }
                catch { missing.Add(f); }
            }
            return missing;
        }

        public const string WpcapMissingText =
            "wpcap.dll is missing in C:\\Windows\\System32 – Npcap is not installed in the \"WinPcap API-compatible Mode\", so Suricata " +
            "(and its service) cannot start. Fix: Settings → \"Set up Suricata\" (installs Npcap again; keep \"Install Npcap in WinPcap " +
            "API-compatible Mode\" ticked in its installer).";

        /// <summary>Exit code of a process the loader could not start (0xC0000135 STATUS_DLL_NOT_FOUND).</summary>
        public static string ExitCodeNote(int code) =>
            code == unchecked((int)0xC0000135) ? " – a required DLL was not found" + (WpcapPresent() ? "" : " (wpcap.dll – Npcap WinPcap API-compatible Mode)")
            : code == unchecked((int)0xC000007B) ? " – a DLL has the wrong architecture (32/64-bit)" : "";

        public static bool NpcapInstalled()
        {
            try
            {
                if (Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap"))) return true;
                var devices = ServiceController.GetDevices();
                bool any = devices.Any(d => d.ServiceName.Equals("npcap", OIC) || d.ServiceName.Equals("npf", OIC));
                foreach (var d in devices) d.Dispose();
                return any;
            }
            catch { return false; }
        }

        /// <summary>Fills in the paths to the configuration and eve.json. force = overwrite values that are already set.</summary>
        public static void AutoDetect(AppSettings s, bool force)
        {
            string exe = FindSuricataExe(s, FindSuricataServiceName());
            if (exe != null)
            {
                string yaml = Path.Combine(Path.GetDirectoryName(exe), "suricata.yaml");
                if ((force || string.IsNullOrWhiteSpace(s.SuricataConfigPath)) && File.Exists(yaml))
                    s.SuricataConfigPath = yaml;
            }
            if (force || string.IsNullOrWhiteSpace(s.SuricataEvePath))
            {
                string eve = EvePathFromYaml(s.SuricataConfigPath);
                if (eve == null && exe != null) eve = Path.Combine(Path.GetDirectoryName(exe), "log", "eve.json");
                if (eve != null) s.SuricataEvePath = eve;
            }
        }

        /// <summary>Reads default-log-dir and the filename of the eve-log output from suricata.yaml.</summary>
        public static string EvePathFromYaml(string yamlPath)
        {
            if (string.IsNullOrWhiteSpace(yamlPath) || !File.Exists(yamlPath)) return null;
            try
            {
                string text = File.ReadAllText(yamlPath);
                string logDir = null;
                var m = Regex.Match(text, @"^default-log-dir:\s*(.+?)\s*$", RegexOptions.Multiline);
                if (m.Success) logDir = CleanYamlScalar(m.Groups[1].Value);

                string fileName = "eve.json";
                var m2 = Regex.Match(text, @"^\s*-\s*eve-log:\s*$[\s\S]*?^\s*filename:\s*(.+?)\s*$", RegexOptions.Multiline);
                if (m2.Success) fileName = CleanYamlScalar(m2.Groups[1].Value);

                if (Path.IsPathRooted(fileName)) return Path.GetFullPath(fileName);
                string yamlDir = Path.GetDirectoryName(yamlPath);
                if (string.IsNullOrEmpty(logDir)) logDir = Path.Combine(yamlDir, "log");
                else if (!Path.IsPathRooted(logDir)) logDir = Path.Combine(yamlDir, logDir);
                // Unquoted YAML keeps "C:\\Program Files\\..." literally – GetFullPath collapses the doubled backslashes
                return Path.GetFullPath(Path.Combine(logDir, fileName));
            }
            catch { return null; }
        }

        static string CleanYamlScalar(string v)
        {
            v = v.Trim();
            if (v.StartsWith("\""))
            {
                int end = v.LastIndexOf('"');
                v = end > 0 ? v.Substring(1, end - 1) : v.Trim('"');
                v = v.Replace("\\\\", "\\");
            }
            else if (v.StartsWith("'"))
            {
                int end = v.LastIndexOf('\'');
                v = end > 0 ? v.Substring(1, end - 1) : v.Trim('\'');
            }
            else
            {
                int hash = v.IndexOf(" #", StringComparison.Ordinal);
                if (hash >= 0) v = v.Substring(0, hash).Trim();
            }
            return v;
        }

        // ------------------------------------------------------------------ helpers

        public static string GetServiceBinary(string service)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service))
                {
                    var raw = k?.GetValue("ImagePath") as string;
                    if (string.IsNullOrWhiteSpace(raw)) return null;
                    raw = Environment.ExpandEnvironmentVariables(raw.Trim());
                    string path;
                    if (raw.StartsWith("\""))
                    {
                        int end = raw.IndexOf('"', 1);
                        path = end > 0 ? raw.Substring(1, end - 1) : raw.Trim('"');
                    }
                    else
                    {
                        int exe = raw.IndexOf(".exe", OIC);
                        path = exe > 0 ? raw.Substring(0, exe + 4) : raw;
                    }
                    string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    if (path.StartsWith(@"\??\")) path = path.Substring(4);
                    if (path.StartsWith(@"\SystemRoot\", OIC)) path = Path.Combine(win, path.Substring(12));
                    else if (path.StartsWith(@"system32\", OIC)) path = Path.Combine(win, path);
                    return File.Exists(path) ? path : null;
                }
            }
            catch { return null; }
        }

        public static ProcessOutput RunProcess(string exe, string args, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.CurrentDirectory
            };
            var res = new ProcessOutput();
            using (var p = Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync();
                var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs))
                {
                    res.TimedOut = true;
                    try { p.Kill(); } catch { }
                }
                else p.WaitForExit();
                Task.WaitAll(new Task[] { o, e }, 3000);
                res.ExitCode = res.TimedOut ? -1 : p.ExitCode;
                string err = e.IsCompleted ? e.Result : "";
                res.Output = (o.IsCompleted ? o.Result : "") + (err.Length > 0 ? Environment.NewLine + err : "");
                if (res.TimedOut) res.Output += Environment.NewLine + "[the process exceeded the time limit and was terminated]";
            }
            return res;
        }

        static string FileVersion(string path)
        {
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                return string.IsNullOrEmpty(v.FileVersion) ? null : v.FileVersion;
            }
            catch { return null; }
        }

        static string StatusText(ServiceControllerStatus st)
        {
            switch (st)
            {
                case ServiceControllerStatus.Running: return "running";
                case ServiceControllerStatus.Stopped: return "stopped";
                case ServiceControllerStatus.StartPending: return "starting";
                case ServiceControllerStatus.StopPending: return "stopping";
                case ServiceControllerStatus.Paused: return "paused";
                default: return st.ToString();
            }
        }

        static string DescribeFile(string label, string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return label + "(not set)";
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return label + path + "  – FILE DOES NOT EXIST";
                return $"{label}{path}  ({FormatSize(fi.Length)}, modified {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss})";
            }
            catch (Exception ex) { return label + path + "  – " + ex.Message; }
        }

        public static string FormatSize(long bytes)
        {
            if (bytes >= 1L << 30) return $"{bytes / (double)(1L << 30):0.0} GB";
            if (bytes >= 1L << 20) return $"{bytes / (double)(1L << 20):0.0} MB";
            if (bytes >= 1L << 10) return $"{bytes / 1024.0:0.0} kB";
            return bytes + " B";
        }
    }
}
