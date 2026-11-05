using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SuricataChecker
{
    /// <summary>
    /// Download, verification and installation of Suricata (Windows MSI of the OISF) and Npcap (capture driver Suricata
    /// needs on Windows) from their official sources only:
    ///   Suricata  https://www.openinfosecfoundation.org/download/windows/  (linked from suricata.io/download)
    ///   Npcap     https://npcap.com/  →  https://npcap.com/dist/
    /// Neither publishes checksums of the Windows installers, so a download must pass:
    ///   1. HTTPS from the official host (also after redirects), size limit;
    ///   2. a valid Authenticode signature (WinVerifyTrust: chain to a trusted root, not revoked, code signing) whose signer
    ///      certificate belongs to the publisher (O=Open Information Security Foundation Inc. / O=Nmap Software LLC);
    ///   3. SHA-256: for the versions listed in KnownSha256 it must match exactly; for a newer version (not known to this
    ///      build) the hash is shown and the signature of the publisher is the proof.
    /// The installer is saved to a new folder under C:\Windows\Temp that only administrators and SYSTEM can access – a
    /// program of the user cannot replace it between the check and the start of the (elevated) installation.
    /// </summary>
    static class SuricataInstaller
    {
        public const string SuricataIndex = "https://www.openinfosecfoundation.org/download/windows/";
        public const string NpcapHome = "https://npcap.com/";
        const string NpcapDist = "https://npcap.com/dist/";
        const long MaxSize = 300L * 1024 * 1024;

        /// <summary>SHA-256 of installers checked when this version was built (file name → hash).</summary>
        static readonly Dictionary<string, string> KnownSha256 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Suricata-8.0.7-1-64bit.msi"] = "F0ACC93179A4FFB05D450BB08153A94BD5AA46B0E56B3B3BE496CABF0B4152B7",
            ["npcap-1.90.exe"] = "682B57E1C05EF375931975C9D6DED40888F4BFDF9F4B11571E654F962F1199B6",
        };

        public class Release
        {
            public string Product, FileName, Url, Publisher, Host;
            public Version Version;
            public string VersionText => Version.Build >= 0 ? Version.ToString(3) : Version.ToString();
        }

        public class Download : IDisposable
        {
            public Release Release;
            public string Folder, Path, Sha256, Signer, Issuer, Thumbprint;
            public long Size;

            /// <summary>true = equals the hash known to this build; null = version not known (signature only).</summary>
            public bool? KnownHashMatch;

            public void Dispose()
            {
                try { if (Folder != null && Directory.Exists(Folder)) Directory.Delete(Folder, true); } catch { }
            }
        }

        static readonly HttpClient http = CreateClient();

        static HttpClient CreateClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var c = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromMinutes(15) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd(Program.AppName + "/" + System.Windows.Forms.Application.ProductVersion);
            return c;
        }

        static async Task<string> GetTextAsync(string url, CancellationToken ct)
        {
            using (var r = await http.GetAsync(url, HttpCompletionOption.ResponseContentRead, ct))
            {
                CheckHost(r.RequestMessage.RequestUri, new Uri(url).Host);
                r.EnsureSuccessStatusCode();
                return await r.Content.ReadAsStringAsync();
            }
        }

        static void CheckHost(Uri final, string host)
        {
            if (final.Scheme != Uri.UriSchemeHttps || !final.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The download was redirected away from the official source: " + final);
        }

        // ------------------------------------------------------------------ latest versions

        static readonly Regex SuricataMsiRx = new Regex(@"href=""(Suricata-(\d+)\.(\d+)\.(\d+)-(\d+)-64bit\.msi)""", RegexOptions.IgnoreCase);

        /// <summary>Newest stable 64-bit MSI in the official download folder (no beta / rc / windivert builds).</summary>
        public static async Task<Release> LatestSuricataAsync(CancellationToken ct)
        {
            string html = await GetTextAsync(SuricataIndex, ct);
            var best = SuricataMsiRx.Matches(html).Cast<Match>()
                .Select(m => new { File = m.Groups[1].Value, V = new Version(int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value), int.Parse(m.Groups[4].Value), int.Parse(m.Groups[5].Value)) })
                .OrderByDescending(x => x.V).FirstOrDefault();
            if (best == null) throw new InvalidOperationException("No Suricata installer was found on " + SuricataIndex);
            return new Release
            {
                Product = "Suricata", FileName = best.File, Url = SuricataIndex + best.File, Host = "www.openinfosecfoundation.org",
                Publisher = "Open Information Security Foundation Inc.", Version = new Version(best.V.Major, best.V.Minor, best.V.Build),
            };
        }

        static readonly Regex NpcapRx = new Regex(@"(?:https://npcap\.com)?/?dist/(npcap-(\d+)\.(\d+)\.exe)", RegexOptions.IgnoreCase);

        /// <summary>The installer offered on the Npcap home page (the dist folder also holds old and OEM builds).</summary>
        public static async Task<Release> LatestNpcapAsync(CancellationToken ct)
        {
            string html = await GetTextAsync(NpcapHome, ct);
            var best = NpcapRx.Matches(html).Cast<Match>()
                .Select(m => new { File = m.Groups[1].Value, V = new Version(int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value)) })
                .OrderByDescending(x => x.V).FirstOrDefault();
            if (best == null) throw new InvalidOperationException("No Npcap installer was found on " + NpcapHome);
            return new Release
            {
                Product = "Npcap", FileName = best.File, Url = NpcapDist + best.File, Host = "npcap.com",
                Publisher = "Nmap Software LLC", Version = best.V,
            };
        }

        // ------------------------------------------------------------------ installed versions

        /// <summary>"This is Suricata version 8.0.7 RELEASE" / "8.0.7.0" → 8.0.7.</summary>
        public static Version ParseVersion(string text)
        {
            var m = Regex.Match(text ?? "", @"(\d+)\.(\d+)(?:\.(\d+))?");
            if (!m.Success) return null;
            return m.Groups[3].Success
                ? new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value))
                : new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value));
        }

        /// <summary>Version of an installed program from the Uninstall keys (DisplayName starting with the given name).</summary>
        public static Version InstalledVersion(string displayName)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                try
                {
                    using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    using (var un = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                    {
                        if (un == null) continue;
                        foreach (var name in un.GetSubKeyNames())
                            using (var k = un.OpenSubKey(name))
                            {
                                var dn = k?.GetValue("DisplayName") as string;
                                if (dn == null || !dn.StartsWith(displayName, StringComparison.OrdinalIgnoreCase)) continue;
                                var v = ParseVersion(k.GetValue("DisplayVersion") as string ?? dn);
                                if (v != null) return v;
                            }
                    }
                }
                catch { }
            return null;
        }

        /// <summary>Compares on the parts both versions have (8.0.7 vs 8.0.7.0 are equal).</summary>
        public static int Compare(Version a, Version b)
        {
            int[] x = { a.Major, a.Minor, Math.Max(0, a.Build) }, y = { b.Major, b.Minor, Math.Max(0, b.Build) };
            for (int i = 0; i < 3; i++) if (x[i] != y[i]) return x[i].CompareTo(y[i]);
            return 0;
        }

        // ------------------------------------------------------------------ download + verification

        /// <summary>Downloads and verifies the installer; throws when any check fails (the folder is then removed).</summary>
        public static async Task<Download> DownloadAsync(Release r, IProgress<string> progress, CancellationToken ct)
        {
            if (!SystemChecks.IsAdmin()) throw new InvalidOperationException("Administrator rights are needed.");
            var d = new Download { Release = r, Folder = AdminOnlyFolder() };
            try
            {
                d.Path = System.IO.Path.Combine(d.Folder, r.FileName);
                using (var resp = await http.GetAsync(r.Url, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    CheckHost(resp.RequestMessage.RequestUri, r.Host);
                    resp.EnsureSuccessStatusCode();
                    long? total = resp.Content.Headers.ContentLength;
                    if (total > MaxSize) throw new InvalidOperationException("The file is unexpectedly large: " + total + " bytes.");
                    using (var src = await resp.Content.ReadAsStreamAsync())
                    using (var dst = new FileStream(d.Path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        var buf = new byte[81920];
                        long done = 0, lastReport = 0;
                        int n;
                        while ((n = await src.ReadAsync(buf, 0, buf.Length, ct)) > 0)
                        {
                            await dst.WriteAsync(buf, 0, n, ct);
                            done += n;
                            if (done > MaxSize) throw new InvalidOperationException("The file is unexpectedly large.");
                            if (done - lastReport > 1024 * 1024)
                            {
                                lastReport = done;
                                progress?.Report(total > 0 ? $"Downloading {r.FileName}… {done * 100 / total.Value} %" : $"Downloading {r.FileName}… {done / 1048576} MB");
                            }
                        }
                        d.Size = done;
                    }
                }

                progress?.Report("Verifying the signature and the hash…");
                await Task.Run(() => Verify(d), ct);
                return d;
            }
            catch
            {
                d.Dispose();
                throw;
            }
        }

        static void Verify(Download d)
        {
            using (var sha = SHA256.Create())
            using (var f = new FileStream(d.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
                d.Sha256 = BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "");

            uint rc = WinVerifyTrust(d.Path);
            if (rc != 0)
                throw new InvalidOperationException($"The digital signature of {d.Release.FileName} is not valid (WinVerifyTrust 0x{rc:X8}" +
                    (rc == 0x800B0100 || rc == 0x800B0003 ? " – the file is not signed" : rc == 0x80096010 ? " – the file was changed after signing" :
                     rc == 0x800B010E ? " – the revocation of the certificate could not be checked (offline?)" :
                     rc == 0x800B010C ? " – the certificate was revoked" : "") + "). Nothing was installed.");

            X509Certificate2 cert;
            try { cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(d.Path)); }
            catch (CryptographicException ex) { throw new InvalidOperationException("The signer certificate could not be read: " + ex.Message); }
            string org = cert.GetNameInfo(X509NameType.SimpleName, false);
            var o = Regex.Match(cert.Subject, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
            string subjectOrg = o.Success ? o.Groups[1].Value.Trim('"') : "";
            if (!subjectOrg.Equals(d.Release.Publisher, StringComparison.Ordinal) && !org.Equals(d.Release.Publisher, StringComparison.Ordinal))
                throw new InvalidOperationException($"{d.Release.FileName} is signed by \"{cert.Subject}\", not by \"{d.Release.Publisher}\". Nothing was installed.");
            d.Signer = cert.Subject;
            d.Issuer = cert.Issuer;
            d.Thumbprint = cert.Thumbprint;

            if (KnownSha256.TryGetValue(d.Release.FileName, out var known))
            {
                if (!known.Equals(d.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"The SHA-256 of {d.Release.FileName} differs from the hash known for this version:\n" +
                        $"downloaded {d.Sha256}\nexpected   {known}\nNothing was installed.");
                d.KnownHashMatch = true;
            }
        }

        /// <summary>New folder C:\Windows\Temp\suricataChecker-setup-&lt;guid&gt; – access for Administrators and SYSTEM only.</summary>
        static string AdminOnlyFolder()
        {
            string dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp",
                                                "suricataChecker-setup-" + Guid.NewGuid().ToString("N"));
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            Directory.CreateDirectory(dir, sec);
            // older setup folders (an interrupted run) – only the ones this code created: owner Administrators / SYSTEM,
            // not a junction (a folder of the same name made by a standard user is left alone)
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            try
            {
                foreach (var old in Directory.GetDirectories(System.IO.Path.GetDirectoryName(dir), "suricataChecker-setup-*"))
                    try
                    {
                        if (old == dir || Directory.GetCreationTimeUtc(old) > DateTime.UtcNow.AddHours(-1)) continue;
                        if ((File.GetAttributes(old) & FileAttributes.ReparsePoint) != 0) continue;
                        var owner = Directory.GetAccessControl(old, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier));
                        if (owner == admins || owner == system) Directory.Delete(old, true);
                    }
                    catch { }
            }
            catch { }
            return dir;
        }

        // ------------------------------------------------------------------ installation

        /// <summary>Starts the installer with its own window (the user chooses the options) and waits for it.</summary>
        /// <param name="exeArgs">Options for an .exe installer (Npcap: "/winpcap_mode=yes" preselects the option in its window).</param>
        public static Task<int> RunInstallerAsync(Download d, string exeArgs = null) => Task.Run(() =>
        {
            string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var psi = d.Path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                ? new ProcessStartInfo(System.IO.Path.Combine(sys, "msiexec.exe"), $"/i \"{d.Path}\" /norestart")
                : new ProcessStartInfo(d.Path, exeArgs ?? "");
            psi.UseShellExecute = false;
            psi.WorkingDirectory = d.Folder;
            using (var p = Process.Start(psi))
            {
                p.WaitForExit();
                return p.ExitCode;
            }
        });

        public static string ExitCodeText(int code) =>
            code == 0 ? "completed" : code == 1602 ? "cancelled by the user" : code == 1641 || code == 3010 ? "completed – Windows must be restarted"
            : code == 1638 ? "another version is already installed – uninstall it first (Settings > Apps) or use the installer of the newer version"
            : code == 1618 ? "another installation is in progress – try again later" : "failed (exit code " + code + ")";

        // ------------------------------------------------------------------ WinVerifyTrust

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile, pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData, pSIPClientData;
            public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData, pwszURLReference;
            public uint dwProvFlags, dwUIContext;
            public IntPtr pSignatureSettings;
        }

        static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        /// <summary>0 = valid Authenticode signature, trusted chain, not revoked (whole chain checked online).</summary>
        static uint WinVerifyTrust(string path)
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            try
            {
                Marshal.StructureToPtr(file, pFile, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = 2,              // WTD_UI_NONE
                    fdwRevocationChecks = 1,     // WTD_REVOKE_WHOLECHAIN
                    dwUnionChoice = 1,           // WTD_CHOICE_FILE
                    pFile = pFile,
                    dwStateAction = 1,           // WTD_STATEACTION_VERIFY
                    dwProvFlags = 0x80,          // WTD_REVOCATION_CHECK_CHAIN
                };
                Marshal.StructureToPtr(data, pData, false);
                uint rc = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, pData);
                data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
                data.dwStateAction = 2;          // WTD_STATEACTION_CLOSE
                Marshal.StructureToPtr(data, pData, true);
                WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, pData);
                return rc;
            }
            finally
            {
                Marshal.FreeHGlobal(pData);
                Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
                Marshal.FreeHGlobal(pFile);
            }
        }
    }
}
