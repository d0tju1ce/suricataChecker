using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SuricataChecker
{
    /// <summary>
    /// Secrets in the Windows Credential Manager (generic credential, persistence "local computer"): stored in the
    /// profile of the current Windows user on this computer, encrypted by Windows, never in the application folder
    /// and not roaming to other computers. Visible in Control Panel → Credential Manager → Windows Credentials.
    /// </summary>
    static class CredentialStore
    {
        const int CRED_TYPE_GENERIC = 1, CRED_PERSIST_LOCAL_MACHINE = 2, ERROR_NOT_FOUND = 1168;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CREDENTIAL
        {
            public int Flags, Type;
            public string TargetName, Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist, AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias, UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredRead(string target, int type, int flags, out IntPtr cred);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWrite(ref CREDENTIAL cred, int flags);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredDelete(string target, int type, int flags);
        [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);

        public static string Read(string target)
        {
            if (!CredRead(target, CRED_TYPE_GENERIC, 0, out var p)) return "";
            try
            {
                var c = Marshal.PtrToStructure<CREDENTIAL>(p);
                if (c.CredentialBlob == IntPtr.Zero || c.CredentialBlobSize == 0) return "";
                var bytes = new byte[c.CredentialBlobSize];
                Marshal.Copy(c.CredentialBlob, bytes, 0, bytes.Length);
                return Encoding.Unicode.GetString(bytes);
            }
            finally { CredFree(p); }
        }

        public static void Write(string target, string userName, string secret, string comment)
        {
            var bytes = Encoding.Unicode.GetBytes(secret);
            var blob = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes, 0, blob, bytes.Length);
                var c = new CREDENTIAL
                {
                    Type = CRED_TYPE_GENERIC, TargetName = target, UserName = userName, Comment = comment,
                    CredentialBlob = blob, CredentialBlobSize = bytes.Length, Persist = CRED_PERSIST_LOCAL_MACHINE
                };
                if (!CredWrite(ref c, 0))
                    throw new InvalidOperationException("The key could not be saved to the Windows Credential Manager (error " + Marshal.GetLastWin32Error() + ").");
            }
            finally { Marshal.FreeHGlobal(blob); }
        }

        public static void Delete(string target)
        {
            if (!CredDelete(target, CRED_TYPE_GENERIC, 0) && Marshal.GetLastWin32Error() != ERROR_NOT_FOUND)
                throw new InvalidOperationException("The key could not be removed from the Windows Credential Manager (error " + Marshal.GetLastWin32Error() + ").");
        }
    }
}
