// MemWatch - spot runaway / leaking processes and kernel pool leaks.
// Single-file C#/WinForms app, compiled with the in-box .NET Framework csc.exe.
//
// Design goals:
//  - Simple by default: a short plain-English list of the programs that need
//    attention, with a Restart button on each. All numbers live behind
//    "Advanced details".
//  - Light: one Process.GetProcesses() snapshot per refresh, no WMI per refresh.
//    Exe path + start time are read ONCE per PID (QueryFullProcessImageName /
//    GetProcessTimes with PROCESS_QUERY_LIMITED_INFORMATION) and cached.
//    WMI is only used on demand (command lines when a program is selected,
//    restarted or killed).
//  - Safe: refuses to touch critical OS processes, and never acts on a whole
//    group of agent hosts (node, claude, powershell, ...) - only on one PID.
//  - Never registers itself to start with Windows.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace MemWatch
{
    // ============================ thresholds (tune here) ============================
    static class Cfg
    {
        public const int    DefaultRefreshSec      = 5;       // sample / UI refresh interval
        public const int    GrowthWindowMin        = 10;      // "recent growth" window
        public const double MinHistoryForGrowthMin = 5;       // history needed before growth can flag

        // Absolute per-instance limits (non-critical processes only)
        public const int    HandlesRunaway         = 10000;
        public const int    HandlesWarn            = 5000;
        public const long   PrivateRunawayMB       = 8192;
        public const long   PrivateWarnMB          = 4096;
        public const int    ThreadsRunaway         = 2000;
        public const int    ThreadsWarn            = 1000;
        public const int    GroupHandlesRunaway    = 150000;  // whole program, all instances together

        // Steady growth per instance, normalised to per-10-min.
        // Warn (yellow) = half of these; runaway (red) = these.
        public const int    HandleGrowthRunaway    = 1000;
        public const long   PrivateGrowthRunawayMB = 500;
        public const int    SteadySteps            = 10;      // the window is checked in this many slices
        public const double SteadyFraction         = 0.75;    // share of slices that must not go down

        // Graphics (GPU) memory per program, dedicated usage summed over its processes
        public const long   GpuWarnMB              = 2048;
        public const long   GpuRunawayMB           = 4096;
        public const long   DwmGpuWarnMB           = 3072;    // dwm.exe (draws the screen) gets its own limits
        public const long   DwmGpuRunawayMB        = 6144;
        public const long   GpuGrowthRunawayMB     = 500;     // steady growth per 10 min (warn = half)
        public const double GpuBannerFraction      = 0.85;    // card memory: yellow at this fraction
        public const double GpuRedFraction         = 0.95;    // card memory: red at this fraction
        public const int    DwmRestartWaitMs       = 10000;   // wait for Windows to start a new dwm.exe

        // System-wide
        public const long   NonpagedPoolRedMB      = 1024;    // normal is a few hundred MB
        public const long   PagedPoolWarnMB        = 6144;

        public const int    NotifyDebounceMin      = 30;      // max one balloon per program per 30 min
        public const int    GracefulCloseWaitMs    = 5000;    // wait after CloseMainWindow before Kill
        public const int    KillWaitMs             = 3000;
        public const int    MaxHistorySamples      = 700;     // per PID / program safety cap
    }

    // ================================== safety ==================================
    static class Safety
    {
        static readonly HashSet<string> CriticalNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "System", "Idle", "Secure System", "Registry", "Memory Compression", "smss", "csrss",
            "wininit", "winlogon", "services", "lsass", "LsaIso", "svchost", "dwm", "fontdrvhost", "MsMpEng" };

        // Coding agents run inside these. Never end the whole group, one PID at a time only.
        // (This also lets a single powershell/cmd be ended even though they live in System32.)
        static readonly HashSet<string> AgentHostNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "node", "claude", "powershell", "pwsh", "python", "pythonw", "cmd", "bash", "wsl",
            "WindowsTerminal", "OpenConsole" };

        static readonly string SysDir = DirPrefix(Environment.GetFolderPath(Environment.SpecialFolder.System));
        static readonly string SysX86Dir = DirPrefix(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86));

        static string DirPrefix(string d) { return string.IsNullOrEmpty(d) ? null : d.TrimEnd('\\') + "\\"; }

        // "chrome.exe" -> "chrome"; also "claude.exe.old.1792..." (renamed old binaries) -> "claude".
        public static string BaseName(string name)
        {
            if (name == null) return "";
            int i = name.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return i > 0 ? name.Substring(0, i) : name;
        }
        public static bool IsAgentHost(string name) { return AgentHostNames.Contains(BaseName(name)); }
        public static bool IsExplorer(string name) { return string.Equals(BaseName(name), "explorer", StringComparison.OrdinalIgnoreCase); }
        // dwm stays critical (no kill), but has one dedicated action: "Restart Windows screen drawing".
        public static bool IsDwm(string name) { return string.Equals(BaseName(name), "dwm", StringComparison.OrdinalIgnoreCase); }

        public static bool IsCritical(string name, string path)
        {
            string b = BaseName(name);
            if (CriticalNames.Contains(b)) return true;
            if (IsAgentHost(b) || IsExplorer(b)) return false;
            if (!string.IsNullOrEmpty(path))
            {
                if (SysDir != null && path.StartsWith(SysDir, StringComparison.OrdinalIgnoreCase)) return true;
                if (SysX86Dir != null && path.StartsWith(SysX86Dir, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    // ================================== native ==================================
    static class Native
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint SYNCHRONIZE = 0x00100000;
        const uint WAIT_TIMEOUT = 0x102;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder buf, ref uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("user32.dll")]
        public static extern bool DestroyIcon(IntPtr h);
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();
        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();

        [StructLayout(LayoutKind.Sequential)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength = 64;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile,
                         ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX m);

        [StructLayout(LayoutKind.Sequential)]
        public struct PERFORMANCE_INFORMATION
        {
            public uint cb;
            public UIntPtr CommitTotal, CommitLimit, CommitPeak, PhysicalTotal, PhysicalAvailable,
                           SystemCache, KernelTotal, KernelPaged, KernelNonpaged, PageSize;
            public uint HandleCount, ProcessCount, ThreadCount;
        }
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetPerformanceInfo(ref PERFORMANCE_INFORMATION pi, uint cb);

        // Exe path + start time with the least-privileged access right. Either may stay null
        // (access denied, protected or pseudo processes); callers must cope.
        public static void QueryPathAndStart(int pid, out string path, out DateTime? start)
        {
            path = null; start = null;
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return;
            try
            {
                var sb = new StringBuilder(1024);
                uint size = (uint)sb.Capacity;
                if (QueryFullProcessImageName(h, 0, sb, ref size)) path = sb.ToString();
                long c, e, k, u;
                if (GetProcessTimes(h, out c, out e, out k, out u) && c > 0) start = DateTime.FromFileTime(c);
            }
            finally { CloseHandle(h); }
        }

        // True while the process object is still running (a zombie whose handles are
        // still held elsewhere counts as exited).
        public static bool IsAlive(int pid)
        {
            IntPtr h = OpenProcess(SYNCHRONIZE, false, pid);
            if (h == IntPtr.Zero)
            {
                if (Marshal.GetLastWin32Error() == 87) return false;   // ERROR_INVALID_PARAMETER = no such PID
                try { using (Process.GetProcessById(pid)) return true; } catch { return false; }
            }
            try { return WaitForSingleObject(h, 0) == WAIT_TIMEOUT; }
            finally { CloseHandle(h); }
        }
    }

    static class Wmi
    {
        // On demand only. Null value = not readable (usually needs admin).
        public static Dictionary<int, string> CommandLines(IList<int> pids)
        {
            var res = new Dictionary<int, string>();
            for (int at = 0; at < pids.Count; at += 40)
            {
                string where = string.Join(" OR ", pids.Skip(at).Take(40).Select(p => "ProcessId=" + p));
                using (var s = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process WHERE " + where))
                using (var col = s.Get())
                {
                    foreach (ManagementObject mo in col)
                        using (mo) res[Convert.ToInt32(mo["ProcessId"])] = mo["CommandLine"] as string;
                }
            }
            return res;
        }
    }

    // Kernel pool tags (what poolmon shows) and a best guess at which driver owns the top one.
    // Only run on demand (once) when the nonpaged pool is high.
    static class PoolTags
    {
        [DllImport("ntdll.dll")]
        static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int retLen);
        const int SystemPoolTagInformation = 22;
        const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        public class Tag { public string Name; public long NonPaged, Paged; }

        public static List<Tag> Read()
        {
            var list = new List<Tag>();
            int len = 256 * 1024;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    int ret;
                    int st = NtQuerySystemInformation(SystemPoolTagInformation, buf, len, out ret);
                    if (st == STATUS_INFO_LENGTH_MISMATCH) { len = Math.Max(len * 2, ret + 65536); continue; }
                    if (st != 0) return list;
                    bool x64 = IntPtr.Size == 8;
                    int count = Marshal.ReadInt32(buf);
                    int first = x64 ? 8 : 4, size = x64 ? 40 : 28;
                    var tb = new byte[4];
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr e = new IntPtr(buf.ToInt64() + first + (long)i * size);
                        Marshal.Copy(e, tb, 0, 4);
                        list.Add(new Tag
                        {
                            Name = Encoding.ASCII.GetString(tb),
                            Paged = x64 ? Marshal.ReadInt64(e, 16) : Marshal.ReadInt32(e, 12),
                            NonPaged = x64 ? Marshal.ReadInt64(e, 32) : Marshal.ReadInt32(e, 24)
                        });
                    }
                    return list;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return list;
        }

        // Scans installed kernel drivers for the largest tags (same idea as "findstr /m tag *.sys"),
        // splits each tag's bytes among the third-party drivers that contain it, and returns the
        // third-party driver holding the most, e.g. "Contoso (contoso.sys)". Null if none stands out.
        public static string FindCause(List<Tag> all, out string detail)
        {
            List<Tag> top = all.Where(t => t.NonPaged > 0).OrderByDescending(t => t.NonPaged).Take(15).ToList();
            detail = "Largest nonpaged pool tags: " + string.Join(", ", top.Take(6).Select(t => "'" + t.Name + "' " + Fmt.Size(t.NonPaged))) + ".";
            if (top.Count == 0) return null;
            byte[][] pats = top.Select(t => Encoding.ASCII.GetBytes(t.Name)).ToArray();
            var hits = top.Select(t => new List<string>()).ToArray();
            var isMs = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            using (var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (root == null) return null;
                foreach (string svc in root.GetSubKeyNames())
                {
                    try
                    {
                        using (var k = root.OpenSubKey(svc))
                        {
                            if (k == null) continue;
                            object t = k.GetValue("Type");
                            if (!(t is int) || ((int)t != 1 && (int)t != 2)) continue;   // kernel / file-system drivers
                            string path = ResolveDriverPath(k.GetValue("ImagePath") as string, svc);
                            if (path == null || isMs.ContainsKey(path) || !System.IO.File.Exists(path)) continue;
                            if (new System.IO.FileInfo(path).Length > 256L * 1048576) continue;
                            byte[] bytes = System.IO.File.ReadAllBytes(path);
                            bool any = false;
                            for (int i = 0; i < pats.Length; i++)
                                if (Contains(bytes, pats[i])) { hits[i].Add(path); any = true; }
                            isMs[path] = any && IsMicrosoft(path);
                        }
                    }
                    catch { }
                }
            }
            var weight = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < top.Count; i++)
            {
                List<string> third = hits[i].Where(x => !isMs[x]).ToList();
                foreach (string x in third)
                {
                    long w;
                    weight.TryGetValue(x, out w);
                    weight[x] = w + top[i].NonPaged / third.Count;
                }
            }
            long total = all.Sum(t => t.NonPaged);
            if (weight.Count == 0) return null;
            KeyValuePair<string, long> best = weight.OrderByDescending(kv => kv.Value).First();
            if (best.Value < total / 20) return null;   // under 5% of the pool: not a convincing culprit
            string file = System.IO.Path.GetFileName(best.Key);
            detail += " Third-party driver owning the most of these: " + file + " (~" + Fmt.Size(best.Value) + ").";
            return Company(best.Key) + " (" + file + ")";
        }

        static string ResolveDriverPath(string img, string svc)
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(img)) return System.IO.Path.Combine(win, @"System32\drivers\" + svc + ".sys");
            img = Environment.ExpandEnvironmentVariables(img.Trim().Trim('"'));
            if (img.StartsWith(@"\??\")) img = img.Substring(4);
            if (img.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return System.IO.Path.Combine(win, img.Substring(12));
            if (img.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) return System.IO.Path.Combine(win, img);
            if (img.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase)) return System.IO.Path.GetPathRoot(win) + img.Substring(1);
            return img;
        }

        static bool Contains(byte[] b, byte[] pat)
        {
            for (int i = 0; i <= b.Length - pat.Length; i++)
            {
                if (b[i] != pat[0]) continue;
                int j = 1;
                while (j < pat.Length && b[i + j] == pat[j]) j++;
                if (j == pat.Length) return true;
            }
            return false;
        }

        static bool IsMicrosoft(string path)
        {
            try { return (FileVersionInfo.GetVersionInfo(path).CompanyName ?? "").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0; }
            catch { return false; }
        }

        static string Company(string path)
        {
            string c = "";
            try
            {
                FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
                c = (vi.CompanyName ?? "").Trim();
                if (c.Length == 0) c = (vi.FileDescription ?? "").Trim();
            }
            catch { }
            // "Contoso Ltd. Redmond, WA" -> "Contoso"
            foreach (string cut in new[] { ",", " S.R.L", " SRL", " Inc", " LLC", " Ltd", " Corporation", " Corp", " GmbH", " B.V", " AG" })
            {
                int at = c.IndexOf(cut, StringComparison.OrdinalIgnoreCase);
                if (at > 0) c = c.Substring(0, at).Trim();
            }
            return c.Length > 0 ? c : "an unknown vendor";
        }
    }

    // ================================ pop-up alerts ================================
    // Persisted in HKCU\Software\MemWatch (not a startup entry).
    class AlertState
    {
        const string KeyPath = @"Software\MemWatch";
        public bool Enabled = true;
        public long PoolBootMin;       // boot time (minutes since 0001) when the pool alert was last shown
        public long PoolBytes;         // nonpaged pool size at that alert
        public long LastBalloonTicks;  // UTC ticks of the last balloon of any kind

        public static AlertState Load()
        {
            var st = new AlertState();
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyPath))
                {
                    if (k == null) return st;
                    st.Enabled = Convert.ToInt32(k.GetValue("PopupAlerts", 1)) != 0;
                    st.PoolBootMin = Convert.ToInt64(k.GetValue("PoolAlertBootMin", 0L));
                    st.PoolBytes = Convert.ToInt64(k.GetValue("PoolAlertBytes", 0L));
                    st.LastBalloonTicks = Convert.ToInt64(k.GetValue("LastBalloonUtcTicks", 0L));
                }
            }
            catch { }
            return st;
        }

        public void Save()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    k.SetValue("PopupAlerts", Enabled ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                    k.SetValue("PoolAlertBootMin", PoolBootMin, Microsoft.Win32.RegistryValueKind.QWord);
                    k.SetValue("PoolAlertBytes", PoolBytes, Microsoft.Win32.RegistryValueKind.QWord);
                    k.SetValue("LastBalloonUtcTicks", LastBalloonTicks, Microsoft.Win32.RegistryValueKind.QWord);
                }
            }
            catch { }
        }
    }

    // Decides when a balloon may appear:
    //  - driver memory: once per Windows boot (survives MemWatch restarts), again only if the pool
    //    grew another 2 GB beyond the level last alerted;
    //  - a program: once per MemWatch session, again only if it was restarted (new start time);
    //  - never more than one balloon per 30 minutes overall (held-back alerts go in the next one).
    class AlertPolicy
    {
        public const long PoolRegrowBytes = 2L * 1024 * 1024 * 1024;
        public readonly AlertState St;
        readonly bool persist;
        readonly Dictionary<string, DateTime?> shownPrograms = new Dictionary<string, DateTime?>();

        public AlertPolicy(AlertState st, bool persist) { St = st; this.persist = persist; }

        public static long CurrentBootMin()
        {
            ulong upMs = Native.GetTickCount64();
            return (DateTime.UtcNow - TimeSpan.FromMilliseconds(upMs)).Ticks / TimeSpan.TicksPerMinute;
        }

        // Disk space never causes a balloon (it is shown on the Disk card only).
        public List<string> Decide(DateTime nowUtc, long bootMin, bool npHigh, long npBytes,
                                   IEnumerable<GroupInfo> groups, Func<GroupInfo, string> describe)
        {
            var lines = new List<string>();
            if (!St.Enabled) return lines;
            // Boot time is derived from uptime, so allow a couple of minutes of jitter.
            bool sameBoot = Math.Abs(St.PoolBootMin - bootMin) <= 2;
            bool poolDue = npHigh && (!sameBoot || npBytes >= St.PoolBytes + PoolRegrowBytes);
            var progDue = new List<GroupInfo>();
            foreach (GroupInfo g in groups.Where(g => g.Level >= 2).OrderByDescending(g => g.Score))
            {
                DateTime? shownStart;
                if (!shownPrograms.TryGetValue(g.Key, out shownStart) || shownStart != g.OldestStart) progDue.Add(g);
            }
            if (!poolDue && progDue.Count == 0) return lines;
            if ((nowUtc - new DateTime(St.LastBalloonTicks, DateTimeKind.Utc)).TotalMinutes < Cfg.NotifyDebounceMin) return lines;

            if (poolDue)
            {
                St.PoolBootMin = bootMin;
                St.PoolBytes = npBytes;
                lines.Add("Windows driver memory is high (" + Fmt.Size(npBytes) + "). Only a reboot clears it.");
            }
            foreach (GroupInfo g in progDue)
            {
                shownPrograms[g.Key] = g.OldestStart;
                lines.Add(describe(g));
            }
            St.LastBalloonTicks = nowUtc.Ticks;
            if (persist) St.Save();
            return lines;
        }

        // Simulated scenarios against an in-memory state (no registry). Returns a report; ok = all passed.
        public static string SelfTest(out bool ok)
        {
            var sb = new StringBuilder();
            bool all = true;
            DateTime t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            long boot1 = 1000000, boot2 = 2000000, gb = 1024L * 1024 * 1024;
            var st = new AlertState();
            var a = new AlertPolicy(st, false);
            var none = new List<GroupInfo>();
            Func<GroupInfo, string> d = g => g.Friendly;
            DateTime start1 = new DateTime(2026, 1, 1, 8, 0, 0), start2 = new DateTime(2026, 1, 1, 15, 0, 0);
            Func<string, DateTime, GroupInfo> prog = (name, st0) => new GroupInfo { Key = name, Friendly = name, Level = 2, OldestStart = st0 };

            Action<string, List<string>, int> check = (label, got, want) =>
            {
                bool pass = got.Count == want;
                all &= pass;
                sb.AppendLine((pass ? "[PASS] " : "[FAIL] ") + label + " -> " + got.Count + " line(s)" + (got.Count > 0 ? ": " + string.Join(" | ", got) : ""));
            };
            long np = (long)(4.5 * gb);
            check("pool high, first time this boot", a.Decide(t0, boot1, true, np, none, d), 1);
            check("+5 min, still high (old bug: repeated)", a.Decide(t0.AddMinutes(5), boot1, true, np, none, d), 0);
            check("+40 min, still high, same boot", a.Decide(t0.AddMinutes(40), boot1, true, np, none, d), 0);
            a = new AlertPolicy(st, false);   // MemWatch restarted, same Windows boot
            check("MemWatch restarted, +45 min, same boot", a.Decide(t0.AddMinutes(45), boot1, true, np, none, d), 0);
            check("value flickers below/above 1 GB threshold", a.Decide(t0.AddMinutes(46), boot1, false, np, none, d).Concat(a.Decide(t0.AddMinutes(47), boot1, true, np, none, d)).ToList(), 0);
            check("pool grew +1.5 GB", a.Decide(t0.AddMinutes(50), boot1, true, np + (long)(1.5 * gb), none, d), 0);
            check("pool grew +2.1 GB", a.Decide(t0.AddMinutes(55), boot1, true, np + (long)(2.1 * gb), none, d), 1);
            check("Windows rebooted, 5 min after last balloon (30-min cap)", a.Decide(t0.AddMinutes(60), boot2, true, np, none, d), 0);
            check("Windows rebooted, 35 min after last balloon", a.Decide(t0.AddMinutes(90), boot2, true, np, none, d), 1);
            var x = prog("ProgramX", start1);
            check("ProgramX becomes Restart suggested", a.Decide(t0.AddMinutes(130), boot2, true, np, new[] { x }, d), 1);
            check("ProgramX still a problem, +80 min", a.Decide(t0.AddMinutes(210), boot2, true, np, new[] { x }, d), 0);
            check("ProgramX restarted and a problem again", a.Decide(t0.AddMinutes(250), boot2, true, np, new[] { prog("ProgramX", start2) }, d), 1);
            var y = prog("ProgramY", start1);
            check("ProgramY new problem 5 min later (held back)", a.Decide(t0.AddMinutes(255), boot2, true, np, new[] { y }, d), 0);
            check("ProgramY after 30-min cap", a.Decide(t0.AddMinutes(285), boot2, true, np, new[] { y }, d), 1);
            st.Enabled = false;
            check("pop-ups turned off, new ProgramZ", a.Decide(t0.AddMinutes(400), boot2, true, np, new[] { prog("ProgramZ", start1) }, d), 0);
            ok = all;
            return "MemWatch alert self-test: " + (all ? "ALL PASSED" : "FAILURES") + "\r\n" + sb.ToString();
        }
    }

    // ============================ trends for the "Always watching" panel ============================
    // One sample per minute, last 6 hours, straight-line fit for "growing about +X per hour/day".
    // Samples thinned to every 10 min are saved in HKCU\Software\MemWatch\<valueName> (well under 1 KB)
    // so the rate survives MemWatch restarts. A "reset key" (dwm PID, or boot time for the driver pool)
    // discards the history when the thing being measured starts over.
    class Trend
    {
        const string KeyPath = @"Software\MemWatch";
        const int KeepMin = 6 * 60, MinSpanMin = 15, SaveEveryMin = 10;
        struct Pt { public long Min; public long MB; }   // UTC minutes, MB
        readonly List<Pt> pts = new List<Pt>();
        readonly string valueName;   // null = in-memory only (self-test)
        long resetKey, lastSavedMin;

        public Trend(string valueName) { this.valueName = valueName; if (valueName != null) Load(); }

        static long NowMin() { return DateTime.UtcNow.Ticks / TimeSpan.TicksPerMinute; }

        public void Add(long key, long bytes) { AddAt(NowMin(), key, bytes); }

        public int Count { get { return pts.Count; } }

        public void AddAt(long now, long key, long bytes)
        {
            if (Math.Abs(key - resetKey) > 2) { pts.Clear(); resetKey = key; lastSavedMin = 0; }   // boot time may jitter by a minute
            if (pts.Count > 0 && now - pts[pts.Count - 1].Min < 1) return;
            pts.Add(new Pt { Min = now, MB = bytes / 1048576 });
            while (pts.Count > 0 && now - pts[0].Min > KeepMin) pts.RemoveAt(0);
            if (valueName != null && now - lastSavedMin >= SaveEveryMin) { Save(); lastSavedMin = now; }
        }

        // Simulated samples, no registry. Returns a report; ok = all passed.
        public static string SelfTest(out bool ok)
        {
            var sb = new StringBuilder();
            bool all = true;
            const long MB = 1048576, t0 = 30000000;
            Action<string, bool, string> check = (label, pass, got) =>
            {
                all &= pass;
                sb.AppendLine((pass ? "[PASS] " : "[FAIL] ") + label + " -> " + got);
            };
            Func<double?, string> show = x => x.HasValue ? x.Value.ToString("0.0") + " MB/hour" : "measuring";

            var tr = new Trend(null);
            for (int m = 0; m < 10; m++) tr.AddAt(t0 + m, 1, 2000 * MB);
            check("9 minutes of samples", tr.RateMBPerHour() == null, show(tr.RateMBPerHour()));

            tr = new Trend(null);
            for (int m = 0; m <= 60; m++) tr.AddAt(t0 + m, 1, (long)((2000 + 50.0 * m / 60) * MB));
            double? r = tr.RateMBPerHour();
            check("steady +50 MB/hour for 1 hour", r.HasValue && Math.Abs(r.Value - 50) < 2, show(r));
            check("time to 6 GB from ~2.0 GB at that rate", Duration((6144 - 2050) / r.Value) == "about 3 days", Duration((6144 - 2050) / r.Value));

            tr = new Trend(null);
            for (int m = 0; m <= 60; m++) tr.AddAt(t0 + m, 1, 2000 * MB);
            r = tr.RateMBPerHour();
            check("flat for 1 hour", r.HasValue && Math.Abs(r.Value) < 1, show(r));

            tr = new Trend(null);
            for (int m = 0; m <= 120; m++) tr.AddAt(t0 + m, 1, (long)((2000 + 120.0 * m / 60 + (m % 7 - 3) * 6) * MB));   // +120 MB/hour with +-18 MB jitter
            r = tr.RateMBPerHour();
            check("noisy +120 MB/hour for 2 hours", r.HasValue && Math.Abs(r.Value - 120) < 12, show(r));

            tr.AddAt(t0 + 121, 999, 2000 * MB);   // dwm restarted (new PID)
            check("reset when dwm PID changes", tr.RateMBPerHour() == null && tr.Count == 1, show(tr.RateMBPerHour()) + ", " + tr.Count + " sample(s)");

            tr = new Trend(null);
            for (int m = 0; m <= 7 * 60; m++) tr.AddAt(t0 + m, 1, (long)((1000 + 30.0 * m / 60) * MB));
            r = tr.RateMBPerHour();
            check("7 hours of data keeps last 6 hours", tr.Count == 361 && Math.Abs(r.Value - 30) < 2, tr.Count + " samples, " + show(r));

            tr = new Trend(null);
            for (int m = 0; m <= 60; m++) tr.AddAt(t0 + m, 1, (long)((5000 - 40.0 * m / 60) * MB));
            r = tr.RateMBPerHour();
            check("shrinking memory (-40 MB/hour)", r.HasValue && Math.Abs(r.Value + 40) < 2, show(r));

            ok = all;
            return "MemWatch trend self-test: " + (all ? "ALL PASSED" : "FAILURES") + Environment.NewLine + sb.ToString();
        }

        static string Duration(double hours)
        {
            if (hours < 1) return "under an hour";
            if (hours < 48) return "about " + Math.Round(hours) + " hours";
            return "about " + Math.Round(hours / 24) + " days";
        }

        public double MeasuredMin { get { return pts.Count < 2 ? 0 : pts[pts.Count - 1].Min - pts[0].Min; } }

        // MB per hour; null while still measuring (under 15 minutes of samples).
        public double? RateMBPerHour()
        {
            if (pts.Count < 5 || MeasuredMin < MinSpanMin) return null;
            double mx = pts.Average(p => (double)p.Min), my = pts.Average(p => (double)p.MB);
            double sxy = 0, sxx = 0;
            foreach (Pt p in pts) { sxy += (p.Min - mx) * (p.MB - my); sxx += (p.Min - mx) * (p.Min - mx); }
            return sxx <= 0 ? (double?)null : sxy / sxx * 60;
        }

        void Load()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyPath))
                {
                    // "key=62416;29654400,2253;29654410,2260"   (key; UTC minute, MB; ...)
                    string h = k == null ? null : k.GetValue(valueName) as string;
                    if (string.IsNullOrEmpty(h)) return;
                    string[] parts = h.Split(';');
                    if (!(parts[0].StartsWith("key=") || parts[0].StartsWith("pid=")) || !long.TryParse(parts[0].Substring(4), out resetKey)) return;
                    long now = NowMin();
                    foreach (string e in parts.Skip(1))
                    {
                        string[] xy = e.Split(',');
                        long m, mb;
                        if (xy.Length == 2 && long.TryParse(xy[0], out m) && long.TryParse(xy[1], out mb) && now - m <= KeepMin)
                            pts.Add(new Pt { Min = m, MB = mb });
                    }
                }
            }
            catch { }
        }

        // Last hour at full one-per-minute detail, older samples every 10 min (about 1.5 KB at most).
        public void Save()
        {
            try
            {
                long now = NowMin();
                var thin = new List<Pt>();
                foreach (Pt p in pts)
                    if (now - p.Min <= 60 || thin.Count == 0 || p.Min - thin[thin.Count - 1].Min >= SaveEveryMin) thin.Add(p);
                if (pts.Count > 0 && thin[thin.Count - 1].Min != pts[pts.Count - 1].Min) thin.Add(pts[pts.Count - 1]);
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(KeyPath))
                    k.SetValue(valueName, "key=" + resetKey + string.Concat(thin.Select(p => ";" + p.Min + "," + p.MB)));
            }
            catch { }
        }
    }

    // Last "Restart screen drawing": when, and dwm graphics memory before/after. Saved in HKCU\Software\MemWatch.
    class DwmRestart
    {
        const string KeyPath = @"Software\MemWatch";
        public DateTime? WhenUtc;
        public long BeforeMB, AfterMB;

        public static DwmRestart Load()
        {
            var r = new DwmRestart();
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyPath))
                {
                    if (k == null) return r;
                    long t = Convert.ToInt64(k.GetValue("DwmRestartUtcTicks", 0L));
                    if (t > 0) r.WhenUtc = new DateTime(t, DateTimeKind.Utc);
                    r.BeforeMB = Convert.ToInt64(k.GetValue("DwmRestartBeforeMB", 0L));
                    r.AfterMB = Convert.ToInt64(k.GetValue("DwmRestartAfterMB", 0L));
                }
            }
            catch { }
            return r;
        }

        public void Record(DateTime utc, long beforeBytes, long afterBytes)
        {
            WhenUtc = utc;
            BeforeMB = beforeBytes / 1048576;
            AfterMB = afterBytes / 1048576;
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    k.SetValue("DwmRestartUtcTicks", utc.Ticks, Microsoft.Win32.RegistryValueKind.QWord);
                    k.SetValue("DwmRestartBeforeMB", BeforeMB, Microsoft.Win32.RegistryValueKind.QWord);
                    k.SetValue("DwmRestartAfterMB", AfterMB, Microsoft.Win32.RegistryValueKind.QWord);
                }
            }
            catch { }
        }
    }

    // =================================== data ===================================
    struct Sample { public DateTime T; public long Priv; public long Handles; public long Gpu; }

    class Hist
    {
        public readonly List<Sample> S = new List<Sample>();
        public Sample First;
        bool hasFirst;

        // Keeps exactly one sample at/before the window start as the window baseline.
        public void Add(Sample x, DateTime windowStart)
        {
            if (!hasFirst) { First = x; hasFirst = true; }
            S.Add(x);
            while (S.Count > 2 && S[1].T <= windowStart) S.RemoveAt(0);
            while (S.Count > Cfg.MaxHistorySamples) S.RemoveAt(0);
        }
    }

    class InstanceInfo
    {
        public int Pid;
        public string Name, Path;
        public DateTime? Start;
        public long WS, Priv;
        public int Handles, Threads;
        public long DWinPriv, DWinHandles, DStartPriv, DStartHandles;
        public double WinSpanMin;
        public int Level;
        public string Reason = "";
        // What tripped (watch or runaway level), for the plain-English "Why" text.
        public bool FHandles, FPriv, FThreads, FHandleGrowth, FPrivGrowth, FGpuGrowth;
        public double HandleRate, PrivRateMB, GpuRateMB;   // per 10 min, only when steady
        public double Score;                    // 1.0 = at the runaway threshold
        public long GpuDed, GpuShared, DWinGpu;  // graphics memory (bytes)
    }

    class GroupInfo
    {
        public string Key, Name, Path, Friendly;
        public InstanceInfo Worst;
        public double Score, GpuScore;
        public bool FGroupHandles, FGpu, IsDwm;
        public long GpuDed, GpuShared;
        public readonly List<InstanceInfo> Instances = new List<InstanceInfo>();
        public long WS, Priv, Handles, Threads;
        public long DWinPriv, DWinHandles, DStartPriv, DStartHandles;
        public double WinSpanMin;
        public DateTime? OldestStart;
        public int Level;
        public string Reason = "";
        public bool Critical, AgentHost, IsSelf;
    }

    class SysInfo
    {
        public ulong TotalPhys, AvailPhys;
        public long CommitTotal, CommitLimit, NonPaged, Paged, NonPagedAtStart;
        public bool GpuOk;                 // GPU counters readable
        public long GpuUsed, GpuTotal;     // busiest adapter's dedicated usage; card memory size (0 = unknown)
        public string GpuName;
        public long Handles;
        public int Procs, Threads;
    }

    class Snapshot
    {
        public DateTime Time;
        public List<GroupInfo> Groups;
        public HashSet<int> Pids;
        public SysInfo Sys;
        public long SampleMs;
    }

    // ================================= sampler =================================
    // Not thread-safe: the form guarantees only one Take() runs at a time.
    class Sampler : IDisposable
    {
        class Meta { public string Name, Path; public DateTime? Start; }

        readonly Dictionary<int, Meta> meta = new Dictionary<int, Meta>();
        readonly Dictionary<int, Hist> pidHist = new Dictionary<int, Hist>();
        readonly Dictionary<string, Hist> groupHist = new Dictionary<string, Hist>();
        // "Windows Explorer", "Google Chrome", ... from the exe's version info; cached per path.
        readonly Dictionary<string, string> friendly = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly int selfPid;
        PerformanceCounter pcNp, pcPp, pcCommit, pcLimit;
        bool pcTried, pcOk;
        long npAtStart = -1;

        public Sampler() { using (var me = Process.GetCurrentProcess()) selfPid = me.Id; }

        // ---- graphics memory ----
        // "GPU Process Memory" instances look like "pid_2648_luid_0x..._phys_0"; one per process per adapter.
        // ReadCategory reads every instance in one call (first call ~3 s setup, then ~1 ms).
        PerformanceCounterCategory gpuProcCat, gpuAdapterCat;
        bool gpuBroken, gpuTotalTried;
        long gpuTotal;
        string gpuName;

        Dictionary<int, long[]> ReadGpu(out bool ok, out long adapterUsed)
        {
            var res = new Dictionary<int, long[]>();
            ok = false;
            adapterUsed = 0;
            if (gpuBroken) return res;
            try
            {
                if (gpuProcCat == null)
                {
                    gpuProcCat = new PerformanceCounterCategory("GPU Process Memory");
                    gpuAdapterCat = new PerformanceCounterCategory("GPU Adapter Memory");
                }
                InstanceDataCollectionCollection all = gpuProcCat.ReadCategory();
                AddGpu(res, all["Dedicated Usage"], 0);
                AddGpu(res, all["Shared Usage"], 1);
                InstanceDataCollection ad = gpuAdapterCat.ReadCategory()["Dedicated Usage"];
                if (ad != null)
                    foreach (InstanceData d in ad.Values) adapterUsed = Math.Max(adapterUsed, d.RawValue);
                ok = true;
            }
            catch { gpuBroken = true; }   // no GPU counters on this system: stop trying
            return res;
        }

        static void AddGpu(Dictionary<int, long[]> res, InstanceDataCollection col, int slot)
        {
            if (col == null) return;
            foreach (InstanceData d in col.Values)
            {
                string n = d.InstanceName;
                if (!n.StartsWith("pid_")) continue;
                int end = n.IndexOf('_', 4);
                int pid;
                if (!int.TryParse(n.Substring(4, (end < 0 ? n.Length : end) - 4), out pid)) continue;
                long[] v;
                if (!res.TryGetValue(pid, out v)) { v = new long[2]; res[pid] = v; }
                v[slot] += d.RawValue;
            }
        }

        // Card memory size, once: nvidia-smi if present, else the display driver's registry value.
        void ReadGpuTotal()
        {
            gpuTotalTried = true;
            try
            {
                var psi = new ProcessStartInfo("nvidia-smi", "--query-gpu=name,memory.total --format=csv,noheader,nounits")
                    { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    foreach (string line in output.Split('\n'))
                    {
                        string[] parts = line.Split(',');
                        long mib;
                        if (parts.Length >= 2 && long.TryParse(parts[1].Trim(), out mib) && mib * 1048576 > gpuTotal)
                        {
                            gpuTotal = mib * 1048576;
                            gpuName = parts[0].Trim();
                        }
                    }
                }
            }
            catch { }
            if (gpuTotal > 0) return;
            try
            {
                using (var cls = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"))
                {
                    if (cls == null) return;
                    foreach (string sub in cls.GetSubKeyNames())
                    {
                        try
                        {
                            using (var k = cls.OpenSubKey(sub))
                            {
                                if (k == null) continue;
                                object v = k.GetValue("HardwareInformation.qwMemorySize");
                                long size = v is long ? (long)v : v is byte[] && ((byte[])v).Length >= 8 ? BitConverter.ToInt64((byte[])v, 0) : 0;
                                if (size > gpuTotal) { gpuTotal = size; gpuName = k.GetValue("DriverDesc") as string; }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        public Snapshot Take()
        {
            var sw = Stopwatch.StartNew();
            DateTime now = DateTime.Now;
            DateTime winStart = now.AddMinutes(-Cfg.GrowthWindowMin);
            var groups = new Dictionary<string, GroupInfo>();
            var seen = new HashSet<int>();
            long totalHandles = 0;
            int totalThreads = 0;
            if (!gpuTotalTried) ReadGpuTotal();
            bool gpuOk;
            long gpuUsed;
            Dictionary<int, long[]> gpu = ReadGpu(out gpuOk, out gpuUsed);

            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    int pid = p.Id;
                    if (pid == 0) continue;   // Idle pseudo-process
                    string pname = p.ProcessName;
                    var inst = new InstanceInfo { Pid = pid };
                    // These come from the snapshot itself, no process handle needed.
                    try { inst.WS = p.WorkingSet64; } catch { }
                    try { inst.Priv = p.PrivateMemorySize64; } catch { }
                    try { inst.Handles = p.HandleCount; } catch { }
                    try { inst.Threads = p.Threads.Count; } catch { }
                    long[] gv;
                    if (gpu.TryGetValue(pid, out gv)) { inst.GpuDed = gv[0]; inst.GpuShared = gv[1]; }

                    Meta m;
                    if (!meta.TryGetValue(pid, out m) || m.Name != pname)
                    {
                        m = new Meta { Name = pname };
                        Native.QueryPathAndStart(pid, out m.Path, out m.Start);
                        meta[pid] = m;
                        pidHist.Remove(pid);
                    }
                    inst.Path = m.Path;
                    inst.Start = m.Start;
                    inst.Name = m.Path != null ? System.IO.Path.GetFileName(m.Path) : pname;

                    seen.Add(pid);
                    totalHandles += inst.Handles;
                    totalThreads += inst.Threads;

                    Hist h;
                    if (!pidHist.TryGetValue(pid, out h)) { h = new Hist(); pidHist[pid] = h; }
                    h.Add(new Sample { T = now, Priv = inst.Priv, Handles = inst.Handles, Gpu = inst.GpuDed }, winStart);

                    string key = m.Path != null ? m.Path.ToLowerInvariant() : "?" + pname.ToLowerInvariant();
                    GroupInfo g;
                    if (!groups.TryGetValue(key, out g))
                    {
                        g = new GroupInfo { Key = key, Name = inst.Name, Path = m.Path,
                            Friendly = Safety.IsDwm(inst.Name) ? "Screen drawing (dwm)" : FriendlyName(m.Path, inst.Name) };
                        g.Critical = Safety.IsCritical(inst.Name, m.Path);
                        g.AgentHost = Safety.IsAgentHost(inst.Name);
                        g.IsDwm = Safety.IsDwm(inst.Name);
                        groups[key] = g;
                    }
                    if (pid == selfPid) g.IsSelf = true;
                    // Critical processes are never flagged, except dwm for graphics memory.
                    EvaluateInstance(inst, h, now, !g.Critical ? 2 : g.IsDwm ? 1 : 0);
                    g.Instances.Add(inst);
                }
                catch { }   // process vanished mid-read, access denied, ... skip it
                finally { p.Dispose(); }
            }

            foreach (int pid in meta.Keys.Where(k => !seen.Contains(k)).ToList()) { meta.Remove(pid); pidHist.Remove(pid); }

            foreach (GroupInfo g in groups.Values)
            {
                foreach (InstanceInfo i in g.Instances)
                {
                    g.WS += i.WS; g.Priv += i.Priv; g.Handles += i.Handles; g.Threads += i.Threads;
                    g.GpuDed += i.GpuDed; g.GpuShared += i.GpuShared;
                    if (i.Start.HasValue && (!g.OldestStart.HasValue || i.Start.Value < g.OldestStart.Value)) g.OldestStart = i.Start;
                }
                Hist gh;
                if (!groupHist.TryGetValue(g.Key, out gh)) { gh = new Hist(); groupHist[g.Key] = gh; }
                gh.Add(new Sample { T = now, Priv = g.Priv, Handles = g.Handles }, winStart);
                Sample b = gh.S[0];
                g.WinSpanMin = (now - b.T).TotalMinutes;
                g.DWinPriv = g.Priv - b.Priv;
                g.DWinHandles = g.Handles - b.Handles;
                g.DStartPriv = g.Priv - gh.First.Priv;
                g.DStartHandles = g.Handles - gh.First.Handles;
                EvaluateGroup(g);
            }
            foreach (string k in groupHist.Keys.Where(k => !groups.ContainsKey(k)).ToList()) groupHist.Remove(k);

            var snap = new Snapshot { Time = now, Groups = groups.Values.ToList(), Pids = seen };
            snap.Sys = ReadSystem(totalHandles, seen.Count, totalThreads);
            snap.Sys.GpuOk = gpuOk;
            snap.Sys.GpuUsed = gpuUsed;
            snap.Sys.GpuTotal = gpuTotal;
            snap.Sys.GpuName = gpuName;
            snap.SampleMs = sw.ElapsedMilliseconds;
            return snap;
        }

        string FriendlyName(string path, string exeName)
        {
            string fallback = Safety.BaseName(exeName);
            if (fallback.Length > 0) fallback = char.ToUpperInvariant(fallback[0]) + fallback.Substring(1);
            if (path == null) return fallback;
            string f;
            if (friendly.TryGetValue(path, out f)) return f;
            f = null;
            try
            {
                FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
                f = (vi.FileDescription ?? "").Trim();
                if (f.Length == 0 || f.Length > 45) f = (vi.ProductName ?? "").Trim();
                if (f.Length > 45) f = null;
            }
            catch { }
            if (string.IsNullOrEmpty(f)) f = fallback;
            if (exeName.IndexOf(".exe.old", StringComparison.OrdinalIgnoreCase) > 0) f += " (old copy)";
            friendly[path] = f;
            return f;
        }

        // mode: 0 = never flag (critical), 1 = graphics-memory growth only (dwm), 2 = everything
        static void EvaluateInstance(InstanceInfo i, Hist h, DateTime now, int mode)
        {
            Sample b = h.S[0];
            i.WinSpanMin = (now - b.T).TotalMinutes;
            i.DWinPriv = i.Priv - b.Priv;
            i.DWinHandles = i.Handles - b.Handles;
            i.DWinGpu = i.GpuDed - b.Gpu;
            i.DStartPriv = i.Priv - h.First.Priv;
            i.DStartHandles = i.Handles - h.First.Handles;
            if (mode == 0) return;

            int level = 0;
            var why = new List<string>();
            double score = 0;
            if (mode == 2)
            {
                long privMB = i.Priv / 1048576;
                score = Math.Max((double)i.Handles / Cfg.HandlesRunaway,
                        Math.Max((double)privMB / Cfg.PrivateRunawayMB, (double)i.Threads / Cfg.ThreadsRunaway));
                if (i.Handles >= Cfg.HandlesRunaway) { level = 2; why.Add("handles " + Fmt.K(i.Handles)); }
                else if (i.Handles >= Cfg.HandlesWarn) { level = Math.Max(level, 1); why.Add("handles " + Fmt.K(i.Handles)); }
                i.FHandles = i.Handles >= Cfg.HandlesWarn;
                if (privMB >= Cfg.PrivateRunawayMB) { level = 2; why.Add("private " + Fmt.Size(i.Priv)); }
                else if (privMB >= Cfg.PrivateWarnMB) { level = Math.Max(level, 1); why.Add("private " + Fmt.Size(i.Priv)); }
                i.FPriv = privMB >= Cfg.PrivateWarnMB;
                if (i.Threads >= Cfg.ThreadsRunaway) { level = 2; why.Add("threads " + Fmt.K(i.Threads)); }
                else if (i.Threads >= Cfg.ThreadsWarn) { level = Math.Max(level, 1); why.Add("threads " + Fmt.K(i.Threads)); }
                i.FThreads = i.Threads >= Cfg.ThreadsWarn;
            }

            if (i.WinSpanMin >= Cfg.MinHistoryForGrowthMin)
            {
                double scale = Cfg.GrowthWindowMin / i.WinSpanMin;
                double hRate = i.DWinHandles * scale;
                double pRateMB = i.DWinPriv / 1048576.0 * scale;
                double gRateMB = i.DWinGpu / 1048576.0 * scale;
                if (mode == 2 && hRate >= Cfg.HandleGrowthRunaway / 2.0 && Steady(h.S, 1))
                {
                    level = Math.Max(level, hRate >= Cfg.HandleGrowthRunaway ? 2 : 1);
                    why.Add("+" + Fmt.K((long)hRate) + " handles/10min");
                    i.FHandleGrowth = true; i.HandleRate = hRate;
                    score = Math.Max(score, hRate / Cfg.HandleGrowthRunaway);
                }
                if (mode == 2 && pRateMB >= Cfg.PrivateGrowthRunawayMB / 2.0 && Steady(h.S, 0))
                {
                    level = Math.Max(level, pRateMB >= Cfg.PrivateGrowthRunawayMB ? 2 : 1);
                    why.Add("+" + pRateMB.ToString("0") + " MB/10min");
                    i.FPrivGrowth = true; i.PrivRateMB = pRateMB;
                    score = Math.Max(score, pRateMB / Cfg.PrivateGrowthRunawayMB);
                }
                if (gRateMB >= Cfg.GpuGrowthRunawayMB / 2.0 && Steady(h.S, 2))
                {
                    level = Math.Max(level, gRateMB >= Cfg.GpuGrowthRunawayMB ? 2 : 1);
                    why.Add("+" + gRateMB.ToString("0") + " MB graphics/10min");
                    i.FGpuGrowth = true; i.GpuRateMB = gRateMB;
                    score = Math.Max(score, gRateMB / Cfg.GpuGrowthRunawayMB);
                }
            }
            i.Score = score;
            i.Level = level;
            i.Reason = string.Join(", ", why);
        }

        // Growth counts as "steady" when most slices of the window do not go down.
        // which: 0 = private bytes, 1 = handles, 2 = graphics memory
        static bool Steady(List<Sample> s, int which)
        {
            int n = s.Count;
            if (n < 3) return false;
            int steps = Math.Min(Cfg.SteadySteps, n - 1);
            int ok = 0;
            Func<Sample, long> f = x => which == 1 ? x.Handles : which == 2 ? x.Gpu : x.Priv;
            long prev = f(s[0]);
            for (int k = 1; k <= steps; k++)
            {
                int idx = (int)Math.Round((double)k * (n - 1) / steps);
                long v = f(s[idx]);
                if (v >= prev) ok++;
                prev = v;
            }
            return ok >= Math.Ceiling(steps * Cfg.SteadyFraction);
        }

        static void EvaluateGroup(GroupInfo g)
        {
            if (g.Critical && !g.IsDwm) return;
            var parts = new List<string>();
            int level = 0;
            if (!g.Critical)
            {
                if (g.Handles >= Cfg.GroupHandlesRunaway) { level = 2; parts.Add("all instances: handles " + Fmt.K(g.Handles)); g.FGroupHandles = true; }
                g.Score = (double)g.Handles / Cfg.GroupHandlesRunaway;
            }
            // Graphics memory is judged for the whole program (dwm has its own limits).
            long warnMB = g.IsDwm ? Cfg.DwmGpuWarnMB : Cfg.GpuWarnMB, runMB = g.IsDwm ? Cfg.DwmGpuRunawayMB : Cfg.GpuRunawayMB;
            long gpuMB = g.GpuDed / 1048576;
            g.GpuScore = (double)gpuMB / runMB;
            if (gpuMB >= warnMB)
            {
                g.FGpu = true;
                level = Math.Max(level, gpuMB >= runMB ? 2 : 1);
                parts.Add("graphics " + Fmt.Size(g.GpuDed));
                g.Score = Math.Max(g.Score, g.GpuScore);
            }
            var flagged = g.Instances.Where(i => i.Level > 0)
                                     .OrderByDescending(i => i.Level).ThenByDescending(i => i.Score).ToList();
            if (flagged.Count > 0)
            {
                InstanceInfo top = flagged[0];
                g.Worst = top;
                g.Score = Math.Max(g.Score, top.Score);
                level = Math.Max(level, top.Level);
                parts.Add(g.Instances.Count > 1 ? "PID " + top.Pid + ": " + top.Reason : top.Reason);
                if (flagged.Count > 1) parts.Add("+" + (flagged.Count - 1) + " more instance(s)");
            }
            g.Level = level;
            g.Reason = string.Join("; ", parts);
        }

        SysInfo ReadSystem(long handles, int procs, int threads)
        {
            var si = new SysInfo { Handles = handles, Procs = procs, Threads = threads };
            var ms = new Native.MEMORYSTATUSEX();
            if (Native.GlobalMemoryStatusEx(ms)) { si.TotalPhys = ms.ullTotalPhys; si.AvailPhys = ms.ullAvailPhys; }

            if (!pcTried)
            {
                pcTried = true;
                try
                {
                    pcNp = new PerformanceCounter("Memory", "Pool Nonpaged Bytes", true);
                    pcPp = new PerformanceCounter("Memory", "Pool Paged Bytes", true);
                    pcCommit = new PerformanceCounter("Memory", "Committed Bytes", true);
                    pcLimit = new PerformanceCounter("Memory", "Commit Limit", true);
                    long probe = pcNp.RawValue;
                    pcOk = probe > 0;
                }
                catch { pcOk = false; }
            }
            bool got = false;
            if (pcOk)
            {
                try
                {
                    si.NonPaged = pcNp.RawValue; si.Paged = pcPp.RawValue;
                    si.CommitTotal = pcCommit.RawValue; si.CommitLimit = pcLimit.RawValue;
                    got = true;
                }
                catch { }
            }
            if (!got)
            {
                // Fallback if the perf counters are broken/disabled.
                var pi = new Native.PERFORMANCE_INFORMATION();
                pi.cb = (uint)Marshal.SizeOf(typeof(Native.PERFORMANCE_INFORMATION));
                if (Native.GetPerformanceInfo(ref pi, pi.cb))
                {
                    long page = (long)pi.PageSize.ToUInt64();
                    si.NonPaged = (long)pi.KernelNonpaged.ToUInt64() * page;
                    si.Paged = (long)pi.KernelPaged.ToUInt64() * page;
                    si.CommitTotal = (long)pi.CommitTotal.ToUInt64() * page;
                    si.CommitLimit = (long)pi.CommitLimit.ToUInt64() * page;
                }
            }
            if (npAtStart < 0 && si.NonPaged > 0) npAtStart = si.NonPaged;
            si.NonPagedAtStart = npAtStart;
            return si;
        }

        public void Dispose()
        {
            foreach (var pc in new[] { pcNp, pcPp, pcCommit, pcLimit }) if (pc != null) pc.Dispose();
        }
    }

    // ================================ formatting ================================
    static class Fmt
    {
        public static string MB(long bytes) { return (bytes / 1048576.0).ToString("N0"); }

        public static string Size(long bytes)
        {
            double mb = bytes / 1048576.0;
            return Math.Abs(mb) >= 1024 ? (mb / 1024).ToString("0.0") + " GB" : mb.ToString("0") + " MB";
        }

        public static string SignedSize(long bytes)
        {
            double mb = bytes / 1048576.0;
            if (Math.Abs(mb) < 0.5) return "0 MB";
            return (mb > 0 ? "+" : "") + Size(bytes);
        }

        public static string K(long n)
        {
            return Math.Abs(n) >= 1000 ? (n / 1000.0).ToString("0.#") + "k" : n.ToString();
        }

        public static string SignedK(long n) { return n > 0 ? "+" + K(n) : K(n); }

        public static string Time(DateTime? t) { return t.HasValue ? t.Value.ToString("MM-dd HH:mm:ss") : ""; }

        public static string Uptime(DateTime? start, DateTime now)
        {
            if (!start.HasValue) return "";
            TimeSpan t = now - start.Value;
            if (t.Ticks < 0) t = TimeSpan.Zero;
            if (t.TotalDays >= 1) return string.Format("{0}d {1:00}h {2:00}m", (int)t.TotalDays, t.Hours, t.Minutes);
            return string.Format("{0:00}:{1:00}:{2:00}", t.Hours, t.Minutes, t.Seconds);
        }

        // "27 days", "3 hours", "12 minutes"
        public static string Ago(TimeSpan t)
        {
            if (t.TotalDays >= 2) return (int)t.TotalDays + " days";
            if (t.TotalDays >= 1) return "1 day";
            if (t.TotalHours >= 2) return (int)t.TotalHours + " hours";
            if (t.TotalHours >= 1) return "1 hour";
            return Math.Max(1, (int)t.TotalMinutes) + " minutes";
        }
    }

    // Sorts ListView items by a typed key read from item.Tag.
    class ColSorter : IComparer
    {
        public int Column;
        public bool Desc;
        readonly Func<object, int, IComparable> key;

        public ColSorter(Func<object, int, IComparable> key, int column, bool desc)
        {
            this.key = key; Column = column; Desc = desc;
        }

        public int Compare(object a, object b)
        {
            IComparable ka = key(((ListViewItem)a).Tag, Column), kb = key(((ListViewItem)b).Tag, Column);
            int r;
            if (ka == null || kb == null) r = (ka == null ? 0 : 1) - (kb == null ? 0 : 1);
            else if (ka is string) r = string.Compare((string)ka, (string)kb, StringComparison.OrdinalIgnoreCase);
            else r = ka.CompareTo(kb);
            return Desc ? -r : r;
        }
    }

    class DBListView : ListView
    {
        public DBListView()
        {
            DoubleBuffered = true;
            View = View.Details;
            FullRowSelect = true;
            HideSelection = false;
            MultiSelect = true;      // for copying several rows; actions require exactly one
            GridLines = true;
            Dock = DockStyle.Fill;
        }
    }

    // ================================== look ==================================
    static class Theme
    {
        public static readonly Color Page = Hex(0xF5F6F8);      // window background
        public static readonly Color Card = Color.White;
        public static readonly Color Border = Hex(0xE3E5E8);
        public static readonly Color Text = Hex(0x1F2328);
        public static readonly Color TextSoft = Hex(0x5F6670);
        public static readonly Color TextMuted = Hex(0x8A8F98);
        public static readonly Color Track = Hex(0xE9EBEE);     // empty part of progress bars
        public static readonly Color RowAlt = Hex(0xFAFBFC);
        public static readonly Color Select = Hex(0xE8F0FE);
        public static readonly Color Hover = Hex(0xF0F2F5);
        public static readonly Color Green = Hex(0x2E9E5B);
        public static readonly Color Amber = Hex(0xD98E04);
        public static readonly Color Red = Hex(0xD64545);
        public static readonly Color Gray = Hex(0x8A8F98);

        static Color Hex(int rgb) { return Color.FromArgb((rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255); }

        // -1 info, 0 OK, 1 watch, 2 act
        public static Color ForLevel(int level) { return level >= 2 ? Red : level == 1 ? Amber : level == 0 ? Green : Gray; }

        public static GraphicsPath Round(RectangleF r, float radius)
        {
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            var p = new GraphicsPath();
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // Small flat "pill" button drawn by hand (tiles and list rows).
        public static void Pill(Graphics g, Rectangle r, bool primary, bool hover, string text, Font f)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color fill = primary ? (hover ? ControlPaint.Dark(Red, 0.05f) : Red) : (hover ? Hover : Card);
            using (GraphicsPath path = Round(new RectangleF(r.X + 0.5f, r.Y + 0.5f, r.Width - 1, r.Height - 1), r.Height / 2f))
            {
                using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                using (var pen = new Pen(primary ? fill : Border)) g.DrawPath(pen, path);
            }
            TextRenderer.DrawText(g, text, f, r, primary ? Color.White : Text,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    // One "Always watching" card: accent bar, dot + title, big value, optional progress bar,
    // one muted subtitle and an optional "Restart" pill. Values are updated in place.
    class WatchTile : Control
    {
        public event EventHandler ActionClick;
        string title = "", value = "", sub = "", action;
        int level = -1;
        double fraction = -1;
        bool hoverAction;
        Rectangle actionRect;
        readonly float dpi;
        static readonly Font TitleFont = new Font("Segoe UI", 9f);
        static readonly Font ValueFont = new Font("Segoe UI Semibold", 14f);
        static readonly Font SubFont = new Font("Segoe UI", 8.5f);
        static readonly Font ActionFont = new Font("Segoe UI Semibold", 8.5f);

        public WatchTile(float dpi)
        {
            this.dpi = dpi;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Page;
        }

        int S(int px) { return (int)(px * dpi); }

        public void Set(string title, string value, string sub, int level, double fraction, string action)
        {
            if (title == this.title && value == this.value && sub == this.sub && level == this.level
                && Math.Abs(fraction - this.fraction) < 0.002 && action == this.action) return;
            this.title = title; this.value = value; this.sub = sub; this.level = level; this.fraction = fraction; this.action = action;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color accent = Theme.ForLevel(level);
            var card = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            using (GraphicsPath path = Theme.Round(card, S(8)))
            {
                using (var b = new SolidBrush(Theme.Card)) g.FillPath(b, path);
                // left accent bar, clipped to the rounded card
                Region old = g.Clip;
                g.SetClip(path);
                using (var b = new SolidBrush(accent)) g.FillRectangle(b, 0, 0, S(4), Height);
                g.Clip = old;
                using (var pen = new Pen(Theme.Border)) g.DrawPath(pen, path);
            }

            int x = S(16), w = Width - x - S(12);
            int y = S(11);
            using (var b = new SolidBrush(accent)) g.FillEllipse(b, x, y + S(5), S(7), S(7));
            TextRenderer.DrawText(g, title, TitleFont, new Rectangle(x + S(12), y, w - S(12), S(18)), Theme.TextSoft,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);

            y += S(22);
            int actionW = action != null ? S(64) : 0;
            actionRect = action != null ? new Rectangle(Width - S(12) - actionW, y + S(3), actionW, S(22)) : Rectangle.Empty;
            TextRenderer.DrawText(g, value, ValueFont, new Rectangle(x, y, w - (actionW > 0 ? actionW + S(6) : 0), S(28)), Theme.Text,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            if (action != null) Theme.Pill(g, actionRect, level >= 2, hoverAction, action, ActionFont);

            y += S(32);
            if (fraction >= 0)
            {
                var track = new RectangleF(x, y, w, S(4));
                using (GraphicsPath tp = Theme.Round(track, S(2)))
                using (var b = new SolidBrush(Theme.Track)) g.FillPath(b, tp);
                float fw = (float)(w * Math.Min(1, Math.Max(0, fraction)));
                if (fw >= 1)
                    using (GraphicsPath fp = Theme.Round(new RectangleF(x, y, Math.Max(fw, S(4)), S(4)), S(2)))
                    using (var b = new SolidBrush(accent)) g.FillPath(b, fp);
            }
            y += S(9);
            TextRenderer.DrawText(g, sub, SubFont, new Rectangle(x, y, w, S(18)), Theme.TextMuted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            bool h = actionRect.Contains(e.Location);
            if (h != hoverAction) { hoverAction = h; Cursor = h ? Cursors.Hand : Cursors.Default; Invalidate(); }
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            if (hoverAction) { hoverAction = false; Cursor = Cursors.Default; Invalidate(); }
            base.OnMouseLeave(e);
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && actionRect.Contains(e.Location) && ActionClick != null) ActionClick(this, EventArgs.Empty);
            base.OnMouseClick(e);
        }
    }

    // ================================== form ==================================
    class MainForm : Form
    {
        static readonly Color RunawayBack = Color.FromArgb(255, 199, 199);
        static readonly Color WarnBack = Color.FromArgb(255, 242, 190);
        static readonly Color AgentFore = Color.FromArgb(0, 70, 160);
        static readonly Color StatusRed = Theme.Red;
        static readonly Color StatusAmber = Theme.Amber;
        static readonly Color StatusGreen = Theme.Green;
        static readonly Color GridSelBack = Theme.Select;
        static readonly string Dot = ((char)0x25CF).ToString();   // filled circle

        readonly Sampler sampler = new Sampler();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Dictionary<int, string> cmdLines = new Dictionary<int, string>();
        readonly AlertPolicy alerts = new AlertPolicy(AlertState.Load(), true);
        readonly int selfPid;
        readonly bool elevated;
        readonly float dpi;
        Snapshot snap;
        bool sampling, loadingCmd, busyAction, poolLookupStarted, splitInit;
        string cmdGroupKey, poolCause, poolTagInfo;

        // simple view
        Panel advancedPanel, simplePanel;
        DataGridView grid;
        DataGridViewButtonColumn colAct;
        Label banner, emptyLabel;
        CheckBox chkShowAll, chkAdvanced;
        string gridKeys = "";

        // Diagnostic: "--selftest-copy=problems|banner|rows|advanced" copies once after the first full sample, then exits.
        public string SelfTest;
        bool selfTestDone;

        // advanced view
        DBListView lvGroups, lvInst;
        ColSorter groupSorter, instSorter;
        SplitContainer split;
        Label lblRam, lblCommit, lblNp, lblPp, lblHandles, lblProcs, lblHint;
        ToolStripLabel lblInst;
        ToolStripStatusLabel lblStatus;
        ToolStripButton btnPause, btnNotify;
        NumericUpDown numRefresh;
        NotifyIcon tray;
        IntPtr hIconOk, hIconAlert;
        Icon iconOk, iconAlert;

        static readonly string[] GroupCols = { "Program", "Count", "WS MB", "Private MB", "Handles", "Threads",
            "Priv 10m", "Hnd 10m", "Priv since start", "Hnd since start", "Oldest start", "Uptime", "Reason", "Path", "GPU MB", "GPU shared MB" };
        static readonly int[] GroupWidths = { 170, 50, 75, 80, 70, 60, 75, 70, 95, 95, 105, 95, 330, 380, 70, 95 };
        static readonly string[] InstCols = { "PID", "Name", "WS MB", "Private MB", "Handles", "Threads",
            "Priv 10m", "Hnd 10m", "Priv since start", "Hnd since start", "Started", "Uptime", "Reason", "Command line", "GPU MB", "GPU shared MB" };
        static readonly int[] InstWidths = { 60, 150, 75, 80, 70, 60, 75, 70, 95, 95, 105, 95, 260, 600, 70, 95 };
        static readonly HashSet<int> RightAligned = new HashSet<int> { 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15 };

        public MainForm()
        {
            using (var me = Process.GetCurrentProcess()) selfPid = me.Id;
            try { elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }
            using (var gr = CreateGraphics()) dpi = gr.DpiX / 96f;

            Text = "MemWatch" + (elevated ? " (admin)" : "");
            Font = new Font("Segoe UI", 9f);
            BackColor = Theme.Page;
            Size = new Size(S(1320), S(720));
            MinimumSize = new Size(S(1020), S(600));
            StartPosition = FormStartPosition.CenterScreen;

            hIconOk = MakeIconHandle(Color.FromArgb(30, 110, 190));
            hIconAlert = MakeIconHandle(Color.FromArgb(200, 40, 40));
            iconOk = Icon.FromHandle(hIconOk);
            iconAlert = Icon.FromHandle(hIconAlert);
            Icon = iconOk;

            // ---- advanced: group list (top) and instances list (bottom) ----
            split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            lvGroups = new DBListView();
            AddColumns(lvGroups, GroupCols, GroupWidths);
            groupSorter = new ColSorter(GroupKey, 3, true);
            lvGroups.ListViewItemSorter = groupSorter;
            lvGroups.ColumnClick += (s, e) => SortBy(lvGroups, groupSorter, e.Column);
            lvGroups.SelectedIndexChanged += (s, e) => OnGroupSelected();
            lvGroups.ContextMenuStrip = BuildGroupMenu();
            lvGroups.KeyDown += (s, e) => { if (e.Control && e.KeyCode == Keys.C) { CopyText(ListRowsText(lvGroups)); e.Handled = true; } };
            split.Panel1.Controls.Add(lvGroups);

            lvInst = new DBListView();
            AddColumns(lvInst, InstCols, InstWidths);
            instSorter = new ColSorter(InstKey, 3, true);
            lvInst.ListViewItemSorter = instSorter;
            lvInst.ColumnClick += (s, e) => SortBy(lvInst, instSorter, e.Column);
            lvInst.ContextMenuStrip = BuildInstMenu();
            lvInst.KeyDown += (s, e) => { if (e.Control && e.KeyCode == Keys.C) { CopyText(ListRowsText(lvInst)); e.Handled = true; } };
            split.Panel2.Controls.Add(lvInst);
            split.Panel2.Controls.Add(BuildInstToolbar());

            // Advanced view = all the numbers; hidden by default. Simple view = the short plain list.
            advancedPanel = new Panel { Dock = DockStyle.Fill, Visible = false };
            advancedPanel.Controls.Add(split);
            advancedPanel.Controls.Add(BuildToolbar());
            advancedPanel.Controls.Add(BuildHeader());
            Controls.Add(advancedPanel);
            Controls.Add(BuildSimple());
            BuildTopBar();

            var status = new StatusStrip { BackColor = Theme.Page, SizingGrip = false };
            lblStatus = new ToolStripStatusLabel { Spring = true, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextSoft };
            status.Items.Add(lblStatus);
            Controls.Add(status);

            BuildTray();

            timer.Interval = Cfg.DefaultRefreshSec * 1000;
            timer.Tick += (s, e) => Tick();
            Load += (s, e) =>
            {
                lblStatus.Text = "Checking your programs...";
                Tick();
                timer.Start();
            };
            Resize += (s, e) => { if (WindowState == FormWindowState.Minimized) { Hide(); } };
            FormClosing += (s, e) => Shutdown();
        }

        int S(int px) { return (int)(px * dpi); }

        void AddColumns(ListView lv, string[] names, int[] widths)
        {
            for (int i = 0; i < names.Length; i++)
                lv.Columns.Add(names[i], S(widths[i]), RightAligned.Contains(i) && !(lv == lvInst && i == 1) ? HorizontalAlignment.Right : HorizontalAlignment.Left);
            // GPU columns are stored last (keeps sort indexes stable) but displayed after "Private MB".
            lv.Columns[14].DisplayIndex = 4;
            lv.Columns[15].DisplayIndex = 5;
        }

        static IntPtr MakeIconHandle(Color bg)
        {
            using (var bmp = new Bitmap(32, 32))
            using (var gr = Graphics.FromImage(bmp))
            {
                gr.SmoothingMode = SmoothingMode.AntiAlias;
                gr.Clear(Color.Transparent);
                using (var b = new SolidBrush(bg)) gr.FillEllipse(b, 1, 1, 30, 30);
                using (var f = new Font("Segoe UI", 15f, FontStyle.Bold, GraphicsUnit.Pixel))
                using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                    gr.DrawString("M", f, Brushes.White, new RectangleF(0, 1, 32, 32), sf);
                return bmp.GetHicon();
            }
        }

        // ------------------------------ simple view ------------------------------
        Panel bannerHost, bannerAccent;

        void BuildTopBar()
        {
            var opts = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, BackColor = Theme.Page, Padding = new Padding(S(12), S(2), S(12), S(4)) };
            var optFont = new Font("Segoe UI", 10f);
            chkShowAll = new CheckBox { Text = "Show all programs", AutoSize = true, Font = optFont, ForeColor = Theme.TextSoft, Margin = new Padding(0, S(5), S(20), 0) };
            chkShowAll.CheckedChanged += (s, e) => { if (snap != null) UpdateSimple(snap); };
            chkAdvanced = new CheckBox { Text = "Advanced details", AutoSize = true, Font = optFont, ForeColor = Theme.TextSoft, Margin = new Padding(0, S(5), S(20), 0) };
            chkAdvanced.CheckedChanged += (s, e) =>
            {
                advancedPanel.Visible = chkAdvanced.Checked;
                simplePanel.Visible = !chkAdvanced.Checked;
                chkShowAll.Enabled = !chkAdvanced.Checked;
                if (chkAdvanced.Checked && !splitInit)
                {
                    splitInit = true;
                    try { split.SplitterDistance = (int)(split.Height * 0.58); } catch { }
                }
                if (snap != null) ApplySnapshot(snap);
            };
            var copyAll = new Button
            {
                Text = "Copy problems to clipboard", AutoSize = true, Font = new Font("Segoe UI", 9f), FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Card, ForeColor = Theme.Text, Margin = new Padding(0, S(2), 0, 0), Padding = new Padding(S(6), 0, S(6), 0), Cursor = Cursors.Hand
            };
            copyAll.FlatAppearance.BorderColor = Theme.Border;
            copyAll.FlatAppearance.MouseOverBackColor = Theme.Hover;
            copyAll.FlatAppearance.MouseDownBackColor = Theme.Border;
            copyAll.Click += (s, e) => CopyText(AllProblemsText());
            new ToolTip().SetToolTip(copyAll, "Copies the health summary, the Always-watching cards and every program that needs attention, ready to paste into a chat.");
            opts.Controls.Add(chkShowAll);
            opts.Controls.Add(chkAdvanced);
            opts.Controls.Add(copyAll);
            Controls.Add(opts);

            // Banner: white card with a colored left bar and one sentence.
            bannerHost = new Panel { Dock = DockStyle.Top, BackColor = Theme.Page, Padding = new Padding(S(14), S(12), S(14), S(6)) };
            var bannerCard = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Card };
            bannerCard.Paint += (s, e) =>
            {
                using (var pen = new Pen(Theme.Border)) e.Graphics.DrawRectangle(pen, 0, 0, bannerCard.Width - 1, bannerCard.Height - 1);
            };
            bannerAccent = new Panel { Dock = DockStyle.Left, Width = S(5), BackColor = Theme.Gray };
            banner = new Label
            {
                Dock = DockStyle.Fill, AutoSize = false, Font = new Font("Segoe UI Semibold", 11.5f), ForeColor = Theme.Text, BackColor = Theme.Card,
                Padding = new Padding(S(12), S(9), S(12), S(9)), Text = "Checking your programs...", TextAlign = ContentAlignment.MiddleLeft
            };
            var bannerMenu = new ContextMenuStrip { Font = new Font("Segoe UI", 10f) };
            bannerMenu.Items.Add("Copy to clipboard", null, (s, e) => CopyText(SnapshotHeader() + "\r\n\r\n" + SystemText()));
            bannerMenu.Items.Add("Copy all problems to clipboard", null, (s, e) => CopyText(AllProblemsText()));
            banner.ContextMenuStrip = bannerMenu;
            bannerCard.Controls.Add(banner);
            bannerCard.Controls.Add(bannerAccent);
            bannerHost.Controls.Add(bannerCard);
            Controls.Add(bannerHost);
            Resize += (s, e) => SizeBanner();
            SizeBanner();
        }

        void SizeBanner()
        {
            if (banner == null || bannerHost == null) return;
            int w = Math.Max(S(200), ClientSize.Width - bannerHost.Padding.Horizontal - S(5) - banner.Padding.Horizontal);
            Size sz = TextRenderer.MeasureText(banner.Text, banner.Font, new Size(w, 0), TextFormatFlags.WordBreak);
            int h = sz.Height + banner.Padding.Vertical + bannerHost.Padding.Vertical + S(2);
            if (bannerHost.Height != h) bannerHost.Height = h;
        }

        readonly Font pillFont = new Font("Segoe UI Semibold", 9.5f);

        Control BuildSimple()
        {
            simplePanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Page };
            grid = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false, RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = true, BackgroundColor = Theme.Card, BorderStyle = BorderStyle.None,
                ClipboardCopyMode = DataGridViewClipboardCopyMode.Disable,
                CellBorderStyle = DataGridViewCellBorderStyle.None, GridColor = Theme.Border,
                Font = new Font("Segoe UI", 11f), EnableHeadersVisualStyles = false, ShowCellToolTips = true,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
                ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None
            };
            grid.ColumnHeadersHeight = S(34);
            grid.RowTemplate.Height = S(40);
            grid.DefaultCellStyle.Padding = new Padding(S(8), 0, S(8), 0);
            grid.DefaultCellStyle.SelectionBackColor = GridSelBack;
            grid.DefaultCellStyle.SelectionForeColor = Theme.Text;
            grid.DefaultCellStyle.ForeColor = Theme.Text;
            grid.AlternatingRowsDefaultCellStyle.BackColor = Theme.RowAlt;
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9.5f);
            grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Card;
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.TextSoft;
            grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Card;
            grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(S(8), 0, S(8), 0);

            grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status", Width = S(165) });
            grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Program", Width = S(230) });
            var mem = new DataGridViewTextBoxColumn { HeaderText = "Memory", Width = S(225) };
            mem.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            grid.Columns.Add(mem);
            grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Why", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, MinimumWidth = S(200) });
            colAct = new DataGridViewButtonColumn { HeaderText = "", Width = S(120), FlatStyle = FlatStyle.Flat };
            colAct.DefaultCellStyle.Padding = new Padding(S(10), S(6), S(10), S(6));
            colAct.DefaultCellStyle.Font = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            grid.Columns.Add(colAct);
            foreach (DataGridViewColumn c in grid.Columns) c.SortMode = DataGridViewColumnSortMode.NotSortable;

            grid.CellPainting += (s, e) =>
            {
                if (e.RowIndex < 0 || e.ColumnIndex != colAct.Index) return;
                bool sel = (e.State & DataGridViewElementStates.Selected) != 0;
                using (var b = new SolidBrush(sel ? GridSelBack : e.RowIndex % 2 == 1 ? Theme.RowAlt : Theme.Card)) e.Graphics.FillRectangle(b, e.CellBounds);
                DataGridViewCell cell = grid.Rows[e.RowIndex].Cells[e.ColumnIndex];
                if (cell is DataGridViewButtonCell && cell.Value != null)
                {
                    var g = grid.Rows[e.RowIndex].Tag as GroupInfo;
                    var r = new Rectangle(e.CellBounds.X + S(12), e.CellBounds.Y + (e.CellBounds.Height - S(26)) / 2, e.CellBounds.Width - S(24), S(26));
                    Point mp = grid.PointToClient(Cursor.Position);
                    Theme.Pill(e.Graphics, r, g != null && g.Level >= 2, r.Contains(mp), cell.Value.ToString(), pillFont);
                }
                e.Handled = true;
            };
            grid.CellMouseEnter += (s, e) => { if (e.RowIndex >= 0 && e.ColumnIndex == colAct.Index && grid.Rows[e.RowIndex].Cells[e.ColumnIndex] is DataGridViewButtonCell) { grid.Cursor = Cursors.Hand; grid.InvalidateCell(e.ColumnIndex, e.RowIndex); } };
            grid.CellMouseLeave += (s, e) => { grid.Cursor = Cursors.Default; if (e.RowIndex >= 0 && e.ColumnIndex == colAct.Index) grid.InvalidateCell(e.ColumnIndex, e.RowIndex); };
            grid.CellContentClick += (s, e) =>
            {
                if (e.RowIndex < 0 || e.ColumnIndex != colAct.Index) return;
                if (grid.Rows[e.RowIndex].Cells[e.ColumnIndex] is DataGridViewButtonCell)
                    RestartGroup(grid.Rows[e.RowIndex].Tag as GroupInfo);
            };
            grid.CellMouseDown += (s, e) =>
            {
                // Right-click on an unselected row selects just that row; on a selected row keeps the multi-selection.
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && !grid.Rows[e.RowIndex].Selected)
                {
                    grid.ClearSelection();
                    grid.Rows[e.RowIndex].Selected = true;
                }
            };
            grid.KeyDown += (s, e) =>
            {
                if (e.Control && e.KeyCode == Keys.C) { CopyText(SelectedProgramsText()); e.Handled = true; }
            };

            var menu = new ContextMenuStrip { Font = new Font("Segoe UI", 10f) };
            var mCopy = new ToolStripMenuItem("Copy to clipboard", null, (s, e) => CopyText(SelectedProgramsText())) { ShortcutKeyDisplayString = "Ctrl+C" };
            var mRestart = new ToolStripMenuItem("Restart", null, (s, e) => RestartGroup(SelectedSimple()));
            var mOpen = new ToolStripMenuItem("Open file location", null, (s, e) => { var g = SelectedSimple(); OpenLocation(g == null ? null : g.Path); });
            var mDetails = new ToolStripMenuItem("Show details", null, (s, e) => ShowInAdvanced(SelectedSimple()));
            menu.Items.Add(mCopy);
            menu.Items.Add(new ToolStripMenuItem("Copy all problems to clipboard", null, (s, e) => CopyText(AllProblemsText())));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(mRestart);
            menu.Items.Add(mOpen);
            menu.Items.Add(mDetails);
            menu.Opening += (s, e) =>
            {
                int n = grid.SelectedRows.Count;
                mCopy.Enabled = n > 0;
                mCopy.Text = n > 1 ? "Copy " + n + " programs to clipboard" : "Copy to clipboard";
                mRestart.Enabled = mOpen.Enabled = mDetails.Enabled = n == 1;
            };
            grid.ContextMenuStrip = menu;

            emptyLabel = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 15f),
                ForeColor = StatusGreen, Visible = false,
                Text = "Everything looks fine.\nNo program needs a restart right now."
            };
            var emptyMenu = new ContextMenuStrip { Font = new Font("Segoe UI", 10f) };
            emptyMenu.Items.Add("Copy status to clipboard", null, (s, e) => CopyText(AllProblemsText()));
            emptyLabel.ContextMenuStrip = emptyMenu;
            emptyLabel.BackColor = Theme.Card;
            var gridBorder = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Border, Padding = new Padding(1) };
            gridBorder.Controls.Add(grid);
            gridBorder.Controls.Add(emptyLabel);
            var gridHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Page, Padding = new Padding(S(14), S(2), S(14), S(12)) };
            gridHost.Controls.Add(gridBorder);
            simplePanel.Controls.Add(gridHost);

            simplePanel.Controls.Add(BuildWatchPanel());
            return simplePanel;
        }

        GroupInfo SelectedSimple()
        {
            return grid.SelectedRows.Count == 0 ? null : grid.SelectedRows[0].Tag as GroupInfo;
        }

        // Selected rows in on-screen order.
        List<GroupInfo> SelectedSimpleAll()
        {
            return grid.SelectedRows.Cast<DataGridViewRow>().OrderBy(r => r.Index)
                       .Select(r => r.Tag as GroupInfo).Where(g => g != null).ToList();
        }

        void ShowInAdvanced(GroupInfo g)
        {
            chkAdvanced.Checked = true;
            if (g == null) return;
            ListViewItem[] found = lvGroups.Items.Find(g.Key, false);
            if (found.Length == 0) return;
            lvGroups.SelectedItems.Clear();
            found[0].Selected = true;
            found[0].EnsureVisible();
            lvGroups.Focus();
        }

        void UpdateSimple(Snapshot s)
        {
            List<GroupInfo> rows = s.Groups.Where(g => chkShowAll.Checked || g.Level > 0)
                .OrderByDescending(g => g.Level).ThenByDescending(g => g.Level > 0 ? g.Score : 0).ThenByDescending(g => g.Priv).ToList();
            emptyLabel.Visible = rows.Count == 0;
            grid.Visible = rows.Count > 0;

            string keys = string.Join("|", rows.Select(g => g.Key));
            if (keys != gridKeys)
            {
                GroupInfo sel = SelectedSimple();
                string selKey = sel == null ? null : sel.Key;
                int first = grid.FirstDisplayedScrollingRowIndex;
                grid.Rows.Clear();
                for (int i = 0; i < rows.Count; i++) grid.Rows.Add();
                gridKeys = keys;
                grid.ClearSelection();
                int selIdx = selKey == null ? -1 : rows.FindIndex(g => g.Key == selKey);
                if (selIdx >= 0) grid.Rows[selIdx].Selected = true;
                if (first >= 0 && first < rows.Count) try { grid.FirstDisplayedScrollingRowIndex = first; } catch { }
            }
            for (int i = 0; i < rows.Count; i++) FillRow(grid.Rows[i], rows[i], s.Time);
        }

        void FillRow(DataGridViewRow row, GroupInfo g, DateTime now)
        {
            row.Tag = g;
            Color c = g.Level >= 2 ? StatusRed : g.Level == 1 ? StatusAmber : StatusGreen;
            SetCell(row.Cells[0], Dot + "  " + StatusWord(g));
            if (row.Cells[0].Style.ForeColor != c)
            {
                row.Cells[0].Style.ForeColor = c;
                row.Cells[0].Style.SelectionForeColor = c;
                row.Cells[0].Style.Font = g.Level > 0 ? new Font("Segoe UI", 11f, FontStyle.Bold) : null;
            }
            SetCell(row.Cells[1], g.Friendly);
            row.Cells[1].ToolTipText = g.Name + (g.Instances.Count > 1 ? " (" + g.Instances.Count + " processes)" : "") + "\n" + (g.Path ?? "");
            SetCell(row.Cells[2], MemoryText(g));
            SetCell(row.Cells[3], WhyText(g, now));

            bool canRestart = g.Level > 0 && GroupRefusal(g, true) == null;
            DataGridViewCell act = row.Cells[colAct.Index];
            if (canRestart)
            {
                if (!(act is DataGridViewButtonCell)) { act = new DataGridViewButtonCell(); row.Cells[colAct.Index] = act; }
                act.Value = "Restart";
                act.ToolTipText = "Close and reopen " + g.Friendly;
            }
            else if (act is DataGridViewButtonCell || act.Value != null)
            {
                act = new DataGridViewTextBoxCell();
                row.Cells[colAct.Index] = act;
            }
        }

        static void SetCell(DataGridViewCell cell, string text)
        {
            if (!Equals(cell.Value, text)) cell.Value = text;
        }

        // "1.9 GB", or "512 MB (+13.6 GB graphics)" when the program holds notable graphics memory.
        static string MemoryText(GroupInfo g)
        {
            return Fmt.Size(g.Priv) + (g.GpuDed >= 512L * 1048576 ? " (+" + Fmt.Size(g.GpuDed) + " graphics)" : "");
        }

        static string StatusWord(GroupInfo g)
        {
            if (g.Level >= 2) return g.AgentHost ? "Needs attention" : "Restart suggested";
            return g.Level == 1 ? "Watch" : "OK";
        }

        // ------------------------------ copy to clipboard ------------------------------
        // Plain-ASCII text meant to be pasted into a chat for diagnosis.

        string SnapshotHeader()
        {
            DateTime t = snap != null ? snap.Time : DateTime.Now;
            return "MemWatch snapshot " + t.ToString("yyyy-MM-dd HH:mm:ss") + " (computer " + Environment.MachineName
                 + (elevated ? ", running as admin" : ", not running as admin") + ")";
        }

        string SystemText()
        {
            if (snap == null) return "System: no data yet.";
            SysInfo y = snap.Sys;
            ulong used = y.TotalPhys - y.AvailPhys;
            var sb = new StringBuilder();
            sb.AppendLine("Health: " + banner.Text.Replace("\n", " "));
            sb.AppendLine(string.Format("RAM: {0:0.0} of {1:0.0} GB used ({2:0}%)", used / 1073741824.0, y.TotalPhys / 1073741824.0,
                y.TotalPhys > 0 ? 100.0 * used / y.TotalPhys : 0));
            sb.AppendLine(string.Format("Commit charge: {0:0.0} of {1:0.0} GB", y.CommitTotal / 1073741824.0, y.CommitLimit / 1073741824.0));
            sb.AppendLine("Kernel pool nonpaged: " + Fmt.Size(y.NonPaged) + " (" + Fmt.SignedSize(y.NonPagedAtStart > 0 ? y.NonPaged - y.NonPagedAtStart : 0)
                + " since MemWatch started; normal is a few hundred MB)");
            sb.AppendLine("Kernel pool paged: " + Fmt.Size(y.Paged));
            if (y.GpuOk)
            {
                sb.AppendLine("Graphics card: " + (y.GpuName ?? "unknown") + ", " + (y.GpuTotal > 0 ? Fmt.Size(y.GpuTotal) : "size unknown")
                    + "; dedicated memory in use " + Fmt.Size(y.GpuUsed) + (GpuHigh(y) ? " (HIGH)" : ""));
                List<GroupInfo> topGpu = snap.Groups.Where(g => g.GpuDed >= 256L * 1048576).OrderByDescending(g => g.GpuDed).Take(5).ToList();
                if (topGpu.Count > 0)
                    sb.AppendLine("Most graphics memory (per-process counters): " + string.Join(", ", topGpu.Select(g => g.Name + " " + Fmt.Size(g.GpuDed))));
            }
            else sb.AppendLine("Graphics memory: counters not available.");
            if (poolTagInfo != null) sb.AppendLine("Pool tags: " + poolTagInfo);
            if (poolCause != null) sb.AppendLine("Likely cause of high driver memory: " + poolCause);
            sb.AppendLine(WatchText());
            sb.AppendLine("Totals: " + y.Handles.ToString("N0") + " handles, " + y.Procs.ToString("N0") + " processes, " + y.Threads.ToString("N0") + " threads");
            return sb.ToString().TrimEnd();
        }

        string ProgramSummary(GroupInfo g)
        {
            DateTime now = snap != null ? snap.Time : DateTime.Now;
            var sb = new StringBuilder();
            sb.AppendLine("Program: " + g.Friendly + " (" + g.Name + ")");
            sb.AppendLine("Path: " + (g.Path ?? "(not readable without admin)"));
            string why = WhyText(g, now);
            sb.AppendLine("Status: " + StatusWord(g) + (why.Length > 0 ? " - " + why : ""));
            if (g.Reason.Length > 0) sb.AppendLine("Technical reason: " + g.Reason);
            if (g.IsDwm) sb.AppendLine("Note: part of Windows (draws the screen); only \"Restart Windows screen drawing\" is offered, never kill.");
            else if (g.Critical) sb.AppendLine("Note: part of Windows; MemWatch will not restart it.");
            else if (g.AgentHost) sb.AppendLine("Note: hosts coding agents/terminals; MemWatch never restarts the whole group.");
            sb.AppendLine("Processes: " + g.Instances.Count);
            sb.AppendLine("Memory: working set " + Fmt.Size(g.WS) + ", private " + Fmt.Size(g.Priv));
            InstanceInfo big = g.Instances.OrderByDescending(i => i.Handles).FirstOrDefault();
            sb.AppendLine("Handles: " + g.Handles.ToString("N0")
                + (big != null && g.Instances.Count > 1 ? " (most in one process: PID " + big.Pid + " with " + big.Handles.ToString("N0") + ")" : ""));
            sb.AppendLine("Threads: " + g.Threads.ToString("N0"));
            sb.AppendLine("Graphics memory: dedicated " + Fmt.Size(g.GpuDed) + ", shared " + Fmt.Size(g.GpuShared));
            sb.AppendLine("Change over last " + Math.Min(g.WinSpanMin, Cfg.GrowthWindowMin).ToString("0.#") + " min: private " + Fmt.SignedSize(g.DWinPriv)
                + ", handles " + Fmt.SignedK(g.DWinHandles) + ", graphics " + Fmt.SignedSize(g.Instances.Sum(i => i.DWinGpu)));
            sb.AppendLine("Change since MemWatch started: private " + Fmt.SignedSize(g.DStartPriv) + ", handles " + Fmt.SignedK(g.DStartHandles));
            if (g.OldestStart.HasValue)
                sb.AppendLine("Oldest process started: " + g.OldestStart.Value.ToString("yyyy-MM-dd HH:mm") + " (running " + Fmt.Ago(now - g.OldestStart.Value) + ")");
            sb.AppendLine("PIDs: " + PidList(g.Instances));
            return sb.ToString().TrimEnd();
        }

        string SelectedProgramsText()
        {
            List<GroupInfo> sel = SelectedSimpleAll();
            if (sel.Count == 0) return null;
            return SnapshotHeader() + "\r\n\r\n" + string.Join("\r\n\r\n", sel.Select(ProgramSummary));
        }

        string AllProblemsText()
        {
            var sb = new StringBuilder();
            sb.AppendLine(SnapshotHeader());
            sb.AppendLine();
            sb.AppendLine(SystemText());
            List<GroupInfo> problems = snap == null ? new List<GroupInfo>()
                : snap.Groups.Where(g => g.Level > 0).OrderByDescending(g => g.Level).ThenByDescending(g => g.Score).ToList();
            sb.AppendLine();
            if (problems.Count == 0) sb.AppendLine("No program needs attention.");
            else
            {
                sb.AppendLine("Programs needing attention (" + problems.Count + "):");
                foreach (GroupInfo g in problems) { sb.AppendLine(); sb.AppendLine(ProgramSummary(g)); }
            }
            return sb.ToString().TrimEnd();
        }

        // Advanced lists: header row + selected rows (all rows if none selected), tab-separated.
        string ListRowsText(ListView lv)
        {
            var items = (lv.SelectedItems.Count > 0 ? lv.SelectedItems.Cast<ListViewItem>() : lv.Items.Cast<ListViewItem>()).ToList();
            if (items.Count == 0) return null;
            var sb = new StringBuilder();
            sb.AppendLine(SnapshotHeader());
            if (lv == lvInst) sb.AppendLine(lblInst.Text.Trim());
            sb.AppendLine(string.Join("\t", lv.Columns.Cast<ColumnHeader>().Select(c => c.Text)));
            foreach (ListViewItem it in items)
                sb.AppendLine(string.Join("\t", it.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(si => si.Text)));
            return sb.ToString().TrimEnd();
        }

        // Keep pasted text plain ASCII: drop (R)/(TM)/(C) marks, replace anything else non-ASCII with '?'.
        static string Ascii(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char ch in s)
            {
                if (ch == '\r' || ch == '\n' || ch == '\t' || (ch >= ' ' && ch <= '~')) sb.Append(ch);
                else if (ch == (char)0xAE || ch == (char)0x2122 || ch == (char)0xA9) continue;
                else if (ch == (char)0x2013 || ch == (char)0x2014) sb.Append('-');
                else if (ch == (char)0x2018 || ch == (char)0x2019) sb.Append('\'');
                else if (ch == (char)0x201C || ch == (char)0x201D) sb.Append('"');
                else if (ch == (char)0xA0) sb.Append(' ');
                else sb.Append('?');
            }
            return sb.ToString();
        }

        // One short plain-English sentence. No handles/private bytes/threads jargon.
        string WhyText(GroupInfo g, DateTime now)
        {
            if (g.Critical && g.Level == 0) return g.IsDwm ? "Part of Windows (draws your screen)" : "Part of Windows";
            if (g.Level == 0) return g.AgentHost ? "Runs your coding agents and terminals" : "";
            InstanceInfo w = g.Worst;
            string up = w != null && w.Start.HasValue ? Fmt.Ago(now - w.Start.Value) : null;
            string what;
            bool gpuLeads = g.FGpu && (w == null || g.GpuScore >= w.Score);
            if (gpuLeads)
                what = "Using " + Fmt.Size(g.GpuDed) + " of graphics memory - this makes windows and scrolling lag";
            else if (w != null && w.FGpuGrowth) what = "Graphics memory growing fast (+" + Fmt.Size((long)(w.GpuRateMB * 1048576)) + " per 10 min)";
            else if (w != null && w.FPrivGrowth) what = "Growing fast (+" + Fmt.Size((long)(w.PrivRateMB * 1048576)) + " per 10 min)";
            else if (w != null && w.FHandleGrowth) what = "Leaking, and still getting worse";
            else if (w != null && w.FHandles) what = up != null ? "Likely leaking (running " + up + ")" : "Likely leaking";
            else if (w != null && w.FPriv) what = "Using a lot of memory";
            else if (w != null && w.FThreads) what = "Unusually busy in the background";
            else if (g.FGroupHandles) what = "All its windows together are leaking";
            else what = "Acting unusually";
            if (g.AgentHost) return what + " - close unused sessions yourself";
            if (gpuLeads && g.Level >= 2) return what;
            if (g.Level >= 2) return what + (GroupRefusal(g, true) == null ? " - restarting frees it" : "");
            return what + " - keep an eye on it";
        }

        static bool GpuHigh(SysInfo y)
        {
            return y.GpuOk && y.GpuTotal > 0 && y.GpuUsed >= Cfg.GpuBannerFraction * y.GpuTotal;
        }

        // One short sentence; the details live in the "Always watching" panel and the list below it.
        void UpdateBanner(Snapshot s, int red, int yellow)
        {
            // Disk space and uptime show on their cards only; they never drive the banner.
            List<string> redWatch = watchItems.Where(i => i.Level >= 2 && i.Name != "Disk space").Select(i => i.Name).ToList();
            List<string> yellowWatch = watchItems.Where(i => i.Level == 1 && i.Name != "Uptime" && i.Name != "Disk space").Select(i => i.Name).ToList();
            string text;
            if (red > 0) text = red == 1 ? "1 program should be restarted." : red + " programs should be restarted.";
            else if (yellow > 0) text = yellow == 1 ? "1 program is worth watching." : yellow + " programs are worth watching.";
            else text = "No program is misbehaving.";
            if (redWatch.Count > 0) text += "  Needs attention: " + string.Join(", ", redWatch) + " (see below).";
            else if (yellowWatch.Count > 0) text += "  Worth watching: " + string.Join(", ", yellowWatch) + ".";
            else if (red == 0 && yellow == 0) text = "Everything looks fine.";

            Color accent = red > 0 || redWatch.Count > 0 ? Theme.Red : yellow > 0 || yellowWatch.Count > 0 ? Theme.Amber : Theme.Green;
            if (banner.Text != text) { banner.Text = text; SizeBanner(); }
            if (bannerAccent.BackColor != accent) bannerAccent.BackColor = accent;
        }

        // Runs once (when the nonpaged pool first looks high): top pool tag -> owning driver.
        void StartPoolLookup()
        {
            poolLookupStarted = true;
            ThreadPool.QueueUserWorkItem(delegate
            {
                string cause = null, info;
                try
                {
                    List<PoolTags.Tag> tags = PoolTags.Read();
                    if (tags.Count == 0) info = "Pool tags not readable on this system.";
                    else cause = PoolTags.FindCause(tags, out info);
                }
                catch (Exception ex) { info = "Pool tag lookup failed: " + ex.Message; }
                UI(delegate
                {
                    poolCause = cause;
                    poolTagInfo = info;
                    lblHint.Text = HintText();
                    if (snap != null) ApplySnapshot(snap);
                });
            });
        }

        string HintText()
        {
            return "Nonpaged pool is above 1 GB (normal is a few hundred MB). That is a kernel/driver leak: restarting apps will NOT free it, only a reboot clears it."
                 + (poolTagInfo != null ? " " + poolTagInfo : "");
        }

        // ------------------------------ advanced UI ------------------------------
        Control BuildHeader()
        {
            var flow = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6, 4, 6, 4), WrapContents = true };
            Func<Label> mk = () => new Label { AutoSize = true, Margin = new Padding(4, 4, 18, 4), Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), Padding = new Padding(3, 1, 3, 1) };
            lblRam = mk(); lblCommit = mk(); lblNp = mk(); lblPp = mk(); lblHandles = mk(); lblProcs = mk();
            lblHint = new Label { AutoSize = true, Margin = new Padding(4, 0, 4, 4), ForeColor = Color.FromArgb(170, 0, 0), Visible = false, Text = HintText() };
            flow.Controls.AddRange(new Control[] { lblRam, lblCommit, lblNp, lblPp, lblHandles, lblProcs, lblHint });
            flow.SetFlowBreak(lblProcs, true);
            return flow;
        }

        ToolStrip BuildToolbar()
        {
            var ts = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(4, 2, 4, 2) };
            ts.Items.Add(new ToolStripLabel("Program:"));
            ts.Items.Add(new ToolStripButton("Restart program", null, (s, e) => RestartGroup(SelectedGroup())));
            ts.Items.Add(new ToolStripButton("Kill all instances", null, (s, e) => KillGroup(SelectedGroup())));
            ts.Items.Add(new ToolStripButton("Open file location", null, (s, e) => OpenLocation(SelectedGroup() == null ? null : SelectedGroup().Path)));
            ts.Items.Add(new ToolStripButton("Copy details", null, (s, e) => CopyText(GroupDetails(SelectedGroup()))));
            ts.Items.Add(new ToolStripSeparator());
            ts.Items.Add(new ToolStripButton("Refresh now", null, (s, e) => Tick()));
            btnPause = new ToolStripButton("Pause") { CheckOnClick = true };
            btnPause.CheckedChanged += (s, e) => { btnPause.Text = btnPause.Checked ? "Paused" : "Pause"; };
            ts.Items.Add(btnPause);
            ts.Items.Add(new ToolStripLabel("  Refresh every (s):"));
            numRefresh = new NumericUpDown { Minimum = 1, Maximum = 300, Value = Cfg.DefaultRefreshSec, Width = S(55) };
            numRefresh.ValueChanged += (s, e) => { timer.Interval = (int)numRefresh.Value * 1000; };
            ts.Items.Add(new ToolStripControlHost(numRefresh));
            btnNotify = new ToolStripButton("Pop-up alerts") { CheckOnClick = true, Checked = alerts.St.Enabled };
            btnNotify.CheckedChanged += (s, e) => { alerts.St.Enabled = btnNotify.Checked; alerts.St.Save(); };
            ts.Items.Add(new ToolStripSeparator());
            ts.Items.Add(btnNotify);
            ts.Items.Add(new ToolStripSeparator());
            ts.Items.Add(new ToolStripLabel("Red = runaway, yellow = watch, blue = agent host (single PID only), gray = critical (view only)") { ForeColor = Color.DimGray });
            return ts;
        }

        ToolStrip BuildInstToolbar()
        {
            var ts = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };
            lblInst = new ToolStripLabel("Select a program above to see its individual processes.") { Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
            ts.Items.Add(lblInst);
            ts.Items.Add(new ToolStripSeparator());
            ts.Items.Add(new ToolStripButton("Restart this process", null, (s, e) => RestartInstance()));
            ts.Items.Add(new ToolStripButton("Kill this process", null, (s, e) => KillInstance()));
            ts.Items.Add(new ToolStripButton("Open file location", null, (s, e) => { var i = SelectedInstance(); OpenLocation(i == null ? null : i.Path); }));
            ts.Items.Add(new ToolStripButton("Copy details", null, (s, e) => CopyText(InstanceDetails(SelectedInstance()))));
            ts.Items.Add(new ToolStripButton("Reload command lines", null, (s, e) => LoadCommandLines(SelectedGroup(), true)));
            return ts;
        }

        ContextMenuStrip BuildGroupMenu()
        {
            var m = new ContextMenuStrip();
            var restart = new ToolStripMenuItem("Restart program", null, (s, e) => RestartGroup(SelectedGroup()));
            var kill = new ToolStripMenuItem("Kill all instances", null, (s, e) => KillGroup(SelectedGroup()));
            m.Items.Add(restart);
            m.Items.Add(kill);
            m.Items.Add(new ToolStripMenuItem("Open file location", null, (s, e) => OpenLocation(SelectedGroup() == null ? null : SelectedGroup().Path)));
            m.Items.Add(new ToolStripMenuItem("Copy details", null, (s, e) => CopyText(GroupDetails(SelectedGroup()))));
            m.Items.Add(new ToolStripMenuItem("Copy row(s)", null, (s, e) => CopyText(ListRowsText(lvGroups))) { ShortcutKeyDisplayString = "Ctrl+C" });
            m.Opening += (s, e) =>
            {
                GroupInfo g = SelectedGroup();
                foreach (ToolStripItem it in m.Items) it.Enabled = g != null || it.Text.StartsWith("Copy row");
                if (g == null) { if (lvGroups.SelectedItems.Count == 0) e.Cancel = true; return; }
                string note = g.Critical ? "  (critical - refused)" : g.AgentHost ? "  (agent host - use single PID below)" : "";
                restart.Text = "Restart program" + note;
                kill.Text = "Kill all " + g.Instances.Count + " instance(s) of " + g.Name + note;
            };
            return m;
        }

        ContextMenuStrip BuildInstMenu()
        {
            var m = new ContextMenuStrip();
            var restart = new ToolStripMenuItem("Restart this process", null, (s, e) => RestartInstance());
            var kill = new ToolStripMenuItem("Kill this process", null, (s, e) => KillInstance());
            m.Items.Add(restart);
            m.Items.Add(kill);
            m.Items.Add(new ToolStripMenuItem("Open file location", null, (s, e) => { var i = SelectedInstance(); OpenLocation(i == null ? null : i.Path); }));
            m.Items.Add(new ToolStripMenuItem("Copy details", null, (s, e) => CopyText(InstanceDetails(SelectedInstance()))));
            m.Items.Add(new ToolStripMenuItem("Copy row(s)", null, (s, e) => CopyText(ListRowsText(lvInst))) { ShortcutKeyDisplayString = "Ctrl+C" });
            m.Opening += (s, e) =>
            {
                InstanceInfo i = SelectedInstance();
                foreach (ToolStripItem it in m.Items) it.Enabled = i != null || it.Text.StartsWith("Copy row");
                if (i == null) { if (lvInst.SelectedItems.Count == 0) e.Cancel = true; return; }
                restart.Text = "Restart PID " + i.Pid + " (" + i.Name + ")";
                kill.Text = "Kill PID " + i.Pid + " (" + i.Name + ")";
            };
            return m;
        }

        void BuildTray()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Show MemWatch", null, (s, e) => ShowFromTray());
            // Saved setting; the tray icon color still shows status when pop-ups are off.
            var notify = new ToolStripMenuItem("Pop-up alerts: On");
            notify.Click += (s, e) => { btnNotify.Checked = !btnNotify.Checked; };
            menu.Opening += (s, e) => { notify.Text = "Pop-up alerts: " + (btnNotify.Checked ? "On" : "Off") + "  (click to turn " + (btnNotify.Checked ? "off)" : "on)"); };
            menu.Items.Add(notify);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (s, e) => Close());
            tray = new NotifyIcon { Icon = iconOk, Text = "MemWatch", Visible = true, ContextMenuStrip = menu };
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowFromTray(); };
            tray.BalloonTipClicked += (s, e) => ShowFromTray();
        }

        void ShowFromTray()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
        }

        void Shutdown()
        {
            timer.Stop();
            dwmTrend.Save();
            poolTrend.Save();
            if (tray != null) { tray.Visible = false; tray.Dispose(); tray = null; }
            sampler.Dispose();
            Native.DestroyIcon(hIconOk);
            Native.DestroyIcon(hIconAlert);
        }

        // ------------------------------ sampling ------------------------------
        void Tick()
        {
            if (sampling || btnPause.Checked) return;
            sampling = true;
            ThreadPool.QueueUserWorkItem(delegate
            {
                Snapshot s = null;
                string err = null;
                try { s = sampler.Take(); } catch (Exception ex) { err = ex.Message; }
                UI(delegate
                {
                    sampling = false;
                    if (s != null) ApplySnapshot(s);
                    else lblStatus.Text = "Sample failed: " + err;
                });
            });
        }

        void UI(MethodInvoker a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(a); } catch { }
        }

        void ApplySnapshot(Snapshot s)
        {
            snap = s;
            SysInfo y = s.Sys;
            ulong used = y.TotalPhys - y.AvailPhys;
            lblRam.Text = string.Format("RAM {0:0.0} / {1:0.0} GB ({2:0}%)", used / 1073741824.0, y.TotalPhys / 1073741824.0,
                y.TotalPhys > 0 ? 100.0 * used / y.TotalPhys : 0);
            lblCommit.Text = string.Format("Commit {0:0.0} / {1:0.0} GB", y.CommitTotal / 1073741824.0, y.CommitLimit / 1073741824.0);
            long npDelta = y.NonPagedAtStart > 0 ? y.NonPaged - y.NonPagedAtStart : 0;
            lblNp.Text = "Pool Nonpaged " + Fmt.Size(y.NonPaged) + " (" + Fmt.SignedSize(npDelta) + " since start)";
            bool npHigh = y.NonPaged / 1048576 >= Cfg.NonpagedPoolRedMB;
            lblNp.BackColor = npHigh ? Color.FromArgb(200, 30, 30) : Color.Transparent;
            lblNp.ForeColor = npHigh ? Color.White : SystemColors.ControlText;
            lblHint.Visible = npHigh;
            lblPp.Text = "Pool Paged " + Fmt.Size(y.Paged);
            bool ppHigh = y.Paged / 1048576 >= Cfg.PagedPoolWarnMB;
            lblPp.BackColor = ppHigh ? Color.Orange : Color.Transparent;
            lblHandles.Text = "Handles " + y.Handles.ToString("N0");
            lblProcs.Text = "Processes " + y.Procs.ToString("N0") + "   Threads " + y.Threads.ToString("N0");

            foreach (int pid in cmdLines.Keys.Where(p => !s.Pids.Contains(p)).ToList()) cmdLines.Remove(pid);
            int runaway = s.Groups.Count(g => g.Level >= 2);
            int watch = s.Groups.Count(g => g.Level == 1);
            if (npHigh && !poolLookupStarted) StartPoolLookup();
            GroupInfo dwmG = s.Groups.FirstOrDefault(x => x.IsDwm);
            if (dwmG != null && s.Sys.GpuOk && dwmG.Instances.Count > 0) dwmTrend.Add(dwmG.Instances[0].Pid, dwmG.GpuDed);
            poolTrend.Add(AlertPolicy.CurrentBootMin(), y.NonPaged);
            UpdateWatchPanel(s);
            UpdateBanner(s, runaway, watch);
            // Only the visible view is refreshed (keeps each tick cheap).
            if (chkAdvanced.Checked)
            {
                SyncList(lvGroups, s.Groups, g => g.Key, g => GroupCells(g, s.Time), (it, g) => Style(it, g.Level, g.Critical, g.AgentHost));
                RefreshInstances();
            }
            else UpdateSimple(s);

            bool alert = runaway > 0 || npHigh;
            Icon want = alert ? iconAlert : iconOk;
            if (tray != null)
            {
                if (tray.Icon != want) tray.Icon = want;
                string tip = string.Format("MemWatch: RAM {0:0}/{1:0} GB, NP pool {2}, {3} runaway",
                    used / 1073741824.0, y.TotalPhys / 1073741824.0, Fmt.Size(y.NonPaged), runaway);
                tray.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
            }
            lblStatus.Text = !chkAdvanced.Checked
                ? string.Format("Last checked {0:h:mm:ss tt}. Checks again every {1} seconds.", s.Time, (int)numRefresh.Value)
                : string.Format("Updated {0:HH:mm:ss}  |  {1} programs, {2} runaway, {3} to watch  |  sample took {4} ms{5}",
                    s.Time, s.Groups.Count, runaway, watch, s.SampleMs,
                    elevated ? "" : "  |  not elevated: some paths, command lines and kills may be denied");
            if (s.Time < dwmCheckUntil)
            {
                // After "Restart Windows screen drawing": show before/after graphics memory of the new dwm.exe.
                GroupInfo d = s.Groups.FirstOrDefault(x => x.IsDwm);
                if (d != null && !d.Instances.Any(i => dwmOldPids.Contains(i.Pid)))
                {
                    lblStatus.Text = "Screen drawing restarted. Its graphics memory: before " + Fmt.Size(dwmBefore) + ", now " + Fmt.Size(d.GpuDed) + ".";
                    if (!dwmRecorded) { dwmRecorded = true; dwmRestart.Record(DateTime.UtcNow, dwmBefore, d.GpuDed); UpdateWatchPanel(s); }
                }
            }

            if (SelfTest == null) Notify(s, npHigh);   // AlertPolicy checks the on/off setting and all rate limits
            if (SelfTest != null && !selfTestDone && (!poolLookupStarted || poolTagInfo != null))
            {
                selfTestDone = true;
                BeginInvoke(new MethodInvoker(RunSelfTest));
            }
        }

        void RunSelfTest()
        {
            switch (SelfTest)
            {
                case "banner": CopyText(SnapshotHeader() + Environment.NewLine + Environment.NewLine + SystemText()); break;
                case "rows":
                    chkShowAll.Checked = true;
                    grid.ClearSelection();
                    for (int i = 0; i < Math.Min(3, grid.Rows.Count); i++) grid.Rows[i].Selected = true;
                    CopyText(SelectedProgramsText());
                    break;
                case "dwm":
                {
                    // Simulates the dwm path up to the confirmation dialog. Never ends dwm.
                    GroupInfo d = snap.Groups.FirstOrDefault(x => x.IsDwm);
                    var sb = new StringBuilder();
                    sb.AppendLine(SnapshotHeader());
                    if (d == null) sb.AppendLine("dwm.exe not found.");
                    else
                    {
                        int pos = grid.Rows.Cast<DataGridViewRow>().ToList().FindIndex(r => r.Tag == d);
                        sb.AppendLine("Simple view row: " + (pos < 0 ? "not listed" : "#" + (pos + 1) + " of " + grid.Rows.Count));
                        sb.AppendLine("Status: " + StatusWord(d) + " | Memory: " + MemoryText(d) + " | Why: " + WhyText(d, snap.Time));
                        sb.AppendLine("Restart button shown: " + (pos >= 0 && grid.Rows[pos].Cells[colAct.Index] is DataGridViewButtonCell));
                        sb.AppendLine("Restart allowed: " + (GroupRefusal(d, true) == null));
                        sb.AppendLine("Kill refused with: " + GroupRefusal(d, false));
                        sb.AppendLine("Other critical (svchost) restart refused with: " + GroupRefusal(snap.Groups.FirstOrDefault(x => Safety.BaseName(x.Name) == "svchost"), true));
                        sb.AppendLine("Confirmation dialog text (No is default):");
                        sb.AppendLine(DwmConfirmText());
                        sb.AppendLine();
                        sb.AppendLine(ProgramSummary(d));
                    }
                    CopyText(sb.ToString());
                    break;
                }
                case "advanced":
                    chkAdvanced.Checked = true;
                    lvGroups.SelectedItems.Clear();
                    for (int i = 0; i < Math.Min(2, lvGroups.Items.Count); i++) lvGroups.Items[i].Selected = true;
                    CopyText(ListRowsText(lvGroups));
                    break;
                default: CopyText(AllProblemsText()); break;
            }
            Close();
        }

        void Notify(Snapshot s, bool npHigh)
        {
            if (tray == null) return;
            List<string> fresh = alerts.Decide(DateTime.UtcNow, AlertPolicy.CurrentBootMin(), npHigh, s.Sys.NonPaged, s.Groups,
                                               g => g.Friendly + ": " + WhyText(g, s.Time));
            if (fresh.Count == 0) return;
            string text = string.Join("\n", fresh.Take(4)) + (fresh.Count > 4 ? "\n+" + (fresh.Count - 4) + " more" : "");
            if (text.Length > 250) text = text.Substring(0, 247) + "...";
            tray.ShowBalloonTip(8000, "MemWatch: something needs attention", text, ToolTipIcon.Warning);
        }

        static void Style(ListViewItem it, int level, bool critical, bool agent)
        {
            Color back = level >= 2 ? RunawayBack : level == 1 ? WarnBack : SystemColors.Window;
            Color fore = critical ? Color.Gray : agent ? AgentFore : SystemColors.WindowText;
            if (it.BackColor != back) it.BackColor = back;
            if (it.ForeColor != fore) it.ForeColor = fore;
        }

        // Updates items in place (keeps selection and scroll position), adds new, removes gone.
        static void SyncList<T>(ListView lv, IList<T> rows, Func<T, string> key, Func<T, string[]> cells, Action<ListViewItem, T> style)
        {
            lv.BeginUpdate();
            try
            {
                var existing = new Dictionary<string, ListViewItem>();
                foreach (ListViewItem it in lv.Items) existing[it.Name] = it;
                var keep = new HashSet<string>();
                var toAdd = new List<ListViewItem>();
                foreach (T r in rows)
                {
                    string k = key(r);
                    if (!keep.Add(k)) continue;
                    string[] c = cells(r);
                    ListViewItem it;
                    if (existing.TryGetValue(k, out it))
                    {
                        for (int i = 0; i < c.Length; i++) if (it.SubItems[i].Text != c[i]) it.SubItems[i].Text = c[i];
                    }
                    else { it = new ListViewItem(c) { Name = k }; toAdd.Add(it); }
                    it.Tag = r;
                    style(it, r);
                }
                for (int i = lv.Items.Count - 1; i >= 0; i--) if (!keep.Contains(lv.Items[i].Name)) lv.Items.RemoveAt(i);
                if (toAdd.Count > 0) lv.Items.AddRange(toAdd.ToArray());
                lv.Sort();
            }
            finally { lv.EndUpdate(); }
        }

        static string Win(double spanMin) { return spanMin < Cfg.GrowthWindowMin - 0.2 ? "~" : ""; }

        static string[] GroupCells(GroupInfo g, DateTime now)
        {
            string w = Win(g.WinSpanMin);
            return new[] { g.Name, g.Instances.Count.ToString(), Fmt.MB(g.WS), Fmt.MB(g.Priv), g.Handles.ToString("N0"), g.Threads.ToString("N0"),
                w + Fmt.SignedSize(g.DWinPriv), w + Fmt.SignedK(g.DWinHandles), Fmt.SignedSize(g.DStartPriv), Fmt.SignedK(g.DStartHandles),
                Fmt.Time(g.OldestStart), Fmt.Uptime(g.OldestStart, now), g.Reason, g.Path ?? "(path not readable)", Fmt.MB(g.GpuDed), Fmt.MB(g.GpuShared) };
        }

        string[] InstCells(InstanceInfo i, DateTime now)
        {
            string cl;
            if (!cmdLines.TryGetValue(i.Pid, out cl)) cl = loadingCmd ? "(loading...)" : "";
            string w = Win(i.WinSpanMin);
            return new[] { i.Pid.ToString(), i.Name, Fmt.MB(i.WS), Fmt.MB(i.Priv), i.Handles.ToString("N0"), i.Threads.ToString("N0"),
                w + Fmt.SignedSize(i.DWinPriv), w + Fmt.SignedK(i.DWinHandles), Fmt.SignedSize(i.DStartPriv), Fmt.SignedK(i.DStartHandles),
                Fmt.Time(i.Start), Fmt.Uptime(i.Start, now), i.Reason, cl, Fmt.MB(i.GpuDed), Fmt.MB(i.GpuShared) };
        }

        static IComparable GroupKey(object o, int col)
        {
            var g = (GroupInfo)o;
            switch (col)
            {
                case 0: return g.Name;
                case 1: return (double)g.Instances.Count;
                case 2: return (double)g.WS;
                case 3: return (double)g.Priv;
                case 4: return (double)g.Handles;
                case 5: return (double)g.Threads;
                case 6: return (double)g.DWinPriv;
                case 7: return (double)g.DWinHandles;
                case 8: return (double)g.DStartPriv;
                case 9: return (double)g.DStartHandles;
                case 10: return g.OldestStart.HasValue ? (double)g.OldestStart.Value.Ticks : double.MaxValue;
                case 11: return g.OldestStart.HasValue ? -(double)g.OldestStart.Value.Ticks : double.MinValue;
                case 12: return g.Level * 1e12 + g.Handles;
                case 14: return (double)g.GpuDed;
                case 15: return (double)g.GpuShared;
                default: return g.Path ?? "";
            }
        }

        IComparable InstKey(object o, int col)
        {
            var i = (InstanceInfo)o;
            switch (col)
            {
                case 0: return (double)i.Pid;
                case 1: return i.Name;
                case 2: return (double)i.WS;
                case 3: return (double)i.Priv;
                case 4: return (double)i.Handles;
                case 5: return (double)i.Threads;
                case 6: return (double)i.DWinPriv;
                case 7: return (double)i.DWinHandles;
                case 8: return (double)i.DStartPriv;
                case 9: return (double)i.DStartHandles;
                case 10: return i.Start.HasValue ? (double)i.Start.Value.Ticks : double.MaxValue;
                case 11: return i.Start.HasValue ? -(double)i.Start.Value.Ticks : double.MinValue;
                case 12: return i.Level * 1e12 + i.Handles;
                case 14: return (double)i.GpuDed;
                case 15: return (double)i.GpuShared;
                default: string cl; return cmdLines.TryGetValue(i.Pid, out cl) && cl != null ? cl : "";
            }
        }

        static void SortBy(ListView lv, ColSorter s, int col)
        {
            if (s.Column == col) s.Desc = !s.Desc;
            else { s.Column = col; s.Desc = !(col == 0 || col == 1 && lv.Columns[1].Text == "Name" || col == 13 || col == 10); }
            lv.Sort();
        }

        GroupInfo SelectedGroup()
        {
            return lvGroups.SelectedItems.Count != 1 ? null : (GroupInfo)lvGroups.SelectedItems[0].Tag;
        }

        InstanceInfo SelectedInstance()
        {
            return lvInst.SelectedItems.Count != 1 ? null : (InstanceInfo)lvInst.SelectedItems[0].Tag;
        }

        GroupInfo GroupOf(InstanceInfo i)
        {
            if (snap == null || i == null) return null;
            return snap.Groups.FirstOrDefault(g => g.Instances.Any(x => x.Pid == i.Pid));
        }

        void OnGroupSelected()
        {
            RefreshInstances();
            GroupInfo g = SelectedGroup();
            if (g != null && g.Key != cmdGroupKey) { cmdGroupKey = g.Key; LoadCommandLines(g, false); }
        }

        void RefreshInstances()
        {
            GroupInfo g = SelectedGroup();
            if (g == null)
            {
                lvInst.Items.Clear();
                lblInst.Text = "Select a program above to see its individual processes.";
                return;
            }
            string tag = g.Critical ? "   [critical Windows process - view only]"
                       : g.AgentHost ? "   [agent host - act on ONE process at a time]" : "";
            lblInst.Text = "Instances of " + g.Name + " (" + g.Instances.Count + ")" + tag;
            DateTime now = snap != null ? snap.Time : DateTime.Now;
            SyncList(lvInst, g.Instances, i => i.Pid.ToString(), i => InstCells(i, now), (it, i) => Style(it, i.Level, g.Critical, g.AgentHost));
        }

        void LoadCommandLines(GroupInfo g, bool force)
        {
            if (g == null || loadingCmd) return;
            List<int> pids = g.Instances.Select(i => i.Pid).Where(p => force || !cmdLines.ContainsKey(p)).ToList();
            if (pids.Count == 0) return;
            loadingCmd = true;
            RefreshInstances();
            ThreadPool.QueueUserWorkItem(delegate
            {
                Dictionary<int, string> res = null;
                string err = null;
                try { res = Wmi.CommandLines(pids); } catch (Exception ex) { err = ex.Message; }
                UI(delegate
                {
                    loadingCmd = false;
                    if (res != null)
                        foreach (int p in pids)
                        {
                            string cl;
                            cmdLines[p] = res.TryGetValue(p, out cl) && cl != null ? cl : "(not readable" + (elevated ? ")" : " - run MemWatch as admin)");
                        }
                    else lblStatus.Text = "Could not read command lines: " + err;
                    RefreshInstances();
                });
            });
        }

        string CommandLineNow(int pid)
        {
            try
            {
                string cl;
                if (Wmi.CommandLines(new[] { pid }).TryGetValue(pid, out cl) && cl != null) { cmdLines[pid] = cl; return cl; }
            }
            catch { }
            return null;
        }

        // ------------------------------ actions ------------------------------
        string GroupRefusal(GroupInfo g, bool restart)
        {
            if (g == null) return "Pick one program in the list first.";
            if (g.IsSelf) return "That is MemWatch itself. Use Exit from the tray menu instead.";
            if (g.IsDwm)   // the one critical process with a dedicated, Windows-supported restart
                return restart ? null : "This is the part of Windows that draws your screen. MemWatch won't kill it; use Restart instead (\"Restart Windows screen drawing\").";
            if (g.Critical) return g.Friendly + " is part of Windows. MemWatch won't close it.";
            if (g.AgentHost)
                return g.Friendly + " runs your coding agents and terminals, so MemWatch won't close all of them at once.\n\n"
                     + "Close the sessions you don't use yourself. (Or turn on Advanced details and pick one single process.)";
            if (restart && g.Path == null && !Safety.IsExplorer(g.Name))
                return "Windows didn't let MemWatch see where " + g.Friendly + " is installed, so it can't reopen it.\n\nRun MemWatch as administrator and try again.";
            return null;
        }

        string InstanceRefusal(InstanceInfo i, GroupInfo g, bool restart)
        {
            if (i == null) return "Select exactly one process in the instances list first.";
            if (i.Pid == selfPid) return "That is MemWatch itself. Use Exit from the tray menu instead.";
            if (g != null && g.Critical) return i.Name + " is a critical Windows process (or lives in System32). MemWatch will not end it.";
            if (restart && i.Path == null) return "The executable path of PID " + i.Pid + " could not be read (access denied). Run MemWatch as administrator to restart it.";
            return null;
        }

        bool Refused(string why)
        {
            if (why == null) return false;
            MessageBox.Show(this, why, "MemWatch", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return true;
        }

        bool Confirm(string text, string title)
        {
            return MessageBox.Show(this, text, title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        bool Busy()
        {
            if (!busyAction) return false;
            MessageBox.Show(this, "Another restart is still running. Wait for it to finish.", "MemWatch", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return true;
        }

        static string PidList(IEnumerable<InstanceInfo> list)
        {
            var pids = list.Select(i => i.Pid).OrderBy(p => p).ToList();
            string s = string.Join(", ", pids.Take(40));
            return pids.Count > 40 ? s + ", ... (" + (pids.Count - 40) + " more)" : s;
        }

        // The "main" instance: prefer one with a top-level window, then the oldest.
        static InstanceInfo PickMain(GroupInfo g)
        {
            InstanceInfo best = null;
            bool bestWin = false;
            foreach (InstanceInfo i in g.Instances)
            {
                bool win = false;
                try { using (var p = Process.GetProcessById(i.Pid)) win = p.MainWindowHandle != IntPtr.Zero; } catch { }
                bool older = best == null || (i.Start.HasValue && (!best.Start.HasValue || i.Start.Value < best.Start.Value));
                if (best == null || (win && !bestWin) || (win == bestWin && older)) { best = i; bestWin = win; }
            }
            return best;
        }

        static string ArgsFrom(string cl, string exe)
        {
            if (string.IsNullOrEmpty(cl)) return "";
            string s = cl.TrimStart();
            if (s.StartsWith("\""))
            {
                int q = s.IndexOf('"', 1);
                return q < 0 ? "" : s.Substring(q + 1).Trim();
            }
            if (!string.IsNullOrEmpty(exe) && s.StartsWith(exe, StringComparison.OrdinalIgnoreCase)) return s.Substring(exe.Length).Trim();
            int sp = s.IndexOf(' ');
            return sp < 0 ? "" : s.Substring(sp + 1).Trim();
        }

        void RestartGroup(GroupInfo g)
        {
            if (Busy() || Refused(GroupRefusal(g, true))) return;
            if (g.IsDwm) { RestartDwm(g); return; }
            var targets = g.Instances.ToList();
            if (Safety.IsExplorer(g.Name))
            {
                if (!Confirm("Restart Windows Explorer?\n\nThe taskbar and any open folder windows will disappear for a moment and come back.\n\n"
                    + "(Details: ends " + targets.Count + " explorer.exe process(es), PIDs " + PidList(targets) + ", then starts explorer.exe.)", "MemWatch - restart")) return;
                RunAction("Restarting Windows Explorer...", () => RestartExplorer(targets));
                return;
            }
            Cursor = Cursors.WaitCursor;
            InstanceInfo main = PickMain(g);
            string cl = CommandLineNow(main.Pid);
            Cursor = Cursors.Default;
            string exe = main.Path ?? g.Path;
            string args = ArgsFrom(cl, exe);
            string text = "Restart " + g.Friendly + "?\n\n"
                + "It will close and reopen. Unsaved work in it may be lost.\n\n"
                + "(Details: closes " + targets.Count + " " + g.Name + " process(es), PIDs " + PidList(targets)
                + ". Anything still open after " + (Cfg.GracefulCloseWaitMs / 1000) + " s is forced closed. Then starts \"" + exe + "\""
                + (args.Length > 0 ? " " + args : "") + (cl == null ? " (its original options could not be read)" : "") + ".)";
            if (!Confirm(text, "MemWatch - restart")) return;
            RunAction("Restarting " + g.Friendly + "...", () => EndAndRelaunch(targets, true, exe, args));
        }

        // ---- dwm.exe: "Restart Windows screen drawing" ----
        // Windows starts a new dwm.exe by itself when it is ended. Ending it needs admin rights, so a
        // non-elevated MemWatch runs "taskkill /f /im dwm.exe" through a UAC prompt (only after the confirmation).
        long dwmBefore;
        DateTime dwmCheckUntil;
        HashSet<int> dwmOldPids = new HashSet<int>();
        bool dwmRecorded;

        // ---------------------- "Always watching" panel ----------------------
        // 7 cards above the problem list. Level: -1 info (gray), 0 OK, 1 watch, 2 act.
        // Text = the long plain-English sentence (tooltip, copy-to-clipboard); Title/Value/Sub = what the card shows.
        class WatchItem
        {
            public string Name, Text, Button, Title, Value, Sub;
            public int Level;
            public double Fraction = -1;   // progress bar 0..1, or -1 for none
            public Action Click;
        }

        const int WatchRows = 7;
        readonly Trend dwmTrend = new Trend("DwmHistory");
        readonly Trend poolTrend = new Trend("PoolHistory");
        readonly DwmRestart dwmRestart = DwmRestart.Load();
        FlowLayoutPanel watchPanel;
        readonly WatchTile[] tiles = new WatchTile[WatchRows];
        readonly ToolTip tileTips = new ToolTip { InitialDelay = 300, AutoPopDelay = 20000 };
        readonly string[] tileTipText = new string[WatchRows];
        List<WatchItem> watchItems = new List<WatchItem>();
        List<KeyValuePair<string, string>> diskCache = new List<KeyValuePair<string, string>>();   // drive -> line part
        int diskLevel = -1;
        DateTime diskCheckedAt = DateTime.MinValue;
        string diskWorstName;                 // tile shows the fullest drive
        long diskWorstFree, diskWorstTotal;
        int diskLowCount;

        Control BuildWatchPanel()
        {
            watchPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, AutoSize = true, WrapContents = true, BackColor = Theme.Page,
                Padding = new Padding(S(10), S(2), S(10), S(8))
            };
            var menu = new ContextMenuStrip { Font = new Font("Segoe UI", 10f) };
            menu.Items.Add("Copy to clipboard", null, (s, e) => CopyText(SnapshotHeader() + Environment.NewLine + WatchText()));
            menu.Items.Add("Copy all problems to clipboard", null, (s, e) => CopyText(AllProblemsText()));
            watchPanel.ContextMenuStrip = menu;
            for (int i = 0; i < WatchRows; i++)
            {
                tiles[i] = new WatchTile(dpi) { Size = new Size(S(176), S(104)), Margin = new Padding(S(4)), ContextMenuStrip = menu };
                int idx = i;
                tiles[i].ActionClick += (s, e) => { if (idx < watchItems.Count && watchItems[idx].Click != null) watchItems[idx].Click(); };
                watchPanel.Controls.Add(tiles[i]);
            }
            // Spread the 7 cards over the window width; they wrap onto a second row on narrow windows.
            watchPanel.Resize += (s, e) => LayoutTiles();
            return watchPanel;
        }

        void LayoutTiles()
        {
            if (watchPanel == null) return;
            int avail = watchPanel.ClientSize.Width - watchPanel.Padding.Horizontal;
            int margin = S(4) * 2;
            int perRow = Math.Max(1, Math.Min(WatchRows, avail / (S(150) + margin)));
            // Spread the leftover pixels over the first tiles of each row so the row ends flush with the list below.
            int inner = avail - perRow * margin;
            int baseW = Math.Max(S(150), inner / perRow), extra = Math.Max(0, inner - baseW * perRow);
            for (int i = 0; i < tiles.Length; i++)
            {
                int w = baseW + (i % perRow < extra ? 1 : 0);
                if (tiles[i].Width != w) tiles[i].Width = w;
            }
        }

        static string Duration(double hours)
        {
            if (hours < 1) return "under an hour";
            if (hours < 48) return "about " + Math.Round(hours) + " hours";
            return "about " + Math.Round(hours / 24) + " days";
        }

        static string ShortRate(double mbPerHour, bool perDay)
        {
            double v = perDay ? mbPerHour * 24 : mbPerHour;
            string size = Math.Abs(v) >= 1024 ? (v / 1024).ToString("0.0") + " GB" : v.ToString("0") + " MB";
            return (v >= 0 ? "+" : "") + size + (perDay ? "/day" : "/hr");
        }

        static string LevelWord(int level) { return level >= 2 ? "RED" : level == 1 ? "YELLOW" : level == 0 ? "OK" : "INFO"; }

        // "Screen drawing (dwm): 2.2 GB graphics memory - OK. Growing about +40 MB per hour. Restart suggested at 6.0 GB (about 4 days)."
        string DwmLine(GroupInfo d, SysInfo y)
        {
            if (d == null) return "Screen drawing (dwm): not found.";
            if (!y.GpuOk) return "Screen drawing (dwm): graphics memory counters are not available on this system.";
            long mb = d.GpuDed / 1048576;
            string text = "Screen drawing (dwm): " + Fmt.Size(d.GpuDed) + " graphics memory - "
                        + (d.Level >= 2 ? "restart suggested" : d.Level == 1 ? "watch" : "OK") + ".";
            double? rate = dwmTrend.RateMBPerHour();
            string limit = Fmt.Size(Cfg.DwmGpuRunawayMB * 1048576);
            if (rate == null) text += " Growth: measuring... (" + (int)dwmTrend.MeasuredMin + " of 15 min).";
            else if (rate.Value < 5) text += " Not growing right now.";
            else
            {
                text += " Growing about +" + Fmt.Size((long)(rate.Value * 1048576)) + " per hour.";
                if (mb < Cfg.DwmGpuRunawayMB)
                    text += " Restart suggested at " + limit + " (" + Duration((Cfg.DwmGpuRunawayMB - mb) / rate.Value) + ").";
            }
            if (dwmRestart.WhenUtc.HasValue)
            {
                long freed = dwmRestart.BeforeMB - dwmRestart.AfterMB;
                text += " Last restarted " + dwmRestart.WhenUtc.Value.ToLocalTime().ToString("MMM d h:mm tt")
                      + (dwmRestart.BeforeMB > 0 && freed > 0 ? " (freed " + Fmt.Size(freed * 1048576) + ")" : "") + ".";
            }
            return text;
        }

        // Fixed drives, refreshed at most once a minute. Red: under 10% or under 20 GB free; yellow: under 15%.
        void RefreshDisks()
        {
            if ((DateTime.Now - diskCheckedAt).TotalSeconds < 60) return;
            diskCheckedAt = DateTime.Now;
            var parts = new List<KeyValuePair<string, string>>();
            int level = -1, low = 0;
            double worstPct = 101;
            try
            {
                foreach (System.IO.DriveInfo di in System.IO.DriveInfo.GetDrives())
                {
                    try
                    {
                        if (di.DriveType != System.IO.DriveType.Fixed || !di.IsReady || di.TotalSize <= 0) continue;
                        string name = di.Name.TrimEnd(System.IO.Path.DirectorySeparatorChar);
                        double pct = 100.0 * di.AvailableFreeSpace / di.TotalSize;
                        int lv = pct < 10 || di.AvailableFreeSpace < 20L * 1073741824 ? 2 : pct < 15 ? 1 : 0;
                        level = Math.Max(level, lv);
                        if (lv >= 1) low++;
                        string free = BigSize(di.AvailableFreeSpace);
                        parts.Add(new KeyValuePair<string, string>(name, name + " " + free + " free (" + pct.ToString("0") + "%)" + (lv >= 2 ? " LOW" : lv == 1 ? " low" : "")));
                        if (pct < worstPct) { worstPct = pct; diskWorstName = name; diskWorstFree = di.AvailableFreeSpace; diskWorstTotal = di.TotalSize; }
                    }
                    catch { }   // unreadable drive: skip
                }
            }
            catch { }
            diskCache = parts;
            diskLevel = level;
            diskLowCount = low;
        }

        static string BigSize(long bytes)
        {
            return bytes >= 1099511627776L ? (bytes / 1099511627776.0).ToString("0.0") + " TB" : Fmt.Size(bytes);
        }

        List<WatchItem> BuildWatchItems(Snapshot s)
        {
            var items = new List<WatchItem>();
            SysInfo y = s.Sys;

            // 1. Screen drawing (dwm)
            GroupInfo d = s.Groups.FirstOrDefault(x => x.IsDwm);
            var it = new WatchItem { Name = "Screen drawing (dwm)", Title = "Screen drawing", Level = d == null || !y.GpuOk ? -1 : d.Level, Text = DwmLine(d, y),
                Button = d != null ? "Restart" : null, Click = () => RestartGroup(snap == null ? null : snap.Groups.FirstOrDefault(x => x.IsDwm)) };
            if (d == null || !y.GpuOk) { it.Value = "n/a"; it.Sub = d == null ? "dwm not found" : "no GPU counters"; }
            else
            {
                double? rate = dwmTrend.RateMBPerHour();
                it.Value = Fmt.Size(d.GpuDed);
                it.Fraction = (double)(d.GpuDed / 1048576) / Cfg.DwmGpuRunawayMB;
                it.Sub = (rate == null ? "measuring growth" : rate.Value < 5 ? "not growing" : ShortRate(rate.Value, false))
                       + " - " + (d.Level >= 2 ? "restart suggested" : d.Level == 1 ? "watch" : "OK");
            }
            items.Add(it);

            // 2. Windows driver memory (kernel pools)
            bool npHigh = y.NonPaged / 1048576 >= Cfg.NonpagedPoolRedMB, ppHigh = y.Paged / 1048576 >= Cfg.PagedPoolWarnMB;
            string t = "Windows driver memory: " + Fmt.Size(y.NonPaged) + " nonpaged + " + Fmt.Size(y.Paged) + " paged - "
                     + (npHigh ? "high" : ppHigh ? "above normal" : "normal") + ".";
            double? pr = poolTrend.RateMBPerHour();
            if (pr == null) t += " Growth: measuring...";
            else if (pr.Value * 24 < 50) t += " Not growing right now.";
            else
            {
                t += " Growing about +" + Fmt.Size((long)(pr.Value * 24 * 1048576)) + " per day.";
                if (!npHigh) t += " Needs attention in " + Duration((Cfg.NonpagedPoolRedMB - y.NonPaged / 1048576) / pr.Value) + ".";
            }
            if (npHigh || ppHigh) t += (poolCause != null ? " Likely cause: " + poolCause + "." : "") + " Only a reboot clears this.";
            string vendor = poolCause == null ? null : poolCause.Split('(')[0].Trim();
            items.Add(new WatchItem { Name = "Windows driver memory", Title = "Driver memory", Level = npHigh ? 2 : ppHigh ? 1 : 0, Text = t,
                Value = Fmt.Size(y.NonPaged),
                Sub = npHigh || ppHigh ? (vendor != null && !vendor.StartsWith("a ") ? vendor + " - needs reboot" : "leak - needs reboot")
                    : (pr == null ? "measuring - normal" : (pr.Value * 24 < 50 ? "not growing" : ShortRate(pr.Value, true)) + " - normal") });

            // 3. Windows Explorer
            GroupInfo ex = s.Groups.FirstOrDefault(x => Safety.IsExplorer(x.Name));
            if (ex == null || ex.Instances.Count == 0)
                items.Add(new WatchItem { Name = "Windows Explorer", Title = "Explorer", Level = -1, Value = "off", Sub = "not running",
                    Text = "Windows Explorer (taskbar, folders): not running." });
            else
            {
                int maxH = ex.Instances.Max(i => i.Handles);
                int lv = maxH >= Cfg.HandlesRunaway ? 2 : maxH >= Cfg.HandlesWarn ? 1 : 0;
                string up = ex.OldestStart.HasValue ? Fmt.Ago(s.Time - ex.OldestStart.Value) : null;
                items.Add(new WatchItem { Name = "Windows Explorer", Title = "Explorer handles", Level = lv, Button = "Restart",
                    Value = Fmt.K(maxH),
                    Fraction = (double)maxH / Cfg.HandlesRunaway,
                    Sub = Fmt.Size(ex.Priv) + (up != null ? ", up " + up : "") + (lv >= 2 ? " - restart" : lv == 1 ? " - watch" : ""),
                    Text = "Windows Explorer (taskbar, folders): " + Fmt.K(maxH) + " handles, " + Fmt.Size(ex.Priv)
                         + (up != null ? ", running " + up : "")
                         + " - " + (lv >= 2 ? "restart suggested" : lv == 1 ? "keep an eye on it" : "fine") + ". Red at 10k handles.",
                    Click = () => RestartGroup(snap == null ? null : snap.Groups.FirstOrDefault(x => Safety.IsExplorer(x.Name))) });
            }

            // 4. RAM and commit
            double usedGB = (y.TotalPhys - y.AvailPhys) / 1073741824.0, totGB = y.TotalPhys / 1073741824.0;
            double commitPct = y.CommitLimit > 0 ? 100.0 * y.CommitTotal / y.CommitLimit : 0;
            int ml = commitPct >= 85 ? 2 : commitPct >= 75 ? 1 : 0;
            items.Add(new WatchItem { Name = "Memory", Title = "RAM", Level = ml,
                Value = string.Format("{0:0} / {1:0} GB", usedGB, totGB),
                Fraction = totGB > 0 ? usedGB / totGB : -1,
                Sub = string.Format("commit {0:0}% - {1}", commitPct, ml >= 2 ? "almost out" : ml == 1 ? "getting full" : "fine"),
                Text = string.Format("Memory: {0:0} of {1:0} GB used, {2:0}% of the commit limit - {3}.", usedGB, totGB, commitPct,
                       ml >= 2 ? "Windows is close to running out of memory" : ml == 1 ? "getting full" : "fine") });

            // 5. Graphics card memory
            if (!y.GpuOk || y.GpuTotal <= 0)
                items.Add(new WatchItem { Name = "Graphics card memory", Title = "Graphics card", Level = -1, Value = "n/a", Sub = "not available",
                    Text = "Graphics card memory: not available." });
            else
            {
                double f = (double)y.GpuUsed / y.GpuTotal;
                int gl = f >= Cfg.GpuRedFraction ? 2 : f >= Cfg.GpuBannerFraction ? 1 : 0;
                items.Add(new WatchItem { Name = "Graphics card memory", Title = "Graphics card", Level = gl,
                    Value = string.Format("{0:0.0} / {1:0} GB", y.GpuUsed / 1073741824.0, y.GpuTotal / 1073741824.0),
                    Fraction = f,
                    Sub = (y.GpuName ?? "GPU").Replace("NVIDIA ", "").Replace("GeForce ", "") + " - " + (gl >= 2 ? "almost full" : gl == 1 ? "getting full" : "fine"),
                    Text = string.Format("Graphics card memory: {0:0.0} of {1:0} GB used{2} - {3}.", y.GpuUsed / 1073741824.0, y.GpuTotal / 1073741824.0,
                           y.GpuName != null ? " (" + y.GpuName + ")" : "", gl >= 2 ? "almost full" : gl == 1 ? "getting full" : "fine") });
            }

            // 6. Disk space (card shows the fullest drive; tooltip lists all)
            RefreshDisks();
            string dt = diskCache.Count == 0 ? "Disks: not readable." : "Disks: " + string.Join(", ", diskCache.Select(kv => kv.Value)) + ".";
            if (diskLevel >= 1) dt += " Free space: Recycle Bin, Disk Cleanup, Downloads.";
            var dIt = new WatchItem { Name = "Disk space", Title = "Disk", Level = diskCache.Count == 0 ? -1 : diskLevel, Text = dt, Value = "n/a", Sub = "not readable" };
            if (diskCache.Count > 0 && diskWorstName != null && diskWorstTotal > 0)
            {
                double freePct = 100.0 * diskWorstFree / diskWorstTotal;
                dIt.Title = "Disk " + diskWorstName;
                dIt.Value = BigSize(diskWorstFree) + " free";
                dIt.Fraction = 1 - (double)diskWorstFree / diskWorstTotal;
                int others = diskLowCount - (diskLevel >= 1 ? 1 : 0);
                dIt.Sub = freePct.ToString("0") + "% free" + (others > 0 ? ", " + others + " more drive" + (others > 1 ? "s" : "") + " low" : diskCache.Count > 1 ? ", others fine" : "");
            }
            items.Add(dIt);

            // 7. Computer uptime (information only; never a pop-up)
            TimeSpan upt = TimeSpan.FromMilliseconds(Native.GetTickCount64());
            bool longUp = upt.TotalDays >= 30;
            items.Add(new WatchItem { Name = "Uptime", Title = "Uptime", Level = longUp ? 1 : -1,
                Value = Fmt.Ago(upt), Sub = longUp ? "a reboot clears leaks" : "since last reboot",
                Text = "Computer running for " + Fmt.Ago(upt) + "." + (longUp ? " A reboot clears driver and graphics leaks." : "") });
            return items;
        }

        void UpdateWatchPanel(Snapshot s)
        {
            watchItems = BuildWatchItems(s);
            if (watchPanel == null) return;
            for (int i = 0; i < WatchRows; i++)
            {
                WatchItem it = i < watchItems.Count ? watchItems[i] : null;
                if (it == null) { tiles[i].Visible = false; continue; }
                tiles[i].Set(it.Title, it.Value, it.Sub, it.Level, it.Fraction, it.Button);
                if (tileTipText[i] != it.Text) { tileTipText[i] = it.Text; tileTips.SetToolTip(tiles[i], it.Text); }
            }
        }

        string WatchText()
        {
            return "Always watching:" + Environment.NewLine
                 + string.Join(Environment.NewLine, watchItems.Select(i => "- [" + LevelWord(i.Level) + "] " + i.Text));
        }

        string DwmConfirmText()
        {
            return "Restart Windows screen drawing (dwm)?\n\n"
                 + "This restarts the part of Windows that draws your screen. The screen will flash black for a second or two and come back; "
                 + "your open programs keep running. Rarely Windows may sign you out instead, so save your work first. Continue?"
                 + (elevated ? "" : "\n\nMemWatch is not running as administrator, so Windows will show a permission (UAC) prompt next.");
        }

        void RestartDwm(GroupInfo g)
        {
            if (!Confirm(DwmConfirmText(), "MemWatch - restart screen drawing")) return;
            long before = g.GpuDed;
            var oldPids = new HashSet<int>(g.Instances.Select(i => i.Pid));
            bool admin = elevated;
            dwmBefore = before;
            dwmOldPids = oldPids;
            dwmRecorded = false;
            dwmCheckUntil = DateTime.Now.AddSeconds(90);
            RunAction("Restarting Windows screen drawing...", () =>
            {
                string how;
                if (admin)
                {
                    foreach (int pid in oldPids)
                    {
                        try { using (var p = Process.GetProcessById(pid)) p.Kill(); }
                        catch (Exception ex) { if (Native.IsAlive(pid)) return "Restart FAILED: " + ex.Message; }
                    }
                    how = "Ended dwm.exe.";
                }
                else
                {
                    try
                    {
                        var psi = new ProcessStartInfo(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "taskkill.exe"), "/f /im dwm.exe")
                            { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
                        using (Process p = Process.Start(psi)) { if (p != null) p.WaitForExit(15000); }
                    }
                    catch (System.ComponentModel.Win32Exception ex)
                    {
                        if (ex.NativeErrorCode == 1223) return "Cancelled: the permission prompt was declined. Nothing was changed.";
                        return "Restart FAILED: " + ex.Message;
                    }
                    how = "Ended dwm.exe (through the administrator prompt).";
                }
                var w = Stopwatch.StartNew();
                int newPid = 0;
                while (w.ElapsedMilliseconds < Cfg.DwmRestartWaitMs && newPid == 0)
                {
                    Thread.Sleep(500);
                    foreach (Process p in Process.GetProcessesByName("dwm")) { if (!oldPids.Contains(p.Id)) newPid = p.Id; p.Dispose(); }
                }
                if (newPid != 0)
                    return how + " Windows started a new one (PID " + newPid + "). Graphics memory before: " + Fmt.Size(before) + "; the new value appears in the status bar shortly.";
                if (oldPids.All(Native.IsAlive))
                    return "Restart FAILED: dwm.exe was not ended (it is still running). Nothing changed.";
                return "Restart FAILED: no new dwm.exe appeared within " + (Cfg.DwmRestartWaitMs / 1000) + " s. If the screen stays black, press Ctrl+Alt+Del and sign out and back in.";
            });
        }

        void KillGroup(GroupInfo g)
        {
            if (Busy() || Refused(GroupRefusal(g, false))) return;
            var targets = g.Instances.ToList();
            string text = "Kill " + g.Name + "?\n\n"
                + "This will immediately FORCE-END " + targets.Count + " process(es) named " + g.Name + ":\n  PIDs " + PidList(targets) + "\n\n"
                + "No graceful close. Unsaved work will be lost.";
            if (!Confirm(text, "MemWatch - confirm kill")) return;
            RunAction("Killing " + g.Name + "...", () => EndAndRelaunch(targets, false, null, null));
        }

        void RestartInstance()
        {
            InstanceInfo i = SelectedInstance();
            GroupInfo g = GroupOf(i);
            if (Busy() || Refused(InstanceRefusal(i, g, true))) return;
            if (Safety.IsExplorer(i.Name)) { RestartGroup(g); return; }
            Cursor = Cursors.WaitCursor;
            string cl = CommandLineNow(i.Pid);
            Cursor = Cursors.Default;
            string args = ArgsFrom(cl, i.Path);
            string text = "Restart ONE process: " + i.Name + " (PID " + i.Pid + ")?\n\n"
                + "Command line:\n  " + (cl ?? "(not readable)") + "\n\n"
                + "1 process will be ended (normal close first, force-kill after " + (Cfg.GracefulCloseWaitMs / 1000) + " s), then started again as:\n  \""
                + i.Path + "\"" + (args.Length > 0 ? " " + args : "") + "\n"
                + (g != null && g.AgentHost ? "\nIf this process is a coding agent session, that agent will stop (it is relaunched without its terminal).\n" : "")
                + "\nOther " + i.Name + " processes are NOT touched.";
            if (!Confirm(text, "MemWatch - confirm restart")) return;
            var targets = new List<InstanceInfo> { i };
            string exe = i.Path;
            RunAction("Restarting PID " + i.Pid + "...", () => EndAndRelaunch(targets, true, exe, args));
        }

        void KillInstance()
        {
            InstanceInfo i = SelectedInstance();
            GroupInfo g = GroupOf(i);
            if (Busy() || Refused(InstanceRefusal(i, g, false))) return;
            Cursor = Cursors.WaitCursor;
            string cl = CommandLineNow(i.Pid);
            Cursor = Cursors.Default;
            string text = "Kill ONE process: " + i.Name + " (PID " + i.Pid + ")?\n\n"
                + "Command line:\n  " + (cl ?? "(not readable)") + "\n\n"
                + "1 process will be force-ended immediately. Unsaved work in it will be lost.\n"
                + (g != null && g.AgentHost ? "\nIf this process is a coding agent session, that agent will stop.\n" : "")
                + "\nOther " + i.Name + " processes are NOT touched.";
            if (!Confirm(text, "MemWatch - confirm kill")) return;
            var targets = new List<InstanceInfo> { i };
            RunAction("Killing PID " + i.Pid + "...", () => EndAndRelaunch(targets, false, null, null));
        }

        void RunAction(string what, Func<string> work)
        {
            busyAction = true;
            lblStatus.Text = what;
            ThreadPool.QueueUserWorkItem(delegate
            {
                string result;
                try { result = work(); } catch (Exception ex) { result = "FAILED: " + ex.Message; }
                UI(delegate
                {
                    busyAction = false;
                    lblStatus.Text = result.Replace("\n", "  ");
                    bool problem = result.IndexOf("FAILED", StringComparison.Ordinal) >= 0 || result.IndexOf("still running", StringComparison.Ordinal) >= 0;
                    MessageBox.Show(this, result, "MemWatch", MessageBoxButtons.OK, problem ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                    Tick();
                });
            });
        }

        // Re-checks name + start time so a reused PID is never hit.
        static bool StillSame(InstanceInfo i)
        {
            try
            {
                using (var p = Process.GetProcessById(i.Pid))
                    if (!string.Equals(p.ProcessName, Safety.BaseName(i.Name), StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(p.ProcessName, i.Name, StringComparison.OrdinalIgnoreCase)) return false;
            }
            catch { return false; }
            string path;
            DateTime? start;
            Native.QueryPathAndStart(i.Pid, out path, out start);
            if (start.HasValue && i.Start.HasValue && Math.Abs((start.Value - i.Start.Value).TotalSeconds) > 1) return false;
            return true;
        }

        // Runs on a worker thread.
        static string EndAndRelaunch(List<InstanceInfo> targets, bool graceful, string exe, string args)
        {
            var log = new StringBuilder();
            List<int> live = targets.Where(StillSame).Select(t => t.Pid).ToList();
            int gone = targets.Count - live.Count;
            if (gone > 0) log.AppendLine(gone + " process(es) had already exited.");

            if (graceful && live.Count > 0)
            {
                int asked = 0;
                foreach (int pid in live)
                {
                    try { using (var p = Process.GetProcessById(pid)) if (p.MainWindowHandle != IntPtr.Zero && p.CloseMainWindow()) asked++; }
                    catch { }
                }
                if (asked > 0)
                {
                    var w = Stopwatch.StartNew();
                    while (w.ElapsedMilliseconds < Cfg.GracefulCloseWaitMs && live.Any(Native.IsAlive)) Thread.Sleep(250);
                    log.AppendLine("Asked " + asked + " window(s) to close; " + live.Count(p => !Native.IsAlive(p)) + " process(es) exited gracefully.");
                }
            }

            int killed = 0;
            foreach (int pid in live)
            {
                if (!Native.IsAlive(pid)) continue;
                try { using (var p = Process.GetProcessById(pid)) { p.Kill(); killed++; } }
                catch (Exception ex) { if (Native.IsAlive(pid)) log.AppendLine("Kill FAILED for PID " + pid + ": " + ex.Message + (ex is System.ComponentModel.Win32Exception ? " (try running MemWatch as admin)" : "")); }
            }
            var kw = Stopwatch.StartNew();
            while (kw.ElapsedMilliseconds < Cfg.KillWaitMs && live.Any(Native.IsAlive)) Thread.Sleep(200);
            int alive = live.Count(Native.IsAlive);
            if (killed > 0) log.AppendLine("Force-killed " + killed + " process(es).");
            if (alive > 0) log.AppendLine(alive + " process(es) still running.");
            else log.AppendLine("All targeted processes are gone.");

            if (exe != null)
            {
                if (alive > 0) log.AppendLine("Relaunch skipped because some processes are still running.");
                else
                {
                    try
                    {
                        var psi = new ProcessStartInfo(exe, args ?? "") { UseShellExecute = true, WorkingDirectory = System.IO.Path.GetDirectoryName(exe) };
                        using (Process.Start(psi)) { }
                        log.AppendLine("Relaunched: \"" + exe + "\" " + args);
                    }
                    catch (Exception ex) { log.AppendLine("Relaunch FAILED: " + ex.Message + " - start it manually."); }
                }
            }
            return log.ToString().Trim();
        }

        // Runs on a worker thread. Windows usually restarts the shell itself; only start it if it did not.
        static string RestartExplorer(List<InstanceInfo> targets)
        {
            string r = EndAndRelaunch(targets, false, null, null);
            var old = new HashSet<int>(targets.Select(t => t.Pid));
            var w = Stopwatch.StartNew();
            while (w.ElapsedMilliseconds < 4000)
            {
                Thread.Sleep(500);
                Process[] ps = Process.GetProcessesByName("explorer");
                bool back = ps.Any(p => !old.Contains(p.Id));
                foreach (Process p in ps) p.Dispose();
                if (back) return r + "\nWindows restarted explorer.exe by itself.";
            }
            try
            {
                using (Process.Start(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))) { }
                return r + "\nStarted explorer.exe.";
            }
            catch (Exception ex) { return r + "\nStarting explorer.exe FAILED: " + ex.Message + " (Ctrl+Shift+Esc > Run new task > explorer)"; }
        }

        void OpenLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) { Refused("The file location is not known (path not readable - run MemWatch as admin)."); return; }
            try { using (Process.Start("explorer.exe", "/select,\"" + path + "\"")) { } }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "MemWatch", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        void CopyText(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            text = Ascii(text).Replace("\r\n", "\n").Replace("\n", "\r\n");
            // UI thread is STA. SetDataObject retries itself; the outer loop covers a clipboard held by another app.
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    Clipboard.SetDataObject(text, true, 5, 100);
                    lblStatus.Text = "Copied to clipboard (" + text.Split('\n').Length + " lines) - paste it anywhere.";
                    return;
                }
                catch (Exception ex)
                {
                    if (attempt == 2) { lblStatus.Text = "Copy failed (clipboard busy?): " + ex.Message; return; }
                    Thread.Sleep(150);
                }
            }
        }

        string InstanceLine(InstanceInfo i)
        {
            string cl;
            cmdLines.TryGetValue(i.Pid, out cl);
            return string.Join("\t", new[] { i.Pid.ToString(), i.Name, Fmt.MB(i.WS), Fmt.MB(i.Priv), i.Handles.ToString(), i.Threads.ToString(),
                Fmt.SignedSize(i.DWinPriv), Fmt.SignedK(i.DWinHandles), Fmt.Time(i.Start), i.Reason, cl ?? "" });
        }

        string GroupDetails(GroupInfo g)
        {
            if (g == null) return null;
            var sb = new StringBuilder();
            sb.AppendLine(SnapshotHeader());
            sb.AppendLine("Program:        " + g.Friendly + " (" + g.Name + ")");
            sb.AppendLine("Path:           " + (g.Path ?? "(not readable)"));
            sb.AppendLine("Instances:      " + g.Instances.Count);
            sb.AppendLine("Working set:    " + Fmt.Size(g.WS));
            sb.AppendLine("Private bytes:  " + Fmt.Size(g.Priv) + "  (" + Fmt.SignedSize(g.DWinPriv) + " over " + g.WinSpanMin.ToString("0.0") + " min, " + Fmt.SignedSize(g.DStartPriv) + " since start)");
            sb.AppendLine("Handles:        " + g.Handles.ToString("N0") + "  (" + Fmt.SignedK(g.DWinHandles) + " over " + g.WinSpanMin.ToString("0.0") + " min, " + Fmt.SignedK(g.DStartHandles) + " since start)");
            sb.AppendLine("Threads:        " + g.Threads.ToString("N0"));
            sb.AppendLine("Oldest start:   " + Fmt.Time(g.OldestStart) + "  (up " + Fmt.Uptime(g.OldestStart, DateTime.Now) + ")");
            sb.AppendLine("Reason:         " + (g.Reason.Length > 0 ? g.Reason : "-"));
            sb.AppendLine();
            sb.AppendLine("PID\tName\tWS MB\tPriv MB\tHandles\tThreads\tPriv 10m\tHnd 10m\tStarted\tReason\tCommand line");
            foreach (InstanceInfo i in g.Instances.OrderByDescending(x => x.Priv)) sb.AppendLine(InstanceLine(i));
            return sb.ToString();
        }

        string InstanceDetails(InstanceInfo i)
        {
            if (i == null) return null;
            var sb = new StringBuilder();
            sb.AppendLine(SnapshotHeader());
            sb.AppendLine("Path: " + (i.Path ?? "(not readable)"));
            sb.AppendLine("PID\tName\tWS MB\tPriv MB\tHandles\tThreads\tPriv 10m\tHnd 10m\tStarted\tReason\tCommand line");
            sb.AppendLine(InstanceLine(i));
            return sb.ToString();
        }
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            string selfTest = args.Select(a => a.ToLowerInvariant()).Where(a => a.StartsWith("--selftest-copy"))
                                  .Select(a => a.Contains("=") ? a.Substring(a.IndexOf('=') + 1) : "problems").FirstOrDefault();
            if (args.Any(a => a.Equals("--selftest-trend", StringComparison.OrdinalIgnoreCase)))
            {
                // Growth-rate math with simulated samples (no registry, no UI): report to clipboard, exit code 0 = all passed.
                bool tok;
                string treport = Trend.SelfTest(out tok);
                try { Clipboard.SetDataObject(treport, true, 5, 100); } catch { }
                Environment.ExitCode = tok ? 0 : 1;
                return;
            }
            if (args.Any(a => a.Equals("--selftest-alerts", StringComparison.OrdinalIgnoreCase)))
            {
                // Simulated alert scenarios (no registry, no UI): report to clipboard, exit code 0 = all passed.
                bool ok;
                string report = AlertPolicy.SelfTest(out ok);
                try { Clipboard.SetDataObject(report, true, 5, 100); } catch { }
                Environment.ExitCode = ok ? 0 : 1;
                return;
            }
            bool created;
            using (var mtx = new Mutex(true, "Local\\MemWatch_SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show("MemWatch is already running (check the tray).", "MemWatch", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                try { Native.SetProcessDPIAware(); } catch { }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += (s, e) =>
                    MessageBox.Show("Unexpected error (MemWatch keeps running):\n\n" + e.Exception.Message, "MemWatch", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Application.Run(new MainForm { SelfTest = selfTest });
            }
        }
    }
}
