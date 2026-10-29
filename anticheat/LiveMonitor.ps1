<#
.SYNOPSIS
    Community Anti-Cheat Live Monitor.

.DESCRIPTION
    Prints one line per event, with time, PID and path:

        FILE CREATED / FILE DELETED / FILE RENAMED
            Temp, Windows\Temp, Prefetch, Downloads, Desktop, Recent,
            Recycle Bin and Roblox logs.
        PROCESS OPENED / PROCESS CLOSED
            Every process, with its parent.
        DRIVER LOADED
            Kernel drivers loaded while the monitor runs.
        CAPTURE HIDDEN / CAPTURE SHOWN
            Windows hidden from screen capture with SetWindowDisplayAffinity
            (WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR).

    As administrator on 64-bit Windows the monitor reads the Windows
    Kernel-File and Kernel-Process event tracing (ETW) providers, which report
    the PID behind every file event and catch short-lived processes. Otherwise
    it falls back to folder watchers and WMI, and file events show no PID.

    Colour key:
        GREY    normal activity
        YELLOW  flagged for staff review
        RED     hidden window, or flagged / unsigned driver

.EXAMPLE
    iex (iwr "https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/LiveMonitor.ps1" -UseBasicParsing).Content
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\LiveMonitor.ps1
#>
[CmdletBinding()]
param(
    # Do not try to relaunch as administrator (file events will have no PID).
    [switch]$NoElevate
)

# =============================================================================
#  Configuration
# =============================================================================
$Config = @{
    # Where this script is hosted. Used to relaunch as administrator when it
    # was started with iex (there is no file to relaunch).
    ScriptUrl = 'https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/LiveMonitor.ps1'

    # Watched folders (environment variables are expanded).
    Folders = @(
        @{ Path = '%TEMP%';                              Recurse = $true },
        @{ Path = '%SystemRoot%\Temp';                   Recurse = $true },
        @{ Path = '%SystemRoot%\Prefetch';               Recurse = $false },
        @{ Path = '%USERPROFILE%\Downloads';             Recurse = $true },
        @{ Path = '%USERPROFILE%\Desktop';               Recurse = $true },
        @{ Path = '%USERPROFILE%\OneDrive\Desktop';      Recurse = $true },
        @{ Path = '%APPDATA%\Microsoft\Windows\Recent';  Recurse = $false },
        @{ Path = '%SystemDrive%\$Recycle.Bin';          Recurse = $true },
        @{ Path = '%LOCALAPPDATA%\Roblox\logs';          Recurse = $true }
    )

    # File events in these folders are always YELLOW (regex on the path).
    FlaggedFolderPattern = '\\Windows\\Prefetch\\|\\\$Recycle\.Bin\\|\\Roblox\\logs\\'

    # File events with these extensions are YELLOW.
    FlaggedExtensions = @('.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.lua', '.luau', '.ahk')

    # Process names (no .exe) shown in YELLOW.
    FlaggedNames = @(
        'synapse', 'synapsex', 'synapse x', 'krnl', 'krnlss', 'fluxus', 'scriptware', 'script-ware',
        'electron', 'oxygenu', 'oxygen u', 'jjsploit', 'comet', 'trigon', 'evon', 'valyse', 'solara',
        'wave', 'celery', 'xeno', 'awp', 'seliware', 'nezur', 'swift', 'sirhurt', 'calamari', 'sentinel',
        'protosmasher', 'zenith', 'volcano', 'velocity',
        'cheatengine', 'cheatengine-x86_64', 'cheatengine-x86_64-sse4-avx2', 'cheatengine-i386',
        'processhacker', 'systeminformer', 'x64dbg', 'x32dbg', 'x96dbg', 'ollydbg', 'ida', 'ida64',
        'dnspy', 'reclass', 'reclass.net', 'reclassex', 'extremeinjector', 'extreme injector v3',
        'xenos', 'xenos64', 'ghinjector', 'gh injector', 'kdmapper', 'ksdumper', 'scylla', 'scylla_x64',
        'httpdebuggerui', 'httpdebuggersvc',
        'autohotkey', 'autohotkey64', 'autohotkeyu64', 'autohotkeyu32', 'autohotkeyux',
        'autoclicker', 'opautoclicker', 'gs auto clicker', 'tinytask', 'macrorecorder'
    )

    # Driver names (no .sys) shown in RED.
    FlaggedDrivers = @('dbk64', 'dbk32', 'capcom', 'kprocesshacker', 'kprocesshacker2', 'kprocesshacker3', 'ksysteminformer', 'iqvw64e', 'gdrv')

    # How often windows are checked for capture exclusion, in seconds.
    CaptureScanSeconds = 2
}

# =============================================================================
#  Native helpers
# =============================================================================
$script:NativeSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AntiCheatMonitor
{
    public class CaptureHiddenWindow
    {
        public long Handle;
        public uint ProcessId;
        public uint Affinity;
        public string Title;
    }

    // Top-level windows whose display affinity hides them from screen capture.
    public static class DisplayAffinity
    {
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint affinity);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);

        public static List<CaptureHiddenWindow> Scan()
        {
            List<CaptureHiddenWindow> found = new List<CaptureHiddenWindow>();
            EnumWindows(delegate (IntPtr hWnd, IntPtr lParam)
            {
                uint affinity;
                if (GetWindowDisplayAffinity(hWnd, out affinity) && affinity != 0)
                {
                    uint processId;
                    GetWindowThreadProcessId(hWnd, out processId);
                    StringBuilder title = new StringBuilder(256);
                    GetWindowText(hWnd, title, title.Capacity);
                    CaptureHiddenWindow window = new CaptureHiddenWindow();
                    window.Handle = hWnd.ToInt64();
                    window.ProcessId = processId;
                    window.Affinity = affinity;
                    window.Title = title.ToString();
                    found.Add(window);
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }
    }

    public class MonitorEvent
    {
        public DateTime Time;
        public string Kind;
        public int ProcessId;
        public int ParentId;
        public string Path;
    }

    // Real-time ETW session over Microsoft-Windows-Kernel-File and
    // Microsoft-Windows-Kernel-Process. 64-bit only (structure offsets).
    public static class EtwMonitor
    {
        public const string SessionName = "AntiCheatLiveMonitor";
        public static readonly ConcurrentQueue<MonitorEvent> Events = new ConcurrentQueue<MonitorEvent>();
        public static long Dropped;

        private static readonly Guid KernelFile    = new Guid("EDD08927-9CC4-4E65-B970-C2560FB5C289");
        private static readonly Guid KernelProcess = new Guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

        // Kernel-File keywords: DELETE_PATH 0x400, RENAME_SETLINK_PATH 0x800, CREATE_NEW_FILE 0x1000.
        private const ulong FileKeywords    = 0x400 | 0x800 | 0x1000;
        // Kernel-Process keywords: PROCESS 0x10, IMAGE 0x40.
        private const ulong ProcessKeywords = 0x10 | 0x40;

        private const uint WNODE_FLAG_TRACED_GUID          = 0x00020000;
        private const uint EVENT_TRACE_REAL_TIME_MODE      = 0x00000100;
        private const uint EVENT_TRACE_CONTROL_STOP        = 1;
        private const uint EVENT_CONTROL_CODE_ENABLE       = 1;
        private const uint PROCESS_TRACE_MODE_REAL_TIME    = 0x00000100;
        private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        private const uint ERROR_ALREADY_EXISTS            = 183;
        private const int  PropertiesSize                  = 120;
        private const int  PropertiesBufferSize            = PropertiesSize + 1024;
        private const int  LogfileSize                     = 448;
        private const int  MaxQueued                       = 20000;

        [StructLayout(LayoutKind.Sequential)]
        private struct PropertyDataDescriptor
        {
            public ulong PropertyName;
            public uint ArrayIndex;
            public uint Reserved;
        }

        private delegate void EventRecordCallback(IntPtr eventRecord);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint ControlTraceW(ulong sessionHandle, string sessionName, IntPtr properties, uint controlCode);

        [DllImport("advapi32.dll")]
        private static extern uint EnableTraceEx2(ulong sessionHandle, ref Guid providerId, uint controlCode, byte level,
            ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

        [DllImport("advapi32.dll")]
        private static extern ulong OpenTraceW(IntPtr logfile);

        [DllImport("advapi32.dll")]
        private static extern uint ProcessTrace(ulong[] handles, uint handleCount, IntPtr startTime, IntPtr endTime);

        [DllImport("advapi32.dll")]
        private static extern uint CloseTrace(ulong traceHandle);

        [DllImport("tdh.dll")]
        private static extern uint TdhGetPropertySize(IntPtr eventRecord, uint contextCount, IntPtr context,
            uint descriptorCount, ref PropertyDataDescriptor descriptor, out uint size);

        [DllImport("tdh.dll")]
        private static extern uint TdhGetProperty(IntPtr eventRecord, uint contextCount, IntPtr context,
            uint descriptorCount, ref PropertyDataDescriptor descriptor, uint bufferSize, IntPtr buffer);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, int max);

        private static ulong sessionHandle;
        private static ulong traceHandle;
        private static IntPtr logfile = IntPtr.Zero;
        private static IntPtr loggerName = IntPtr.Zero;
        private static EventRecordCallback callback;
        private static Thread worker;
        private static int ownProcessId;
        private static string[] watchPrefixes = new string[0];
        private static bool[] watchRecurse = new bool[0];
        private static readonly List<KeyValuePair<string, string>> deviceMap = new List<KeyValuePair<string, string>>();
        private static readonly Dictionary<string, IntPtr> propertyNames = new Dictionary<string, IntPtr>();

        public static bool Start(string[] folders, bool[] recurse, int processId, out string error)
        {
            error = null;
            if (IntPtr.Size != 8) { error = "64-bit PowerShell required"; return false; }

            ownProcessId = processId;
            watchPrefixes = new string[folders.Length];
            for (int i = 0; i < folders.Length; i++) { watchPrefixes[i] = folders[i].TrimEnd('\\').ToLowerInvariant() + "\\"; }
            watchRecurse = recurse;
            BuildDeviceMap();
            foreach (string name in new[] { "FileName", "FilePath", "ProcessID", "ParentProcessID", "ImageName" })
            {
                if (!propertyNames.ContainsKey(name)) { propertyNames[name] = Marshal.StringToHGlobalUni(name); }
            }

            StopSession();
            IntPtr properties = NewProperties();
            try
            {
                uint status = StartTraceW(out sessionHandle, SessionName, properties);
                if (status == ERROR_ALREADY_EXISTS)
                {
                    StopSession();
                    status = StartTraceW(out sessionHandle, SessionName, properties);
                }
                if (status != 0) { error = "StartTrace failed (" + status + ")"; return false; }
            }
            finally { Marshal.FreeHGlobal(properties); }

            Guid file = KernelFile;
            Guid process = KernelProcess;
            uint fileStatus = EnableTraceEx2(sessionHandle, ref file, EVENT_CONTROL_CODE_ENABLE, 5, FileKeywords, 0, 0, IntPtr.Zero);
            uint processStatus = EnableTraceEx2(sessionHandle, ref process, EVENT_CONTROL_CODE_ENABLE, 5, ProcessKeywords, 0, 0, IntPtr.Zero);
            if (fileStatus != 0 || processStatus != 0)
            {
                error = "EnableTraceEx2 failed (" + fileStatus + "/" + processStatus + ")";
                StopSession();
                return false;
            }

            // EVENT_TRACE_LOGFILEW (x64): LoggerName @8, ProcessTraceMode @28, EventRecordCallback @424.
            callback = OnEvent;
            loggerName = Marshal.StringToHGlobalUni(SessionName);
            logfile = Marshal.AllocHGlobal(LogfileSize);
            for (int i = 0; i < LogfileSize; i++) { Marshal.WriteByte(logfile, i, 0); }
            Marshal.WriteIntPtr(logfile, 8, loggerName);
            Marshal.WriteInt32(logfile, 28, unchecked((int)(PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD)));
            Marshal.WriteIntPtr(logfile, 424, Marshal.GetFunctionPointerForDelegate(callback));

            traceHandle = OpenTraceW(logfile);
            if (traceHandle == ulong.MaxValue)
            {
                error = "OpenTrace failed (" + Marshal.GetLastWin32Error() + ")";
                StopSession();
                return false;
            }

            worker = new Thread(delegate () { ProcessTrace(new ulong[] { traceHandle }, 1, IntPtr.Zero, IntPtr.Zero); });
            worker.IsBackground = true;
            worker.Start();
            return true;
        }

        public static void Stop()
        {
            StopSession();
            if (traceHandle != 0 && traceHandle != ulong.MaxValue) { CloseTrace(traceHandle); }
            traceHandle = 0;
            if (worker != null) { worker.Join(3000); worker = null; }
            if (logfile != IntPtr.Zero) { Marshal.FreeHGlobal(logfile); logfile = IntPtr.Zero; }
            if (loggerName != IntPtr.Zero) { Marshal.FreeHGlobal(loggerName); loggerName = IntPtr.Zero; }
        }

        // Stops the named session, including one left behind by an earlier run.
        private static void StopSession()
        {
            IntPtr properties = NewProperties();
            try { ControlTraceW(0, SessionName, properties, EVENT_TRACE_CONTROL_STOP); }
            finally { Marshal.FreeHGlobal(properties); }
        }

        // EVENT_TRACE_PROPERTIES (x64) followed by room for the session name.
        private static IntPtr NewProperties()
        {
            IntPtr p = Marshal.AllocHGlobal(PropertiesBufferSize);
            for (int i = 0; i < PropertiesBufferSize; i++) { Marshal.WriteByte(p, i, 0); }
            Marshal.WriteInt32(p, 0, PropertiesBufferSize);                        // Wnode.BufferSize
            Marshal.WriteInt32(p, 40, 1);                                          // Wnode.ClientContext (QPC)
            Marshal.WriteInt32(p, 44, unchecked((int)WNODE_FLAG_TRACED_GUID));     // Wnode.Flags
            Marshal.WriteInt32(p, 48, 256);                                        // BufferSize (KB)
            Marshal.WriteInt32(p, 52, 8);                                          // MinimumBuffers
            Marshal.WriteInt32(p, 56, 64);                                         // MaximumBuffers
            Marshal.WriteInt32(p, 64, unchecked((int)EVENT_TRACE_REAL_TIME_MODE)); // LogFileMode
            Marshal.WriteInt32(p, 68, 1);                                          // FlushTimer (s)
            Marshal.WriteInt32(p, 116, PropertiesSize);                            // LoggerNameOffset
            return p;
        }

        private static void BuildDeviceMap()
        {
            deviceMap.Clear();
            foreach (string drive in Environment.GetLogicalDrives())
            {
                string letter = drive.Substring(0, 2);
                StringBuilder target = new StringBuilder(1024);
                if (QueryDosDeviceW(letter, target, target.Capacity) != 0)
                {
                    deviceMap.Add(new KeyValuePair<string, string>(target.ToString() + "\\", letter + "\\"));
                }
            }
        }

        private static string ToDosPath(string path)
        {
            if (string.IsNullOrEmpty(path)) { return path; }
            if (path.StartsWith("\\??\\")) { path = path.Substring(4); }
            foreach (KeyValuePair<string, string> map in deviceMap)
            {
                if (path.StartsWith(map.Key, StringComparison.OrdinalIgnoreCase)) { return map.Value + path.Substring(map.Key.Length); }
            }
            return path;
        }

        private static bool IsWatched(string path)
        {
            string lower = path.ToLowerInvariant();
            for (int i = 0; i < watchPrefixes.Length; i++)
            {
                if (!lower.StartsWith(watchPrefixes[i])) { continue; }
                if (watchRecurse[i] || lower.IndexOf('\\', watchPrefixes[i].Length) < 0) { return true; }
            }
            return false;
        }

        private static string GetString(IntPtr record, string name)
        {
            PropertyDataDescriptor descriptor = new PropertyDataDescriptor();
            descriptor.PropertyName = (ulong)propertyNames[name].ToInt64();
            descriptor.ArrayIndex = uint.MaxValue;
            uint size;
            if (TdhGetPropertySize(record, 0, IntPtr.Zero, 1, ref descriptor, out size) != 0 || size == 0) { return null; }
            IntPtr buffer = Marshal.AllocHGlobal((int)size + 2);
            try
            {
                if (TdhGetProperty(record, 0, IntPtr.Zero, 1, ref descriptor, size, buffer) != 0) { return null; }
                return Marshal.PtrToStringUni(buffer, (int)size / 2).TrimEnd('\0');
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static int GetInt32(IntPtr record, string name)
        {
            PropertyDataDescriptor descriptor = new PropertyDataDescriptor();
            descriptor.PropertyName = (ulong)propertyNames[name].ToInt64();
            descriptor.ArrayIndex = uint.MaxValue;
            IntPtr buffer = Marshal.AllocHGlobal(8);
            try
            {
                if (TdhGetProperty(record, 0, IntPtr.Zero, 1, ref descriptor, 4, buffer) != 0) { return -1; }
                return Marshal.ReadInt32(buffer);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void Add(DateTime time, string kind, int processId, int parentId, string path)
        {
            if (Events.Count >= MaxQueued) { Interlocked.Increment(ref Dropped); return; }
            MonitorEvent e = new MonitorEvent();
            e.Time = time;
            e.Kind = kind;
            e.ProcessId = processId;
            e.ParentId = parentId;
            e.Path = path;
            Events.Enqueue(e);
        }

        // EVENT_RECORD (x64): EventHeader.ProcessId @12, TimeStamp @16, ProviderId @24, EventDescriptor.Id @40.
        private static void OnEvent(IntPtr record)
        {
            try
            {
                byte[] guidBytes = new byte[16];
                Marshal.Copy(IntPtr.Add(record, 24), guidBytes, 0, 16);
                Guid provider = new Guid(guidBytes);
                int id = Marshal.ReadInt16(record, 40) & 0xFFFF;
                int headerPid = Marshal.ReadInt32(record, 12);
                DateTime time;
                try { time = DateTime.FromFileTime(Marshal.ReadInt64(record, 16)); } catch { time = DateTime.Now; }
                if (time.Year < 2000 || time > DateTime.Now.AddMinutes(5)) { time = DateTime.Now; }

                if (provider == KernelFile)
                {
                    // 30 CreateNewFile, 26 DeletePath, 27 RenamePath.
                    string kind = id == 30 ? "FILE CREATED" : id == 26 ? "FILE DELETED" : id == 27 ? "FILE RENAMED" : null;
                    if (kind == null || headerPid == ownProcessId) { return; }
                    string path = GetString(record, "FileName") ?? GetString(record, "FilePath");
                    path = ToDosPath(path);
                    if (string.IsNullOrEmpty(path) || !IsWatched(path)) { return; }
                    Add(time, kind, headerPid, -1, path);
                }
                else if (provider == KernelProcess)
                {
                    if (id == 1)
                    {
                        Add(time, "PROCESS OPENED", GetInt32(record, "ProcessID"), GetInt32(record, "ParentProcessID"), ToDosPath(GetString(record, "ImageName")));
                    }
                    else if (id == 2)
                    {
                        Add(time, "PROCESS CLOSED", GetInt32(record, "ProcessID"), -1, ToDosPath(GetString(record, "ImageName")));
                    }
                    else if (id == 5 && headerPid <= 4)
                    {
                        // Image loads in the System process are kernel drivers.
                        string image = ToDosPath(GetString(record, "ImageName"));
                        if (image != null && image.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                        {
                            Add(time, "DRIVER LOADED", 4, -1, image);
                        }
                    }
                }
            }
            catch { }
        }
    }
}
'@

# =============================================================================
#  Helpers
# =============================================================================
$script:ProcPaths  = @{}
$script:HiddenSeen = @{}
$script:SigCache   = @{}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SignatureStatus([string]$Path) {
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    # Store apps are package-signed, which Get-AuthenticodeSignature reports as NotSigned.
    if ($Path -match '\\Program Files\\WindowsApps\\') { return $null }
    $key = $Path.ToLowerInvariant()
    if (-not $script:SigCache.ContainsKey($key)) {
        $status = 'Unreadable'
        try { $status = "$((Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status)" } catch { }
        $script:SigCache[$key] = $status
    }
    $script:SigCache[$key]
}

function Test-FlaggedName([string]$Path) {
    if (-not $Path) { return $false }
    $name = [IO.Path]::GetFileNameWithoutExtension(($Path -split '\\')[-1]).ToLowerInvariant()
    $Config.FlaggedNames -contains $name
}

function Resolve-ProcessPath([int]$ProcessId) {
    if ($script:ProcPaths.ContainsKey($ProcessId)) { return $script:ProcPaths[$ProcessId] }
    try {
        $path = (Get-Process -Id $ProcessId -ErrorAction Stop).Path
        if ($path) { return $path }
    }
    catch { }
    try {
        $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
        if ($cim) { if ($cim.ExecutablePath) { return $cim.ExecutablePath } else { return $cim.Name } }
    }
    catch { }
    'unknown'
}

function Get-ProcessLabel([int]$ProcessId) {
    if ($ProcessId -le 0) { return '' }
    $path = Resolve-ProcessPath $ProcessId
    "$(($path -split '\\')[-1]) ($ProcessId)"
}

function Write-MonitorLine {
    param([datetime]$Time, [string]$Kind, $ProcessId, [string]$Path, [string]$Extra = '', [string]$Colour = 'Gray')
    $idText = if ($null -ne $ProcessId -and "$ProcessId" -ne '' -and [int]$ProcessId -ge 0) { "$ProcessId" } else { '-' }
    $line   = '{0:HH:mm:ss.fff}  {1,-14} {2,-7} {3}' -f $Time, $Kind, $idText, $Path
    if ($Extra) { $line += "  [$Extra]" }
    Write-Host $line -ForegroundColor $Colour
}

function Show-ProcessOpened([datetime]$Time, [int]$ProcessId, [int]$ParentId, [string]$Path) {
    if (-not $Path) { $Path = Resolve-ProcessPath $ProcessId }
    $script:ProcPaths[$ProcessId] = $Path

    $extra = @()
    $flagged = $false
    if (Test-FlaggedName $Path) { $flagged = $true; $extra += 'flagged name' }
    $sig = Get-SignatureStatus $Path
    if ($sig -and $sig -ne 'Valid') { $flagged = $true; $extra += $sig }
    if ($ParentId -gt 0) { $extra += "parent $(Get-ProcessLabel $ParentId)" }
    $colour = if ($flagged) { 'Yellow' } else { 'Gray' }
    Write-MonitorLine $Time 'PROCESS OPENED' $ProcessId $Path ($extra -join ', ') $colour
}

function Show-ProcessClosed([datetime]$Time, [int]$ProcessId, [string]$Path) {
    if ($script:ProcPaths.ContainsKey($ProcessId)) {
        $Path = $script:ProcPaths[$ProcessId]
        $script:ProcPaths.Remove($ProcessId)
    }
    elseif (-not $Path) { $Path = 'unknown' }
    $colour = if (Test-FlaggedName $Path) { 'Yellow' } else { 'Gray' }
    Write-MonitorLine $Time 'PROCESS CLOSED' $ProcessId $Path '' $colour
}

function Show-FileEvent([datetime]$Time, [string]$Kind, $ProcessId, [string]$Path, [string]$OldPath = '') {
    $flagged = $Path -match $Config.FlaggedFolderPattern -or
               $Config.FlaggedExtensions -contains [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($OldPath -and -not $flagged) {
        $flagged = $Config.FlaggedExtensions -contains [IO.Path]::GetExtension($OldPath).ToLowerInvariant()
    }
    $shown = if ($OldPath) { "$OldPath -> $Path" } else { $Path }
    $extra = if ($null -ne $ProcessId -and [int]$ProcessId -gt 0) { Get-ProcessLabel ([int]$ProcessId) } else { '' }
    $colour = if ($flagged) { 'Yellow' } else { 'Gray' }
    Write-MonitorLine $Time $Kind $ProcessId $shown $extra $colour
}

function Show-DriverLoaded([datetime]$Time, [string]$Path) {
    $name = [IO.Path]::GetFileNameWithoutExtension($Path).ToLowerInvariant()
    $extra = @()
    $red = $false
    if ($Config.FlaggedDrivers -contains $name) { $red = $true; $extra += 'flagged driver' }
    $sig = Get-SignatureStatus $Path
    if ($sig -and $sig -ne 'Valid') { $red = $true; $extra += $sig }
    $colour = if ($red) { 'Red' } else { 'Yellow' }
    Write-MonitorLine $Time 'DRIVER LOADED' 4 $Path ($extra -join ', ') $colour
}

function Get-AffinityName([uint32]$Affinity) {
    switch ($Affinity) {
        0x11    { 'ExcludeFromCapture' }
        0x1     { 'Monitor' }
        default { '0x{0:X}' -f $Affinity }
    }
}

function Update-CaptureHidden {
    $now     = Get-Date
    $current = @{}
    foreach ($w in @([AntiCheatMonitor.DisplayAffinity]::Scan())) {
        $key = "$($w.Handle)"
        $current[$key] = $w
        $previous = $script:HiddenSeen[$key]
        if (-not $previous -or $previous.Affinity -ne $w.Affinity) {
            Write-MonitorLine $now 'CAPTURE HIDDEN' $w.ProcessId (Resolve-ProcessPath ([int]$w.ProcessId)) "$(Get-AffinityName $w.Affinity): '$($w.Title)'" Red
        }
    }
    foreach ($key in @($script:HiddenSeen.Keys)) {
        if (-not $current.ContainsKey($key)) {
            $old = $script:HiddenSeen[$key]
            Write-MonitorLine $now 'CAPTURE SHOWN' $old.ProcessId (Resolve-ProcessPath ([int]$old.ProcessId)) "closed or no longer hidden: '$($old.Title)'" Yellow
        }
    }
    $script:HiddenSeen = $current
}

function Get-WatchedFolders {
    $seen = @{}
    foreach ($folder in $Config.Folders) {
        $path = [Environment]::ExpandEnvironmentVariables($folder.Path).TrimEnd('\')
        if ($seen.ContainsKey($path) -or -not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        $seen[$path] = $true
        [pscustomobject]@{ Path = $path; Recurse = [bool]$folder.Recurse }
    }
}

# =============================================================================
#  Monitor modes
# =============================================================================
# ETW: PIDs for file events, short-lived processes and driver loads.
function Start-EtwMonitor($Folders) {
    $paths   = [string[]]@($Folders | ForEach-Object { $_.Path })
    $recurse = [bool[]]@($Folders | ForEach-Object { $_.Recurse })
    $err = $null
    if (-not [AntiCheatMonitor.EtwMonitor]::Start($paths, $recurse, $PID, [ref]$err)) {
        Write-Host "Event tracing unavailable ($err) - file events have no PID" -ForegroundColor Yellow
        return $false
    }

    $nextScan = Get-Date
    $dropped  = 0
    try {
        while ($true) {
            $e = $null
            while ([AntiCheatMonitor.EtwMonitor]::Events.TryDequeue([ref]$e)) {
                switch ($e.Kind) {
                    'PROCESS OPENED' { Show-ProcessOpened $e.Time $e.ProcessId $e.ParentId $e.Path }
                    'PROCESS CLOSED' { Show-ProcessClosed $e.Time $e.ProcessId $e.Path }
                    'DRIVER LOADED'  { Show-DriverLoaded $e.Time $e.Path }
                    default          { Show-FileEvent $e.Time $e.Kind $e.ProcessId $e.Path }
                }
            }
            $nowDropped = [AntiCheatMonitor.EtwMonitor]::Dropped
            if ($nowDropped -gt $dropped) {
                Write-MonitorLine (Get-Date) 'EVENTS DROPPED' $null "$($nowDropped - $dropped) events (too much activity)" '' Yellow
                $dropped = $nowDropped
            }
            if ((Get-Date) -ge $nextScan) {
                Update-CaptureHidden
                $nextScan = (Get-Date).AddSeconds($Config.CaptureScanSeconds)
            }
            Start-Sleep -Milliseconds 200
        }
    }
    finally {
        [AntiCheatMonitor.EtwMonitor]::Stop()
    }
    $true
}

# Fallback: folder watchers (no PID for file events) and WMI process events.
function Start-FallbackMonitor($Folders) {
    $watchers = New-Object System.Collections.Generic.List[object]
    $cleanup = {
        Get-EventSubscriber -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like 'ACM.*' } | Unregister-Event -ErrorAction SilentlyContinue
        Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like 'ACM.*' } | Remove-Event -ErrorAction SilentlyContinue
    }
    & $cleanup
    try {
        # Trace classes catch short-lived processes but need administrator rights.
        try {
            Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier 'ACM.ProcStart' -ErrorAction Stop | Out-Null
            Register-CimIndicationEvent -ClassName Win32_ProcessStopTrace  -SourceIdentifier 'ACM.ProcStop'  -ErrorAction Stop | Out-Null
        }
        catch {
            & $cleanup
            Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier 'ACM.ProcStart' | Out-Null
            Register-CimIndicationEvent -Query "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier 'ACM.ProcStop'  | Out-Null
        }

        $i = 0
        foreach ($folder in $Folders) {
            try {
                $watcher = New-Object IO.FileSystemWatcher
                $watcher.Path                  = $folder.Path
                $watcher.IncludeSubdirectories = $folder.Recurse
                $watcher.NotifyFilter          = [IO.NotifyFilters]'FileName, DirectoryName'
                $watcher.InternalBufferSize    = 65536
                $i++
                foreach ($eventName in 'Created', 'Deleted', 'Renamed') {
                    Register-ObjectEvent -InputObject $watcher -EventName $eventName -SourceIdentifier "ACM.File.$i.$eventName" | Out-Null
                }
                $watcher.EnableRaisingEvents = $true
                $watchers.Add($watcher)
            }
            catch { }
        }

        $nextScan = Get-Date
        while ($true) {
            $evt = Wait-Event -Timeout 1
            if ($evt) {
                Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction SilentlyContinue
                if ($evt.SourceIdentifier -like 'ACM.Proc*') {
                    $data   = $evt.SourceEventArgs.NewEvent
                    $target = if ($data.TargetInstance) { $data.TargetInstance } else { $data }
                    $procId = [int]$target.ProcessId
                    $time   = $evt.TimeGenerated
                    if ($evt.SourceIdentifier -eq 'ACM.ProcStart') {
                        $path   = if ($target.ExecutablePath) { "$($target.ExecutablePath)" } else { '' }
                        $parent = if ($null -ne $target.ParentProcessId) { [int]$target.ParentProcessId } else { -1 }
                        Show-ProcessOpened $time $procId $parent $path
                    }
                    else {
                        Show-ProcessClosed $time $procId "$($target.ProcessName)$($target.Name)"
                    }
                }
                elseif ($evt.SourceIdentifier -like 'ACM.File.*') {
                    $a = $evt.SourceEventArgs
                    $kind = 'FILE ' + "$($a.ChangeType)".ToUpperInvariant()
                    $old  = if ("$($a.ChangeType)" -eq 'Renamed') { $a.OldFullPath } else { '' }
                    Show-FileEvent $evt.TimeGenerated $kind $null $a.FullPath $old
                }
            }
            if ((Get-Date) -ge $nextScan) {
                Update-CaptureHidden
                $nextScan = (Get-Date).AddSeconds($Config.CaptureScanSeconds)
            }
        }
    }
    finally {
        & $cleanup
        foreach ($w in $watchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
    }
}

# =============================================================================
#  Main
# =============================================================================
function Invoke-LiveMonitor {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Write-Host '[FAIL] Operating system is Windows' -ForegroundColor Red
        return
    }

    if (-not $NoElevate -and -not (Test-IsAdmin)) {
        if ($PSCommandPath) {
            $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        }
        else {
            $command = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; iex (iwr '$($Config.ScriptUrl)' -UseBasicParsing).Content"
            $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "`"$command`"")
        }
        try {
            Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            return
        }
        catch { }
    }

    try { $Host.UI.RawUI.WindowTitle = 'Anti-Cheat Live Monitor' } catch { }
    Clear-Host

    # Compiled before monitoring starts so the compiler's temp files are not reported.
    if (-not ('AntiCheatMonitor.EtwMonitor' -as [type])) {
        try { Add-Type -TypeDefinition $script:NativeSource -ErrorAction Stop }
        catch {
            Write-Host "[FAIL] Live monitor could not start: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        $script:ProcPaths[[int]$p.ProcessId] = if ($p.ExecutablePath) { $p.ExecutablePath } else { $p.Name }
    }
    $folders = @(Get-WatchedFolders)

    $useEtw = Test-IsAdmin
    if ($useEtw) {
        Write-Host 'Live monitor' -ForegroundColor Cyan
    }
    else {
        Write-Host 'Live monitor (limited: not administrator, file events have no PID)' -ForegroundColor Yellow
    }
    Write-Host ('{0,-12}  {1,-14} {2,-7} {3}' -f 'TIME', 'EVENT', 'PID', 'PATH') -ForegroundColor White

    if ($useEtw -and (Start-EtwMonitor $folders)) { return }
    Start-FallbackMonitor $folders
}

Invoke-LiveMonitor
