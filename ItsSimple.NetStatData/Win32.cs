using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace ItsSimple.NetStatData
{
    [SupportedOSPlatform("windows")]
    public static class Win32
    {
        public delegate bool EnumedWindow(IntPtr handleWindow, ArrayList handles);
        public delegate bool EnumDelegate(IntPtr hWnd, int lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumWindows(EnumedWindow lpEnumFunc, ArrayList lParam);

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint GetProcessImageFileName(IntPtr hProcess, [Out] StringBuilder lpImageFileName, [In][MarshalAs(UnmanagedType.U4)] int nSize);
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct WNDCLASSEX
        {
            [MarshalAs(UnmanagedType.U4)]
            public int cbSize;
            [MarshalAs(UnmanagedType.U4)]
            public int style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            public string lpszMenuName;
            public string lpszClassName;
            public IntPtr hIconSm;

            public static WNDCLASSEX Build()
            {
                return new WNDCLASSEX
                {
                    cbSize = Marshal.SizeOf(typeof(WNDCLASSEX))
                };
            }
        }

        // Following code was found at https://stackoverflow.com/a/577660/1025823
        // I've done some modifications to keep track of named states instead of just integers

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_TCPROW_OWNER_PID table;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tblClass,
            int reserved);

        public static MIB_TCPROW_OWNER_PID[] GetAllTcpConnections()
        {
            if (CachedProcesses == null)
            {
                CachedProcesses = new Hashtable();
            }
            else
            {
                CachedProcesses.Clear();
            }

            MIB_TCPROW_OWNER_PID[] tTable;
            int AF_INET = 2;    // IP_v4
            int buffSize = 0;

            // how much memory do we need?
            uint ret = GetExtendedTcpTable(IntPtr.Zero,
                ref buffSize,
                true,
                AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL,
                0);
            if (ret != 0 && ret != 122) // 122 insufficient buffer size
                throw new Exception("bad ret on check " + ret);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedTcpTable(buffTable,
                    ref buffSize,
                    true,
                    AF_INET,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (ret != 0)
                {
                    throw new Exception("bad ret " + ret);
                }


                // get the number of entries in the table
#pragma warning disable CS8605 // Unboxing a possibly null value.
                MIB_TCPTABLE_OWNER_PID tab =
                    (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(
                        buffTable,
                        typeof(MIB_TCPTABLE_OWNER_PID));

                IntPtr rowPtr = (IntPtr)((long)buffTable +
                    Marshal.SizeOf(tab.dwNumEntries));
                tTable = new MIB_TCPROW_OWNER_PID[tab.dwNumEntries];

                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal
                        .PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    tTable[i] = tcpRow;
                    // next entry
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));
                }
#pragma warning restore CS8605 // Unboxing a possibly null value.
            }
            finally
            {
                // Free the Memory
                Marshal.FreeHGlobal(buffTable);
            }
            return tTable;
        }

        public enum TCP_TABLE_CLASS : int
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        /// <summary>
        /// ConnectionState shows you in an easy way, what state the connection is in
        /// </summary>
        public enum ConnectionState : uint
        {
            Closed = 1,
            Listen = 2,
            SynSent = 3,
            SynReceieved = 4,
            Established = 5,
            FinWait1 = 6,
            FinWait2 = 7,
            CloseWait = 8,
            Closing = 9,
            LastAck = 10,
            TimeWait = 11,
            DeleteTCB = 12
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public ConnectionState state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;

            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { localPort2, localPort1 }, 0);
                }
            }

            public ushort RemotePort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { remotePort2, remotePort1 }, 0);
                }
            }

            public ProcessInfo GetProcessInfo()
            {
                if (CachedProcesses == null)
                {
                    CachedProcesses = new Hashtable();
                }

                if (CachedProcesses.ContainsKey(owningPid))
                {
#pragma warning disable CS8605 // Unboxing a possibly null value.
                    return (ProcessInfo)CachedProcesses[owningPid];
#pragma warning restore CS8605 // Unboxing a possibly null value.
                }

                static bool cb(IntPtr windowHandle, ArrayList windowHandles)
                {
                    windowHandles.Add(windowHandle);
                    return true;
                }

                string? processPath = null;

                var windows = new ArrayList();
                _ = EnumWindows(cb, windows);

                foreach (var window in windows)
                {
                    var sb = new StringBuilder(2000);
                    _ = GetWindowThreadProcessId((IntPtr)window, out uint processId);
                    if ((int)processId == owningPid)
                    {
                        var winHandle = OpenProcess(0x0400, false, (int)processId);
                        _ = GetProcessImageFileName(winHandle, sb, sb.Capacity);

                        processPath = sb.ToString().Trim();
                        CloseHandle(winHandle);
                        break;
                    }
                }

                IntPtr processHandle = IntPtr.Zero;
                WindowsIdentity? ident = null;

                try
                {
                    var pHandle = Process.GetProcessById(owningPid);

                    try
                    {
                        if (string.IsNullOrWhiteSpace(processPath))
                        {
                            processPath = pHandle.MainModule?.FileName ?? "Missing executable";
                        }
                    }
                    catch
                    {

                    }

                    if (OpenProcessToken(pHandle.Handle, 8, out processHandle))
                    {
                        ident = new WindowsIdentity(processHandle);
                    }
                }
                catch { }
                finally
                {
                    if (processHandle != IntPtr.Zero)
                    {
                        CloseHandle(processHandle);
                    }
                }

                var o = new ProcessInfo
                {
                    ProcessPath = processPath,
                    Owner = ident?.Name
                };

                ident?.Dispose();

                CachedProcesses[owningPid] = o;

                return o;
            }
        }

        public struct ProcessInfo
        {
            public string? ProcessPath;
            public string? Owner;
        }

        /// <summary>
        /// Normal Process IDs that you usually can ignore
        /// </summary>
        public static int[] SystemPIDs = new int[] { 0, 4, 8 };

        internal static Hashtable? CachedProcesses;
    }

}
