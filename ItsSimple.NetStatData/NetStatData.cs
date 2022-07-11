using System.Runtime.Versioning;
using static ItsSimple.NetStatData.Win32;

namespace ItsSimple.NetStatData
{
    [SupportedOSPlatform("windows")]
    public class NetStatData
    {
        /// <summary>
        /// Gets a unfiltered list of TCP connections through <c>GetExtendedTcpTable</c> from <c>iphlpapi.dll</c>
        /// </summary>
        /// <returns>Unfiltered list of TCP connections</returns>
        public static IEnumerable<MIB_TCPROW_OWNER_PID> GetTcpConnections()
        {
            return GetAllTcpConnections();
        }

        /// <summary>
        /// Gets a filtered list of TCP connections through <c>GetExtendedTcpTable</c> from <c>iphlpapi.dll</c>
        /// </summary>
        /// <returns>Filtered list of TCP connections</returns>
        public static IEnumerable<MIB_TCPROW_OWNER_PID> GetTcpConnections(Func<MIB_TCPROW_OWNER_PID, bool> predicate)
        {
            return GetAllTcpConnections().Where(predicate);
        }

        /// <summary>
        /// Gets a unfiltered list of TCP connections, with process information (executable path and owner)
        /// </summary>
        /// <returns>Unfiltered list of TCP connections, with process information</returns>
        public static IEnumerable<NetStatDataItem> GetTcpConnectionsWithProcessInformation()
        {
            return GetAllTcpConnections().Select(i => new NetStatDataItem(i));
        }

        /// <summary>
        /// Gets a filtered list of TCP connections, with process information (executable path and owner)
        /// </summary>
        /// <returns>Filtered list of TCP connections, with process information</returns>
        public static IEnumerable<NetStatDataItem> GetTcpConnectionsWithProcessInformation(Func<MIB_TCPROW_OWNER_PID, bool> predicate)
        {
            return GetAllTcpConnections().Where(predicate).Select(i => new NetStatDataItem(i));
        }
    }

    [SupportedOSPlatform("windows")]
    public class NetStatDataItem
    {
        public ConnectionState State { get; internal set; }
        public uint LocalAddr { get; internal set; }
        internal byte LocalPort1 { get; set; }
        internal byte LocalPort2 { get; set; }
        internal byte LocalPort3 { get; set; }
        internal byte LocalPort4 { get; set; }
        public uint RemoteAddr { get; internal set; }
        internal byte RemotePort1 { get; set; }
        internal byte RemotePort2 { get; set; }
        internal byte RemotePort3 { get; set; }
        internal byte RemotePort4 { get; set; }
        public int ProcessId { get; internal set; }

        public ushort LocalPort
        {
            get
            {
                return BitConverter.ToUInt16(
                    new byte[2] { LocalPort2, LocalPort1 }, 0);
            }
        }

        public ushort RemotePort
        {
            get
            {
                return BitConverter.ToUInt16(
                    new byte[2] { RemotePort2, RemotePort1 }, 0);
            }
        }

        public string? ProcessExecutable { get; set; }
        public string? ProcessOwner { get; set; }

        internal NetStatDataItem(MIB_TCPROW_OWNER_PID row)
        {
            LocalAddr = row.localAddr;
            LocalPort1 = row.localPort1;
            LocalPort2 = row.localPort2;
            LocalPort3 = row.localPort3;
            LocalPort4 = row.localPort4;
            RemoteAddr = row.remoteAddr;
            RemotePort1 = row.remotePort1;
            RemotePort2 = row.remotePort2;
            RemotePort3 = row.remotePort3;
            RemotePort4 = row.remotePort4;
            State = row.state;
            ProcessId = row.owningPid;

            var po = row.GetProcessInfo();

            ProcessExecutable = po.ProcessPath;
            ProcessOwner = po.Owner;
        }
    }
}