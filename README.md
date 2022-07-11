# ItsSimple.NetStatData

## Usage

Fetch the list of connections like this

```csharp
// Slow (fetching owner and executable path takes considerable time)
var connections = NetStatData.GetTcpConnectionsWithProcessInformation();

// Not as slow
var connections2 = NetStatData.GetTcpConnections();

// Both methods support filters

var filter = NetStatData.GetTcpConnections(f => 
  f.state == ItsSimple.NetStatData.Win32.ConnectionState.TimeWait
);
```