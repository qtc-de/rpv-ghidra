package rpv.objects;

import java.util.ArrayList;

public class RpvRpcInfo
{
    public RpvRpcServerInfo serverInfo;
    public ArrayList<RpvRpcInterfaceInfo> interfaceInfos;

    public RpvRpcServerInfo getServerInfo()
    {
        return serverInfo;
    }

    public void setServerInfo(RpvRpcServerInfo serverInfo)
    {
        this.serverInfo = serverInfo;
    }

    public ArrayList<RpvRpcInterfaceInfo> getInterfaceInfos()
    {
        return interfaceInfos;
    }

    public void setInterfaceInfos(ArrayList<RpvRpcInterfaceInfo> interfaceInfos)
    {
        this.interfaceInfos = interfaceInfos;
    }
}
