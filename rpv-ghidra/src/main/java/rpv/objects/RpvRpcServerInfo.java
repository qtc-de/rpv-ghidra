package rpv.objects;

import java.util.ArrayList;

public class RpvRpcServerInfo
{
    public String base;
    public ArrayList<RpvRpcEndpoint> endpoints;

    public String getBase()
    {
        return base;
    }

    public void setBase(String base)
    {
        this.base = base;
    }

    public ArrayList<RpvRpcEndpoint> getEndpoints()
    {
        return endpoints;
    }

    public void setEndpoints(ArrayList<RpvRpcEndpoint> endpoints)
    {
        this.endpoints = endpoints;
    }
}
