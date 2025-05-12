package rpv.objects;

import java.util.ArrayList;

public class RpvRpcInterfaceInfo
{
    public String id;
    public String base;
    public String location;
    public String name;
    public String typ;
    public String description;
    public RpvIdlData idl;
    public RpvRpcSecurityCallback secCallback;
    public ArrayList<RpvRpcMethod> methods;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getBase()
    {
        return base;
    }

    public void setBase(String base)
    {
        this.base = base;
    }

    public String getLocation()
    {
        return location;
    }

    public void setLocation(String location)
    {
        this.location = location;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getTyp()
    {
        return typ;
    }

    public void setTyp(String typ)
    {
        this.typ = typ;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public RpvIdlData getIdl()
    {
        return idl;
    }

    public void setIdl(RpvIdlData idl)
    {
        this.idl = idl;
    }

    public RpvRpcSecurityCallback getSecCallback()
    {
        return secCallback;
    }

    public void setSecCallback(RpvRpcSecurityCallback secCallback)
    {
        this.secCallback = secCallback;
    }

    public ArrayList<RpvRpcMethod> getMethods()
    {
        return methods;
    }

    public void setMethods(ArrayList<RpvRpcMethod> methods)
    {
        this.methods = methods;
    }

    public boolean hasCallback()
    {
        return Long.decode(this.secCallback.addr) != 0;
    }

    public RpvRpcMethod getRpcMethod(String methodName)
    {
        for (RpvRpcMethod method : methods)
        {
            if (method.name.equals(methodName))
            {
                return method;
            }
        }

        return null;
    }
}
