package rpv.objects;

public class RpvProcess
{
    public int pid;
    public int ppid;
    public String name;
    public String path;
    public String cmdline;
    public String user;
    public String version;
    public String desc;
    public RpvRpcInfo rpcInfo;

    public int getPid()
    {
        return pid;
    }

    public void setPid(int pid)
    {
        this.pid = pid;
    }

    public int getPpid()
    {
        return ppid;
    }

    public void setPpid(int ppid)
    {
        this.ppid = ppid;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getPath()
    {
        return path;
    }

    public void setPath(String path)
    {
        this.path = path;
    }

    public String getCmdline()
    {
        return cmdline;
    }

    public void setCmdline(String cmdline)
    {
        this.cmdline = cmdline;
    }

    public String getUser()
    {
        return user;
    }

    public void setUser(String user)
    {
        this.user = user;
    }

    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
    }

    public String getDesc()
    {
        return desc;
    }

    public void setDesc(String desc)
    {
        this.desc = desc;
    }

    public RpvRpcInfo getRpcInfo()
    {
        return rpcInfo;
    }

    public void setRpcInfo(RpvRpcInfo rpcInfo)
    {
        this.rpcInfo = rpcInfo;
    }
}
