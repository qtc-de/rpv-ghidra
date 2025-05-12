package rpv.objects;

public class RpvRpcSecurityCallback
{
    public String addr;
    public String offset;
    public String location;
    public String description;
    public String name;

    public String getAddr()
    {
        return addr;
    }

    public void setAddr(String base)
    {
        this.addr = base;
    }

    public String getOffset()
    {
        return offset;
    }

    public void setOffset(String offset)
    {
        this.offset = offset;
    }

    public String getLocation()
    {
        return location;
    }

    public void setLocation(String location)
    {
        this.location = location;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }
}
