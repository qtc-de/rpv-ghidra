package rpv.objects;

public class RpvIdlData
{
    public String id;
    public String name;
    public String version;
    public String code;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
    }

    public String getCode()
    {
        return code;
    }

    public void setCode(String code)
    {
        this.code = code;
    }

    public String getCCode(boolean is64)
    {
        String result = code;

        int cEnd = code.lastIndexOf("}");
        int cStart = code.indexOf("{");

        if (cStart >= 0 && cEnd > cStart)
        {
            StringBuilder sb = new StringBuilder();

            sb.append("typedef unsigned int error_status_t;\n");
            sb.append("typedef void* handle_t;\n");
            sb.append("typedef long long hyper;\n");

            if (is64)
            {
                sb.append("typedef long long __int3264;\n");
            }

            else
            {
                sb.append("typedef int __int3264;\n");
            }

            sb.append(code.substring(cStart + 1, cEnd));
            result = sb.toString();

            result = result.replaceAll("\\[[^\\d\\]]+[^\\]]+\\]", "");
        }

        return result;
    }
}
