package rpv.gui.tree.nodes;

import javax.swing.tree.DefaultMutableTreeNode;

import rpv.objects.RpvRpcMethod;
import rpv.utils.RpvFormatting;

public class RpvMethodTreeNode extends DefaultMutableTreeNode implements RpvAddrTreeNode
{
    private final String name;
    private final long addr;
    private final long offset;
    private final String location;

    public RpvMethodTreeNode(RpvRpcMethod method, String location)
    {
        super(String.format("%s (Addr: %s, Offset: %s)", method.getName(), method.getAddr(), method.getOffset()));

        this.name = method.getName();
        this.addr = Long.decode(method.getAddr());
        this.offset = Long.decode(method.getOffset());
        this.location = location;
    }

    public String getName()
    {
        return name;
    }

    @Override
    public long getAddr()
    {
        return addr;
    }

    @Override
    public long getOffset()
    {
        return offset;
    }

    public String getLocation()
    {
        return RpvFormatting.getFilename(location);
    }
}
