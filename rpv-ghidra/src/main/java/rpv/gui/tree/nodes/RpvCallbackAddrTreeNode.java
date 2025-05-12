package rpv.gui.tree.nodes;

import javax.swing.tree.DefaultMutableTreeNode;

import rpv.objects.RpvRpcSecurityCallback;
import rpv.utils.RpvFormatting;

public class RpvCallbackAddrTreeNode extends DefaultMutableTreeNode implements RpvAddrTreeNode
{
    private final long addr;
    private final long offset;
    private final String location;

    public RpvCallbackAddrTreeNode(RpvRpcSecurityCallback callback)
    {
        super(String.format("Addr: %s, Offset: %s", callback.getAddr(), callback.getOffset()));

        this.addr = Long.decode(callback.getAddr());
        this.offset = Long.decode(callback.getOffset());
        this.location = callback.getLocation();
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

    @Override
    public String getLocation()
    {
        return RpvFormatting.getFilename(location);
    }
}
