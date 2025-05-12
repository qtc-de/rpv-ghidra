package rpv.gui.tree.nodes;

import javax.swing.tree.DefaultMutableTreeNode;

import rpv.objects.RpvRpcInterfaceInfo;
import rpv.utils.RpvFormatting;

public class RpvInterfaceTreeNode extends DefaultMutableTreeNode
{
    private final String name;
    private final String location;

    public RpvInterfaceTreeNode(RpvRpcInterfaceInfo info)
    {
        super(info.getName());

        this.name = info.getName();
        this.location = info.getLocation();

        RpvMethodsTreeNode methodsNode = new RpvMethodsTreeNode(info);
        this.add(methodsNode);

        if (info.hasCallback())
        {
            RpvCallbackTreeNode secCallbackNode = new RpvCallbackTreeNode(info.getSecCallback());
            this.add(secCallbackNode);
        }
    }

    public String getName()
    {
        return name;
    }

    public String getLocation()
    {
        return RpvFormatting.getFilename(location);
    }
}
