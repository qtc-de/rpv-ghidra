package rpv.gui.tree.nodes;

import javax.swing.tree.DefaultMutableTreeNode;

import rpv.objects.RpvRpcInterfaceInfo;
import rpv.objects.RpvRpcMethod;

public class RpvMethodsTreeNode extends DefaultMutableTreeNode
{
    public RpvMethodsTreeNode(RpvRpcInterfaceInfo info)
    {
        super("Methods");

        for (RpvRpcMethod method : info.getMethods())
        {
            DefaultMutableTreeNode child = new RpvMethodTreeNode(method, info.getLocation());
            this.add(child);
        }
    }
}
