package rpv.gui.tree.nodes;

import javax.swing.tree.DefaultMutableTreeNode;

import rpv.objects.RpvRpcSecurityCallback;

public class RpvCallbackTreeNode extends DefaultMutableTreeNode
{
    public RpvCallbackTreeNode(RpvRpcSecurityCallback callback)
    {
        super("Security Callback");

        if (!callback.getName().isEmpty())
        {
            DefaultMutableTreeNode secCallbackName = new DefaultMutableTreeNode("Name: " + callback.getName());
            this.add(secCallbackName);
        }

        DefaultMutableTreeNode secCallbackAddr = new RpvCallbackAddrTreeNode(callback);
        DefaultMutableTreeNode secCallbackLoc = new DefaultMutableTreeNode("Location: " + callback.getLocation());

        this.add(secCallbackLoc);
        this.add(secCallbackAddr);
    }
}
