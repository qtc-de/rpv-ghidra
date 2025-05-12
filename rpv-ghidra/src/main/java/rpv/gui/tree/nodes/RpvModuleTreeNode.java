package rpv.gui.tree.nodes;

import java.util.List;

import javax.swing.tree.DefaultMutableTreeNode;

public class RpvModuleTreeNode extends DefaultMutableTreeNode
{
    private List<String> interfaces;

    public RpvModuleTreeNode(String name)
    {
        super(name);
    }

    public void add(DefaultMutableTreeNode node)
    {
        String intfId = node.getUserObject().toString();

        for (String intf : interfaces)
        {
            if (intf.equals(intfId))
            {
                return;
            }
        }

        super.add(node);
        interfaces.add(intfId);
    }
}
