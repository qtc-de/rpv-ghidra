package rpv.gui.tree;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import rpv.gui.tree.nodes.RpvInterfaceTreeNode;
import rpv.gui.tree.nodes.RpvModuleTreeNode;
import rpv.objects.RpvRpcInterfaceInfo;
import rpv.utils.RpvFormatting;

public class RpvModuleTree extends JTree
{
    private final DefaultMutableTreeNode moduleRootNode;
    private final List<DefaultMutableTreeNode> moduleNodes;

    public RpvModuleTree(DefaultMutableTreeNode moduleRootNode)
    {
        super(moduleRootNode);

        this.moduleRootNode = moduleRootNode;
        moduleNodes = new ArrayList<DefaultMutableTreeNode>();
    }

    private DefaultMutableTreeNode getOrCreateModuleNode(String name)
    {
        for (DefaultMutableTreeNode moduleNode : moduleNodes)
        {
            if (moduleNode.getUserObject().toString().equals(name))
            {
                return moduleNode;
            }
        }

        RpvModuleTreeNode moduleNode = new RpvModuleTreeNode(name);
        moduleNodes.add(moduleNode);

        DefaultTreeModel model = (DefaultTreeModel)this.getModel();
        model.insertNodeInto(moduleNode, moduleRootNode, moduleRootNode.getChildCount());

        this.expandPath(new TreePath(moduleRootNode.getPath()));

        return moduleNode;
    }

    public void addModuleNode(RpvRpcInterfaceInfo info)
    {
        String moduleName = RpvFormatting.getFilename(info.getLocation());
        DefaultMutableTreeNode moduleNode = getOrCreateModuleNode(moduleName);

        RpvInterfaceTreeNode interfaceNode = new RpvInterfaceTreeNode(info);
        moduleNode.add(interfaceNode);
    }

    public void removeModuleNode(String name)
    {
        DefaultMutableTreeNode found = null;

        for (DefaultMutableTreeNode node : moduleNodes)
        {
            if (node.getUserObject().toString().equals(name))
            {
                found = node;
            }
        }

        if (found != null)
        {
            moduleNodes.remove(found);

            DefaultTreeModel model = (DefaultTreeModel)this.getModel();
            model.removeNodeFromParent(found);
        }
    }

    public void removeAllModuleNodes()
    {
        for (DefaultMutableTreeNode node : moduleNodes)
        {
            DefaultTreeModel model = (DefaultTreeModel)this.getModel();
            model.removeNodeFromParent(node);
        }

        moduleNodes.clear();
    }
}
