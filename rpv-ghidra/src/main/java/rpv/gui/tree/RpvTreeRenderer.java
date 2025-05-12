package rpv.gui.tree;

import java.awt.Component;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

import rpv.gui.tree.nodes.RpvCallbackTreeNode;
import rpv.gui.tree.nodes.RpvInterfaceTreeNode;
import rpv.gui.tree.nodes.RpvMethodTreeNode;
import rpv.gui.tree.nodes.RpvMethodsTreeNode;
import rpv.gui.tree.nodes.RpvModuleTreeNode;
import rpv.utils.RpvMedia;

public class RpvTreeRenderer extends DefaultTreeCellRenderer
{
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean focus)
    {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode)value;
        DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)node.getParent();

        if (node instanceof RpvModuleTreeNode)
        {
            setIcon(RpvMedia.getImageIcon("programm"));
        }

        else if (node instanceof RpvInterfaceTreeNode)
        {
            setIcon(RpvMedia.getImageIcon("gear"));
        }

        else if (node instanceof RpvMethodsTreeNode || node instanceof RpvMethodTreeNode)
        {
            setIcon(RpvMedia.getImageIcon("lambda"));
        }

        else if (node instanceof RpvCallbackTreeNode || parentNode instanceof RpvCallbackTreeNode)
        {
            setIcon(RpvMedia.getImageIcon("shield"));
        }

        return this;
    }
}
