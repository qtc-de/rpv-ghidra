package rpv.gui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import rpv.gui.tree.nodes.RpvAddrTreeNode;

public class RpvMouseAdapters
{
    public static void addCodeBrowserMouseAdapter(JTree tree, RpvComponentProvider rpv)
    {
        MouseListener ml = new MouseAdapter()
        {
            public void mousePressed(MouseEvent e)
            {
                int row = tree.getRowForLocation(e.getX(), e.getY());
                TreePath path = tree.getPathForLocation(e.getX(), e.getY());

                if (row != -1 && e.getClickCount() == 2)
                {
                    Object node = path.getLastPathComponent();

                    if (node instanceof RpvAddrTreeNode)
                    {
                        RpvAddrTreeNode addrTreeNode = (RpvAddrTreeNode)node;
                        DomainFile file = rpv.getDomainFile(addrTreeNode.getLocation());

                        if (file == null)
                        {
                            rpv.showError("Program not found", String.format("%s seems not to be loaded", addrTreeNode.getLocation()));
                            return;
                        }

                        Program prog = rpv.getProgramManager().openProgram(file);

                        Address methodAddress = prog.getImageBase();
                        methodAddress = methodAddress.add(addrTreeNode.getOffset());

                        rpv.getGotoService().goTo(methodAddress, prog);
                    }
                }
            }
        };

        tree.addMouseListener(ml);
    }
}
