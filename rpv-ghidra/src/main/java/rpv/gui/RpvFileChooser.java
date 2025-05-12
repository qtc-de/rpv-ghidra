package rpv.gui;

import java.awt.Component;
import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;

public class RpvFileChooser extends GhidraFileChooser
{
    RpvFileChooser(Component parent)
    {
        super(parent);
        this.setFileFilter(new JsonFilter());
    }

    private class JsonFilter implements GhidraFileFilter
    {
        public boolean accept(File pathname, GhidraFileChooserModel model)
        {
            if (pathname.isDirectory() || pathname.getName().endsWith(".json"))
            {
                return true;
            }

            return false;
        }

        @Override
        public String getDescription()
        {
            return "RPV Snapshot";
        }
    }
}
