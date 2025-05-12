package rpv.utils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import rpv.gui.RpvComponentProvider;

public class RpvDataTypeConflictHandler extends DataTypeConflictHandler
{
    private final RpvComponentProvider prov;

    public RpvDataTypeConflictHandler(RpvComponentProvider prov)
    {
        this.prov = prov;
    }

    @Override
    public DataTypeConflictHandler getSubsequentHandler()
    {
        return this;
    }

    @Override
    public ConflictResult resolveConflict(DataType arg0, DataType arg1)
    {
        if (arg0.toString().equals(arg1.toString()))
        {
            return ConflictResult.REPLACE_EXISTING;
        }

        prov.writeConsole("Skipping duplicate typedef: " + arg0.toString() + " vs " + arg1.toString());
        return ConflictResult.USE_EXISTING;
    }

    @Override
    public boolean shouldUpdate(DataType arg0, DataType arg1)
    {
        return false;
    }
}
