package rpv.utils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import rpv.objects.RpvRpcMethod;

public class RpvFormatting
{
    public static String getFilename(String path)
    {
        return path.substring(path.lastIndexOf("\\") + 1);
    }

    public static void adjustTypeName(DataType dataType, RpvRpcMethod method)
    {
        int transactionId = dataType.getDataTypeManager().startTransaction("rpv - adjusting type name for " + dataType.getName());

        try
        {
            if (dataType instanceof FunctionDefinition)
            {
                if (dataType.getName().startsWith("Proc"))
                {
                    dataType.setName(dataType.getName() + "_" + method.getAddr());
                }
            }
        }

        catch (InvalidNameException e)
        {
            // pass
        }

        catch (DuplicateNameException e)
        {
            // pass
        }

        finally
        {
            dataType.getDataTypeManager().endTransaction(transactionId, true);
        }
    }
}
