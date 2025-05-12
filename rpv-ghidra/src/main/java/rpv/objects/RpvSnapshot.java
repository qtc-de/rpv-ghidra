package rpv.objects;

import java.io.File;
import java.util.ArrayList;

public class RpvSnapshot
{
    private File snapshotFile;
    public final ArrayList<RpvProcess> processes;

    public RpvSnapshot(ArrayList<RpvProcess> processes)
    {
        this.processes = processes;
    }

    public ArrayList<RpvRpcInterfaceInfo> getRpcInterfaceInfo(String file)
    {
        ArrayList<RpvRpcInterfaceInfo> infos = new ArrayList<RpvRpcInterfaceInfo>() {};

        for (RpvProcess process : processes)
        {
            RpvRpcInfo rpcInfo = process.getRpcInfo();

            for (RpvRpcInterfaceInfo interfaceInfo : rpcInfo.getInterfaceInfos())
            {
                String filename = interfaceInfo.location.substring(interfaceInfo.location.lastIndexOf('\\') + 1);

                if (filename.toLowerCase().equals(file.toLowerCase()))
                {
                    infos.add(interfaceInfo);
                }
            }
        }

        return infos;
    }

    public void setSnapshotFile(File snapshotFile)
    {
        this.snapshotFile = snapshotFile;
    }

    public File getetSnapshotFile()
    {
        return snapshotFile;
    }
}
