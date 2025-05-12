package rpv.gui;

import java.awt.BorderLayout;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.tree.DefaultMutableTreeNode;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import resources.Icons;
import rpv.gui.tree.RpvModuleTree;
import rpv.gui.tree.RpvTreeRenderer;
import rpv.objects.RpvProcess;
import rpv.objects.RpvRpcInterfaceInfo;
import rpv.objects.RpvRpcMethod;
import rpv.objects.RpvRpcSecurityCallback;
import rpv.objects.RpvSnapshot;
import rpv.utils.RpvDataTypeConflictHandler;
import rpv.utils.RpvFormatting;
import rpv.utils.RpvMedia;

/**
 * RpvComponentProvider creates the GUI component for the plugin and is
 * responsible for updating it on newly opened or closed programs.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RpvComponentProvider extends ComponentProviderAdapter
{
    private RpvSnapshot snapshot;
    private RpvModuleTree moduleTree;

    private DockingAction actionShowHelp;
    private DockingAction actionLoadSnapshot;
    private DockingAction actionUnloadSnapshot;
    private DockingAction actionApplySignatures;

    private final JPanel panel;
    private DefaultMutableTreeNode moduleRootNode;

    public RpvComponentProvider(PluginTool tool, String owner)
    {
        super(tool, owner, owner);

        panel = new JPanel(new BorderLayout());
        panel.setVisible(true);

        addRpvTree();

        setDefaultWindowPosition(WindowPosition.RIGHT);
        setTitle("RPV");
        setVisible(true);

        createActions();
    }

    private void addRpvTree()
    {
        moduleRootNode = new DefaultMutableTreeNode("PE Files");

        moduleTree = new RpvModuleTree(moduleRootNode);
        moduleTree.setRootVisible(false);
        moduleTree.setShowsRootHandles(true);

        RpvTreeRenderer renderer = new RpvTreeRenderer();
        moduleTree.setCellRenderer(renderer);

        RpvMouseAdapters.addCodeBrowserMouseAdapter(moduleTree, this);

        JScrollPane scrollPane = new JScrollPane(moduleTree);
        panel.add(scrollPane);
    }

    private void createActions()
    {
        actionLoadSnapshot = new DockingAction("Load rpv Snapshot", getName())
        {
            @Override
            public void actionPerformed(ActionContext context)
            {
                RpvFileChooser fileChooser = new RpvFileChooser(null);
                File selected = fileChooser.getSelectedFile();

                if (selected == null)
                {
                    return;
                }

                loadRpvSnapshot(selected, true);
            }
        };

        actionLoadSnapshot.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
        actionLoadSnapshot.setEnabled(true);
        actionLoadSnapshot.markHelpUnnecessary();

        actionShowHelp = new DockingAction("Show Help", getName())
        {
            @Override
            public void actionPerformed(ActionContext context)
            {
                showInfo("RPV Ghidra Help", "Icons by https://icons8.de");
            }
        };

        actionShowHelp.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));
        actionShowHelp.setEnabled(true);
        actionShowHelp.markHelpUnnecessary();


        actionUnloadSnapshot = new DockingAction("Unload rpv Snapshot", getName())
        {
            @Override
            public void actionPerformed(ActionContext context)
            {
                unloadRpvSnapshot();
            }
        };

        actionUnloadSnapshot.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
        actionUnloadSnapshot.setEnabled(true);
        actionUnloadSnapshot.markHelpUnnecessary();

        actionApplySignatures = new DockingAction("Reapply types for current Program", getName())
        {
            @Override
            public void actionPerformed(ActionContext context)
            {
                Program currentProgram = getProgramManager().getCurrentProgram();
                ArrayList<RpvRpcInterfaceInfo> intfInfos = snapshot.getRpcInterfaceInfo(currentProgram.getName());

                if (intfInfos.size() > 0)
                {
                    for (RpvRpcInterfaceInfo info : intfInfos)
                    {
                        applySignatures(currentProgram, info);
                    }
                }
            }
        };

        actionApplySignatures.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        actionApplySignatures.setEnabled(true);
        actionApplySignatures.markHelpUnnecessary();

        dockingTool.addLocalAction(this, actionLoadSnapshot);
        dockingTool.addLocalAction(this, actionUnloadSnapshot);
        dockingTool.addLocalAction(this, actionShowHelp);
        dockingTool.addLocalAction(this, actionApplySignatures);

    }

    public void loadRpvSnapshot(File snapshotFile, boolean showMessage)
    {
        try
        {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

            ArrayList<RpvProcess> processes = mapper.readValue(snapshotFile, new TypeReference<ArrayList<RpvProcess>>() {});

            snapshot = new RpvSnapshot(processes);
            snapshot.setSnapshotFile(snapshotFile);

            if (showMessage)
            {
                showInfo("Success", "Snapshot loaded successfully.");
            }

            for (Program prog : getProgramManager().getAllOpenPrograms())
            {
                programOpened(prog);
            }
        }

        catch (DatabindException e)
        {
            showError("Invalid Snapshot", e.getMessage());
        }

        catch (IOException e)
        {
            showError("IO Error", e.getMessage());
        }
    }

    public void unloadRpvSnapshot()
    {
        snapshot = null;
        moduleTree.removeAllModuleNodes();
    }

    @Override
    public JComponent getComponent()
    {
        return panel;
    }

    @Override
    public ImageIcon getIcon()
    {
        return RpvMedia.getImageIcon("rpv");
    }

    public void writeConsole(String msg)
    {
        ConsoleService consoleService = (ConsoleService)tool.getService(ConsoleService.class);
        consoleService.addMessage("rpv-ghidra", msg);
    }

    public void writeConsoleError(String msg)
    {
        ConsoleService consoleService = (ConsoleService)tool.getService(ConsoleService.class);
        consoleService.addErrorMessage("rpv-ghidra", msg);
    }

    public void writeConsoleException(Exception e)
    {
        ConsoleService consoleService = (ConsoleService)tool.getService(ConsoleService.class);
        consoleService.addException("rpv-ghidra", e);
    }

    public void showInfo(String title, String msg)
    {
        Msg.showInfo(getClass(), panel, title, msg);
    }

    public void showError(String title, String msg)
    {
        Msg.showError(getClass(), panel, title, msg);
    }

    public RpvSnapshot getRpvSnapshot()
    {
        return snapshot;
    }

    public GoToService getGotoService()
    {
        return tool.getService(GoToService.class);
    }

    public ProgramManager getProgramManager()
    {
        return tool.getService(ProgramManager.class);
    }

    public DomainFile getDomainFile(String path)
    {
        return tool.getProject().getProjectData().getFile("/" + path);
    }

    public void programOpened(Program program)
    {
        if (this.snapshot == null)
        {
            return;
        }

        ArrayList<RpvRpcInterfaceInfo> intfInfos = snapshot.getRpcInterfaceInfo(program.getName());

        if (intfInfos.size() > 0)
        {
            for (RpvRpcInterfaceInfo info : intfInfos)
            {
                moduleTree.addModuleNode(info);
                applySignatures(program, info);
            }
        }
    }

    public void programClosed(Program program)
    {
        if (this.snapshot == null)
        {
            return;
        }

        moduleTree.removeModuleNode(program.getName());
    }

    public void applySignatures(Program program, RpvRpcInterfaceInfo info)
    {
        DataTypeManager progDtMgr = program.getDataTypeManager();
        DataTypeConflictHandler conflictHandler = new RpvDataTypeConflictHandler(this);

        RpvRpcSecurityCallback secCallback = info.getSecCallback();

        try
        {
            boolean is64 = (program.getDefaultPointerSize() == 8) ? true : false;

            CParser parser = new CParser();
            InputStream idlInputStream = new ByteArrayInputStream(info.getIdl().getCCode(is64).getBytes());

            parser.setParseFileName(info.id + ".idl");
            parser.parse(idlInputStream);

            DataTypeManager dtMgr = parser.getDataTypeManager();

            Iterator<FunctionDefinition> functions = dtMgr.getAllFunctionDefinitions();
            while (functions.hasNext())
            {
                FunctionDefinition funcDef = functions.next();
                RpvRpcMethod method = info.getRpcMethod(funcDef.getName());

                RpvFormatting.adjustTypeName(funcDef, method);
                writeConsole("Adding method signature for " + funcDef.getName());

                int transactionId = program.startTransaction("rpv - adding function types from idl.");
                progDtMgr.addDataType(funcDef, conflictHandler);

                Address methodAddress = program.getImageBase();
                methodAddress = methodAddress.add(Long.decode(method.getOffset()));

                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(methodAddress, funcDef, SourceType.IMPORTED, true, false, conflictHandler, FunctionRenameOption.RENAME_IF_DEFAULT);
                cmd.applyTo(program);

                program.endTransaction(transactionId, true);
            }

            Iterator<Structure> structs = dtMgr.getAllStructures();
            while (structs.hasNext())
            {
                Structure struct = structs.next();
                writeConsole("Adding struct type " + struct.getName());

                int transactionId = program.startTransaction("rpv - adding struct types from idl.");
                progDtMgr.addDataType(struct, conflictHandler);

                program.endTransaction(transactionId, true);
            }
        }

        catch (ParseException e)
        {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));

            writeConsole("Got exception while parsing idl for RPC interface " + info.id);
            writeConsoleException(e);
        }
    }
}
