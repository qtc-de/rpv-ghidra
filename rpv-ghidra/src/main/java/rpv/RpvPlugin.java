/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rpv;

import java.io.File;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import rpv.gui.RpvComponentProvider;
import rpv.objects.RpvSnapshot;

/**
 * RPV Ghidra allows importing rpv-web snapshots into Ghidra. Once imported,
 * available RPC interfaces for a program are displayed within a separate pane
 * making it easy to jump between the available RPC methods.
 *
 * @author Tobias Neitzel (@qtc_de)
 */

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "RpvGhidraPlugin",
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Import rpv-web snapshots and jump between RPC methods.",
    description = "RPV Ghidra allows importing rpv-web snapshots into Ghidra. Once imported,"
                + "available RPC interfaces for a program are displayed within a separate pane"
                + "making it easy to jump between the available RPC methods."
)
//@formatter:on

/**
 * RpvPlugin implements the ProgramPlugin class and is responsible for initialization
 * of the plugin.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RpvPlugin extends ProgramPlugin
{
    // provider stores the ComponentProvider that is responsible for creating the GUI component
    private final RpvComponentProvider provider;

    // configSnapshotFile stores the property name that is used to cache the last used snapshot path
    private final String configSnapshotFile = "snapshotPath";

    /**
     * Plugin constructor. Just creates the RpvComponentProvider and stores it
     * for later use.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public RpvPlugin(PluginTool tool)
    {
        super(tool);

        String pluginName = "rpv";
        provider = new RpvComponentProvider(tool, pluginName);
    }

    /**
     * The last successfully loaded rpv-web snapshot path is cached within the plugin state.
     * On restart, we attempt to read that path and import the snapshot again.
     *
     * @param state     the SaveState that was stored on last close
     */
    @Override
    public void readConfigState(SaveState state)
    {
        String snapshotPath = state.getString(configSnapshotFile, null);
        File snapshotFile = new File(snapshotPath);

        if (snapshotFile.exists())
        {
            provider.loadRpvSnapshot(snapshotFile, false);
        }
    }

    /**
     * On closing, the last successfully loaded rpv-snapshot path is written to the plugin
     * state. This rpv-snapshot is attempted to reload during the next startup.
     *
     * @param state     the SaveState to store the last successful snapshot path in
     */
    @Override
    public void writeConfigState(SaveState state)
    {
        RpvSnapshot snapshot = provider.getRpvSnapshot();

        if (snapshot != null)
        {
            File snapshotFile = snapshot.getetSnapshotFile();

            if (snapshotFile != null && snapshotFile.exists())
            {
                state.putString(configSnapshotFile, snapshotFile.getAbsolutePath());
            }
        }
    }

    /**
     * When the use opens a new program, we check whether it is contained within the rpv-web
     * snapshot and has RPC interfaces assigned. If so, these interfaces are added to the UI.
     *
     * @param program  the program that was just opened
     */
    @Override
    public void programOpened(Program program)
    {
        provider.programOpened(program);
    }

    /**
     * When a program gets closed and it had available RPC interfaces within the UI, we remove
     * the associated interfaces.
     *
     * @param program  the program that was just closed
     */
    @Override
    public void programClosed(Program program)
    {
        provider.programClosed(program);
    }

    /**
     * When the plugin is closed, we simply hide it's UI.
     */
    @Override
    public void dispose()
    {
        provider.setVisible(false);
    }
}
