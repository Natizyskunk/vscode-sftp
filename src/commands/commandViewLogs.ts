import * as vscode from 'vscode';
import { COMMAND_VIEW_LOGS } from '../constants';
import { getAllFileService } from '../modules/serviceManager';
import { ExplorerRoot } from '../modules/remoteExplorer';
import { LogViewerPanel } from '../modules/logViewer';
import { checkCommand } from './abstract/createCommand';

export default checkCommand({
  id: COMMAND_VIEW_LOGS,

  async handleCommand(exploreItem?: ExplorerRoot) {
    let fileService;
    let config;

    if (exploreItem && exploreItem.explorerContext) {
      fileService = exploreItem.explorerContext.fileService;
      config = exploreItem.explorerContext.config;
      if (config.protocol !== 'sftp') {
        vscode.window.showWarningMessage('Log viewer is only available for SFTP connections.');
        return;
      }
    } else {
      const remoteItems = getAllFileService().reduce<
        { label: string; description: string; fileService: any; config: any }[]
      >((result, fs) => {
        const cfg = fs.getConfig();
        if (cfg.protocol === 'sftp') {
          result.push({
            label: cfg.name || cfg.remotePath,
            description: cfg.host,
            fileService: fs,
            config: cfg,
          });
        }
        return result;
      }, []);

      if (remoteItems.length <= 0) {
        vscode.window.showWarningMessage('No SFTP connections available.');
        return;
      }

      const item = await vscode.window.showQuickPick(remoteItems, {
        placeHolder: 'Select a server to view logs...',
      });
      if (item === undefined) {
        return;
      }

      fileService = item.fileService;
      config = item.config;
    }

    LogViewerPanel.create(fileService, config);
  },
});
