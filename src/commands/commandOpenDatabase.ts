import * as vscode from 'vscode';
import { COMMAND_DATABASE_OPEN } from '../constants';
import { getAllFileService } from '../modules/serviceManager';
import { DatabasePanel, DbTableItem } from '../modules/databaseManager';
import app from '../app';
import { checkCommand } from './abstract/createCommand';
import { DatabaseConfig } from '../modules/databaseManager/types';

export default checkCommand({
  id: COMMAND_DATABASE_OPEN,

  async handleCommand(item?: DbTableItem) {
    let fileService;
    let config;
    let dbConfig: DatabaseConfig;
    let tableName: string | undefined;

    if (item && item.type === 'table') {
      fileService = item.root.fileService;
      config = item.root.config;
      dbConfig = item.root.dbConfig;
      tableName = item.tableName;
    } else {
      const dbItems: { label: string; description: string; fileService: any; config: any; dbConfig: DatabaseConfig }[] = [];
      getAllFileService().forEach(fs => {
        const cfg = fs.getConfig();
        const databases: DatabaseConfig[] = (cfg as any).database;
        if (databases && Array.isArray(databases)) {
          databases.forEach(db => {
            dbItems.push({
              label: `${db.database} @ ${cfg.name || cfg.host}`,
              description: `${db.host}:${db.port}`,
              fileService: fs,
              config: cfg,
              dbConfig: db,
            });
          });
        }
      });

      if (dbItems.length <= 0) {
        vscode.window.showWarningMessage(
          'No database configurations found. Add a "database" array to your sftp.json.'
        );
        return;
      }

      const selected = await vscode.window.showQuickPick(dbItems, {
        placeHolder: 'Select a database to manage...',
      });
      if (!selected) {
        return;
      }

      fileService = selected.fileService;
      config = selected.config;
      dbConfig = selected.dbConfig;
    }

    try {
      const treeProvider = app.databaseExplorer.treeDataProvider;
      const rootItem = {
        type: 'root' as const,
        label: `[${config.name || config.host}] ${dbConfig.database}`,
        fileService,
        config,
        dbConfig,
      };
      const client = await treeProvider.getClient(rootItem);
      const serverName = config.name || config.host;

      if (tableName) {
        DatabasePanel.openToTable(client, dbConfig, serverName, tableName);
      } else {
        DatabasePanel.create(client, dbConfig, serverName);
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to open database: ${err.message}`);
    }
  },
});
