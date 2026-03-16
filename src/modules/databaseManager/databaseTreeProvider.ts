import * as vscode from 'vscode';
import { FileService, ServiceConfig } from '../../core';
import { DatabaseConfig } from './types';
import { DatabaseClient } from './databaseClient';
import { needsTunnel, createTunnel } from './sshTunnelManager';
import { getAllFileService } from '../serviceManager';
import logger from '../../logger';

type DatabaseTreeItem = DbRootItem | DbCategoryItem | DbTableItem;

export interface DbRootItem {
  type: 'root';
  label: string;
  fileService: FileService;
  config: ServiceConfig;
  dbConfig: DatabaseConfig;
}

interface DbCategoryItem {
  type: 'category';
  label: string;
  category: 'tables';
  root: DbRootItem;
}

export interface DbTableItem {
  type: 'table';
  tableName: string;
  root: DbRootItem;
}

export default class DatabaseTreeProvider
  implements vscode.TreeDataProvider<DatabaseTreeItem> {

  private _onDidChangeTreeData = new vscode.EventEmitter<DatabaseTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private _clients: Map<string, DatabaseClient> = new Map();

  refresh() {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: DatabaseTreeItem): vscode.TreeItem {
    switch (element.type) {
      case 'root': {
        const item = new vscode.TreeItem(
          element.label,
          vscode.TreeItemCollapsibleState.Collapsed
        );
        item.contextValue = 'dbRoot';
        return item;
      }
      case 'category': {
        const item = new vscode.TreeItem(
          element.label,
          vscode.TreeItemCollapsibleState.Collapsed
        );
        item.contextValue = 'dbCategory';
        item.iconPath = vscode.ThemeIcon.Folder;
        return item;
      }
      case 'table': {
        const item = new vscode.TreeItem(
          element.tableName,
          vscode.TreeItemCollapsibleState.None
        );
        item.contextValue = 'dbTable';
        item.command = {
          command: 'sftp.database.open',
          title: 'Open Table',
          arguments: [element],
        };
        return item;
      }
    }
  }

  async getChildren(element?: DatabaseTreeItem): Promise<DatabaseTreeItem[]> {
    if (!element) {
      return this._getRoots();
    }

    switch (element.type) {
      case 'root':
        return [{
          type: 'category',
          label: 'Tables',
          category: 'tables',
          root: element,
        }];
      case 'category':
        return this._getTables(element.root);
      default:
        return [];
    }
  }

  async getClient(root: DbRootItem): Promise<DatabaseClient> {
    const key = `${root.config.host}:${root.dbConfig.database}`;
    let client = this._clients.get(key);
    if (client) {
      return client;
    }

    let connectHost = root.dbConfig.host;
    let connectPort = root.dbConfig.port;

    if (needsTunnel(root.dbConfig.host) && root.config.protocol === 'sftp') {
      try {
        const remotefs = await root.fileService.getRemoteFileSystem(root.config) as any;
        const sshClient = remotefs.getClient().getUnderlyingClient();
        const tunnel = await createTunnel(sshClient, root.dbConfig.host, root.dbConfig.port);
        connectHost = tunnel.host;
        connectPort = tunnel.port;
      } catch (err) {
        logger.error(err, 'Failed to create SSH tunnel for database');
        throw err;
      }
    }

    client = new DatabaseClient(root.dbConfig, connectHost, connectPort);
    this._clients.set(key, client);
    return client;
  }

  async dispose() {
    const promises = Array.from(this._clients.values()).map(c => c.dispose());
    await Promise.all(promises);
    this._clients.clear();
  }

  private _getRoots(): DbRootItem[] {
    const roots: DbRootItem[] = [];
    getAllFileService().forEach(fileService => {
      const config = fileService.getConfig();
      const databases: DatabaseConfig[] = (config as any).database;
      if (!databases || !Array.isArray(databases)) {
        return;
      }
      databases.forEach(dbConfig => {
        roots.push({
          type: 'root',
          label: `[${config.name || config.host}] ${dbConfig.database}`,
          fileService,
          config,
          dbConfig,
        });
      });
    });
    return roots;
  }

  private async _getTables(root: DbRootItem): Promise<DbTableItem[]> {
    try {
      const client = await this.getClient(root);
      const tables = await client.getTables();
      return tables.map(t => ({
        type: 'table' as const,
        tableName: t.name,
        root,
      }));
    } catch (err) {
      vscode.window.showErrorMessage(
        `Failed to connect to database "${root.dbConfig.database}": ${err.message}`
      );
      return [];
    }
  }
}
