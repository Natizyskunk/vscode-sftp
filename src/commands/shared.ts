import * as path from 'path';
import { Uri, window } from 'vscode';
import { FileService, FileType } from '../core';
import logger from '../logger';
import { getAllFileService, getFileService } from '../modules/serviceManager';
import { ExplorerItem } from '../modules/remoteExplorer';
import { getActiveTextEditor, showInformationMessage } from '../host';
import { connectionToken, ConnectIdentity } from '../credentialStore';
import { listFiles, toLocalPath, simplifyPath } from '../helper';

function configIngoreFilterCreator(config) {
  if (!config || !config.ignore) {
    return;
  }

  return file => !config.ignore(file.fsPath);
}

function createFileSelector(filterCreator?) {
  return async (): Promise<Uri | undefined> => {
    const remoteItems = getAllFileService().map((fileService, index) => {
      const config = fileService.getConfig();
      return {
        name: config.name || config.remotePath,
        description: config.host,
        fsPath: config.remotePath,
        type: FileType.Directory,
        filter: filterCreator ? filterCreator(config) : undefined,
        getFs: () => fileService.getRemoteFileSystem(config),
        index,
        remoteBaseDir: config.remotePath,
        baseDir: fileService.baseDir,
      };
    });

    const selected = await listFiles(remoteItems);

    if (!selected) {
      return;
    }

    const rootItem = remoteItems[selected.index];
    const localTarget = toLocalPath(selected.fsPath, rootItem.remoteBaseDir, rootItem.baseDir);

    return Uri.file(localTarget);
  };
}

export function selectContext(): Promise<Uri | undefined> {
  return new Promise((resolve, reject) => {
    const sercives = getAllFileService();
    const projectsList = sercives
      .map(service => ({
        value: service.baseDir,
        label: service.name || simplifyPath(service.baseDir),
        description: '',
        detail: service.baseDir,
      }))
      .sort((l, r) => l.label.localeCompare(r.label));

    // if (projectsList.length === 1) {
    // return resolve(projectsList[0].value);
    // }

    window
      .showQuickPick(projectsList, {
        placeHolder: 'Select a folder...',
      })
      .then(selection => {
        if (selection) {
          return resolve(Uri.file(selection.value));
        }

        // cancel selection
        resolve(undefined);
      }, reject);
  });
}

// pick one remote server (including profiles) from all configured file services
export async function selectRemoteConnection(): Promise<ConnectIdentity | undefined> {
  const items: Array<{ label: string; description: string; identity: ConnectIdentity }> = [];
  const seen = new Set<string>();
  for (const service of getAllFileService()) {
    let configs;
    try {
      configs =
        service.getAvailableProfiles().length > 0
          ? service.getAllConfig()
          : [service.getConfig()];
    } catch (error) {
      logger.warn(`skip config at ${service.baseDir}: ${error.message}`);
      continue;
    }

    for (const config of configs) {
      if (config.protocol === 'local') {
        continue;
      }

      const token = connectionToken(config);
      if (seen.has(token)) {
        continue;
      }
      seen.add(token);

      items.push({
        label: token,
        description: config.name || '',
        identity: {
          protocol: config.protocol,
          host: config.host,
          port: config.port,
          username: config.username,
        },
      });
    }
  }

  if (items.length <= 0) {
    showInformationMessage('No sftp/ftp remote found in the current workspace.');
    return;
  }

  const picked =
    items.length === 1
      ? items[0]
      : await window.showQuickPick(items, { placeHolder: 'Select a remote...' });

  return picked ? picked.identity : undefined;
}

// resolve the config a command should act on: an explicit uri (context menu,
// CodeLens), else the active editor, else the only config in the workspace,
// else ask
export async function resolveTargetService(
  uri: Uri | undefined,
  placeHolder: string
): Promise<FileService | undefined> {
  if (uri) {
    const service = getFileService(uri);
    if (service) {
      return service;
    }
  }

  const activeUri = getActiveDocumentUri();
  if (activeUri) {
    const service = getFileService(activeUri);
    if (service) {
      return service;
    }
  }

  const services = getAllFileService();
  if (services.length <= 1) {
    return services[0];
  }

  const pick = await window.showQuickPick(
    services.map(service => ({
      label: service.name || service.workspace,
      description: service.workspace,
      service,
    })),
    { placeHolder }
  );
  return pick && pick.service;
}

export function applySelector<T>(...selectors: ((...args: any[]) => T | Promise<T>)[]) {
  return function combinedSelector(...args: any[]): T | Promise<T> {
    let result;
    for (const selector of selectors) {
      result = selector.apply(this, args);
      if (result) {
        break;
      }
    }

    return result;
  };
}

export function uriFromfspath(fileList: string[]): Uri[] | undefined {
  if (!Array.isArray(fileList) || typeof fileList[0] !== 'string') {
    return;
  }

  return fileList.map(file => Uri.file(file));
}

export function getActiveDocumentUri() {
  const active = getActiveTextEditor();
  if (!active || !active.document) {
    return;
  }

  return active.document.uri;
}

export function getActiveFolder() {
  const uri = getActiveDocumentUri();
  if (!uri) {
    return;
  }

  return Uri.file(path.dirname(uri.fsPath));
}

// selected file or activeTarget or configContext
export function uriFromExplorerContextOrEditorContext(item, items): undefined | Uri | Uri[] {
  // from explorer or editor context
  if (item instanceof Uri) {
    if (Array.isArray(items) && items[0] instanceof Uri) {
      // multi-select in explorer
      return items;
    } else {
      return item;
    }
  } else if ((item as ExplorerItem).resource) {
    // from remote explorer
    if (Array.isArray(items) && (items[0] as ExplorerItem).resource) {
      // multi-select in remote explorer
      return items.map(_ => _.resource.uri);
    } else {
      return item.resource.uri;
    }
  }

  return;
}

// selected folder or configContext
export function selectFolderFallbackToConfigContext(item, items): Promise<undefined | Uri | Uri[]> {
  // from explorer or editor context
  if (item) {
    if (item instanceof Uri) {
      if (Array.isArray(items) && items[0] instanceof Uri) {
        // multi-select in explorer
        return Promise.resolve(items);
      } else {
        return Promise.resolve(item);
      }
    } else if ((item as ExplorerItem).resource) {
      // from remote explorer
      return Promise.resolve(item.resource.uri);
    }
  }

  return selectContext();
}

// selected file from all remote files
export const selectFileFromAll = createFileSelector();

// selected file from remote files expect ignored
export const selectFile = createFileSelector(configIngoreFilterCreator);
