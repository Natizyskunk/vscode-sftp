import * as vscode from 'vscode';
import * as path from 'path';
import { getFileService } from '../modules/serviceManager';
import { FileType } from '../core/fs';
import logger from '../logger';

/**
 * sftp.search.remote — поиск файлов на удалённом сервере по имени.
 */
export default {
  id: 'sftp.search.remote',
  async run() {
    // Берём активный редактор для определения fileService
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) {
      vscode.window.showErrorMessage('SFTP: Откройте файл проекта чтобы определить конфигурацию');
      return;
    }

    const fileService = getFileService(activeEditor.document.uri);
    if (!fileService) {
      vscode.window.showErrorMessage('SFTP: Конфигурация SFTP не найдена');
      return;
    }

    const config = fileService.getConfig();
    const remoteRoot = config.remotePath;

    let remoteFs: any;
    try {
      remoteFs = await fileService.getRemoteFileSystem(config);
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: Не удалось подключиться: ${(err as Error).message}`);
      return;
    }

    const quickPick = vscode.window.createQuickPick();
    quickPick.placeholder = 'Введите имя файла (мин. 2 символа)...';
    quickPick.title = `🔍 Поиск на ${config.host}:${remoteRoot}`;
    quickPick.matchOnDescription = true;

    let searchTimeout: ReturnType<typeof setTimeout> | undefined;
    let currentSearch = 0;

    async function search(query: string, searchId: number) {
      if (!query || query.length < 2) {
        quickPick.items = [];
        quickPick.busy = false;
        return;
      }
      quickPick.busy = true;
      const results: vscode.QuickPickItem[] = [];
      const queryLower = query.toLowerCase();

      async function walk(dirPath: string, depth: number) {
        if (depth > 6 || searchId !== currentSearch) return;
        try {
          const entries = await remoteFs.list(dirPath);
          for (const entry of entries) {
            if (searchId !== currentSearch) return;
            if (entry.name.toLowerCase().includes(queryLower)) {
              const fullPath = path.posix.join(dirPath, entry.name);
              const isDir = entry.type === FileType.Directory;
              results.push({
                label: `${isDir ? '📁' : '📄'} ${entry.name}`,
                description: fullPath,
                detail: isDir ? 'Папка' : `${(entry.size / 1024).toFixed(1)} КБ`,
              });
              if (results.length <= 50) quickPick.items = [...results];
            }
            if (entry.type === FileType.Directory && depth < 4) {
              await walk(path.posix.join(dirPath, entry.name), depth + 1);
            }
          }
        } catch { /* ignore inaccessible dirs */ }
      }

      try {
        await walk(remoteRoot, 0);
        if (searchId === currentSearch) {
          quickPick.items = results.length > 0
            ? results
            : [{ label: '$(search) Ничего не найдено', description: `По запросу "${query}"` }];
          quickPick.busy = false;
        }
      } catch (err) {
        logger.error(`[SearchRemote] ${(err as Error).message}`);
        quickPick.busy = false;
      }
    }

    quickPick.onDidChangeValue(value => {
      if (searchTimeout) clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => { currentSearch++; search(value, currentSearch); }, 400);
    });

    quickPick.onDidAccept(() => {
      const selected = quickPick.selectedItems[0];
      if (selected?.description) {
        vscode.env.clipboard.writeText(selected.description);
        vscode.window.showInformationMessage(`Путь скопирован: ${selected.description}`);
      }
      quickPick.hide();
    });

    quickPick.show();
  },
};
