import * as vscode from 'vscode';
import { getFileService } from '../modules/serviceManager';
import logger from '../logger';

/**
 * Команда sftp.chmod — диалог изменения прав доступа на удалённом файле.
 */
export default {
  id: 'sftp.chmod',
  async run(item?: { resource?: vscode.Uri; fsPath?: string; uri?: vscode.Uri }) {
    const uri = item?.resource || item?.uri;
    const remotePath = item?.fsPath || uri?.fsPath;
    if (!remotePath) {
      vscode.window.showWarningMessage('SFTP: Выберите файл или папку в Remote Explorer');
      return;
    }

    const modeInput = await vscode.window.showInputBox({
      placeHolder: '755',
      prompt: `Права доступа для ${remotePath.split('/').pop()} (например: 644, 755, 777)`,
    });

    if (!modeInput) return;

    if (!/^[0-7]{3,4}$/.test(modeInput)) {
      vscode.window.showErrorMessage(
        'SFTP: Некорректный формат прав доступа. Используйте формат: 644, 755, 777'
      );
      return;
    }

    try {
      const fileService = uri ? getFileService(uri) : null;
      if (!fileService) {
        vscode.window.showErrorMessage('SFTP: Конфигурация не найдена для этого файла');
        return;
      }

      const config = fileService.getConfig();
      const remoteFs = await fileService.getRemoteFileSystem(config);
      const octalMode = parseInt(modeInput, 8);
      await remoteFs.chmod(remotePath, octalMode);

      logger.info(`[CHMOD] ${remotePath} → ${modeInput}`);
      vscode.window.showInformationMessage(
        `SFTP: Права изменены: ${remotePath.split('/').pop()} → ${modeInput}`
      );
    } catch (err) {
      const message = (err as Error).message;
      logger.error(`[CHMOD] Failed: ${message}`);
      vscode.window.showErrorMessage(`SFTP: Не удалось изменить права: ${message}`);
    }
  },
};
