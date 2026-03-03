import * as vscode from 'vscode';
import { QueuePanel } from '../ui/queuePanel';

/**
 * Открывает панель очереди передачи файлов (Transfer Queue).
 */
export default {
  id: 'sftp.openTransferQueue',
  run(_context: vscode.ExtensionContext) {
    // Pass a dummy Uri (QueuePanel doesn't use it currently)
    QueuePanel.createOrShow(vscode.Uri.file(__dirname));
  },
};
