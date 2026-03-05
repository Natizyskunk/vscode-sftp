import { COMMAND_DELETE_BOTH } from '../constants';
import { upath } from '../core';
import { removeBoth } from '../fileHandlers';
import { showConfirmMessage } from '../host';
import { checkFileCommand } from './abstract/createCommand';
import { uriFromExplorerContextOrEditorContext } from './shared';

export default checkFileCommand({
  id: COMMAND_DELETE_BOTH,
  async getFileTarget(item, items) {
    const targets = await uriFromExplorerContextOrEditorContext(item, items);

    if (!targets) {
      return;
    }

    const filename = Array.isArray(targets)
      ? targets.map(t => upath.basename(t.fsPath)).join(',')
      : upath.basename(targets.fsPath);
    const result = await showConfirmMessage(
      `Удалить '${filename}' локально и на сервере?`,
      'Удалить',
      'Отмена'
    );

    return result ? targets : undefined;
  },

  handleFile: removeBoth,
});
