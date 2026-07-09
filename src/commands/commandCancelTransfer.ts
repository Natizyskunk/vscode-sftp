import { COMMAND_CANCEL_TRANSFER } from '../constants';
import { checkCommand } from './abstract/createCommand';
import TransferTask from '../core/transferTask';

export default checkCommand({
  id: COMMAND_CANCEL_TRANSFER,

  async handleCommand(task?: TransferTask) {
    if (task) {
      task.cancel();
    }
  },
});
