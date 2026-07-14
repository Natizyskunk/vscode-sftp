import { Uri } from 'vscode';
import { COMMAND_RETRY_TRANSFER } from '../constants';
import { checkCommand } from './abstract/createCommand';
import TransferTask from '../core/transferTask';
import { getFileService } from '../modules/serviceManager';
import { reportError } from '../helper';
import logger from '../logger';

export default checkCommand({
  id: COMMAND_RETRY_TRANSFER,

  async handleCommand(task?: TransferTask) {
    if (!task) {
      return;
    }

    // localFsPath is always the local side, so it resolves the owning config
    // for both upload and download tasks.
    const fileService = getFileService(Uri.file(task.localFsPath));
    if (!fileService) {
      logger.warn(`Retry Transfer: no config found for ${task.localFsPath}`);
      return;
    }

    // Re-enqueue the same task with its original direction and options; reset()
    // clears its transient state and resetting the view status to queued
    // happens via the QUEUE_TRANSFER event fired by the scheduler.
    const config = fileService.getConfig();
    const scheduler = fileService.createTransferScheduler(config.concurrency);
    task.reset();
    scheduler.add(task);
    try {
      await scheduler.run();
    } catch (error) {
      reportError(error);
    }
  },
});
