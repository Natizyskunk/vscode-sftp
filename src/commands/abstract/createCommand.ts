import { Uri } from 'vscode';
import logger from '../../logger';
import { reportError } from '../../helper';
import { executeCommand } from '../../host';
import app from '../../app';
import { COMMAND_SET_PROFILE } from '../../constants';
import { getAllFileService } from '../../modules/serviceManager';
import { handleCtxFromUri, allHandleCtxFromUri, FileHandlerContext } from '../../fileHandlers';
import Command from './command';

const MISSING_PROFILE_HINT = 'You might want to set a profile first.';

interface BaseCommandOption {
  id: string;
  name?: string;
}

interface CommandOption extends BaseCommandOption {
  handleCommand: (this: Command, ...args: any[]) => unknown | Promise<unknown>;
}

interface FileCommandOption extends BaseCommandOption {
  handleFile: (ctx: FileHandlerContext) => Promise<unknown>;
  getFileTarget: (...args: any[]) => undefined | Uri | Uri[] | Promise<undefined | Uri | Uri[]>;
}

function checkType<T>() {
  return (a: T) => a;
}

export const checkCommand = checkType<CommandOption>();
export const checkFileCommand = checkType<FileCommandOption>();

function shouldPromptProfileSelection(error: any) {
  if (app.state.profile !== null) {
    return false;
  }

  if (!(error instanceof Error) || error.message.indexOf(MISSING_PROFILE_HINT) === -1) {
    return false;
  }

  const profiles = new Set<string>();
  getAllFileService().forEach(service => {
    service.getAvailableProfiles().forEach(profile => profiles.add(profile));
  });

  return profiles.size > 1;
}

async function trySetProfileAndRetry(
  error: any,
  runHandler: () => Promise<unknown>,
  canPrompt: () => boolean
) {
  if (!shouldPromptProfileSelection(error) || !canPrompt()) {
    return false;
  }

  await executeCommand(COMMAND_SET_PROFILE);
  if (!app.state.profile) {
    return true;
  }

  try {
    await runHandler();
  } catch (retryError) {
    reportError(retryError);
  }

  return true;
}

export function createCommand(commandOption: CommandOption & { name: string }) {
  return class NormalCommand extends Command {
    constructor() {
      super();
      this.id = commandOption.id;
      this.name = commandOption.name;
    }

    doCommandRun(...args) {
      return commandOption.handleCommand.apply(this, args);
    }
  };
}

export function createFileCommand(commandOption: FileCommandOption & { name: string }) {
  return class FileCommand extends Command {
    constructor() {
      super();
      this.id = commandOption.id;
      this.name = commandOption.name;
    }

    protected async doCommandRun(...args) {
      const target = await commandOption.getFileTarget(...args);
      if (!target) {
        logger.warn(`The "${this.name}" command get canceled because of missing targets.`);
        return;
      }

      const targetList: Uri[] = Array.isArray(target) ? target : [target];
      let isProfileFlowAttempted = false;
      const pendingTasks = targetList.map(async uri => {
        const runHandler = () => commandOption.handleFile(handleCtxFromUri(uri));
        try {
          await runHandler();
        } catch (error) {
          const handled = await trySetProfileAndRetry(error, runHandler, () => {
            if (isProfileFlowAttempted) {
              return false;
            }

            isProfileFlowAttempted = true;
            return true;
          });

          if (!handled) {
            reportError(error);
          }
        }
      });

      await Promise.all(pendingTasks);
    }
  };
}

export function createFileMultiCommand(commandOption: FileCommandOption & { name: string }) {
  return class FileCommand extends Command {
    constructor() {
      super();
      this.id = commandOption.id;
      this.name = commandOption.name;
    }

    protected async doCommandRun(...args) {
      const target = await commandOption.getFileTarget(...args);
      if (!target) {
        logger.warn(`The "${this.name}" command get canceled because of missing targets.`);
        return;
      }

      const targetList: Uri[] = Array.isArray(target) ? target : [target];
      let isProfileFlowAttempted = false;
      const pendingTasks = targetList.map(async uri => {
        const runHandler = () => Promise.all(allHandleCtxFromUri(uri).map(commandOption.handleFile));
        try {
          await runHandler();
        } catch (error) {
          const handled = await trySetProfileAndRetry(error, runHandler, () => {
            if (isProfileFlowAttempted) {
              return false;
            }

            isProfileFlowAttempted = true;
            return true;
          });

          if (!handled) {
            reportError(error);
          }
        }
      });

      await Promise.all(pendingTasks);
    }
  };
}