import { reportError } from '../../helper';
import logger from '../../logger';
import { executeCommand } from '../../host';
import app from '../../app';
import { COMMAND_SET_PROFILE } from '../../constants';
import { getAllFileService } from '../../modules/serviceManager';

const MISSING_PROFILE_HINT = 'You might want to set a profile first.';

export interface ITarget {
  fsPath: string;
}

export interface CommandOption {
  [x: string]: any;
}

export default abstract class Command {
  id: string;
  name!: string;
  private _commandDoneListeners: Array<(...args: any[]) => void>;

  constructor() {
    this._commandDoneListeners = [];
  }

  onCommandDone(listener) {
    this._commandDoneListeners.push(listener);

    return () => {
      const index = this._commandDoneListeners.indexOf(listener);
      if (index > -1) this._commandDoneListeners.splice(index, 1);
    };
  }

  protected abstract doCommandRun(...args: any[]): Promise<any> | any;

  async run(...args) {
    logger.trace(`run command '${this.name}'`);
    try {
      await this.doCommandRun(...args);
    } catch (error) {
      const handled = await this.trySetProfileAndRetry(error, args);
      if (!handled) {
        reportError(error);
      }
    } finally {
      this.commitCommandDone(...args);
    }
  }

  private async trySetProfileAndRetry(error: any, args: any[]): Promise<boolean> {
    if (!this.shouldPromptProfileSelection(error)) {
      return false;
    }

    await executeCommand(COMMAND_SET_PROFILE);
    if (!app.state.profile) {
      return true;
    }

    try {
      await this.doCommandRun(...args);
    } catch (retryError) {
      reportError(retryError);
    }

    return true;
  }

  private shouldPromptProfileSelection(error: any): boolean {
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

  private commitCommandDone(...args: any[]) {
    this._commandDoneListeners.forEach(listener => listener(...args));
  }
}
