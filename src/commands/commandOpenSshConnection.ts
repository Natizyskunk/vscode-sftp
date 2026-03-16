import * as vscode from 'vscode';
import { COMMAND_OPEN_CONNECTION_IN_TERMINAL } from '../constants';
import { getAllFileService } from '../modules/serviceManager';
import { ExplorerRoot } from '../modules/remoteExplorer';
import { interpolate } from '../utils';
import { checkCommand } from './abstract/createCommand';
import logger from '../logger';

const isWindows = process.platform === 'win32';

function shouldUseAgent(config) {
  return typeof config.agent === 'string' && config.agent.length > 0;
}

function shouldUseKey(config) {
  return typeof config.privateKeyPath === 'string' && config.privateKeyPath.length > 0;
}

function adaptPath(filepath) {
  if (isWindows) {
    return filepath.replace(/\\\\/g, '\\');
  }

  // convert to unix style
  return filepath.replace(/\\\\/g, '/').replace(/\\/g, '/');
}

function getSshCommand(
  config: { host: string; port: number; username: string; ssh_prefix?: string },
  extraOption?: string
) {
  let sshStr;
  logger.warn(`${config.ssh_prefix}`);
  if(config.ssh_prefix && config.ssh_prefix != 'undefined') {
    var prefix = config.ssh_prefix.replace(/::\/::/g, "\\");
    sshStr = `${prefix} ssh -t ${config.username}@${config.host} -p ${config.port}`;
  }else{
    sshStr = `ssh -t ${config.username}@${config.host} -p ${config.port}`;
  }
  if (extraOption) {
    sshStr += ` ${extraOption}`;
  }
  return sshStr;
}

export default checkCommand({
  id: COMMAND_OPEN_CONNECTION_IN_TERMINAL,

  async handleCommand(exploreItem?: ExplorerRoot) {
    let remoteConfig;
    if (exploreItem && exploreItem.explorerContext) {
      remoteConfig = exploreItem.explorerContext.config;
      if (remoteConfig.protocol !== 'sftp') {
        return;
      }
    } else {
      const remoteItems = getAllFileService().reduce<
        { label: string; description: string; config: any }[]
      >((result, fileService) => {
        const config = fileService.getConfig();
        if (config.protocol === 'sftp') {
          result.push({
            label: config.name || config.remotePath,
            description: config.host,
            config,
          });
        }
        return result;
      }, []);
      if (remoteItems.length <= 0) {
        return;
      }

      const item = await vscode.window.showQuickPick(remoteItems, {
        placeHolder: 'Select a folder...',
      });
      if (item === undefined) {
        return;
      }

      remoteConfig = item.config;
    }

    const sshConfig = {
      host: remoteConfig.host,
      port: remoteConfig.port,
      username: remoteConfig.username,
      ssh_prefix: remoteConfig.ssh_prefix,
    };
    const terminal = vscode.window.createTerminal(remoteConfig.name);
    let sshCommand;
    if (shouldUseAgent(remoteConfig)) {
      sshCommand = getSshCommand(sshConfig);
    } else if (shouldUseKey(remoteConfig)) {
      sshCommand = getSshCommand(sshConfig, `-i "${adaptPath(remoteConfig.privateKeyPath)}"`);
    } else {
      sshCommand = getSshCommand(sshConfig);
    }

    if (remoteConfig.sshCustomParams) {
      sshCommand =
        sshCommand +
        ' ' +
        interpolate(remoteConfig.sshCustomParams, {
          remotePath: remoteConfig.remotePath,
        });
    }

    terminal.sendText(sshCommand);
    terminal.show();

    // Send post_connect commands to terminal after SSH connects
    if (remoteConfig.post_connect) {
      const commands = Array.isArray(remoteConfig.post_connect)
        ? remoteConfig.post_connect
        : [remoteConfig.post_connect];
      setTimeout(() => {
        commands.forEach(cmd => terminal.sendText(cmd));
      }, 2000);
    }
  },
});
