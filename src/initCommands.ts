import { ExtensionContext } from 'vscode';
import logger from './logger';
import { registerCommand } from './host';
import Command from './commands/abstract/command';
import { createCommand, createFileCommand, createFileMultiCommand } from './commands/abstract/createCommand';
import commandModules from './commands';

export default function init(context: ExtensionContext) {
  loadCommands(/^command(.*)/, createCommand, context);
  loadCommands(/^fileCommand(.*)/, createFileCommand, context);
  loadCommands(/^fileMultiCommand(.*)/, createFileMultiCommand, context);
}

function nomalizeCommandName(rawName) {
  const firstLetter = rawName[0].toUpperCase();
  return firstLetter + rawName.slice(1).replace(/[A-Z]/g, token => ` ${token[0]}`);
}

function loadCommands(nameRegex: RegExp, commandCreator, context: ExtensionContext) {
  Object.keys(commandModules).forEach(moduleName => {
    const match = nameRegex.exec(moduleName);
    if (!match || !match[1]) {
      return;
    }

    const commandOption = commandModules[moduleName];
    commandOption.name = nomalizeCommandName(match[1]);

    try {
      const Cmd = commandCreator(commandOption);
      const cmdInstance: Command = new Cmd();
      logger.debug(`register command "${commandOption.name}" from "${moduleName}"`);
      registerCommand(context, commandOption.id, cmdInstance.run, cmdInstance);
    } catch (error) {
      logger.error(error, `load command "${moduleName}"`);
    }
  });
}
