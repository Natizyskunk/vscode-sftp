import * as vscode from 'vscode';
import { EXTENSION_NAME } from '../constants';
import StatusBarItem from './statusBarItem';

let isShow = false;
const outputChannel = vscode.window.createOutputChannel(EXTENSION_NAME);

export function show() {
  // lazy require: a static `import app` here makes logger -> output -> app a
  // load-time edge that drags the whole app graph into every module (cycle).
  const app = require('../app').default;
  app.sftpBarItem.updateStatus(StatusBarItem.Status.ok);
  outputChannel.show();
  isShow = true;
}

export function hide() {
  outputChannel.hide();
  isShow = false;
}

export function toggle() {
  if (isShow) {
    hide();
  } else {
    show();
  }
}

export function print(...args) {
  const msg = args
    .map(arg => {
      if (!arg) {
        return arg;
      }

      if (arg instanceof Error) {
        return arg.stack;
      } else if (!arg.toString || arg.toString() === '[object Object]') {
        return JSON.stringify(arg);
      }

      return arg;
    })
    .join(' ');

  outputChannel.appendLine(msg);
}
