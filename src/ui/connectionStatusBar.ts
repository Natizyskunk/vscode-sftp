import * as vscode from 'vscode';
import { COMMAND_TEST_CONNECTION } from '../constants';

export enum ConnectionState {
  Idle = 'idle',
  Connecting = 'connecting',
  Reconnecting = 'reconnecting',
  Connected = 'connected',
  Error = 'error',
}

// Precedence when several connections are live at once: an in-flight
// (re)connect wins over an error, which wins over a healthy connection.
const STATE_PRIORITY = [
  ConnectionState.Reconnecting,
  ConnectionState.Connecting,
  ConnectionState.Error,
  ConnectionState.Connected,
  ConnectionState.Idle,
];

interface StatePresentation {
  text: string;
  tooltip: string;
  background?: string;
}

function present(state: ConnectionState): StatePresentation {
  switch (state) {
    case ConnectionState.Connecting:
      return { text: '$(sync~spin) SFTP', tooltip: 'connecting…' };
    case ConnectionState.Reconnecting:
      return { text: '$(sync~spin) SFTP', tooltip: 'reconnecting…' };
    case ConnectionState.Connected:
      return { text: '$(vm-active) SFTP', tooltip: 'connected' };
    case ConnectionState.Error:
      return {
        text: '$(error) SFTP',
        tooltip: 'connection error',
        background: 'statusBarItem.errorBackground',
      };
    case ConnectionState.Idle:
    default:
      return { text: '$(plug) SFTP', tooltip: 'idle' };
  }
}

// A single status-bar indicator that surfaces the health of the remote
// connections. Connections reconnect lazily, so this makes silent
// reconnects and auth failures visible. Clicking it runs Test Connection.
export default class ConnectionStatusBar {
  private statusBarItem: vscode.StatusBarItem;
  private states: Map<string, ConnectionState> = new Map();

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    this.statusBarItem.command = COMMAND_TEST_CONNECTION;
    this._render();
  }

  setState(id: string, state: ConnectionState) {
    this.states.set(id, state);
    this._render();
  }

  clear(id: string) {
    this.states.delete(id);
    this._render();
  }

  show() {
    this.statusBarItem.show();
  }

  hide() {
    this.statusBarItem.hide();
  }

  dispose() {
    this.statusBarItem.dispose();
  }

  private _aggregate(): ConnectionState {
    const active = new Set(this.states.values());
    for (const state of STATE_PRIORITY) {
      if (active.has(state)) {
        return state;
      }
    }
    return ConnectionState.Idle;
  }

  private _render() {
    const { text, tooltip, background } = present(this._aggregate());
    this.statusBarItem.text = text;
    this.statusBarItem.tooltip = `SFTPresso: ${tooltip} — click to test connection`;
    this.statusBarItem.backgroundColor = background
      ? new vscode.ThemeColor(background)
      : undefined;
  }
}
