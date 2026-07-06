import * as vscode from 'vscode';
import * as LRU from 'lru-cache';
import StatusBarItem from './ui/statusBarItem';
import { COMMAND_SET_PROFILE, SET_PROFILE_ACTIVE_CONTEXT } from './constants';
import AppState from './modules/appState';
// type-only: importing the value here creates a require cycle
// (app -> remoteExplorer -> serviceManager -> fileHandlers -> transfer -> app)
import type RemoteExplorer from './modules/remoteExplorer';

interface App {
  fsCache: LRU.Cache<string, string>;
  state: AppState;
  sftpBarItem: StatusBarItem;
  remoteExplorer: RemoteExplorer;
  // per-workspace storage; set on activate. Used to persist the active profile
  // of each context across window reloads.
  workspaceState?: vscode.Memento;
}

const app: App = Object.create(null);

app.state = new AppState();
app.sftpBarItem = new StatusBarItem(
  () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return 'SFTP';
    }
    try {
      // lazy require to avoid the app <-> serviceManager import cycle; tolerate
      // being rendered before the module graph is ready (activation / tests).
      const { getFileService } = require('./modules/serviceManager');
      const service = getFileService(editor.document.uri);
      if (!service) {
        return 'SFTP';
      }
      const base = service.name ? `SFTP: ${service.name}` : 'SFTP';
      const profile = service.getActiveProfile();
      return profile ? `${base} [${profile}]` : base;
    } catch (e) {
      return 'SFTP';
    }
  },
  'SFTP@Natizyskunk',
  // click the bar to switch the active context's profile
  {
    title: 'Set Profile',
    command: COMMAND_SET_PROFILE,
    arguments: [SET_PROFILE_ACTIVE_CONTEXT],
  }
);
app.fsCache = LRU<string, string>({ max: 6 });

export default app;
