import { ExtensionContext } from 'vscode';
import { LRUCache } from 'lru-cache';
import StatusBarItem from './ui/statusBarItem';
import ConnectionStatusBar from './ui/connectionStatusBar';
import {
  COMMAND_TOGGLE_OUTPUT,
  COMMAND_CANCEL_ALL_TRANSFER,
  COMMAND_SET_PROFILE,
} from './constants';
import AppState from './modules/appState';
import RemoteExplorer from './modules/remoteExplorer';
import TransferView from './modules/transferView';

interface App {
  vscodeContext: ExtensionContext;
  fsCache: LRUCache<string, string>;
  state: AppState;
  sftpBarItem: StatusBarItem;
  connectionBarItem: ConnectionStatusBar;
  transferBarItem: StatusBarItem;
  remoteExplorer: RemoteExplorer;
  transferView: TransferView;
}

const app: App = Object.create(null);

app.state = new AppState();
app.sftpBarItem = new StatusBarItem(
  () => {
    let label: string;
    if (app.state.profile) {
      label = `SFTP: ${app.state.profile}`;
    } else if (app.state.availableProfiles.length > 0) {
      label = 'SFTP: (no profile)';
    } else {
      label = 'SFTP';
    }

    // surface an "upload on save" indicator when it's active
    if (app.state.uploadOnSave === true) {
      label += ' $(cloud-upload)';
    }
    return label;
  },
  () => {
    const parts: string[] = [];
    if (app.state.availableProfiles.length > 0) {
      parts.push('SFTPresso — click to switch profile');
    } else {
      parts.push('SFTPresso');
    }
    if (app.state.uploadOnSave !== null) {
      parts.push(`Upload on Save: ${app.state.uploadOnSave ? 'On' : 'Off'}`);
    }
    return parts.join('\n');
  },
  () =>
    app.state.availableProfiles.length > 0 ? COMMAND_SET_PROFILE : COMMAND_TOGGLE_OUTPUT
);
app.connectionBarItem = new ConnectionStatusBar();
app.transferBarItem = new StatusBarItem(
  () => '',
  'SFTPresso transfers (click to cancel)',
  COMMAND_CANCEL_ALL_TRANSFER
);
app.fsCache = new LRUCache<string, string>({ max: 6 });

export default app;
