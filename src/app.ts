import { ExtensionContext } from 'vscode';
import { LRUCache } from 'lru-cache';
import StatusBarItem from './ui/statusBarItem';
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
  transferBarItem: StatusBarItem;
  remoteExplorer: RemoteExplorer;
  transferView: TransferView;
}

const app: App = Object.create(null);

app.state = new AppState();
app.sftpBarItem = new StatusBarItem(
  () => {
    if (app.state.profile) {
      return `SFTP: ${app.state.profile}`;
    } else if (app.state.availableProfiles.length > 0) {
      return 'SFTP: (no profile)';
    } else {
      return 'SFTP';
    }
  },
  () =>
    app.state.availableProfiles.length > 0
      ? 'SFTPresso — click to switch profile'
      : 'SFTPresso',
  () =>
    app.state.availableProfiles.length > 0 ? COMMAND_SET_PROFILE : COMMAND_TOGGLE_OUTPUT
);
app.transferBarItem = new StatusBarItem(
  () => '',
  'SFTPresso transfers (click to cancel)',
  COMMAND_CANCEL_ALL_TRANSFER
);
app.fsCache = new LRUCache<string, string>({ max: 6 });

export default app;
