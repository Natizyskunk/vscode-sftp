import { LRUCache } from 'lru-cache';
import StatusBarItem from './ui/statusBarItem';
import { COMMAND_TOGGLE_OUTPUT, COMMAND_CANCEL_ALL_TRANSFER } from './constants';
import AppState from './modules/appState';
import RemoteExplorer from './modules/remoteExplorer';
import TransferView from './modules/transferView';

interface App {
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
    } else {
      return 'SFTP';
    }
  },
  'SFTPresso',
  COMMAND_TOGGLE_OUTPUT
);
app.transferBarItem = new StatusBarItem(
  () => '',
  'SFTPresso transfers (click to cancel)',
  COMMAND_CANCEL_ALL_TRANSFER
);
app.fsCache = new LRUCache<string, string>({ max: 6 });

export default app;
