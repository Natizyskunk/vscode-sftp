import * as LRU from 'lru-cache';
import StatusBarItem from './ui/statusBarItem';
import { COMMAND_TOGGLE_OUTPUT, COMMAND_CANCEL_ALL_TRANSFER } from './constants';
import AppState from './modules/appState';
import RemoteExplorer from './modules/remoteExplorer';

interface App {
  fsCache: LRU.Cache<string, string>;
  state: AppState;
  sftpBarItem: StatusBarItem;
  transferBarItem: StatusBarItem;
  remoteExplorer: RemoteExplorer;
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
app.fsCache = LRU<string, string>({ max: 6 });

export default app;
