import LRU = require('lru-cache');
import StatusBarItem from './ui/statusBarItem';
import { COMMAND_TOGGLE_OUTPUT } from './constants';
import AppState from './modules/appState';
import RemoteExplorer from './modules/remoteExplorer';
import { SftpFileDecorationProvider } from './modules/fileDecorationProvider';

interface App {
  fsCache: LRU.Cache<string, string>;
  state: AppState;
  sftpBarItem: StatusBarItem;
  remoteExplorer: RemoteExplorer;
  decorationProvider: SftpFileDecorationProvider;
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
  'SFTP@Natizyskunk',
  COMMAND_TOGGLE_OUTPUT
);
app.fsCache = new LRU<string, string>({ max: 6 });

export default app;
