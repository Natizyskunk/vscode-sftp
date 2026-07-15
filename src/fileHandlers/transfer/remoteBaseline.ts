import app from '../../app';
import logger from '../../logger';
import { FileHandlerContext } from '../createFileHandler';
import { FileStat } from './conflictCheck';

const STORE_KEY = 'sftp.remoteBaseline';

// Baselines are a cache, not a record: dropping one costs at most a spurious
// prompt, so cap the store rather than let it grow with the workspace.
const MAX_ENTRIES = 500;

interface BaselineEntry extends FileStat {
  savedAt: number;
}

interface BaselineStore {
  [key: string]: BaselineEntry;
}

function storeKey(ctx: FileHandlerContext): string {
  const config = ctx.config as any;
  return `${config.protocol}://${config.username}@${config.host}:${config.port}${ctx.target.remoteFsPath}`;
}

function readStore(): BaselineStore | null {
  const vscodeContext = app.vscodeContext;
  if (!vscodeContext) {
    return null;
  }
  return vscodeContext.workspaceState.get<BaselineStore>(STORE_KEY) || {};
}

export function getRemoteBaseline(ctx: FileHandlerContext): FileStat | null {
  const store = readStore();
  if (!store) {
    return null;
  }

  const entry = store[storeKey(ctx)];
  return entry ? { mtime: entry.mtime, size: entry.size } : null;
}

export function recordRemoteBaseline(ctx: FileHandlerContext, stat: FileStat): void {
  const store = readStore();
  if (!store) {
    return;
  }

  store[storeKey(ctx)] = { ...stat, savedAt: Date.now() };

  const keys = Object.keys(store);
  if (keys.length > MAX_ENTRIES) {
    keys
      .sort((a, b) => store[a].savedAt - store[b].savedAt)
      .slice(0, keys.length - MAX_ENTRIES)
      .forEach(key => delete store[key]);
  }

  // Fire and forget: a lost write just means a prompt we could have skipped.
  Promise.resolve(app.vscodeContext.workspaceState.update(STORE_KEY, store)).then(
    undefined,
    error => logger.warn(error, 'failed to persist remote baseline')
  );
}
