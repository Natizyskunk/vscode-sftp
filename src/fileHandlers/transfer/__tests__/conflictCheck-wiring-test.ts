// Drives confirmUpload/updateBaselineAfterTransfer against fake filesystems.
// The pure rule is covered in conflictCheck-test; this covers the wiring:
// config gating, stat plumbing, prompt-choice mapping, and the baseline
// round-trip through workspaceState.
const showWarningMessage = jest.fn();

jest.mock('vscode', () => {
  const disposable = { dispose() {} };
  const anyFn = () => disposable;
  const ns = () =>
    new Proxy(
      {
        createStatusBarItem: () => ({ show() {}, hide() {}, dispose() {}, text: '' }),
        createOutputChannel: () => ({ appendLine() {}, show() {}, dispose() {} }),
        getConfiguration: () => ({ get: () => undefined }),
        showWarningMessage,
        workspaceFolders: [],
      },
      { get: (t, k) => (k in t ? t[k] : anyFn) }
    );

  return {
    window: ns(),
    workspace: ns(),
    commands: ns(),
    env: ns(),
    EventEmitter: class {
      get event() {
        return () => disposable;
      }
      fire() {}
      dispose() {}
    },
    Uri: { file: (p: string) => ({ fsPath: p, scheme: 'file', query: '' }) },
    StatusBarAlignment: { Left: 1, Right: 2 },
    ThemeColor: class {},
    TreeItem: class {},
    Disposable: class {},
  };
});

import app from '../../../app';
import { FileType } from '../../../core';
import { confirmUpload, updateBaselineAfterTransfer } from '../conflictCheck';

interface FakeStat {
  mtime: number;
  size: number;
  type: FileType;
}

const T1 = 1_000_000_000_000;
const T2 = 1_000_000_060_000;
const T3 = 1_000_000_120_000;

function fakeFs(stats: { [fsPath: string]: FakeStat }) {
  return {
    lstat: jest.fn(async (fsPath: string) => {
      const stat = stats[fsPath];
      if (!stat) {
        throw new Error(`ENOENT: ${fsPath}`);
      }
      return stat;
    }),
  };
}

function file(mtime: number, size = 100): FakeStat {
  return { mtime, size, type: FileType.File };
}

const LOCAL = '/local/app.js';
const REMOTE = '/remote/app.js';

function makeCtx({
  conflictCheck = true,
  local = file(T1),
  remote = null as FakeStat | null,
}: { conflictCheck?: boolean; local?: FakeStat | null; remote?: FakeStat | null } = {}) {
  const localStats: { [fsPath: string]: FakeStat } = local ? { [LOCAL]: local } : {};
  const remoteStats: { [fsPath: string]: FakeStat } = remote ? { [REMOTE]: remote } : {};
  const remoteFs = fakeFs(remoteStats);

  return {
    ctx: {
      config: {
        conflictCheck,
        protocol: 'sftp',
        username: 'me',
        host: 'example.com',
        port: 22,
      },
      target: { localFsPath: LOCAL, remoteFsPath: REMOTE },
      fileService: {
        getLocalFileSystem: () => fakeFs(localStats),
        getRemoteFileSystem: async () => remoteFs,
      },
    } as any,
    remoteFs,
  };
}

// Minimal in-memory Memento so baselines actually round-trip.
function installWorkspaceState() {
  const store: { [key: string]: any } = {};
  (app as any).vscodeContext = {
    workspaceState: {
      get: (key: string) => store[key],
      update: (key: string, value: any) => {
        store[key] = value;
        return Promise.resolve();
      },
    },
  };
  return store;
}

describe('confirmUpload', () => {
  beforeEach(() => {
    showWarningMessage.mockReset();
    installWorkspaceState();
  });

  it('is a no-op when conflictCheck is off, without touching the remote', async () => {
    // The remote is newer — would conflict if the feature were on.
    const { ctx, remoteFs } = makeCtx({ conflictCheck: false, local: file(T1), remote: file(T3) });

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).not.toHaveBeenCalled();
    // no extra round-trip when disabled
    expect(remoteFs.lstat).not.toHaveBeenCalled();
  });

  it('proceeds without prompting when the remote does not exist', async () => {
    const { ctx } = makeCtx({ local: file(T1), remote: null });

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).not.toHaveBeenCalled();
  });

  it('proceeds without prompting when the remote matches local', async () => {
    const { ctx } = makeCtx({ local: file(T2), remote: file(T2) });

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).not.toHaveBeenCalled();
  });

  it('skips folder uploads', async () => {
    const { ctx } = makeCtx({
      local: { mtime: T1, size: 0, type: FileType.Directory },
      remote: file(T3),
    });

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).not.toHaveBeenCalled();
  });

  it('prompts when the remote is newer and there is no baseline', async () => {
    const { ctx } = makeCtx({ local: file(T1), remote: file(T3) });
    showWarningMessage.mockResolvedValue('Overwrite');

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).toHaveBeenCalledTimes(1);
    const [message, options] = showWarningMessage.mock.calls[0];
    expect(message).toContain('app.js');
    expect(options.modal).toBe(true);
  });

  it('maps the prompt choices to decisions', async () => {
    const cases: Array<[any, string]> = [
      ['Overwrite', 'proceed'],
      ['Open Diff', 'diff'],
      [undefined, 'cancel'], // dismissed / Cancel
    ];

    for (const [choice, expected] of cases) {
      const { ctx } = makeCtx({ local: file(T1), remote: file(T3) });
      showWarningMessage.mockResolvedValue(choice);
      await expect(confirmUpload(ctx)).resolves.toBe(expected);
    }
  });

  it('prompts when a recorded baseline no longer matches the remote', async () => {
    // Local edited last (T3) so an mtime-only check would wave this through.
    const { ctx } = makeCtx({ local: file(T3), remote: file(T2) });
    showWarningMessage.mockResolvedValue(undefined);

    // Establish the baseline as a download would: remote was T1 back then.
    const stale = makeCtx({ local: file(T3), remote: file(T1) });
    await updateBaselineAfterTransfer(stale.ctx);

    await expect(confirmUpload(ctx)).resolves.toBe('cancel');
    expect(showWarningMessage).toHaveBeenCalledTimes(1);
  });

  it('stays quiet once the baseline matches the remote again', async () => {
    const { ctx } = makeCtx({ local: file(T3), remote: file(T2) });

    // Record the current remote, as a transfer of this file would.
    await updateBaselineAfterTransfer(ctx);

    await expect(confirmUpload(ctx)).resolves.toBe('proceed');
    expect(showWarningMessage).not.toHaveBeenCalled();
  });

  it('records no baseline while the feature is off', async () => {
    const store = installWorkspaceState();
    const { ctx } = makeCtx({ conflictCheck: false, local: file(T1), remote: file(T2) });

    await updateBaselineAfterTransfer(ctx);
    expect(Object.keys(store)).toHaveLength(0);
  });
});
