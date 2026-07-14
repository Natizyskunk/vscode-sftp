jest.mock('fs');

import { vol } from 'memfs';
import * as fs from 'fs';
import * as path from 'path';
import TransferTask, { TransferDirection } from '../transferTask';
import { FileType } from '../fs';
import localFs from '../localFs';
import RemoteFs from '../../../test/helper/localRemoteFs';

function createRemoteFs() {
  return new RemoteFs(path, {
    clientOption: {} as any,
    remoteTimeOffsetInHours: 0,
  });
}

function makeUploadTask(size: number, { withSize = true } = {}) {
  vol.reset();
  vol.fromJSON({ '/local/big.bin': 'x'.repeat(size) }, '/');
  fs.mkdirSync('/remote');

  const remoteFs = createRemoteFs();
  return new TransferTask(
    { fsPath: '/local/big.bin', fileSystem: localFs },
    { fsPath: '/remote/big.bin', fileSystem: remoteFs as any },
    {
      fileType: FileType.File,
      transferDirection: TransferDirection.LOCAL_TO_REMOTE,
      transferOption: {
        perserveTargetMode: false,
        atime: 0,
        mtime: 0,
        size: withSize ? size : undefined,
      },
    }
  );
}

describe('TransferTask progress', () => {
  afterEach(() => vol.reset());

  it('reports byte progress up to the total size', async () => {
    const size = 300 * 1024;
    const task = makeUploadTask(size);
    let progressCalls = 0;
    task.setProgressListener(() => {
      progressCalls += 1;
    });

    expect(task.totalBytes).toBe(size);
    await task.run();

    expect(progressCalls).toBeGreaterThan(0);
    expect(task.transferredBytes).toBe(size);
    // the file actually landed on the "remote"
    expect(fs.readFileSync('/remote/big.bin', 'utf8').length).toBe(size);
  });

  it('degrades to unknown total size', async () => {
    const size = 4096;
    const task = makeUploadTask(size, { withSize: false });
    await task.run();

    expect(task.totalBytes).toBeUndefined();
    expect(task.transferredBytes).toBe(size);
  });

  it('reset() clears state so the task can be retried', async () => {
    const size = 8192;
    const task = makeUploadTask(size);
    await task.run();
    expect(task.transferredBytes).toBe(size);

    // simulate the failed->retry path
    task.reset();
    expect(task.transferredBytes).toBe(0);
    expect(task.isCancelled()).toBe(false);

    await task.run();
    expect(task.transferredBytes).toBe(size);
    expect(fs.readFileSync('/remote/big.bin', 'utf8').length).toBe(size);
  });

  it('cancel still works with a progress listener attached', async () => {
    const size = 64 * 1024;
    const task = makeUploadTask(size);
    task.setProgressListener(() => undefined);
    task.cancel();
    expect(task.isCancelled()).toBe(true);
    // a task cancelled before start never transfers
    await task.run();
    expect(task.transferredBytes).toBe(0);
  });
});
