import { computeSyncPlan } from '../syncPreview';
import { CompareResult } from '../compareFolders';
import { TransferDirection, FileType } from '../../core';

function result(
  relativePath: string,
  status: CompareResult['status'],
  { localMtime = 0, remoteMtime = 0 }: { localMtime?: number; remoteMtime?: number } = {}
): CompareResult {
  return {
    relativePath,
    name: relativePath,
    type: FileType.File,
    status,
    localFsPath: `/local/${relativePath}`,
    remoteFsPath: `/remote/${relativePath}`,
    localMtime,
    remoteMtime,
  };
}

const L2R = TransferDirection.LOCAL_TO_REMOTE;
const R2L = TransferDirection.REMOTE_TO_LOCAL;

describe('computeSyncPlan', () => {
  const diff = [
    result('same.txt', 'same'),
    result('newLocal.txt', 'localOnly'),
    result('newRemote.txt', 'remoteOnly'),
    result('changed.txt', 'modified', { localMtime: 2000, remoteMtime: 1000 }),
  ];

  it('local → remote: creates local-only, overwrites modified, no deletes without delete', () => {
    const plan = computeSyncPlan(diff, L2R, {});
    expect(plan.create).toEqual(['newLocal.txt']);
    expect(plan.overwrite).toEqual(['changed.txt']);
    expect(plan.delete).toEqual([]);
  });

  it('local → remote with delete: remote-only files are deletions', () => {
    const plan = computeSyncPlan(diff, L2R, { delete: true });
    expect(plan.create).toEqual(['newLocal.txt']);
    expect(plan.delete).toEqual(['newRemote.txt']);
  });

  it('remote → local: mirrors direction (remote-only creates, local-only deletes)', () => {
    const plan = computeSyncPlan(diff, R2L, { delete: true });
    expect(plan.create).toEqual(['newRemote.txt']);
    expect(plan.overwrite).toEqual(['changed.txt']);
    expect(plan.delete).toEqual(['newLocal.txt']);
  });

  it('skipCreate suppresses creates', () => {
    const plan = computeSyncPlan(diff, L2R, { skipCreate: true });
    expect(plan.create).toEqual([]);
    expect(plan.overwrite).toEqual(['changed.txt']);
  });

  it('ignoreExisting suppresses overwrites', () => {
    const plan = computeSyncPlan(diff, L2R, { ignoreExisting: true });
    expect(plan.overwrite).toEqual([]);
    expect(plan.create).toEqual(['newLocal.txt']);
  });

  it('update only overwrites when the source side is newer', () => {
    const localNewer = [result('a.txt', 'modified', { localMtime: 2000, remoteMtime: 1000 })];
    const remoteNewer = [result('a.txt', 'modified', { localMtime: 1000, remoteMtime: 2000 })];

    expect(computeSyncPlan(localNewer, L2R, { update: true }).overwrite).toEqual(['a.txt']);
    expect(computeSyncPlan(remoteNewer, L2R, { update: true }).overwrite).toEqual([]);
    // reversed direction flips which side must be newer
    expect(computeSyncPlan(remoteNewer, R2L, { update: true }).overwrite).toEqual(['a.txt']);
  });

  it('both directions: creates each side, overwrites modified, never deletes', () => {
    const plan = computeSyncPlan(diff, L2R, { bothDiretions: true, delete: true });
    expect(plan.create.sort()).toEqual(['newLocal.txt', 'newRemote.txt']);
    expect(plan.overwrite).toEqual(['changed.txt']);
    expect(plan.delete).toEqual([]);
  });
});
