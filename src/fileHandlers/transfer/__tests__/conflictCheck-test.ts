import { detectUploadConflict, FileStat } from '../conflictCheck';

function stat(mtime: number, size = 100): FileStat {
  return { mtime, size };
}

// Times are ms since epoch; the guard compares at second granularity.
const T1 = 1_000_000_000_000; // "last sync"
const T2 = 1_000_000_060_000; // a minute later
const T3 = 1_000_000_120_000; // two minutes later

describe('detectUploadConflict', () => {
  it('proceeds when the remote file does not exist yet', () => {
    expect(detectUploadConflict(stat(T1), null, null)).toBe('proceed');
    // even with a stale baseline lying around
    expect(detectUploadConflict(stat(T1), null, stat(T3))).toBe('proceed');
  });

  it('proceeds when the remote already matches local (the post-upload state)', () => {
    // A transfer copies the source mtime onto the target, so an untouched
    // remote looks exactly like the local file.
    expect(detectUploadConflict(stat(T1), stat(T1), null)).toBe('proceed');
    // and that holds even if no baseline was recorded (folder upload / sync)
    expect(detectUploadConflict(stat(T2), stat(T2), stat(T1))).toBe('proceed');
  });

  it('ignores sub-second differences but not size differences', () => {
    expect(detectUploadConflict(stat(T1 + 400), stat(T1 + 900), null)).toBe('proceed');
    // same second, different content: the remote is not what we last left
    expect(detectUploadConflict(stat(T1, 100), stat(T1, 250), stat(T1, 100))).toBe('conflict');
  });

  describe('with a baseline', () => {
    it('conflicts when the remote no longer matches what we last transferred', () => {
      // We downloaded at T1; someone else wrote the remote at T3; we then
      // edited locally at T2. Local is *older* than remote here.
      expect(detectUploadConflict(stat(T2), stat(T3), stat(T1))).toBe('conflict');
    });

    it('conflicts even when our local edit is newer than the remote change', () => {
      // The case an mtime-only check misses: baseline T1, they wrote the
      // remote at T2, we edited at T3 so local looks newest.
      expect(detectUploadConflict(stat(T3), stat(T2), stat(T1))).toBe('conflict');
    });

    it('proceeds when the remote is untouched since our last transfer', () => {
      // Baseline matches the remote; our local edits sit on top of it.
      expect(detectUploadConflict(stat(T3), stat(T1), stat(T1))).toBe('proceed');
    });

    it('detects a remote replaced by different content at the same size', () => {
      expect(detectUploadConflict(stat(T3), stat(T2), stat(T1))).toBe('conflict');
    });
  });

  describe('without a baseline', () => {
    it('conflicts when the remote is newer than the local copy', () => {
      expect(detectUploadConflict(stat(T1), stat(T2), null)).toBe('conflict');
    });

    it('proceeds when the local copy is newer than the remote', () => {
      // Can't distinguish "we edited after downloading" from "we edited after
      // their change" without a baseline; stay out of the way.
      expect(detectUploadConflict(stat(T2), stat(T1), null)).toBe('proceed');
    });

    it('proceeds when the remote is newer only by sub-second noise', () => {
      expect(detectUploadConflict(stat(T1, 100), stat(T1 + 900, 250), null)).toBe('proceed');
    });
  });
});
