'use strict';
const { computeDiff } = require('../src/core/deltaSync');

// Helpers
function makeEntry(name: string, mtime: number, size: number, type = 2 /* FileType.File */) {
  return { name, fspath: `/local/${name}`, type, mtime, atime: mtime, size, mode: 0o644 };
}

describe('deltaSync.computeDiff()', () => {
  const localRoot = '/local';
  const remoteRoot = '/remote';

  test('файлы только локально → action=upload', () => {
    const local = new Map([['index.js', makeEntry('index.js', 1700000000, 1024)]]);
    const remote = new Map();
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs).toHaveLength(1);
    expect(diffs[0].status).toBe('new_local');
    expect(diffs[0].action).toBe('upload');
  });

  test('файлы только на сервере → action=download', () => {
    const local = new Map();
    const remote = new Map([['config.php', makeEntry('config.php', 1700000000, 512)]]);
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs).toHaveLength(1);
    expect(diffs[0].status).toBe('new_remote');
    expect(diffs[0].action).toBe('download');
  });

  test('идентичные файлы (одинаковые mtime и size) → action=skip', () => {
    const ts = 1700000000;
    const local = new Map([['app.js', makeEntry('app.js', ts, 2048)]]);
    const remote = new Map([['app.js', makeEntry('app.js', ts, 2048)]]);
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs).toHaveLength(1);
    expect(diffs[0].status).toBe('identical');
    expect(diffs[0].action).toBe('skip');
  });

  test('mtime в пределах delta (2с) → identical (FAT-диски)', () => {
    const local = new Map([['fat.txt', makeEntry('fat.txt', 1700000000, 100)]]);
    const remote = new Map([['fat.txt', makeEntry('fat.txt', 1700000001, 100)]]);
    const diffs = computeDiff(local, remote, localRoot, remoteRoot, { mtimeDeltaSeconds: 2, ignoreMtime: false, conflictResolution: 'newer', ignore: null });
    expect(diffs[0].status).toBe('identical');
  });

  test('локальный файл новее → action=upload', () => {
    const local = new Map([['script.js', makeEntry('script.js', 1700000100, 999)]]);
    const remote = new Map([['script.js', makeEntry('script.js', 1700000000, 999)]]);
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs[0].action).toBe('upload');
    expect(diffs[0].status).toBe('modified');
  });

  test('удалённый файл новее → action=download', () => {
    const local = new Map([['data.json', makeEntry('data.json', 1700000000, 200)]]);
    const remote = new Map([['data.json', makeEntry('data.json', 1700000200, 200)]]);
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs[0].action).toBe('download');
  });

  test('conflictResolution=local → всегда upload', () => {
    const ts = 1700000000;
    const local = new Map([['conflict.ts', makeEntry('conflict.ts', ts, 500)]]);
    const remote = new Map([['conflict.ts', makeEntry('conflict.ts', ts + 5, 600)]]);
    const opts = { mtimeDeltaSeconds: 2, ignoreMtime: false, conflictResolution: 'local', ignore: null };
    const diffs = computeDiff(local, remote, localRoot, remoteRoot, opts);
    expect(diffs[0].action).toBe('upload');
  });

  test('conflictResolution=remote → всегда download', () => {
    const ts = 1700000000;
    const local = new Map([['conflict.ts', makeEntry('conflict.ts', ts + 10, 500)]]);
    const remote = new Map([['conflict.ts', makeEntry('conflict.ts', ts, 600)]]);
    const opts = { mtimeDeltaSeconds: 2, ignoreMtime: false, conflictResolution: 'remote', ignore: null };
    const diffs = computeDiff(local, remote, localRoot, remoteRoot, opts);
    expect(diffs[0].action).toBe('download');
  });

  test('ignoreMtime=true → сравниваем только size', () => {
    const local = new Map([['img.png', makeEntry('img.png', 1000, 4096)]]);
    const remote = new Map([['img.png', makeEntry('img.png', 9999, 4096)]]);
    const opts = { mtimeDeltaSeconds: 2, ignoreMtime: true, conflictResolution: 'newer', ignore: null };
    const diffs = computeDiff(local, remote, localRoot, remoteRoot, opts);
    expect(diffs[0].status).toBe('identical'); // same size, mtime ignored
  });

  test('несколько файлов — результаты отсортированы по пути', () => {
    const local = new Map([
      ['z.ts', makeEntry('z.ts', 1000, 10)],
      ['a.ts', makeEntry('a.ts', 1000, 10)],
      ['m.ts', makeEntry('m.ts', 1000, 10)],
    ]);
    const remote = new Map();
    const diffs = computeDiff(local, remote, localRoot, remoteRoot);
    expect(diffs.map(d => d.relativePath)).toEqual(['a.ts', 'm.ts', 'z.ts']);
  });

  test('ignore функция исключает файлы', () => {
    const local = new Map([
      ['index.js', makeEntry('index.js', 1000, 100)],
      ['node_modules/pkg.js', makeEntry('pkg.js', 1000, 100)],
    ]);
    const remote = new Map();
    const opts = {
      mtimeDeltaSeconds: 2, ignoreMtime: false, conflictResolution: 'newer',
      ignore: (p) => p.includes('node_modules'),
    };
    const diffs = computeDiff(local, remote, localRoot, remoteRoot, opts);
    expect(diffs.every(d => !d.relativePath.includes('node_modules'))).toBe(true);
  });
});
