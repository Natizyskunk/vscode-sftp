const fs = jest.requireActual('fs');
const os = require('os');
const path = require('path');
const { toRemotePath } = require('../src/helper/paths');

describe('toRemotePath', () => {
  let localRoot;

  beforeAll(() => {
    localRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'vscode-sftp-paths-'));
    fs.mkdirSync(path.join(localRoot, 'dir'));
    fs.writeFileSync(path.join(localRoot, 'dir', 'file.txt'), '');
  });

  afterAll(() => {
    fs.rmSync(localRoot, { recursive: true, force: true });
  });

  test('existing file', () => {
    expect(toRemotePath(path.join(localRoot, 'dir', 'file.txt'), localRoot, '/remote')).toEqual(
      '/remote/dir/file.txt'
    );
  });

  test('file that does not exist locally', () => {
    expect(toRemotePath(path.join(localRoot, 'dir', 'deleted.txt'), localRoot, '/remote')).toEqual(
      '/remote/dir/deleted.txt'
    );
    expect(toRemotePath(path.join(localRoot, 'missing', 'deleted.txt'), localRoot, '/remote')).toEqual(
      '/remote/missing/deleted.txt'
    );
  });
});
