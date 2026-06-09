jest.mock('vscode');

import * as fse from 'fs-extra';
import * as os from 'os';
import * as path from 'path';
import { readConfigsFromFile } from '../config';

describe('readConfigsFromFile JSONC support', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fse.mkdtemp(path.join(os.tmpdir(), 'sftp-jsonc-'));
  });

  afterEach(async () => {
    await fse.remove(tempDir);
  });

  test('parses config with comments and trailing comma', async () => {
    const configPath = path.join(tempDir, 'sftp.json');
    await fse.writeFile(
      configPath,
      `{
        // Server profile
        "host": "example.com",
        "username": "dev",
        "remotePath": "/",
        "uploadOnSave": true,
      }`
    );

    const [config] = await readConfigsFromFile(configPath);

    expect(config.host).toBe('example.com');
    expect(config.username).toBe('dev');
    expect(config.remotePath).toBe('/');
    expect(config.uploadOnSave).toBe(true);
    expect(config.protocol).toBe('sftp');
  });

  test('throws for invalid JSONC', async () => {
    const configPath = path.join(tempDir, 'sftp.json');
    await fse.writeFile(configPath, '{ "host": "example.com" "username": "dev" }');

    await expect(readConfigsFromFile(configPath)).rejects.toThrow('Invalid JSONC');
  });
});
