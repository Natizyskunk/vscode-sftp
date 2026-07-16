import * as os from 'os';
import * as path from 'path';
import * as fse from 'fs-extra';
import { writeConfigValue } from '../config';

async function withTempConfig(contents: string, run: (configPath: string) => Promise<void>) {
  const dir = await fse.mkdtemp(path.join(os.tmpdir(), 'sftp-config-'));
  const configPath = path.join(dir, 'sftp.json');
  try {
    await fse.writeFile(configPath, contents, 'utf8');
    await run(configPath);
  } finally {
    await fse.remove(dir);
  }
}

describe('writeConfigValue', () => {
  it('flips a top-level boolean while preserving comments and formatting', async () => {
    const original = [
      '{',
      '    // upload changes automatically',
      '    "uploadOnSave": false,',
      '    "host": "example.com"',
      '}',
      '',
    ].join('\n');

    await withTempConfig(original, async configPath => {
      await writeConfigValue(configPath, 'uploadOnSave', true);
      const updated = await fse.readFile(configPath, 'utf8');
      expect(updated).toContain('// upload changes automatically');
      expect(updated).toContain('"uploadOnSave": true');
      expect(updated).toContain('"host": "example.com"');
    });
  });

  it('inserts the option when it is missing', async () => {
    const original = '{\n    "host": "example.com"\n}\n';

    await withTempConfig(original, async configPath => {
      await writeConfigValue(configPath, 'uploadOnSave', true);
      const updated = await fse.readFile(configPath, 'utf8');
      expect(updated).toContain('"uploadOnSave": true');
      expect(updated).toContain('"host": "example.com"');
    });
  });

  it('edits the matched element in an array of configs', async () => {
    const original = [
      '[',
      '    { "host": "a.example.com", "uploadOnSave": false },',
      '    { "host": "b.example.com", "uploadOnSave": false }',
      ']',
      '',
    ].join('\n');

    await withTempConfig(original, async configPath => {
      await writeConfigValue(
        configPath,
        'uploadOnSave',
        true,
        config => config.host === 'b.example.com'
      );
      const updated = await fse.readFile(configPath, 'utf8');
      const parsed = JSON.parse(updated);
      expect(parsed[0].uploadOnSave).toBe(false);
      expect(parsed[1].uploadOnSave).toBe(true);
    });
  });

  it('defaults to the first element when no matcher hits', async () => {
    const original = '[\n    { "host": "a" },\n    { "host": "b" }\n]\n';

    await withTempConfig(original, async configPath => {
      await writeConfigValue(configPath, 'uploadOnSave', true, () => false);
      const parsed = JSON.parse(await fse.readFile(configPath, 'utf8'));
      expect(parsed[0].uploadOnSave).toBe(true);
      expect(parsed[1].uploadOnSave).toBeUndefined();
    });
  });
});
