jest.mock('fs');

import { vol } from 'memfs';
import { readConfigsFromFile, validateConfig } from '../config';

const CONFIG_PATH = '/ws/.vscode/sftp.json';

beforeEach(() => {
  vol.reset();
});

describe('readConfigsFromFile', () => {
  test('parses a config containing comments and a trailing comma', async () => {
    vol.fromJSON({
      [CONFIG_PATH]: `{
  // the server we deploy to
  "name": "My Server", // inline comment
  "host": "example.com",
  /* credentials are prompted at connect time,
     see the SFTP: Save Password command */
  "protocol": "sftp",
  "port": 22,
  "username": "bob",
  "remotePath": "/var/www",
}`,
    });

    const configs = await readConfigsFromFile(CONFIG_PATH);
    expect(configs).toHaveLength(1);

    const config = configs[0];
    expect(config.name).toBe('My Server');
    expect(config.host).toBe('example.com');
    expect(config.port).toBe(22);
    expect(config.username).toBe('bob');
    expect(config.remotePath).toBe('/var/www');
    // defaults are still merged over the parsed result
    expect(config.concurrency).toBe(4);
    // and the parsed result still passes joi validation
    expect(validateConfig(config)).toBeUndefined();
  });

  test('parses an array config with comments and trailing commas', async () => {
    vol.fromJSON({
      [CONFIG_PATH]: `[
  {
    "name": "A", // first server
    "context": "a",
    "host": "a.example.com",
    "username": "bob",
    "remotePath": "/a",
  },
  {
    "name": "B",
    "context": "b",
    "host": "b.example.com",
    "username": "bob",
    "remotePath": "/b",
  },
]`,
    });

    const configs = await readConfigsFromFile(CONFIG_PATH);
    expect(configs).toHaveLength(2);
    expect(configs[0].host).toBe('a.example.com');
    expect(configs[1].host).toBe('b.example.com');
  });

  test('reports line and column on a parse error', async () => {
    vol.fromJSON({
      [CONFIG_PATH]: '{\n  "host": "example.com"\n  "username": "bob"\n}',
    });

    await expect(readConfigsFromFile(CONFIG_PATH)).rejects.toThrow(/line 3, column 3/);
  });

  test('rejects an empty file', async () => {
    vol.fromJSON({
      [CONFIG_PATH]: '',
    });

    await expect(readConfigsFromFile(CONFIG_PATH)).rejects.toThrow(/Failed to parse/);
  });
});
