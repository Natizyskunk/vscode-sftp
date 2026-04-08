jest.mock('../../app', () => ({
  __esModule: true,
  default: {
    fsCache: new Map(),
    state: {
      profile: null,
    },
  },
}));

jest.mock('../../logger', () => ({
  __esModule: true,
  default: {
    trace: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    critical: jest.fn(),
  },
}));

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import FileService from '../fileService';

describe('FileService ssh config integration', () => {
  test('preserves ProxyJump when HostName is resolved from ssh config', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sftp-proxyjump-'));
    const sshConfigPath = path.join(tempDir, 'ssh_config');

    fs.writeFileSync(
      sshConfigPath,
      `
Host target-alias
  HostName target.internal
  User root
  Port 22
  ProxyJump bastion
  IdentityFile ~/.ssh/id_ed25519

Host bastion
  HostName bastion.example.com
  User root
  Port 2222
  IdentityFile ~/.ssh/id_ed25519
`
    );

    const service = new FileService(tempDir, tempDir, {
      name: 'target-alias',
      protocol: 'sftp',
      host: 'target-alias',
      remotePath: '/workspace/project',
      uploadOnSave: true,
      useTempFile: false,
      ignore: [],
      sshConfigPath,
    } as any);

    const config = service.getConfig();

    expect(config.host).toBe('target.internal');
    expect(config.port).toBe(22);
    expect(config.username).toBe('root');
    expect(config.sshHostAlias).toBe('target-alias');
    expect(config.proxyJump).toEqual([
      {
        host: 'bastion.example.com',
        port: 2222,
        username: 'root',
        privateKeyPath: `${os.homedir()}/.ssh/id_ed25519`,
        connectTimeout: undefined,
      },
    ]);
  });
});
