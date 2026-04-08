jest.mock('../../../logger', () => ({
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

import SSHClient from '../sshClient';
import localFs from '../../localFs';

describe('SSHClient proxyJump', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('does not open sftp subsystems on proxy jump intermediates', async () => {
    jest
      .spyOn(localFs, 'readFile')
      .mockImplementation(async () => Buffer.from('PRIVATE KEY'));

    const connectSSHClient = jest
      .spyOn(SSHClient.prototype as any, '_connectSSHClient')
      .mockImplementation(async () => undefined);
    const getSftp = jest
      .spyOn(SSHClient.prototype as any, '_getSftp')
      .mockResolvedValue({ readdir: jest.fn() });
    const makeHopping = jest
      .spyOn(SSHClient.prototype as any, '_makeHopping')
      .mockImplementation(async () => ({ on() {}, once() {}, end() {} }));

    const option: any = {
      host: 'target.internal',
      port: 22,
      username: 'root',
      privateKeyPath: '/tmp/target-key',
      proxyJump: [
        {
          host: 'bastion.example.com',
          port: 2222,
          username: 'root',
          privateKeyPath: '/tmp/jump-key',
        },
      ],
      debug() {},
    };

    const client = new SSHClient(option);
    await client.connect(option, {
      askForPasswd: async () => undefined,
    });

    expect(connectSSHClient).toHaveBeenCalledTimes(2);
    expect(makeHopping).toHaveBeenCalledTimes(1);
    expect(getSftp).toHaveBeenCalledTimes(1);
  });
});
