import * as os from 'os';
import * as sshConfig from 'ssh-config';
import {
  resolveProxyJumpChain,
  resolveSSHConfig,
  splitProxyJump,
} from '../sshConfigResolver';

function parse(content: string) {
  return sshConfig.parse(content);
}

describe('sshConfigResolver', () => {
  test('splitProxyJump keeps hop order', () => {
    expect(splitProxyJump('jump-a, jump-b ,jump-c')).toEqual([
      'jump-a',
      'jump-b',
      'jump-c',
    ]);
  });

  test('resolveSSHConfig includes proxy jump aliases from ssh config', () => {
    const parsed = parse(`
Host jump-a
  HostName bastion.example.com
  User root
  IdentityFile ~/.ssh/jump_a

Host target
  HostName target.internal
  User app
  Port 2222
  ProxyJump jump-a
  IdentityFile ~/.ssh/target_key
`);

    const resolved = resolveSSHConfig(parsed as any, 'target');

    expect(resolved.host).toBe('target.internal');
    expect(resolved.username).toBe('app');
    expect(resolved.port).toBe(2222);
    expect(resolved.privateKeyPath).toBe(`${os.homedir()}/.ssh/target_key`);
    expect(resolved.proxyJump).toEqual([
      {
        host: 'bastion.example.com',
        port: undefined,
        username: 'root',
        privateKeyPath: `${os.homedir()}/.ssh/jump_a`,
        connectTimeout: undefined,
      },
    ]);
  });

  test('resolveProxyJumpChain flattens nested proxy jumps', () => {
    const parsed = parse(`
Host edge
  HostName edge.example.com

Host mid
  HostName mid.internal
  ProxyJump edge

Host target
  HostName target.internal
  ProxyJump mid
`);

    const resolved = resolveSSHConfig(parsed as any, 'target', {
      privateKeyPath: '/tmp/shared-key',
    });

    expect(resolved.proxyJump).toEqual([
      {
        host: 'edge.example.com',
        port: undefined,
        username: undefined,
        privateKeyPath: '/tmp/shared-key',
        connectTimeout: undefined,
      },
      {
        host: 'mid.internal',
        port: undefined,
        username: undefined,
        privateKeyPath: '/tmp/shared-key',
        connectTimeout: undefined,
      },
    ]);
  });

  test('resolveProxyJumpChain supports literal user host port specs', () => {
    const parsed = parse(`
Host target
  HostName target.internal
  ProxyJump root@bastion.example.com:2222
`);

    const chain = resolveProxyJumpChain(
      parsed as any,
      'root@bastion.example.com:2222'
    );

    expect(chain).toEqual([
      {
        host: 'bastion.example.com',
        port: 2222,
        username: 'root',
      },
    ]);
  });
});
