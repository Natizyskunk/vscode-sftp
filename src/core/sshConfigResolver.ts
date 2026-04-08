import * as os from 'os';

interface SSHConfigLike {
  find(query: { Host: string }): any;
  compute(host: string): any;
}

interface JumpFallbackOption {
  agent?: string;
  privateKeyPath?: string;
  passphrase?: string | boolean;
  interactiveAuth?: boolean | string[];
  algorithms?: any;
  connectTimeout?: number;
}

interface ResolvedConnectionOption extends JumpFallbackOption {
  host: string;
  port?: number;
  username?: string;
  proxyJump?: ResolvedConnectionOption[];
}

function replaceHomePath(pathname: string) {
  return pathname.substr(0, 2) === '~/' ? `${os.homedir()}/${pathname.slice(2)}` : pathname;
}

function parseInteger(value: any): number | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }

  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}

function firstIdentityFile(value: any): string | undefined {
  if (Array.isArray(value)) {
    return value.length > 0 ? replaceHomePath(value[0]) : undefined;
  }

  if (typeof value === 'string' && value.length > 0) {
    return replaceHomePath(value);
  }

  return undefined;
}

function applyFallbacks(
  option: ResolvedConnectionOption,
  fallback: JumpFallbackOption
): ResolvedConnectionOption {
  const resolved = Object.assign({}, option);
  const keys = [
    'agent',
    'privateKeyPath',
    'passphrase',
    'interactiveAuth',
    'algorithms',
    'connectTimeout',
  ];

  keys.forEach(key => {
    if (resolved[key] === undefined && fallback[key] !== undefined) {
      resolved[key] = fallback[key];
    }
  });

  return resolved;
}

function parseProxyJumpSpec(spec: string): ResolvedConnectionOption {
  const trimmed = spec.trim();
  if (!trimmed) {
    throw new Error('ProxyJump contains an empty host');
  }

  let username;
  let hostPort = trimmed;
  const atIndex = trimmed.lastIndexOf('@');
  if (atIndex > 0) {
    username = trimmed.slice(0, atIndex);
    hostPort = trimmed.slice(atIndex + 1);
  }

  const lastColonIndex = hostPort.lastIndexOf(':');
  const hasPort =
    lastColonIndex > 0 &&
    hostPort.indexOf(']') === -1 &&
    hostPort.indexOf(':') === lastColonIndex;

  let host = hostPort;
  let port;
  if (hasPort) {
    host = hostPort.slice(0, lastColonIndex);
    port = parseInteger(hostPort.slice(lastColonIndex + 1));
  }

  return {
    host,
    port,
    username,
  };
}

function mapComputedConfig(computed: any): ResolvedConnectionOption {
  return {
    host: computed.HostName || computed.Host,
    port: parseInteger(computed.Port),
    username: computed.User,
    privateKeyPath: firstIdentityFile(computed.IdentityFile),
    connectTimeout: parseInteger(computed.ConnectTimeout),
  };
}

function resolveProxyJumpTarget(
  parsedSSHConfig: SSHConfigLike,
  spec: string,
  fallback: JumpFallbackOption,
  visited: Set<string>
): ResolvedConnectionOption[] {
  const found = parsedSSHConfig.find({ Host: spec });
  if (found === null) {
    return [applyFallbacks(parseProxyJumpSpec(spec), fallback)];
  }

  if (visited.has(spec)) {
    throw new Error(`Circular ProxyJump detected for "${spec}"`);
  }

  const nextVisited = new Set(visited);
  nextVisited.add(spec);

  const computed = parsedSSHConfig.compute(spec);
  const current = applyFallbacks(mapComputedConfig(computed), fallback);
  const nested = computed.ProxyJump
    ? resolveProxyJumpChain(parsedSSHConfig, computed.ProxyJump, fallback, nextVisited)
    : [];

  return nested.concat(current);
}

export function splitProxyJump(value: string): string[] {
  return value
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);
}

export function resolveProxyJumpChain(
  parsedSSHConfig: SSHConfigLike,
  proxyJump: string,
  fallback: JumpFallbackOption = {},
  visited: Set<string> = new Set()
): ResolvedConnectionOption[] {
  return splitProxyJump(proxyJump).reduce<ResolvedConnectionOption[]>(
    (result, spec) =>
      result.concat(resolveProxyJumpTarget(parsedSSHConfig, spec, fallback, visited)),
    []
  );
}

export function resolveSSHConfig(
  parsedSSHConfig: SSHConfigLike,
  host: string,
  fallback: JumpFallbackOption = {}
): ResolvedConnectionOption {
  const computed = parsedSSHConfig.compute(host);
  const resolved = applyFallbacks(mapComputedConfig(computed), fallback);
  if (computed.ProxyJump) {
    resolved.proxyJump = resolveProxyJumpChain(
      parsedSSHConfig,
      computed.ProxyJump,
      fallback,
      new Set([host])
    );
  }
  return resolved;
}
