import * as net from 'net';
import logger from '../../logger';

const INTERNAL_HOSTS = ['127.0.0.1', 'localhost', '::1'];

interface TunnelInfo {
  server: net.Server;
  localPort: number;
}

const tunnelCache: Map<string, TunnelInfo> = new Map();

function isInternalHost(host: string): boolean {
  return INTERNAL_HOSTS.indexOf(host) !== -1;
}

function getTunnelKey(dbHost: string, dbPort: number): string {
  return `${dbHost}:${dbPort}`;
}

export function needsTunnel(dbHost: string): boolean {
  return isInternalHost(dbHost);
}

export function createTunnel(
  sshClient: any,
  dbHost: string,
  dbPort: number
): Promise<{ host: string; port: number }> {
  const key = getTunnelKey(dbHost, dbPort);
  const existing = tunnelCache.get(key);
  if (existing) {
    return Promise.resolve({ host: '127.0.0.1', port: existing.localPort });
  }

  return new Promise((resolve, reject) => {
    const server = net.createServer(socket => {
      sshClient.forwardOut(
        '127.0.0.1',
        0,
        dbHost,
        dbPort,
        (err: Error | undefined, stream: any) => {
          if (err) {
            socket.end();
            return;
          }
          socket.pipe(stream).pipe(socket);
        }
      );
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as net.AddressInfo;
      const info: TunnelInfo = { server, localPort: addr.port };
      tunnelCache.set(key, info);
      logger.info(`SSH tunnel created: 127.0.0.1:${addr.port} -> ${dbHost}:${dbPort}`);
      resolve({ host: '127.0.0.1', port: addr.port });
    });

    server.on('error', (err: Error) => {
      logger.error(err, 'SSH tunnel server error');
      reject(err);
    });

    sshClient.on('close', () => {
      closeTunnel(dbHost, dbPort);
    });

    sshClient.on('end', () => {
      closeTunnel(dbHost, dbPort);
    });
  });
}

export function closeTunnel(dbHost: string, dbPort: number) {
  const key = getTunnelKey(dbHost, dbPort);
  const info = tunnelCache.get(key);
  if (info) {
    info.server.close();
    tunnelCache.delete(key);
    logger.info(`SSH tunnel closed: ${key}`);
  }
}

export function closeAllTunnels() {
  tunnelCache.forEach((info, key) => {
    info.server.close();
    logger.info(`SSH tunnel closed: ${key}`);
  });
  tunnelCache.clear();
}
