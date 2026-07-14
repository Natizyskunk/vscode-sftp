import { Socket } from 'net';
import upath from '../../src/core/upath';
import FTPFileSystem from '../../src/core/fs/ftpFileSystem';
import { ConnectOption } from '../../src/core/remote-client';

// Matches the compose stack in ./docker-compose.yml. Everything here is
// throwaway test-only credentials.
export interface ServerConfig {
  /** describe() label */
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  secure: boolean | 'control';
  secureOptions?: object;
  /** absolute directory the login user may write to */
  baseDir: string;
  /** true when the server advertises MLSD (machine-readable UTC listings) */
  mlsd: boolean;
}

const TLS_OPTIONS = {
  // self-signed test cert
  rejectUnauthorized: false,
  // pure-ftpd needs TLS session reuse on data connections; with TLS 1.3 the
  // control-socket ticket isn't reusable in time, so pin 1.2 for the tests.
  maxVersion: 'TLSv1.2',
};

export const VSFTPD: ServerConfig = {
  name: 'vsftpd (plain FTP, LIST)',
  host: '127.0.0.1',
  port: 2121,
  username: 'testuser',
  password: 'testpass',
  secure: false,
  baseDir: '/ftp/testuser',
  mlsd: false,
};

export const PUREFTPD_TLS: ServerConfig = {
  name: 'pure-ftpd (explicit FTPS, MLSD)',
  host: '127.0.0.1',
  port: 2101,
  username: 'testuser',
  password: 'testpass',
  secure: true,
  secureOptions: TLS_OPTIONS,
  baseDir: '/',
  mlsd: true,
};

export const PUREFTPD_CONTROL: ServerConfig = {
  ...PUREFTPD_TLS,
  name: 'pure-ftpd (secure: "control", clear-text data)',
  secure: 'control',
};

function toConnectOption(server: ServerConfig): ConnectOption {
  return {
    protocol: 'ftp',
    host: server.host,
    port: server.port,
    username: server.username,
    password: server.password,
    connectTimeout: 10 * 1000,
    secure: server.secure,
    secureOptions: server.secureOptions,
    debug: () => undefined,
  };
}

function newFs(server: ServerConfig): FTPFileSystem {
  return new FTPFileSystem(upath, { clientOption: toConnectOption(server) });
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Connect with a few retries ONLY at setup (never wrap assertions in retries):
// the compose stack may still be settling when the first spec runs.
export async function connectFs(
  server: ServerConfig,
  attempts = 4
): Promise<FTPFileSystem> {
  let lastError: unknown;
  for (let i = 0; i < attempts; i += 1) {
    const fs = newFs(server);
    try {
      await fs.connect(toConnectOption(server), {
        askForPasswd: async () => undefined,
      });
      return fs;
    } catch (error) {
      lastError = error;
      fs.end();
      await sleep(1000);
    }
  }
  throw lastError;
}

// The raw net.Socket carrying the control connection. Destroying it simulates a
// server dropping an idle connection (the extension sends no NOOP keepalives).
export function controlSocket(fs: FTPFileSystem): Socket {
  // FTPFileSystem.ftp is the basic-ftp Client; .ftp is its FTPContext.
  return (fs as any).ftp.ftp.socket as Socket;
}

let counter = 0;
// Unique working directory per test so specs don't collide on shared servers.
export function uniqueDir(server: ServerConfig): string {
  counter += 1;
  return upath.join(server.baseDir, `it-${Date.now()}-${counter}`);
}

// Mirrors the app's KeepAliveRemoteFs reconnect contract without any VS Code
// dependency: mark the connection invalid when it drops, and transparently
// reconnect on the next operation.
export class ReconnectingFtpFs {
  private fs: FTPFileSystem | null = null;
  private valid = false;

  constructor(private readonly server: ServerConfig) {}

  private async ensure(): Promise<FTPFileSystem> {
    if (this.valid && this.fs) {
      return this.fs;
    }
    const fs = await connectFs(this.server);
    fs.onDisconnected(() => {
      this.valid = false;
    });
    this.fs = fs;
    this.valid = true;
    return fs;
  }

  async run<T>(op: (fs: FTPFileSystem) => Promise<T>): Promise<T> {
    const fs = await this.ensure();
    return op(fs);
  }

  isValid(): boolean {
    return this.valid;
  }

  dropControlConnection(): void {
    if (this.fs) {
      controlSocket(this.fs).destroy();
    }
  }

  end(): void {
    if (this.fs) {
      this.fs.end();
    }
  }
}
