import { Readable } from 'stream';
import { randomBytes } from 'crypto';
import upath from '../../src/core/upath';
import { FileType } from '../../src/core/fs/fileSystem';
import FTPFileSystem from '../../src/core/fs/ftpFileSystem';
import {
  ServerConfig,
  VSFTPD,
  PUREFTPD_TLS,
  PUREFTPD_CONTROL,
  connectFs,
  controlSocket,
  uniqueDir,
  ReconnectingFtpFs,
} from './helpers';

const upload = (fs: FTPFileSystem, buf: Buffer, path: string): Promise<void> =>
  fs.put(Readable.from(buf), path);

const download = (fs: FTPFileSystem, path: string): Promise<Buffer> =>
  fs.readFile(path) as Promise<Buffer>;

// ---------------------------------------------------------------------------
// connect / disconnect across all three `secure` semantics. For secure:"control"
// this is the only place that proves clear-text data connections still transfer.
// ---------------------------------------------------------------------------
describe.each([VSFTPD, PUREFTPD_TLS, PUREFTPD_CONTROL])(
  'connect / disconnect — $name',
  (server: ServerConfig) => {
    test('connects, transfers data, and reports disconnect', async () => {
      const fs = await connectFs(server);
      try {
        // TLS on the control channel for both FTPS modes (secure:true and
        // secure:"control"); plain FTP leaves it unencrypted.
        expect(Boolean((controlSocket(fs) as any).encrypted)).toBe(server.secure !== false);

        const dir = uniqueDir(server);
        await fs.ensureDir(dir);
        const path = upath.join(dir, 'probe.bin');
        const blob = randomBytes(64 * 1024);
        await upload(fs, blob, path);
        expect(Buffer.compare(await download(fs, path), blob)).toBe(0);
        await fs.rmdir(dir, true);

        // end() must notify onDisconnected listeners (drives app-level reconnect)
        const disconnected = new Promise<string>(resolve =>
          fs.onDisconnected(reason => resolve(reason))
        );
        fs.end();
        expect(await disconnected).toBeTruthy();
      } finally {
        fs.end();
      }
    });
  }
);

// ---------------------------------------------------------------------------
// Full filesystem operation set against a plain (LIST) and an FTPS (MLSD) server.
// ---------------------------------------------------------------------------
describe.each([VSFTPD, PUREFTPD_TLS])(
  'filesystem operations — $name',
  (server: ServerConfig) => {
    let fs: FTPFileSystem;

    beforeAll(async () => {
      fs = await connectFs(server);
    });

    afterAll(() => {
      if (fs) fs.end();
    });

    test('mkdir (nested) + list + lstat', async () => {
      const dir = uniqueDir(server);
      const nested = upath.join(dir, 'a', 'b');
      await fs.ensureDir(nested);

      const stat = await fs.lstat(nested);
      expect(stat.type).toBe(FileType.Directory);

      const entries = await fs.list(upath.join(dir, 'a'));
      expect(entries.map(e => e.name)).toContain('b');

      await fs.rmdir(dir, true);
    });

    test('put / get text roundtrip', async () => {
      const dir = uniqueDir(server);
      await fs.ensureDir(dir);
      const path = upath.join(dir, 'hello.txt');
      const text = 'héllo\nworld — ftp roundtrip\n'.repeat(20);

      await upload(fs, Buffer.from(text, 'utf8'), path);
      const got = await fs.readFile(path, { encoding: 'utf8' });
      expect(got).toBe(text);

      await fs.rmdir(dir, true);
    });

    test('put / get binary roundtrip (a few MB, byte-for-byte)', async () => {
      const dir = uniqueDir(server);
      await fs.ensureDir(dir);
      const path = upath.join(dir, 'blob.bin');
      const blob = randomBytes(3 * 1024 * 1024 + 7);

      await upload(fs, blob, path);
      const got = await download(fs, path);
      expect(got.length).toBe(blob.length);
      expect(Buffer.compare(got, blob)).toBe(0);

      const stat = await fs.lstat(path);
      expect(stat.size).toBe(blob.length);

      await fs.rmdir(dir, true);
    });

    test('rename', async () => {
      const dir = uniqueDir(server);
      await fs.ensureDir(dir);
      const src = upath.join(dir, 'src.txt');
      const dest = upath.join(dir, 'dest.txt');
      await upload(fs, Buffer.from('rename me'), src);

      await fs.rename(src, dest);

      const names = (await fs.list(dir)).map(e => e.name);
      expect(names).toContain('dest.txt');
      expect(names).not.toContain('src.txt');

      await fs.rmdir(dir, true);
    });

    test('delete file + recursive delete directory', async () => {
      const dir = uniqueDir(server);
      const sub = upath.join(dir, 'sub');
      await fs.ensureDir(sub);
      const top = upath.join(dir, 'top.txt');
      const nested = upath.join(sub, 'nested.txt');
      await upload(fs, Buffer.from('1'), top);
      await upload(fs, Buffer.from('2'), nested);

      await fs.unlink(top);
      expect((await fs.list(dir)).map(e => e.name)).not.toContain('top.txt');

      await fs.rmdir(dir, true);
      await expect(fs.lstat(dir)).rejects.toBeDefined();
    });

    test('passive-mode data transfer', async () => {
      // basic-ftp opens every data connection with EPSV (passive); a completed
      // transfer of a non-trivial payload exercises that path end-to-end.
      const dir = uniqueDir(server);
      await fs.ensureDir(dir);
      const path = upath.join(dir, 'passive.bin');
      const blob = randomBytes(512 * 1024);

      await upload(fs, blob, path);
      expect(Buffer.compare(await download(fs, path), blob)).toBe(0);

      await fs.rmdir(dir, true);
    });

    test('get() rejects for a missing file', async () => {
      const dir = uniqueDir(server);
      await fs.ensureDir(dir);
      await expect(download(fs, upath.join(dir, 'nope.txt'))).rejects.toBeDefined();
      await fs.rmdir(dir, true);
    });
  }
);

// ---------------------------------------------------------------------------
// MLSD gives machine-readable, second-precision UTC timestamps.
// ---------------------------------------------------------------------------
describe('MLSD timestamp precision — pure-ftpd', () => {
  let fs: FTPFileSystem;

  beforeAll(async () => {
    fs = await connectFs(PUREFTPD_TLS);
  });

  afterAll(() => {
    if (fs) fs.end();
  });

  test('listed mtime is second-precision UTC close to now', async () => {
    const dir = uniqueDir(PUREFTPD_TLS);
    await fs.ensureDir(dir);
    const path = upath.join(dir, 'stamp.txt');

    const before = Date.now();
    await upload(fs, Buffer.from('now'), path);
    const after = Date.now();

    const entry = (await fs.list(dir)).find(e => e.name === 'stamp.txt');
    expect(entry).toBeDefined();

    // No sub-second component.
    expect(entry!.mtime % 1000).toBe(0);
    // MLSD reports UTC; a LIST-style local time or minute-rounded value with a
    // timezone offset would land hours away. UTC seconds land within our window.
    expect(entry!.mtime).toBeGreaterThanOrEqual(before - 120000);
    expect(entry!.mtime).toBeLessThanOrEqual(after + 120000);

    await fs.rmdir(dir, true);
  });
});

// ---------------------------------------------------------------------------
// secure:"control" — TLS control channel, clear-text data channel.
// ---------------------------------------------------------------------------
describe('secure: "control" — pure-ftpd', () => {
  let fs: FTPFileSystem;

  beforeAll(async () => {
    fs = await connectFs(PUREFTPD_CONTROL);
  });

  afterAll(() => {
    if (fs) fs.end();
  });

  test('control channel is TLS while data transfers succeed in clear text', async () => {
    expect((controlSocket(fs) as any).encrypted).toBe(true);

    const dir = uniqueDir(PUREFTPD_CONTROL);
    await fs.ensureDir(dir);
    const path = upath.join(dir, 'control.bin');
    const blob = randomBytes(256 * 1024);

    await upload(fs, blob, path);
    expect(Buffer.compare(await download(fs, path), blob)).toBe(0);

    await fs.rmdir(dir, true);
  });
});

// ---------------------------------------------------------------------------
// Idle reconnect: no NOOP keepalive, so a dropped control connection is
// re-established transparently on the next operation.
// ---------------------------------------------------------------------------
describe('idle reconnect — vsftpd', () => {
  test('transparently reconnects after the control connection drops', async () => {
    const wrapper = new ReconnectingFtpFs(VSFTPD);
    try {
      const dir = uniqueDir(VSFTPD);
      await wrapper.run(fs => fs.ensureDir(dir));
      expect(wrapper.isValid()).toBe(true);

      // Simulate the server dropping an idle connection.
      wrapper.dropControlConnection();
      await new Promise(resolve => setTimeout(resolve, 300));
      expect(wrapper.isValid()).toBe(false);

      // The next operation must reconnect on its own and succeed.
      const path = upath.join(dir, 'after-reconnect.txt');
      await wrapper.run(fs => upload(fs, Buffer.from('back'), path));
      const got = await wrapper.run(fs => fs.readFile(path, { encoding: 'utf8' }));
      expect(got).toBe('back');
      expect(wrapper.isValid()).toBe(true);

      await wrapper.run(fs => fs.rmdir(dir, true));
    } finally {
      wrapper.end();
    }
  });
});
