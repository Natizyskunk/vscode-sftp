import logger from '../../logger';
import { DEFAULT_LOG_PATHS } from './types';

export interface StopHandle {
  stop(): void;
}

export function fetchLogLines(
  client: any,
  logPath: string,
  maxLines: number = 1000
): Promise<string[]> {
  return new Promise((resolve, reject) => {
    client.exec(`tail -n ${maxLines} ${escapeShellArg(logPath)}`, (err, stream) => {
      if (err) return reject(err);
      let output = '';
      stream.on('data', (data) => { output += data.toString(); });
      stream.stderr.on('data', (data) => {
        logger.warn(`fetchLogLines stderr: ${data.toString()}`);
      });
      stream.on('close', () => {
        resolve(output.split('\n').filter(l => l.trim()));
      });
      stream.on('error', reject);
    });
  });
}

export function streamLog(
  client: any,
  logPath: string,
  onLine: (line: string) => void,
  onError: (err: Error) => void
): StopHandle {
  let stream: any = null;
  let stopped = false;

  client.exec(`tail -f ${escapeShellArg(logPath)}`, (err, s) => {
    if (err) {
      onError(err);
      return;
    }
    if (stopped) {
      s.close();
      return;
    }
    stream = s;
    let buffer = '';
    s.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) onLine(line);
      }
    });
    s.stderr.on('data', (data) => {
      logger.warn(`streamLog stderr: ${data.toString()}`);
    });
    s.on('close', () => {
      if (!stopped) {
        onError(new Error('Stream closed unexpectedly'));
      }
    });
    s.on('error', onError);
  });

  return {
    stop() {
      stopped = true;
      if (stream) {
        stream.close();
      }
    },
  };
}

export function discoverLogFiles(
  client: any,
  customPaths: string[] = []
): Promise<string[]> {
  const searchDirs = ['/var/log/nginx', '/var/log/apache2', '/var/log/httpd'];
  const findCmd = searchDirs
    .map(d => `find ${d} -name '*.log' -o -name '*_log' 2>/dev/null`)
    .join('; ');

  return new Promise((resolve, reject) => {
    client.exec(findCmd, (err, stream) => {
      if (err) return reject(err);
      let output = '';
      stream.on('data', (data) => { output += data.toString(); });
      stream.stderr.on('data', () => { /* ignore */ });
      stream.on('close', () => {
        const found = output.split('\n').filter(l => l.trim());
        // Combine discovered files, defaults, and custom paths — deduplicate
        const all = [...new Set([...found, ...DEFAULT_LOG_PATHS, ...customPaths])];
        resolve(all);
      });
      stream.on('error', reject);
    });
  });
}

function escapeShellArg(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}
