import { LogEntry } from './types';

// Combined Log Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
const ACCESS_LOG_REGEX =
  /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/;

// Nginx error log: YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message
const NGINX_ERROR_REGEX =
  /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s+(?:\*\d+\s+)?(.+)/;

// Apache error log: [Day Mon DD HH:MM:SS.USEC YYYY] [module:level] [pid PID] message
const APACHE_ERROR_REGEX =
  /^\[([^\]]+)\]\s+\[(?:\w+:)?(\w+)\]\s+\[pid\s+\d+\]\s+(.+)/;

function parseAccessLogDate(dateStr: string): Date | null {
  // Format: 10/Oct/2000:13:55:36 -0700
  const match = dateStr.match(
    /(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})/
  );
  if (!match) return null;
  const months = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
  };
  return new Date(
    parseInt(match[3]),
    months[match[2]] || 0,
    parseInt(match[1]),
    parseInt(match[4]),
    parseInt(match[5]),
    parseInt(match[6])
  );
}

export function parseAccessLog(line: string): LogEntry | null {
  const match = line.match(ACCESS_LOG_REGEX);
  if (!match) return null;

  return {
    ip: match[1],
    timestamp: parseAccessLogDate(match[2]),
    method: match[3],
    uri: match[4],
    status: parseInt(match[5]),
    size: match[6] === '-' ? 0 : parseInt(match[6]),
    referer: match[7],
    userAgent: match[8],
    level: '',
    message: '',
    raw: line,
  };
}

export function parseErrorLog(line: string): LogEntry | null {
  let match = line.match(NGINX_ERROR_REGEX);
  if (match) {
    return {
      ip: '',
      timestamp: new Date(match[1].replace(/\//g, '-')),
      method: '',
      uri: '',
      status: 0,
      size: 0,
      referer: '',
      userAgent: '',
      level: match[2],
      message: match[3],
      raw: line,
    };
  }

  match = line.match(APACHE_ERROR_REGEX);
  if (match) {
    return {
      ip: '',
      timestamp: new Date(match[1]),
      method: '',
      uri: '',
      status: 0,
      size: 0,
      referer: '',
      userAgent: '',
      level: match[2],
      message: match[3],
      raw: line,
    };
  }

  return null;
}

export type LogFormat = 'access' | 'error';

export function detectLogFormat(lines: string[]): LogFormat {
  let accessCount = 0;
  let errorCount = 0;
  const sample = lines.slice(0, 20);
  for (const line of sample) {
    if (ACCESS_LOG_REGEX.test(line)) accessCount++;
    if (NGINX_ERROR_REGEX.test(line) || APACHE_ERROR_REGEX.test(line)) errorCount++;
  }
  return accessCount >= errorCount ? 'access' : 'error';
}

export function parseLogLines(lines: string[], format?: LogFormat): LogEntry[] {
  if (!format) {
    format = detectLogFormat(lines);
  }
  const parser = format === 'access' ? parseAccessLog : parseErrorLog;
  const entries: LogEntry[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const entry = parser(line);
    if (entry) entries.push(entry);
  }
  return entries;
}
