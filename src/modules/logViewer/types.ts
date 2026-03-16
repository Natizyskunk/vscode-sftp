export interface LogEntry {
  ip: string;
  timestamp: Date | null;
  method: string;
  uri: string;
  status: number;
  size: number;
  referer: string;
  userAgent: string;
  level: string;
  message: string;
  raw: string;
}

export interface LogFilter {
  dateFrom?: Date;
  dateTo?: Date;
  statusCodes?: number[];
  ipFilter?: string;
  uriPattern?: string;
  userAgentPattern?: string;
}

export interface LogGroup {
  key: string;
  count: number;
  entries: LogEntry[];
}

export interface LogStats {
  totalRequests: number;
  uniqueIPs: number;
  statusBreakdown: { [code: number]: number };
  topIPs: { ip: string; count: number }[];
  topURIs: { uri: string; count: number }[];
  suspiciousPatterns: SuspiciousPattern[];
}

export interface SuspiciousPattern {
  type: string;
  description: string;
  count: number;
  entries: LogEntry[];
}

export const DEFAULT_LOG_PATHS = [
  '/var/log/nginx/access.log',
  '/var/log/nginx/error.log',
  '/var/log/apache2/access.log',
  '/var/log/apache2/error.log',
  '/var/log/httpd/access_log',
  '/var/log/httpd/error_log',
];
