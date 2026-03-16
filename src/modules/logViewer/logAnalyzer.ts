import { LogEntry, LogFilter, LogGroup, LogStats, SuspiciousPattern } from './types';

export function filterEntries(entries: LogEntry[], filter: LogFilter): LogEntry[] {
  return entries.filter(entry => {
    if (filter.dateFrom && entry.timestamp && entry.timestamp < filter.dateFrom) return false;
    if (filter.dateTo && entry.timestamp && entry.timestamp > filter.dateTo) return false;
    if (filter.statusCodes && filter.statusCodes.length > 0 && !filter.statusCodes.includes(entry.status)) return false;
    if (filter.ipFilter && entry.ip && !entry.ip.includes(filter.ipFilter)) return false;
    if (filter.uriPattern) {
      try {
        if (!new RegExp(filter.uriPattern).test(entry.uri)) return false;
      } catch {
        if (!entry.uri.includes(filter.uriPattern)) return false;
      }
    }
    if (filter.userAgentPattern) {
      try {
        if (!new RegExp(filter.userAgentPattern).test(entry.userAgent)) return false;
      } catch {
        if (!entry.userAgent.includes(filter.userAgentPattern)) return false;
      }
    }
    return true;
  });
}

export function groupBy(
  entries: LogEntry[],
  key: 'ip' | 'uri' | 'userAgent' | 'status'
): LogGroup[] {
  const map = new Map<string, LogEntry[]>();
  for (const entry of entries) {
    const k = String(entry[key] || 'unknown');
    const group = map.get(k);
    if (group) {
      group.push(entry);
    } else {
      map.set(k, [entry]);
    }
  }
  return Array.from(map.entries())
    .map(([k, v]) => ({ key: k, count: v.length, entries: v }))
    .sort((a, b) => b.count - a.count);
}

export function computeStats(entries: LogEntry[]): LogStats {
  const ips = new Map<string, number>();
  const uris = new Map<string, number>();
  const statusBreakdown: { [code: number]: number } = {};

  for (const entry of entries) {
    if (entry.ip) {
      ips.set(entry.ip, (ips.get(entry.ip) || 0) + 1);
    }
    if (entry.uri) {
      uris.set(entry.uri, (uris.get(entry.uri) || 0) + 1);
    }
    if (entry.status) {
      statusBreakdown[entry.status] = (statusBreakdown[entry.status] || 0) + 1;
    }
  }

  const topIPs = Array.from(ips.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const topURIs = Array.from(uris.entries())
    .map(([uri, count]) => ({ uri, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalRequests: entries.length,
    uniqueIPs: ips.size,
    statusBreakdown,
    topIPs,
    topURIs,
    suspiciousPatterns: detectSuspiciousPatterns(entries),
  };
}

const SUSPICIOUS_PATTERNS: { type: string; description: string; pattern: RegExp }[] = [
  { type: 'sql_injection', description: 'Potential SQL injection', pattern: /('|--|;|union\s+select|drop\s+table)/i },
  { type: 'path_traversal', description: 'Path traversal attempt', pattern: /(\.\.[\/\\]|%2e%2e)/i },
  { type: 'xss', description: 'Potential XSS attempt', pattern: /(<script|javascript:|onerror=|onload=)/i },
  { type: 'scanner', description: 'Known scanner/bot', pattern: /(nikto|sqlmap|nmap|masscan|zgrab)/i },
  { type: 'shell_shock', description: 'Shellshock attempt', pattern: /\(\)\s*\{/i },
  { type: 'wp_scan', description: 'WordPress scan', pattern: /(wp-admin|wp-login|xmlrpc\.php|wp-content\/uploads)/i },
];

export function detectSuspiciousPatterns(entries: LogEntry[]): SuspiciousPattern[] {
  const results: SuspiciousPattern[] = [];

  for (const sp of SUSPICIOUS_PATTERNS) {
    const matched = entries.filter(e =>
      sp.pattern.test(e.uri) || sp.pattern.test(e.userAgent) || sp.pattern.test(e.message)
    );
    if (matched.length > 0) {
      results.push({
        type: sp.type,
        description: sp.description,
        count: matched.length,
        entries: matched.slice(0, 5),
      });
    }
  }

  // High request rate per IP (>100 requests)
  const ipCounts = new Map<string, number>();
  for (const entry of entries) {
    if (entry.ip) {
      ipCounts.set(entry.ip, (ipCounts.get(entry.ip) || 0) + 1);
    }
  }
  const highRate = Array.from(ipCounts.entries()).filter(([, count]) => count > 100);
  if (highRate.length > 0) {
    results.push({
      type: 'high_rate',
      description: `High request rate from ${highRate.length} IP(s)`,
      count: highRate.reduce((sum, [, c]) => sum + c, 0),
      entries: [],
    });
  }

  return results;
}
