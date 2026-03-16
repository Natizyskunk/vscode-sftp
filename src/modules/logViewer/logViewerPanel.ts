import * as vscode from 'vscode';
import { FileService, ServiceConfig } from '../../core';
import { parseLogLines } from './logParser';
import { filterEntries, groupBy, computeStats } from './logAnalyzer';
import { fetchLogLines, streamLog, discoverLogFiles, StopHandle } from './logFetcher';
import { LogEntry, LogFilter } from './types';
import { getExtensionSetting } from '../ext';
import logger from '../../logger';

export class LogViewerPanel {
  public static readonly viewType = 'sftpLogViewer';
  private static panels: Map<string, LogViewerPanel> = new Map();

  private readonly _panel: vscode.WebviewPanel;
  private readonly _fileService: FileService;
  private readonly _config: ServiceConfig;
  private _entries: LogEntry[] = [];
  private _streamHandle: StopHandle | null = null;
  private _disposed = false;

  static create(fileService: FileService, config: ServiceConfig): LogViewerPanel {
    const key = `${config.host}:${config.port}`;
    const existing = LogViewerPanel.panels.get(key);
    if (existing) {
      existing._panel.reveal();
      return existing;
    }

    const panel = vscode.window.createWebviewPanel(
      LogViewerPanel.viewType,
      `Logs: ${config.name || config.host}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    const instance = new LogViewerPanel(panel, fileService, config);
    LogViewerPanel.panels.set(key, instance);
    return instance;
  }

  private constructor(
    panel: vscode.WebviewPanel,
    fileService: FileService,
    config: ServiceConfig
  ) {
    this._panel = panel;
    this._fileService = fileService;
    this._config = config;

    this._panel.webview.html = this._getHtmlContent();
    this._panel.webview.onDidReceiveMessage(msg => this._handleMessage(msg));
    this._panel.onDidDispose(() => this._dispose());
  }

  private async _getClient(): Promise<any> {
    const remotefs = await this._fileService.getRemoteFileSystem(this._config) as any;
    return remotefs.getClient().getUnderlyingClient();
  }

  private async _handleMessage(msg: any) {
    try {
      switch (msg.type) {
        case 'discoverLogs': {
          const client = await this._getClient();
          const customPaths = getExtensionSetting().get('logViewer.customLogPaths', []) as string[];
          const files = await discoverLogFiles(client, customPaths);
          this._postMessage({ type: 'logFiles', files });
          break;
        }
        case 'loadLog': {
          const client = await this._getClient();
          const lines = await fetchLogLines(client, msg.path, msg.maxLines || 1000);
          this._entries = parseLogLines(lines);
          this._postMessage({
            type: 'logData',
            entries: this._entries.map(this._serializeEntry),
            stats: computeStats(this._entries),
          });
          break;
        }
        case 'startRealtime': {
          this._stopStreaming();
          const client = await this._getClient();
          this._streamHandle = streamLog(
            client,
            msg.path,
            line => {
              const entries = parseLogLines([line]);
              if (entries.length > 0) {
                this._entries.push(entries[0]);
                this._postMessage({
                  type: 'realtimeLine',
                  entry: this._serializeEntry(entries[0]),
                });
              }
            },
            err => {
              logger.warn(`Realtime stream error: ${err.message}`);
              this._postMessage({ type: 'realtimeError', error: err.message });
            }
          );
          break;
        }
        case 'stopRealtime': {
          this._stopStreaming();
          break;
        }
        case 'applyFilter': {
          const filter: LogFilter = {};
          if (msg.filter.dateFrom) filter.dateFrom = new Date(msg.filter.dateFrom);
          if (msg.filter.dateTo) filter.dateTo = new Date(msg.filter.dateTo);
          if (msg.filter.statusCodes) filter.statusCodes = msg.filter.statusCodes;
          if (msg.filter.ipFilter) filter.ipFilter = msg.filter.ipFilter;
          if (msg.filter.uriPattern) filter.uriPattern = msg.filter.uriPattern;
          if (msg.filter.userAgentPattern) filter.userAgentPattern = msg.filter.userAgentPattern;
          const filtered = filterEntries(this._entries, filter);
          this._postMessage({
            type: 'logData',
            entries: filtered.map(this._serializeEntry),
            stats: computeStats(filtered),
          });
          break;
        }
        case 'groupBy': {
          const groups = groupBy(this._entries, msg.key);
          this._postMessage({
            type: 'groupData',
            groups: groups.map(g => ({ key: g.key, count: g.count })),
          });
          break;
        }
        case 'getStats': {
          this._postMessage({
            type: 'statsData',
            stats: computeStats(this._entries),
          });
          break;
        }
      }
    } catch (err) {
      this._postMessage({ type: 'error', message: err.message || String(err) });
    }
  }

  private _serializeEntry(entry: LogEntry) {
    return {
      ...entry,
      timestamp: entry.timestamp ? entry.timestamp.toISOString() : null,
    };
  }

  private _postMessage(msg: any) {
    if (!this._disposed) {
      this._panel.webview.postMessage(msg);
    }
  }

  private _stopStreaming() {
    if (this._streamHandle) {
      this._streamHandle.stop();
      this._streamHandle = null;
    }
  }

  private _dispose() {
    this._disposed = true;
    this._stopStreaming();
    const key = `${this._config.host}:${this._config.port}`;
    LogViewerPanel.panels.delete(key);
  }

  private _getHtmlContent(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Server Logs</title>
<style>
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --border: var(--vscode-panel-border);
    --input-bg: var(--vscode-input-background);
    --input-fg: var(--vscode-input-foreground);
    --input-border: var(--vscode-input-border);
    --btn-bg: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--vscode-font-family); font-size: 13px; color: var(--fg); background: var(--bg); padding: 8px; }
  .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; padding: 8px; background: var(--vscode-sideBar-background); border-radius: 4px; }
  .filter-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; padding: 8px; background: var(--vscode-sideBar-background); border-radius: 4px; }
  select, input { background: var(--input-bg); color: var(--input-fg); border: 1px solid var(--input-border); padding: 4px 8px; border-radius: 3px; font-size: 12px; }
  select { min-width: 200px; }
  input { min-width: 120px; }
  button { background: var(--btn-bg); color: var(--btn-fg); border: none; padding: 4px 12px; border-radius: 3px; cursor: pointer; font-size: 12px; }
  button:hover { background: var(--btn-hover); }
  button.active { outline: 2px solid var(--vscode-focusBorder); }
  .group-bar { display: flex; gap: 4px; margin-bottom: 8px; }
  .group-bar button { font-size: 11px; padding: 2px 8px; }
  .layout { display: flex; gap: 8px; }
  .main { flex: 1; overflow: hidden; }
  .sidebar { width: 280px; flex-shrink: 0; overflow-y: auto; max-height: calc(100vh - 180px); }
  .stats-card { background: var(--vscode-sideBar-background); border-radius: 4px; padding: 8px; margin-bottom: 8px; }
  .stats-card h3 { font-size: 12px; margin-bottom: 4px; opacity: 0.8; }
  .stats-card .value { font-size: 18px; font-weight: bold; }
  .stats-row { display: flex; justify-content: space-between; padding: 2px 0; font-size: 12px; }
  .suspicious { color: var(--vscode-errorForeground); }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { position: sticky; top: 0; background: var(--vscode-sideBar-background); text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; }
  th:hover { opacity: 0.8; }
  td { padding: 3px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
  tr.s2xx { color: #4ec9b0; }
  tr.s3xx { color: #569cd6; }
  tr.s4xx { color: #ce9178; }
  tr.s5xx { color: #f44747; }
  .log-table-container { overflow: auto; max-height: calc(100vh - 180px); }
  .status-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }
  .status-badge.s2xx { background: rgba(78,201,176,0.2); }
  .status-badge.s3xx { background: rgba(86,156,214,0.2); }
  .status-badge.s4xx { background: rgba(206,145,120,0.2); }
  .status-badge.s5xx { background: rgba(244,71,71,0.2); }
  .loading { text-align: center; padding: 40px; opacity: 0.6; }
  .group-table { margin-bottom: 8px; }
  label { font-size: 12px; opacity: 0.8; }
</style>
</head>
<body>
  <div class="toolbar">
    <select id="logFile"><option value="">Select log file...</option></select>
    <button id="loadBtn">Load</button>
    <input type="number" id="maxLines" value="1000" min="100" max="50000" style="width:80px" title="Max lines">
    <button id="realtimeBtn">Start Realtime</button>
    <span id="statusText" style="opacity:0.6; font-size:11px;"></span>
  </div>
  <div class="filter-bar">
    <label>IP:</label><input id="ipFilter" placeholder="IP filter">
    <label>URI:</label><input id="uriFilter" placeholder="URI pattern">
    <label>Status:</label><input id="statusFilter" placeholder="e.g. 404,500">
    <label>UA:</label><input id="uaFilter" placeholder="User-Agent">
    <button id="applyFilterBtn">Filter</button>
    <button id="clearFilterBtn">Clear</button>
  </div>
  <div class="group-bar">
    <span style="opacity:0.6; font-size:11px;">Group by:</span>
    <button data-group="ip">IP</button>
    <button data-group="uri">URI</button>
    <button data-group="userAgent">User-Agent</button>
    <button data-group="status">Status</button>
    <button data-group="none">None</button>
  </div>
  <div class="layout">
    <div class="main">
      <div id="groupView" style="display:none;"></div>
      <div class="log-table-container" id="tableContainer">
        <table>
          <thead>
            <tr>
              <th data-sort="timestamp">Time</th>
              <th data-sort="ip">IP</th>
              <th data-sort="method">Method</th>
              <th data-sort="uri">URI</th>
              <th data-sort="status">Status</th>
              <th data-sort="size">Size</th>
              <th data-sort="userAgent">User-Agent</th>
            </tr>
          </thead>
          <tbody id="logBody"></tbody>
        </table>
        <div id="loadingMsg" class="loading" style="display:none;">Loading...</div>
      </div>
    </div>
    <div class="sidebar" id="sidebar">
      <div class="stats-card"><h3>Total Requests</h3><div class="value" id="statTotal">-</div></div>
      <div class="stats-card"><h3>Unique IPs</h3><div class="value" id="statIPs">-</div></div>
      <div class="stats-card"><h3>Status Breakdown</h3><div id="statStatus"></div></div>
      <div class="stats-card"><h3>Top IPs</h3><div id="statTopIPs"></div></div>
      <div class="stats-card"><h3>Top URIs</h3><div id="statTopURIs"></div></div>
      <div class="stats-card"><h3>Suspicious Patterns</h3><div id="statSuspicious"></div></div>
    </div>
  </div>
<script>
(function() {
  const vscode = acquireVsCodeApi();
  const logFileSelect = document.getElementById('logFile');
  const logBody = document.getElementById('logBody');
  const loadingMsg = document.getElementById('loadingMsg');
  const statusText = document.getElementById('statusText');
  const groupView = document.getElementById('groupView');
  const tableContainer = document.getElementById('tableContainer');
  let isRealtime = false;
  let autoScroll = true;
  let currentEntries = [];

  // Init: discover log files
  vscode.postMessage({ type: 'discoverLogs' });

  document.getElementById('loadBtn').addEventListener('click', () => {
    const path = logFileSelect.value;
    if (!path) return;
    loadingMsg.style.display = 'block';
    logBody.innerHTML = '';
    statusText.textContent = 'Loading...';
    vscode.postMessage({ type: 'loadLog', path, maxLines: parseInt(document.getElementById('maxLines').value) || 1000 });
  });

  document.getElementById('realtimeBtn').addEventListener('click', () => {
    const path = logFileSelect.value;
    if (!path) return;
    if (isRealtime) {
      vscode.postMessage({ type: 'stopRealtime' });
      document.getElementById('realtimeBtn').textContent = 'Start Realtime';
      isRealtime = false;
      statusText.textContent = 'Stopped';
    } else {
      vscode.postMessage({ type: 'startRealtime', path });
      document.getElementById('realtimeBtn').textContent = 'Stop Realtime';
      document.getElementById('realtimeBtn').classList.add('active');
      isRealtime = true;
      statusText.textContent = 'Streaming...';
    }
  });

  document.getElementById('applyFilterBtn').addEventListener('click', () => {
    const filter = {};
    const ip = document.getElementById('ipFilter').value.trim();
    const uri = document.getElementById('uriFilter').value.trim();
    const status = document.getElementById('statusFilter').value.trim();
    const ua = document.getElementById('uaFilter').value.trim();
    if (ip) filter.ipFilter = ip;
    if (uri) filter.uriPattern = uri;
    if (status) filter.statusCodes = status.split(',').map(Number).filter(n => !isNaN(n));
    if (ua) filter.userAgentPattern = ua;
    vscode.postMessage({ type: 'applyFilter', filter });
  });

  document.getElementById('clearFilterBtn').addEventListener('click', () => {
    document.getElementById('ipFilter').value = '';
    document.getElementById('uriFilter').value = '';
    document.getElementById('statusFilter').value = '';
    document.getElementById('uaFilter').value = '';
    vscode.postMessage({ type: 'applyFilter', filter: {} });
  });

  document.querySelectorAll('.group-bar button').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.group;
      if (key === 'none') {
        groupView.style.display = 'none';
        tableContainer.style.display = '';
        return;
      }
      vscode.postMessage({ type: 'groupBy', key });
    });
  });

  // Sort
  let sortKey = 'timestamp';
  let sortAsc = false;
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) sortAsc = !sortAsc;
      else { sortKey = key; sortAsc = true; }
      renderEntries(currentEntries);
    });
  });

  function statusClass(code) {
    if (code >= 200 && code < 300) return 's2xx';
    if (code >= 300 && code < 400) return 's3xx';
    if (code >= 400 && code < 500) return 's4xx';
    if (code >= 500) return 's5xx';
    return '';
  }

  function formatSize(bytes) {
    if (!bytes) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/1048576).toFixed(1) + ' MB';
  }

  function renderEntries(entries) {
    currentEntries = entries;
    const sorted = [...entries].sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey];
      if (va == null) va = '';
      if (vb == null) vb = '';
      if (typeof va === 'number') return sortAsc ? va - vb : vb - va;
      return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    logBody.innerHTML = sorted.map(e => {
      const cls = statusClass(e.status);
      const time = e.timestamp ? new Date(e.timestamp).toLocaleString() : (e.level || '-');
      const display = e.method ? [time, e.ip, e.method, e.uri, e.status, formatSize(e.size), e.userAgent]
        : [time, e.ip || '-', '-', '-', '-', '-', e.message || e.raw];
      return '<tr class="' + cls + '">' + display.map(v =>
        '<td title="' + escHtml(String(v || '')) + '">' + escHtml(String(v || '-')) + '</td>'
      ).join('') + '</tr>';
    }).join('');
  }

  function renderStats(stats) {
    document.getElementById('statTotal').textContent = stats.totalRequests;
    document.getElementById('statIPs').textContent = stats.uniqueIPs;
    document.getElementById('statStatus').innerHTML = Object.entries(stats.statusBreakdown)
      .sort(([a],[b]) => Number(a) - Number(b))
      .map(([code, count]) => '<div class="stats-row"><span class="status-badge ' + statusClass(Number(code)) + '">' + code + '</span><span>' + count + '</span></div>')
      .join('');
    document.getElementById('statTopIPs').innerHTML = stats.topIPs
      .map(i => '<div class="stats-row"><span>' + escHtml(i.ip) + '</span><span>' + i.count + '</span></div>')
      .join('');
    document.getElementById('statTopURIs').innerHTML = stats.topURIs
      .map(u => '<div class="stats-row"><span title="' + escHtml(u.uri) + '">' + escHtml(u.uri.substring(0,40)) + '</span><span>' + u.count + '</span></div>')
      .join('');
    const suspHtml = stats.suspiciousPatterns.length === 0
      ? '<div style="opacity:0.6">None detected</div>'
      : stats.suspiciousPatterns.map(s => '<div class="stats-row suspicious"><span>' + escHtml(s.description) + '</span><span>' + s.count + '</span></div>').join('');
    document.getElementById('statSuspicious').innerHTML = suspHtml;
  }

  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  window.addEventListener('message', event => {
    const msg = event.data;
    switch (msg.type) {
      case 'logFiles':
        logFileSelect.innerHTML = '<option value="">Select log file...</option>' +
          msg.files.map(f => '<option value="' + escHtml(f) + '">' + escHtml(f) + '</option>').join('');
        statusText.textContent = msg.files.length + ' log files found';
        break;
      case 'logData':
        loadingMsg.style.display = 'none';
        renderEntries(msg.entries);
        renderStats(msg.stats);
        statusText.textContent = msg.entries.length + ' entries';
        break;
      case 'realtimeLine':
        appendRow(msg.entry);
        break;
      case 'realtimeError':
        statusText.textContent = 'Error: ' + msg.error;
        isRealtime = false;
        document.getElementById('realtimeBtn').textContent = 'Start Realtime';
        document.getElementById('realtimeBtn').classList.remove('active');
        break;
      case 'groupData':
        groupView.style.display = '';
        tableContainer.style.display = 'none';
        groupView.innerHTML = '<table class="group-table"><thead><tr><th>Key</th><th>Count</th></tr></thead><tbody>' +
          msg.groups.map(g => '<tr><td title="' + escHtml(g.key) + '">' + escHtml(g.key.substring(0,60)) + '</td><td>' + g.count + '</td></tr>').join('') +
          '</tbody></table>';
        break;
      case 'statsData':
        renderStats(msg.stats);
        break;
      case 'error':
        loadingMsg.style.display = 'none';
        statusText.textContent = 'Error: ' + msg.message;
        break;
    }
  });

  function appendRow(entry) {
    currentEntries.push(entry);
    const cls = statusClass(entry.status);
    const time = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : (entry.level || '-');
    const display = entry.method ? [time, entry.ip, entry.method, entry.uri, entry.status, formatSize(entry.size), entry.userAgent]
      : [time, entry.ip || '-', '-', '-', '-', '-', entry.message || entry.raw];
    const tr = document.createElement('tr');
    tr.className = cls;
    tr.innerHTML = display.map(v =>
      '<td title="' + escHtml(String(v || '')) + '">' + escHtml(String(v || '-')) + '</td>'
    ).join('');
    logBody.appendChild(tr);
    if (autoScroll) {
      const container = document.getElementById('tableContainer');
      container.scrollTop = container.scrollHeight;
    }
    statusText.textContent = currentEntries.length + ' entries (live)';
  }
})();
</script>
</body>
</html>`;
  }
}
