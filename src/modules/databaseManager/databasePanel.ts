import * as vscode from 'vscode';
import { DatabaseClient } from './databaseClient';
import { DatabaseConfig } from './types';
import logger from '../../logger';

export class DatabasePanel {
  public static readonly viewType = 'sftpDatabaseManager';
  private static panels: Map<string, DatabasePanel> = new Map();

  private readonly _panel: vscode.WebviewPanel;
  private readonly _client: DatabaseClient;
  private _disposed = false;

  static create(client: DatabaseClient, dbConfig: DatabaseConfig, serverName: string): DatabasePanel {
    const key = `${serverName}:${dbConfig.database}`;
    const existing = DatabasePanel.panels.get(key);
    if (existing) {
      existing._panel.reveal();
      return existing;
    }

    const panel = vscode.window.createWebviewPanel(
      DatabasePanel.viewType,
      `DB: ${dbConfig.database} @ ${serverName}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    const instance = new DatabasePanel(panel, client, dbConfig, serverName);
    DatabasePanel.panels.set(key, instance);
    return instance;
  }

  static openToTable(
    client: DatabaseClient,
    dbConfig: DatabaseConfig,
    serverName: string,
    tableName: string
  ): DatabasePanel {
    const panel = DatabasePanel.create(client, dbConfig, serverName);
    panel._postMessage({ type: 'selectTable', tableName });
    return panel;
  }

  private constructor(
    panel: vscode.WebviewPanel,
    client: DatabaseClient,
    _dbConfig: DatabaseConfig,
    _serverName: string
  ) {
    this._panel = panel;
    this._client = client;

    this._panel.webview.html = this._getHtmlContent();
    this._panel.webview.onDidReceiveMessage(msg => this._handleMessage(msg));
    this._panel.onDidDispose(() => this._dispose());
  }

  private async _handleMessage(msg: any) {
    try {
      switch (msg.type) {
        case 'getTables': {
          const tables = await this._client.getTables();
          this._postMessage({ type: 'tables', tables });
          break;
        }
        case 'getColumns': {
          const columns = await this._client.getColumns(msg.table);
          this._postMessage({ type: 'columns', table: msg.table, columns });
          break;
        }
        case 'getIndexes': {
          const indexes = await this._client.getIndexes(msg.table);
          this._postMessage({ type: 'indexes', table: msg.table, indexes });
          break;
        }
        case 'getData': {
          const data = await this._client.getData(msg.table, msg.page || 1, msg.pageSize || 50);
          this._postMessage({
            type: 'data',
            table: msg.table,
            columns: data.columns,
            rows: data.rows,
            total: data.total,
            page: msg.page || 1,
            pageSize: msg.pageSize || 50,
          });
          break;
        }
        case 'executeQuery': {
          const sql = msg.sql.trim();
          if (!sql) break;

          const isModifying = !/^\s*SELECT\b/i.test(sql);
          if (isModifying) {
            const confirm = await vscode.window.showWarningMessage(
              `This will execute a non-SELECT statement. Continue?\n\n${sql.substring(0, 200)}`,
              { modal: true },
              'Execute'
            );
            if (confirm !== 'Execute') {
              this._postMessage({ type: 'queryCancelled' });
              break;
            }
          }

          const result = await this._client.executeQuery(sql);
          this._postMessage({ type: 'queryResult', result });
          break;
        }
      }
    } catch (err) {
      logger.error(err, 'Database panel error');
      this._postMessage({ type: 'error', message: err.message || String(err) });
    }
  }

  private _postMessage(msg: any) {
    if (!this._disposed) {
      this._panel.webview.postMessage(msg);
    }
  }

  private _dispose() {
    this._disposed = true;
    const key = Array.from(DatabasePanel.panels.entries())
      .find(([, v]) => v === this)?.[0];
    if (key) {
      DatabasePanel.panels.delete(key);
    }
  }

  private _getHtmlContent(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Database Manager</title>
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
    --sidebar-bg: var(--vscode-sideBar-background);
    --badge-bg: var(--vscode-badge-background);
    --badge-fg: var(--vscode-badge-foreground);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--vscode-font-family); font-size: 13px; color: var(--fg); background: var(--bg); display: flex; height: 100vh; }

  .sidebar {
    width: 220px; flex-shrink: 0; background: var(--sidebar-bg);
    border-right: 1px solid var(--border); overflow-y: auto; padding: 8px;
  }
  .sidebar h3 { font-size: 11px; text-transform: uppercase; opacity: 0.7; margin-bottom: 6px; }
  .table-list { list-style: none; }
  .table-list li {
    padding: 4px 8px; cursor: pointer; border-radius: 3px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 12px;
  }
  .table-list li:hover { background: var(--vscode-list-hoverBackground); }
  .table-list li.active { background: var(--vscode-list-activeSelectionBackground); color: var(--vscode-list-activeSelectionForeground); }

  .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .tabs {
    display: flex; gap: 0; border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg); flex-shrink: 0;
  }
  .tab {
    padding: 8px 16px; cursor: pointer; font-size: 12px;
    border-bottom: 2px solid transparent; opacity: 0.7;
  }
  .tab:hover { opacity: 1; }
  .tab.active { opacity: 1; border-bottom-color: var(--btn-bg); }

  .tab-content { flex: 1; overflow: auto; padding: 12px; display: none; }
  .tab-content.active { display: block; }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { position: sticky; top: 0; background: var(--sidebar-bg); text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); font-weight: 600; }
  td { padding: 4px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
  tr:hover td { background: var(--vscode-list-hoverBackground); }

  .query-area { display: flex; flex-direction: column; height: 100%; }
  .query-editor {
    width: 100%; min-height: 120px; background: var(--input-bg); color: var(--input-fg);
    border: 1px solid var(--input-border); padding: 8px; font-family: var(--vscode-editor-font-family);
    font-size: 13px; resize: vertical; border-radius: 3px;
  }
  .query-toolbar { display: flex; gap: 8px; align-items: center; margin: 8px 0; }
  .query-results { flex: 1; overflow: auto; }

  button {
    background: var(--btn-bg); color: var(--btn-fg); border: none;
    padding: 6px 14px; border-radius: 3px; cursor: pointer; font-size: 12px;
  }
  button:hover { background: var(--btn-hover); }
  button:disabled { opacity: 0.5; cursor: default; }

  .pagination { display: flex; gap: 8px; align-items: center; padding: 8px 0; font-size: 12px; }
  .status { font-size: 11px; opacity: 0.7; padding: 4px 0; }
  .badge { background: var(--badge-bg); color: var(--badge-fg); padding: 1px 6px; border-radius: 10px; font-size: 10px; }
  .key-pri { color: #e5c07b; }
  .key-mul { color: #61afef; }
  .key-uni { color: #c678dd; }
  .null-val { opacity: 0.4; font-style: italic; }
  .loading { text-align: center; padding: 40px; opacity: 0.6; }
  .error-msg { color: var(--vscode-errorForeground); padding: 8px; }
</style>
</head>
<body>
  <div class="sidebar">
    <h3>Tables</h3>
    <ul class="table-list" id="tableList"></ul>
  </div>
  <div class="main">
    <div class="tabs">
      <div class="tab active" data-tab="structure">Structure</div>
      <div class="tab" data-tab="data">Data</div>
      <div class="tab" data-tab="query">Query</div>
    </div>

    <div class="tab-content active" id="tab-structure">
      <div id="structureContent" class="loading">Select a table to view its structure</div>
    </div>

    <div class="tab-content" id="tab-data">
      <div id="dataContent" class="loading">Select a table to view data</div>
    </div>

    <div class="tab-content" id="tab-query">
      <div class="query-area">
        <textarea class="query-editor" id="queryEditor" placeholder="Enter SQL query..."></textarea>
        <div class="query-toolbar">
          <button id="runQueryBtn">Run Query</button>
          <span id="queryStatus" class="status"></span>
        </div>
        <div class="query-results" id="queryResults"></div>
      </div>
    </div>
  </div>

<script>
(function() {
  const vscode = acquireVsCodeApi();
  const tableList = document.getElementById('tableList');
  let currentTable = null;
  let currentPage = 1;
  const pageSize = 50;

  vscode.postMessage({ type: 'getTables' });

  // Tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });

  // Run query
  document.getElementById('runQueryBtn').addEventListener('click', () => {
    const sql = document.getElementById('queryEditor').value.trim();
    if (!sql) return;
    document.getElementById('queryStatus').textContent = 'Executing...';
    document.getElementById('queryResults').innerHTML = '<div class="loading">Running query...</div>';
    vscode.postMessage({ type: 'executeQuery', sql });
  });

  // Ctrl+Enter to run
  document.getElementById('queryEditor').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('runQueryBtn').click();
    }
  });

  function selectTable(name) {
    currentTable = name;
    currentPage = 1;
    document.querySelectorAll('.table-list li').forEach(li => {
      li.classList.toggle('active', li.textContent === name);
    });
    vscode.postMessage({ type: 'getColumns', table: name });
    vscode.postMessage({ type: 'getIndexes', table: name });
    vscode.postMessage({ type: 'getData', table: name, page: 1, pageSize: pageSize });
  }

  function escHtml(s) {
    if (s == null) return '<span class="null-val">NULL</span>';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function renderTables(tables) {
    tableList.innerHTML = tables.map(t =>
      '<li title="' + escHtml(t.name) + ' (' + (t.rowCount || 0) + ' rows)">' + escHtml(t.name) + '</li>'
    ).join('');
    tableList.querySelectorAll('li').forEach(li => {
      li.addEventListener('click', () => selectTable(li.textContent));
    });
  }

  function keyClass(key) {
    if (key === 'PRI') return 'key-pri';
    if (key === 'MUL') return 'key-mul';
    if (key === 'UNI') return 'key-uni';
    return '';
  }

  function renderStructure(columns, indexes) {
    let html = '<h3 style="margin-bottom:8px;">Columns</h3>';
    html += '<table><thead><tr><th>Name</th><th>Type</th><th>Nullable</th><th>Key</th><th>Default</th><th>Extra</th><th>Comment</th></tr></thead><tbody>';
    columns.forEach(c => {
      html += '<tr><td>' + escHtml(c.name) + '</td><td>' + escHtml(c.type) + '</td>';
      html += '<td>' + escHtml(c.nullable) + '</td>';
      html += '<td class="' + keyClass(c.key) + '">' + escHtml(c.key || '-') + '</td>';
      html += '<td>' + (c.defaultValue != null ? escHtml(c.defaultValue) : '<span class="null-val">NULL</span>') + '</td>';
      html += '<td>' + escHtml(c.extra || '-') + '</td>';
      html += '<td>' + escHtml(c.comment || '-') + '</td></tr>';
    });
    html += '</tbody></table>';

    if (indexes && indexes.length > 0) {
      html += '<h3 style="margin:16px 0 8px;">Indexes</h3>';
      html += '<table><thead><tr><th>Name</th><th>Columns</th><th>Unique</th><th>Type</th></tr></thead><tbody>';
      indexes.forEach(idx => {
        html += '<tr><td>' + escHtml(idx.name) + '</td>';
        html += '<td>' + idx.columns.map(c => escHtml(c)).join(', ') + '</td>';
        html += '<td>' + (idx.unique ? '<span class="badge">UNIQUE</span>' : 'No') + '</td>';
        html += '<td>' + escHtml(idx.type) + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    document.getElementById('structureContent').innerHTML = html;
  }

  function renderData(columns, rows, total, page, ps) {
    const totalPages = Math.ceil(total / ps) || 1;
    let html = '<div class="pagination">';
    html += '<button id="prevPage" ' + (page <= 1 ? 'disabled' : '') + '>Prev</button>';
    html += '<span>Page ' + page + ' of ' + totalPages + ' (' + total + ' rows)</span>';
    html += '<button id="nextPage" ' + (page >= totalPages ? 'disabled' : '') + '>Next</button>';
    html += '</div>';

    html += '<table><thead><tr>';
    columns.forEach(c => { html += '<th>' + escHtml(c) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(row => {
      html += '<tr>';
      row.forEach(val => {
        html += '<td title="' + (val != null ? escHtml(val) : 'NULL') + '">';
        html += val != null ? escHtml(val) : '<span class="null-val">NULL</span>';
        html += '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table>';

    document.getElementById('dataContent').innerHTML = html;

    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');
    if (prevBtn) prevBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        vscode.postMessage({ type: 'getData', table: currentTable, page: currentPage, pageSize: ps });
      }
    });
    if (nextBtn) nextBtn.addEventListener('click', () => {
      if (currentPage < totalPages) {
        currentPage++;
        vscode.postMessage({ type: 'getData', table: currentTable, page: currentPage, pageSize: ps });
      }
    });
  }

  function renderQueryResult(result) {
    document.getElementById('queryStatus').textContent =
      result.columns.length > 0
        ? result.rowCount + ' rows in ' + result.executionTime + 'ms'
        : result.affectedRows + ' rows affected in ' + result.executionTime + 'ms';

    if (result.columns.length === 0) {
      document.getElementById('queryResults').innerHTML =
        '<div class="status">' + result.affectedRows + ' rows affected</div>';
      return;
    }

    let html = '<table><thead><tr>';
    result.columns.forEach(c => { html += '<th>' + escHtml(c) + '</th>'; });
    html += '</tr></thead><tbody>';
    result.rows.forEach(row => {
      html += '<tr>';
      row.forEach(val => {
        html += '<td>' + (val != null ? escHtml(val) : '<span class="null-val">NULL</span>') + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('queryResults').innerHTML = html;
  }

  let pendingColumns = null;
  let pendingIndexes = null;

  window.addEventListener('message', event => {
    const msg = event.data;
    switch (msg.type) {
      case 'tables':
        renderTables(msg.tables);
        break;
      case 'columns':
        pendingColumns = msg.columns;
        if (pendingIndexes !== null) {
          renderStructure(pendingColumns, pendingIndexes);
          pendingColumns = null;
          pendingIndexes = null;
        }
        break;
      case 'indexes':
        pendingIndexes = msg.indexes;
        if (pendingColumns !== null) {
          renderStructure(pendingColumns, pendingIndexes);
          pendingColumns = null;
          pendingIndexes = null;
        }
        break;
      case 'data':
        currentPage = msg.page;
        renderData(msg.columns, msg.rows, msg.total, msg.page, msg.pageSize);
        break;
      case 'queryResult':
        renderQueryResult(msg.result);
        break;
      case 'queryCancelled':
        document.getElementById('queryStatus').textContent = 'Query cancelled';
        document.getElementById('queryResults').innerHTML = '';
        break;
      case 'selectTable':
        selectTable(msg.tableName);
        break;
      case 'error':
        document.getElementById('queryStatus').textContent = '';
        document.getElementById('queryResults').innerHTML =
          '<div class="error-msg">Error: ' + escHtml(msg.message) + '</div>';
        break;
    }
  });
})();
</script>
</body>
</html>`;
  }
}
