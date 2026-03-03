import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

/**
 * ServerConfigPanel — визуальный конфигуратор SFTP серверов.
 *
 * Открывает Webview с формой для редактирования sftp.json:
 * - host, port, protocol, username/password/privateKey
 * - remotePath, uploadOnSave, ignore, syncOption
 * - Кнопка "Тест соединения" прямо в форме
 */
export class ServerConfigPanel {
  static readonly viewType = 'sftp.serverConfig';
  private static _instance: ServerConfigPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _configPath: string;
  private _config: Record<string, any> = {};

  static createOrShow(configPath: string): ServerConfigPanel {
    if (ServerConfigPanel._instance) {
      ServerConfigPanel._instance._panel.reveal(vscode.ViewColumn.One);
      return ServerConfigPanel._instance;
    }

    const panel = vscode.window.createWebviewPanel(
      ServerConfigPanel.viewType,
      '⚙ SFTP: Конфигурация сервера',
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    ServerConfigPanel._instance = new ServerConfigPanel(panel, configPath);
    return ServerConfigPanel._instance;
  }

  private constructor(panel: vscode.WebviewPanel, configPath: string) {
    this._panel = panel;
    this._configPath = configPath;

    // Load existing config
    try {
      if (fs.existsSync(configPath)) {
        this._config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      }
    } catch { /* use empty config */ }

    this._panel.onDidDispose(() => {
      ServerConfigPanel._instance = undefined;
    });

    this._panel.webview.onDidReceiveMessage(async msg => {
      switch (msg.command) {
        case 'save':
          await this._save(msg.config);
          break;
        case 'testConnection':
          await this._testConnection(msg.config);
          break;
        case 'openFile':
          vscode.workspace.openTextDocument(this._configPath).then(doc =>
            vscode.window.showTextDocument(doc)
          );
          break;
      }
    });

    this._render();
  }

  private async _save(config: Record<string, any>) {
    try {
      // Merge with existing config, preserve unknown keys
      const merged = { ...this._config, ...config };
      // Remove empty values
      for (const key of Object.keys(merged)) {
        if (merged[key] === '' || merged[key] === null) {
          delete merged[key];
        }
      }
      // Ensure .vscode directory exists
      const dir = path.dirname(this._configPath);
      try { if (!fs.existsSync(dir)) fs.mkdirSync(dir); } catch { /* may already exist */ }

      fs.writeFileSync(this._configPath, JSON.stringify(merged, null, 2), 'utf8');
      this._config = merged;
      this._panel.webview.postMessage({ command: 'saved' });
      vscode.window.showInformationMessage('SFTP: Конфигурация сохранена ✓');
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: Ошибка сохранения: ${(err as Error).message}`);
    }
  }

  private async _testConnection(config: Record<string, any>) {
    this._panel.webview.postMessage({ command: 'testingConnection' });
    try {
      // Dynamic import to avoid circular dependencies
      const { Client } = require('ssh2');
      const client = new Client();
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout (10s)')), 10000);
        client
          .on('ready', () => {
            clearTimeout(timeout);
            client.end();
            resolve();
          })
          .on('error', (err: Error) => {
            clearTimeout(timeout);
            reject(err);
          })
          .connect({
            host: config.host,
            port: parseInt(config.port || '22', 10),
            username: config.username,
            password: config.password || undefined,
            privateKey: config.privateKeyPath
              ? fs.readFileSync(config.privateKeyPath.replace('~', process.env.HOME || ''))
              : undefined,
            readyTimeout: 9000,
          });
      });
      this._panel.webview.postMessage({ command: 'testSuccess' });
      vscode.window.showInformationMessage(`SFTP: ✅ Подключение к ${config.host} успешно!`);
    } catch (err) {
      const msg = (err as Error).message;
      this._panel.webview.postMessage({ command: 'testError', message: msg });
      vscode.window.showErrorMessage(`SFTP: ❌ Ошибка подключения: ${msg}`);
    }
  }

  private _v(key: string, fallback = ''): string {
    const val = this._config[key];
    return val !== undefined && val !== null ? String(val) : fallback;
  }

  private _render() {
    const c = this._config;
    const protocol = c.protocol || 'sftp';
    const syncOpt = c.syncOption || {};

    this._panel.webview.html = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<style>
  :root { --bg: #1e1e2e; --surface: #2a2a3d; --surface2: #313145; --border: #3a3a5c; --text: #cdd6f4; --muted: #6c7086; --green: #a6e3a1; --red: #f38ba8; --yellow: #f9e2af; --blue: #89b4fa; --teal: #94e2d5; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; font-size: 13px; background: var(--bg); color: var(--text); margin: 0; padding: 0; display: flex; flex-direction: column; min-height: 100vh; }
  .header { background: var(--surface); padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
  .header h1 { margin: 0; font-size: 15px; color: var(--blue); }
  .header .path { font-size: 11px; color: var(--muted); font-family: monospace; }
  .content { flex: 1; padding: 20px; max-width: 900px; margin: 0 auto; width: 100%; }
  .section { background: var(--surface); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; border: 1px solid var(--border); }
  .section h3 { margin: 0 0 14px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .grid.three { grid-template-columns: 1fr 1fr 1fr; }
  .field { display: flex; flex-direction: column; gap: 5px; }
  .field.full { grid-column: 1 / -1; }
  label { font-size: 12px; color: var(--muted); font-weight: 500; }
  label .required { color: var(--red); margin-left: 2px; }
  input, select, textarea { background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 7px 10px; font-size: 13px; width: 100%; outline: none; transition: border-color 0.15s; font-family: inherit; }
  input:focus, select:focus, textarea:focus { border-color: var(--blue); }
  textarea { resize: vertical; font-family: monospace; font-size: 12px; }
  .checkbox-row { display: flex; align-items: center; gap: 8px; }
  .checkbox-row input { width: auto; }
  .checkbox-row label { font-size: 13px; color: var(--text); font-weight: normal; }
  .divider { border: none; border-top: 1px solid var(--border); margin: 8px 0; }
  .footer { padding: 14px 20px; border-top: 1px solid var(--border); background: var(--surface); display: flex; gap: 10px; align-items: center; justify-content: space-between; }
  .footer-left { display: flex; gap: 10px; align-items: center; }
  button { padding: 7px 18px; border-radius: 7px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.15s; }
  button:hover { background: var(--border); }
  button.primary { background: var(--blue); border-color: var(--blue); color: #1e1e2e; }
  button.primary:hover { background: #6da5e8; }
  button.success { background: var(--green); border-color: var(--green); color: #1e1e2e; }
  button.danger { border-color: var(--red); color: var(--red); }
  .status { font-size: 12px; color: var(--muted); }
  .status.ok { color: var(--green); }
  .status.err { color: var(--red); }
  .status.testing { color: var(--yellow); }
  .protocol-tabs { display: flex; gap: 4px; margin-bottom: 14px; }
  .protocol-tab { padding: 5px 14px; border-radius: 6px; border: 1px solid var(--border); cursor: pointer; font-size: 12px; }
  .protocol-tab.active { background: var(--blue); border-color: var(--blue); color: #1e1e2e; font-weight: 600; }
  .sftp-only, .ftp-only { transition: opacity 0.2s; }
  .hidden { display: none !important; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>⚙ Конфигуратор SFTP сервера</h1>
    <div class="path">${this._configPath}</div>
  </div>
</div>

<div class="content">

  <!-- Protocol -->
  <div class="section">
    <h3>Протокол</h3>
    <div class="protocol-tabs">
      <div class="protocol-tab ${protocol === 'sftp' ? 'active' : ''}" onclick="setProtocol('sftp')">SFTP (SSH)</div>
      <div class="protocol-tab ${protocol === 'ftp' ? 'active' : ''}" onclick="setProtocol('ftp')">FTP</div>
      <div class="protocol-tab ${protocol === 'ftps' ? 'active' : ''}" onclick="setProtocol('ftps')">FTPS</div>
    </div>
    <input type="hidden" id="protocol" value="${protocol}">
  </div>

  <!-- Connection -->
  <div class="section">
    <h3>Соединение</h3>
    <div class="grid three">
      <div class="field">
        <label>Хост <span class="required">*</span></label>
        <input id="host" type="text" placeholder="example.com или IP" value="${this._v('host')}" required>
      </div>
      <div class="field">
        <label>Порт</label>
        <input id="port" type="number" placeholder="22" value="${this._v('port', '22')}">
      </div>
      <div class="field">
        <label>Таймаут (мс)</label>
        <input id="connectTimeout" type="number" placeholder="10000" value="${this._v('connectTimeout', '10000')}">
      </div>
    </div>
  </div>

  <!-- Auth -->
  <div class="section">
    <h3>Аутентификация</h3>
    <div class="grid">
      <div class="field">
        <label>Пользователь <span class="required">*</span></label>
        <input id="username" type="text" placeholder="root" value="${this._v('username')}">
      </div>
      <div class="field">
        <label>Пароль</label>
        <input id="password" type="password" placeholder="(не сохранять — используй privateKey)" value="${this._v('password')}">
      </div>
      <div class="field sftp-only ${protocol !== 'sftp' ? 'hidden' : ''}">
        <label>Путь к приватному ключу</label>
        <input id="privateKeyPath" type="text" placeholder="~/.ssh/id_rsa" value="${this._v('privateKeyPath')}">
      </div>
      <div class="field sftp-only ${protocol !== 'sftp' ? 'hidden' : ''}">
        <label>Passphrase</label>
        <input id="passphrase" type="password" placeholder="(если ключ защищён паролем)" value="${this._v('passphrase')}">
      </div>
    </div>
  </div>

  <!-- Paths -->
  <div class="section">
    <h3>Пути</h3>
    <div class="grid">
      <div class="field">
        <label>Удалённый путь <span class="required">*</span></label>
        <input id="remotePath" type="text" placeholder="/var/www/html" value="${this._v('remotePath', '/')}">
      </div>
      <div class="field">
        <label>Локальный контекст (относит. от workspace)</label>
        <input id="context" type="text" placeholder="/" value="${this._v('context', '/')}">
      </div>
    </div>
  </div>

  <!-- Sync -->
  <div class="section">
    <h3>Поведение синхронизации</h3>
    <div class="grid">
      <div class="checkbox-row">
        <input type="checkbox" id="uploadOnSave" ${c.uploadOnSave ? 'checked' : ''}>
        <label for="uploadOnSave">Загружать при сохранении файла</label>
      </div>
      <div class="checkbox-row">
        <input type="checkbox" id="downloadOnOpen" ${c.downloadOnOpen ? 'checked' : ''}>
        <label for="downloadOnOpen">Скачивать при открытии файла</label>
      </div>
      <div class="checkbox-row">
        <input type="checkbox" id="smartSync" ${syncOpt.smartSync ? 'checked' : ''}>
        <label for="smartSync">🧠 Умная синхронизация (только изменённые файлы)</label>
      </div>
      <div class="field">
        <label>Разрешение конфликтов</label>
        <select id="conflictResolution">
          <option value="newer" ${(syncOpt.conflictResolution || 'newer') === 'newer' ? 'selected' : ''}>Более новый файл (newer)</option>
          <option value="local" ${syncOpt.conflictResolution === 'local' ? 'selected' : ''}>Всегда локальный (local wins)</option>
          <option value="remote" ${syncOpt.conflictResolution === 'remote' ? 'selected' : ''}>Всегда сервер (remote wins)</option>
          <option value="skip" ${syncOpt.conflictResolution === 'skip' ? 'selected' : ''}>Пропускать конфликты (skip)</option>
        </select>
      </div>
    </div>

    <hr class="divider">
    <div class="grid">
      <div class="field">
        <label>Игнорировать файлы (glob, по одному на строку)</label>
        <textarea id="ignore" rows="4" placeholder=".git&#10;node_modules&#10;.DS_Store">${
          Array.isArray(c.ignore) ? c.ignore.join('\n') : ''
        }</textarea>
      </div>
      <div class="field">
        <label>Макс. соединений (concurrency)</label>
        <input id="maxConnections" type="number" placeholder="4" value="${this._v('maxConnections', '4')}">
        <label style="margin-top:10px">Попыток переподключения (retryCount)</label>
        <input id="retryCount" type="number" placeholder="3" value="${this._v('retryCount', '3')}">
        <label style="margin-top:10px">Задержка между попытками (мс)</label>
        <input id="retryDelay" type="number" placeholder="3000" value="${this._v('retryDelay', '3000')}">
      </div>
    </div>
  </div>

</div>

<div class="footer">
  <div class="footer-left">
    <button onclick="testConnection()">🔌 Тест соединения</button>
    <span id="testStatus" class="status"></span>
  </div>
  <div style="display:flex;gap:10px">
    <button onclick="openFile()">📝 Открыть sftp.json</button>
    <button class="primary" onclick="save()">💾 Сохранить</button>
  </div>
</div>

<script>
  const vscode = acquireVsCodeApi();

  function setProtocol(p) {
    document.getElementById('protocol').value = p;
    document.querySelectorAll('.protocol-tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    const show = p === 'sftp';
    document.querySelectorAll('.sftp-only').forEach(el => el.classList.toggle('hidden', !show));
  }

  function getConfig() {
    const ignore = document.getElementById('ignore').value
      .split('\\n').map(s => s.trim()).filter(Boolean);

    return {
      protocol: document.getElementById('protocol').value,
      host: document.getElementById('host').value.trim(),
      port: parseInt(document.getElementById('port').value) || 22,
      username: document.getElementById('username').value.trim(),
      password: document.getElementById('password').value || undefined,
      privateKeyPath: document.getElementById('privateKeyPath').value.trim() || undefined,
      passphrase: document.getElementById('passphrase').value || undefined,
      remotePath: document.getElementById('remotePath').value.trim() || '/',
      context: document.getElementById('context').value.trim() || '/',
      uploadOnSave: document.getElementById('uploadOnSave').checked,
      downloadOnOpen: document.getElementById('downloadOnOpen').checked,
      ignore: ignore.length > 0 ? ignore : undefined,
      maxConnections: parseInt(document.getElementById('maxConnections').value) || 4,
      retryCount: parseInt(document.getElementById('retryCount').value) || 3,
      retryDelay: parseInt(document.getElementById('retryDelay').value) || 3000,
      syncOption: {
        smartSync: document.getElementById('smartSync').checked,
        conflictResolution: document.getElementById('conflictResolution').value,
      }
    };
  }

  function save() {
    vscode.postMessage({ command: 'save', config: getConfig() });
  }

  function testConnection() {
    const status = document.getElementById('testStatus');
    status.textContent = '⏳ Подключаюсь...';
    status.className = 'status testing';
    vscode.postMessage({ command: 'testConnection', config: getConfig() });
  }

  function openFile() {
    vscode.postMessage({ command: 'openFile' });
  }

  window.addEventListener('message', e => {
    const msg = e.data;
    const status = document.getElementById('testStatus');
    if (msg.command === 'saved') {
      // brief visual feedback
    } else if (msg.command === 'testingConnection') {
      status.textContent = '⏳ Проверяю...';
      status.className = 'status testing';
    } else if (msg.command === 'testSuccess') {
      status.textContent = '✅ Соединение успешно';
      status.className = 'status ok';
    } else if (msg.command === 'testError') {
      status.textContent = '❌ ' + msg.message;
      status.className = 'status err';
    }
  });
</script>
</body>
</html>`;
  }
}
