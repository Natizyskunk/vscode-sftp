import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { logEmitter } from './output';

export class ServerConfigPanel {
  static readonly viewType = 'sftp.serverConfig';
  private static _instance: ServerConfigPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _configPath: string;
  private _config: Record<string, any> = {};
  private _logListener: (msg: string) => void;

  static createOrShow(configPath: string): ServerConfigPanel {
    if (ServerConfigPanel._instance) {
      ServerConfigPanel._instance._panel.reveal(vscode.ViewColumn.One);
      return ServerConfigPanel._instance;
    }
    const panel = vscode.window.createWebviewPanel(
      ServerConfigPanel.viewType, '⚙ SFTP', vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    ServerConfigPanel._instance = new ServerConfigPanel(panel, configPath);
    return ServerConfigPanel._instance;
  }

  private constructor(panel: vscode.WebviewPanel, configPath: string) {
    this._panel = panel;
    this._configPath = configPath;
    try {
      if (fs.existsSync(configPath)) {
        this._config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      }
    } catch { /* empty */ }

    this._panel.onDidDispose(() => {
      logEmitter.removeListener('log', this._logListener);
      ServerConfigPanel._instance = undefined;
    });

    this._logListener = (msg: string) => {
      this._panel.webview.postMessage({ command: 'log', line: msg });
    };
    logEmitter.on('log', this._logListener);

    this._panel.webview.onDidReceiveMessage(async msg => {
      switch (msg.command) {
        case 'save': await this._save(msg.config); break;
        case 'testConnection': await this._testConnection(msg.config); break;
        case 'openFile':
          vscode.workspace.openTextDocument(this._configPath).then(d => vscode.window.showTextDocument(d));
          break;
        case 'listDir': await this._listDir(msg.remotePath); break;
        case 'downloadFile': await this._downloadFile(msg.remotePath, false); break;
        case 'deleteRemote': await this._deleteRemote(msg.remotePath, msg.isDir); break;
        case 'uploadToDir': await this._uploadToDir(msg.remotePath); break;
        case 'openLocalFile': await this._openLocalFile(msg.localPath, msg.remotePath); break;
        case 'openInBrowser': this._openInBrowser(msg.remotePath); break;
      }
    });

    this._render();
  }

  private async _save(config: Record<string, any>) {
    try {
      const merged = { ...this._config, ...config };
      for (const k of Object.keys(merged)) {
        if (merged[k] === '' || merged[k] === null) delete merged[k];
      }
      const dir = path.dirname(this._configPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this._configPath, JSON.stringify(merged, null, 2), 'utf8');
      this._config = merged;
      this._panel.webview.postMessage({ command: 'saved' });
      vscode.window.showInformationMessage('SFTP: Конфигурация сохранена ✓');
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: Ошибка: ${(err as Error).message}`);
    }
  }

  private _connect(cfg: Record<string, any>) {
    const { Client } = require('ssh2');
    const client = new Client();
    const opts: any = {
      host: cfg.host,
      port: parseInt(cfg.port || '22', 10),
      username: cfg.username,
      password: cfg.password || undefined,
      readyTimeout: 9000,
    };
    if (cfg.privateKeyPath) {
      opts.privateKey = fs.readFileSync(cfg.privateKeyPath.replace('~', process.env.HOME || ''));
    }
    return { client, opts };
  }

  private async _testConnection(cfg: Record<string, any>) {
    this._panel.webview.postMessage({ command: 'testingConnection' });
    try {
      const { client, opts } = this._connect(cfg);
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout (10s)')), 10000);
        client.on('ready', () => { clearTimeout(t); client.end(); resolve(); })
              .on('error', (e: Error) => { clearTimeout(t); reject(e); })
              .connect(opts);
      });
      this._panel.webview.postMessage({ command: 'testSuccess' });
      vscode.window.showInformationMessage(`SFTP: ✅ Подключение к ${cfg.host} успешно!`);
    } catch (err) {
      const msg = (err as Error).message;
      this._panel.webview.postMessage({ command: 'testError', message: msg });
      vscode.window.showErrorMessage(`SFTP: ❌ ${msg}`);
    }
  }

  private async _listDir(remotePath: string) {
    try {
      const { client, opts } = this._connect(this._config);
      const listing: any[] = await new Promise((resolve, reject) => {
        client.on('ready', () => {
          client.sftp((err, sftp) => {
            if (err) { client.end(); return reject(err); }
            sftp.readdir(remotePath, (err2, list) => {
              client.end();
              if (err2) return reject(err2);
              resolve(list);
            });
          });
        }).on('error', reject).connect(opts);
      });

      const localBase = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      const configRemoteBase = this._config.remotePath || '/';

      const files = listing
        .sort((a, b) => {
          const aD = !!(a.attrs.mode & 0o040000), bD = !!(b.attrs.mode & 0o040000);
          if (aD && !bD) return -1; if (!aD && bD) return 1;
          return a.filename.localeCompare(b.filename);
        })
        .map(f => {
          const isDir = !!(f.attrs.mode & 0o040000);
          const fp = remotePath.replace(/\/+$/, '') + '/' + f.filename;
          const rel = path.posix.relative(configRemoteBase, fp);
          const localFsPath = localBase ? path.join(localBase, rel) : null;
          let localStatus: 'ok' | 'outdated' | 'none' = 'none';
          if (!isDir && localFsPath) {
            try {
              const ls = fs.statSync(localFsPath);
              localStatus = ls.mtimeMs >= f.attrs.mtime * 1000 - 2000 ? 'ok' : 'outdated';
            } catch { /* no local file */ }
          }
          return { name: f.filename, isDir, size: f.attrs.size, mtime: f.attrs.mtime * 1000, localStatus, localPath: localFsPath || '' };
        });

      this._panel.webview.postMessage({ command: 'dirListing', remotePath, files });
    } catch (err) {
      this._panel.webview.postMessage({ command: 'dirError', message: (err as Error).message });
    }
  }

  private async _downloadFile(remotePath: string, skipMsg = false) {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) return;
    const localBase = folders[0].uri.fsPath;
    const rel = path.posix.relative(this._config.remotePath || '/', remotePath);
    const localPath = path.join(localBase, rel);
    const { client, opts } = this._connect(this._config);
    await new Promise<void>((resolve, reject) => {
      client.on('ready', () => {
        client.sftp((err, sftp) => {
          if (err) { client.end(); return reject(err); }
          fs.mkdirSync(path.dirname(localPath), { recursive: true });
          sftp.fastGet(remotePath, localPath, err2 => { client.end(); err2 ? reject(err2) : resolve(); });
        });
      }).on('error', reject).connect(opts);
    });
    if (!skipMsg) {
      vscode.window.showInformationMessage(`SFTP: ✅ Скачан → ${localPath}`);
      this._panel.webview.postMessage({ command: 'downloadDone' });
    }
    return localPath;
  }

  private async _deleteRemote(remotePath: string, isDir: boolean) {
    const ok = await vscode.window.showWarningMessage(`Удалить на сервере: ${remotePath}?`, { modal: true }, 'Удалить');
    if (ok !== 'Удалить') return;
    try {
      const { client, opts } = this._connect(this._config);
      await new Promise<void>((resolve, reject) => {
        client.on('ready', () => {
          client.sftp((err, sftp) => {
            if (err) { client.end(); return reject(err); }
            const done = (e?) => { client.end(); e ? reject(e) : resolve(); };
            if (isDir) {
              client.exec(`rm -rf "${remotePath}"`, (e, stream) => {
                if (e) return done(e);
                stream.on('close', () => done()).stderr.on('data', d => reject(new Error(d.toString())));
              });
            } else { sftp.unlink(remotePath, done); }
          });
        }).on('error', reject).connect(opts);
      });
      vscode.window.showInformationMessage(`SFTP: ✅ Удалено: ${remotePath}`);
      this._panel.webview.postMessage({ command: 'deleteRemoteDone' });
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: ❌ ${(err as Error).message}`);
    }
  }

  private async _uploadToDir(remotePath: string) {
    const uris = await vscode.window.showOpenDialog({ canSelectFiles: true, canSelectFolders: false, canSelectMany: false, openLabel: 'Выгрузить' });
    if (!uris?.[0]) return;
    const localFile = uris[0].fsPath;
    const remoteFile = remotePath.replace(/\/+$/, '') + '/' + path.basename(localFile);
    try {
      const { client, opts } = this._connect(this._config);
      await new Promise<void>((resolve, reject) => {
        client.on('ready', () => {
          client.sftp((err, sftp) => {
            if (err) { client.end(); return reject(err); }
            sftp.fastPut(localFile, remoteFile, err2 => { client.end(); err2 ? reject(err2) : resolve(); });
          });
        }).on('error', reject).connect(opts);
      });
      vscode.window.showInformationMessage(`SFTP: ✅ Выгружен → ${remoteFile}`);
      this._panel.webview.postMessage({ command: 'uploadDone' });
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: ❌ ${(err as Error).message}`);
    }
  }

  private async _openLocalFile(localPath: string, remotePath: string) {
    try {
      if (!fs.existsSync(localPath)) {
        vscode.window.showInformationMessage(`SFTP: Скачиваю ${path.basename(remotePath)}...`);
        await this._downloadFile(remotePath, true);
      }
      const doc = await vscode.workspace.openTextDocument(localPath);
      await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside });
    } catch (err) {
      vscode.window.showErrorMessage(`SFTP: ❌ ${(err as Error).message}`);
    }
  }

  private _openInBrowser(remotePath: string) {
    const siteUrl = (this._config.siteUrl || '').replace(/\/+$/, '');
    if (!siteUrl) {
      vscode.window.showWarningMessage('SFTP: Укажите URL сайта в настройках (поле "URL сайта")');
      return;
    }
    const rel = path.posix.relative(this._config.remotePath || '/', remotePath);
    vscode.env.openExternal(vscode.Uri.parse(siteUrl + '/' + rel));
  }

  private _v(k: string, fb = '') {
    const v = this._config[k];
    return v !== undefined && v !== null ? String(v) : fb;
  }

  private _render() {
    const c = this._config;
    const protocol = c.protocol || 'sftp';
    const syncOpt = c.syncOption || {};
    const remotePath = this._v('remotePath', '/');

    // ─── CSS ───────────────────────────────────────────────────────────────
    const css = `
:root {
  --bg:#0f0f17;--surface:#16161f;--surface2:#1e1e2a;--surface3:#252533;
  --border:#2e2e42;--text:#d4d4f0;--muted:#5c5c7a;--green:#4ec994;
  --red:#f07070;--yellow:#f0c060;--blue:#6ba3f5;--teal:#5fc0b0;--purple:#a078f0;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;background:var(--bg);color:var(--text);display:flex;flex-direction:column;height:100vh;overflow:hidden;}
.tabs{display:flex;background:var(--surface);border-bottom:1px solid var(--border);height:48px;flex-shrink:0;align-items:flex-end;gap:2px;padding:0 16px;}
.tab{padding:10px 20px;font-size:13px;font-weight:500;cursor:pointer;border-radius:8px 8px 0 0;color:var(--muted);border:1px solid transparent;border-bottom:none;position:relative;top:1px;transition:all .15s;user-select:none;}
.tab:hover{color:var(--text);background:var(--surface2);}
.tab.active{background:var(--bg);border-color:var(--border);color:var(--blue);}
.panel{flex:1;overflow:hidden;display:none;flex-direction:column;}
.panel.active{display:flex;}
.scroll{flex:1;overflow-y:auto;padding:20px;}
.scroll::-webkit-scrollbar{width:6px;}.scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
.section{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:14px;}
.section h3{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:600;margin-bottom:14px;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.grid.three{grid-template-columns:1fr 1fr 1fr;}
.field{display:flex;flex-direction:column;gap:5px;}
.field.full{grid-column:1/-1;}
label{font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.3px;}
label .req{color:var(--red);}
input,select,textarea{background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font-size:13px;width:100%;outline:none;transition:border-color .15s;font-family:inherit;}
input:focus,select:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 2px rgba(107,163,245,.1);}
textarea{resize:vertical;font-family:'Consolas',monospace;font-size:12px;}
.check-row{display:flex;align-items:center;gap:8px;padding:6px 0;}
.check-row input[type=checkbox]{width:16px;height:16px;accent-color:var(--blue);cursor:pointer;}
.check-row span{font-size:13px;color:var(--text);cursor:pointer;}
.divider{border:none;border-top:1px solid var(--border);margin:10px 0;}
.proto-tabs{display:flex;gap:6px;margin-bottom:14px;}
.proto-tab{padding:6px 16px;border-radius:6px;border:1px solid var(--border);cursor:pointer;font-size:12px;font-weight:500;color:var(--muted);transition:all .15s;}
.proto-tab:hover{color:var(--text);border-color:var(--blue);}
.proto-tab.active{background:var(--blue);border-color:var(--blue);color:#0f0f17;}
.sftp-only.hidden{display:none;}
.footer{padding:12px 16px;border-top:1px solid var(--border);background:var(--surface);display:flex;gap:8px;align-items:center;justify-content:space-between;flex-shrink:0;}
.status-text{font-size:12px;}
.status-text.ok{color:var(--green);}.status-text.err{color:var(--red);}.status-text.testing{color:var(--yellow);}
button{padding:7px 16px;border-radius:7px;border:1px solid var(--border);background:var(--surface2);color:var(--text);cursor:pointer;font-size:13px;font-weight:500;transition:all .12s;display:inline-flex;align-items:center;gap:6px;white-space:nowrap;}
button:hover{background:var(--surface3);border-color:var(--blue);}
button.primary{background:var(--blue);border-color:var(--blue);color:#0f0f17;}
button.primary:hover{filter:brightness(1.15);}
button.danger{border-color:var(--red);color:var(--red);}button.danger:hover{background:rgba(240,112,112,.1);}
button.success{border-color:var(--green);color:var(--green);}button.success:hover{background:rgba(78,201,148,.1);}
button.sm{padding:4px 10px;font-size:12px;border-radius:5px;}
.fm-toolbar{display:flex;align-items:center;gap:8px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0;}
.fm-path{flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-family:monospace;font-size:12px;color:var(--teal);outline:none;}
.fm-path:focus{border-color:var(--blue);}
.file-list{flex:1;overflow-y:auto;}
.file-list::-webkit-scrollbar{width:6px;}.file-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
.file-item{display:flex;align-items:center;padding:7px 16px;gap:10px;border-bottom:1px solid rgba(46,46,66,.5);transition:background .1s;}
.file-item:hover{background:var(--surface2);}
.fi-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0;}
.fi-name{flex:1;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fi-name.dir{color:var(--blue);cursor:pointer;font-weight:500;}
.fi-name.dir:hover{text-decoration:underline;}
.fi-name.file-link{cursor:pointer;}
.fi-name.file-link:hover{color:var(--blue);text-decoration:underline;}
.fi-local{font-size:11px;width:90px;text-align:center;flex-shrink:0;}
.fi-local.ok{color:var(--green);}.fi-local.outdated{color:var(--yellow);}.fi-local.none{color:var(--muted);}
.fi-size{font-size:11px;color:var(--muted);width:70px;text-align:right;flex-shrink:0;}
.fi-date{font-size:11px;color:var(--muted);width:130px;text-align:right;flex-shrink:0;}
.fi-actions{display:flex;gap:4px;opacity:0;transition:opacity .15s;flex-shrink:0;}
.file-item:hover .fi-actions{opacity:1;}
.fm-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;flex:1;color:var(--muted);gap:10px;padding:40px;}
.fm-empty .em-icon{font-size:40px;}
.fm-loader{display:flex;align-items:center;justify-content:center;flex:1;color:var(--muted);gap:10px;}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.log-toolbar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0;}
.log-filter{display:flex;gap:4px;}
.log-filter button{padding:4px 10px;font-size:11px;border-radius:4px;}
.log-filter button.active{background:var(--surface3);border-color:var(--blue);color:var(--blue);}
.log-area{flex:1;overflow-y:auto;padding:8px 0;font-family:'Consolas',monospace;font-size:12px;}
.log-area::-webkit-scrollbar{width:6px;}.log-area::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
.log-line{padding:2px 14px;line-height:1.6;display:flex;gap:8px;}
.log-line:hover{background:var(--surface2);}
.ll-time{color:var(--muted);font-size:11px;flex-shrink:0;}
.ll-level{font-size:11px;font-weight:700;padding:1px 5px;border-radius:3px;flex-shrink:0;min-width:50px;text-align:center;}
.ll-msg{color:var(--text);word-break:break-all;}
.log-line.info .ll-level{background:rgba(107,163,245,.15);color:var(--blue);}
.log-line.warn .ll-level{background:rgba(240,192,96,.15);color:var(--yellow);}
.log-line.error .ll-level,.log-line.critical .ll-level{background:rgba(240,112,112,.15);color:var(--red);}
.log-line.debug .ll-level,.log-line.trace .ll-level{background:rgba(92,92,122,.2);color:var(--muted);}
.log-line.conflict .ll-level{background:rgba(160,120,240,.15);color:var(--purple);}
.log-count{font-size:11px;color:var(--muted);margin-left:auto;}
.autoscroll-btn.on{border-color:var(--green);color:var(--green);}`;

    // ─── HTML ──────────────────────────────────────────────────────────────
    const ignore = Array.isArray(c.ignore) ? c.ignore.join('\n') : '';

    this._panel.webview.html = `<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<style>${css}</style></head><body>

<div class="tabs">
  <div class="tab active" onclick="switchTab('fm')" id="tab-fm">📁 Файловый менеджер</div>
  <div class="tab" onclick="switchTab('logs')" id="tab-logs">📋 Логи <span id="log-badge" style="font-size:10px;opacity:.6"></span></div>
  <div class="tab" onclick="switchTab('config')" id="tab-config">⚙ Конфигурация</div>
</div>

<!-- CONFIG TAB -->
<div class="panel" id="panel-config">
<div class="scroll">

  <div class="section">
    <h3>Протокол</h3>
    <div class="proto-tabs">
      <div class="proto-tab ${protocol==='sftp'?'active':''}" onclick="setProtocol('sftp')">SFTP (SSH)</div>
      <div class="proto-tab ${protocol==='ftp'?'active':''}" onclick="setProtocol('ftp')">FTP</div>
      <div class="proto-tab ${protocol==='ftps'?'active':''}" onclick="setProtocol('ftps')">FTPS</div>
    </div>
    <input type="hidden" id="protocol" value="${protocol}">
  </div>

  <div class="section">
    <h3>Соединение</h3>
    <div class="grid three">
      <div class="field"><label>Хост <span class="req">*</span></label><input id="host" type="text" placeholder="example.com" value="${this._v('host')}"></div>
      <div class="field"><label>Порт</label><input id="port" type="number" placeholder="22" value="${this._v('port','22')}"></div>
      <div class="field"><label>Таймаут (мс)</label><input id="connectTimeout" type="number" placeholder="10000" value="${this._v('connectTimeout','10000')}"></div>
    </div>
  </div>

  <div class="section">
    <h3>Аутентификация</h3>
    <div class="grid">
      <div class="field"><label>Пользователь <span class="req">*</span></label><input id="username" type="text" placeholder="root" value="${this._v('username')}"></div>
      <div class="field"><label>Пароль</label><input id="password" type="password" placeholder="••••••••" value="${this._v('password')}"></div>
      <div class="field sftp-only ${protocol!=='sftp'?'hidden':''}"><label>Путь к приватному ключу</label><input id="privateKeyPath" type="text" placeholder="~/.ssh/id_rsa" value="${this._v('privateKeyPath')}"></div>
      <div class="field sftp-only ${protocol!=='sftp'?'hidden':''}"><label>Passphrase</label><input id="passphrase" type="password" placeholder="(если ключ защищён)" value="${this._v('passphrase')}"></div>
    </div>
  </div>

  <div class="section">
    <h3>Пути и сайт</h3>
    <div class="grid">
      <div class="field"><label>Удалённый путь <span class="req">*</span></label><input id="remotePath" type="text" placeholder="/var/www/html" value="${this._v('remotePath','/')}"></div>
      <div class="field"><label>Имя профиля</label><input id="name" type="text" placeholder="production" value="${this._v('name')}"></div>
      <div class="field full"><label>URL сайта (для открытия файлов в браузере)</label><input id="siteUrl" type="text" placeholder="https://example.com" value="${this._v('siteUrl')}"></div>
    </div>
  </div>

  <div class="section">
    <h3>Поведение</h3>
    <div class="grid">
      <div>
        <div class="check-row"><input type="checkbox" id="uploadOnSave" ${c.uploadOnSave?'checked':''}><span onclick="document.getElementById('uploadOnSave').click()">Выгружать при сохранении</span></div>
        <div class="check-row"><input type="checkbox" id="downloadOnOpen" ${c.downloadOnOpen?'checked':''}><span onclick="document.getElementById('downloadOnOpen').click()">Скачивать при открытии</span></div>
        <div class="check-row"><input type="checkbox" id="smartSync" ${syncOpt.smartSync?'checked':''}><span onclick="document.getElementById('smartSync').click()">🧠 Умная синхронизация</span></div>
      </div>
      <div class="field">
        <label>Разрешение конфликтов</label>
        <select id="conflictResolution">
          <option value="newer" ${(syncOpt.conflictResolution||'newer')==='newer'?'selected':''}>Новее (newer)</option>
          <option value="local" ${syncOpt.conflictResolution==='local'?'selected':''}>Всегда локальный</option>
          <option value="remote" ${syncOpt.conflictResolution==='remote'?'selected':''}>Всегда сервер</option>
          <option value="skip" ${syncOpt.conflictResolution==='skip'?'selected':''}>Пропускать</option>
        </select>
        <label style="margin-top:10px">Параллельных соединений</label>
        <input id="concurrency" type="number" placeholder="4" value="${this._v('concurrency','4')}">
      </div>
    </div>
    <hr class="divider">
    <div class="field"><label>Игнорировать (glob, по одному на строку)</label>
      <textarea id="ignore" rows="5" placeholder=".git&#10;node_modules&#10;.DS_Store">${ignore}</textarea>
    </div>
  </div>

</div>
<div class="footer">
  <div style="display:flex;gap:8px;align-items:center">
    <button onclick="testConnection()">🔌 Тест соединения</button>
    <span id="testStatus" class="status-text"></span>
  </div>
  <div style="display:flex;gap:8px">
    <button onclick="openFile()">📝 Открыть sftp.json</button>
    <button class="primary" onclick="save()">💾 Сохранить</button>
  </div>
</div>
</div>

<!-- FILE MANAGER TAB -->
<div class="panel active" id="panel-fm">
  <div class="fm-toolbar">
    <button class="sm" onclick="fmGoUp()">↑ Вверх</button>
    <input class="fm-path" id="fm-path-input" type="text" value="${remotePath}" onkeydown="if(event.key==='Enter')fmNavigate(this.value.trim())">
    <button class="sm" onclick="fmRefresh()">↻ Обновить</button>
    <button class="sm success" onclick="fmUpload()">⬆ Загрузить файл</button>
  </div>
  <div id="fm-content" class="fm-empty">
    <div class="em-icon">📡</div>
    <div>Нажмите «Обновить» для подключения к серверу</div>
    <button onclick="fmRefresh()">Подключиться</button>
  </div>
</div>

<!-- LOGS TAB -->
<div class="panel" id="panel-logs">
  <div class="log-toolbar">
    <div class="log-filter">
      <button class="active" id="filter-all" onclick="setFilter('all')">Все</button>
      <button id="filter-info" onclick="setFilter('info')">Info</button>
      <button id="filter-warn" onclick="setFilter('warn')">Warn</button>
      <button id="filter-error" onclick="setFilter('error')">Error</button>
      <button id="filter-conflict" onclick="setFilter('conflict')">Конфликты</button>
    </div>
    <span class="log-count" id="log-count">0 строк</span>
    <button class="autoscroll-btn on sm" id="autoscroll-btn" onclick="toggleAutoscroll()" style="margin-left:auto">📌 Автопрокрутка</button>
    <button class="sm" onclick="clearLogs()">🗑 Очистить</button>
  </div>
  <div class="log-area" id="log-area"></div>
</div>

<script>
const vscode = acquireVsCodeApi();
let currentFilter = 'all', autoscroll = true, logCount = 0, allLogs = [];
let fmCurrentPath = ${JSON.stringify(remotePath)};

// ── Tabs
function switchTab(tab) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + tab).classList.add('active');
  document.getElementById('tab-' + tab).classList.add('active');
  if (tab === 'fm' && !document.querySelector('.file-item')) fmRefresh();
}

// ── Config
function setProtocol(p) {
  document.getElementById('protocol').value = p;
  document.querySelectorAll('.proto-tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.sftp-only').forEach(el => el.classList.toggle('hidden', p !== 'sftp'));
}
function getConfig() {
  const ignore = document.getElementById('ignore').value.split('\\n').map(s => s.trim()).filter(Boolean);
  return {
    protocol: document.getElementById('protocol').value,
    name: document.getElementById('name').value.trim() || undefined,
    host: document.getElementById('host').value.trim(),
    port: parseInt(document.getElementById('port').value) || 22,
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value || undefined,
    privateKeyPath: document.getElementById('privateKeyPath')?.value.trim() || undefined,
    passphrase: document.getElementById('passphrase')?.value || undefined,
    remotePath: document.getElementById('remotePath').value.trim() || '/',
    siteUrl: document.getElementById('siteUrl').value.trim() || undefined,
    uploadOnSave: document.getElementById('uploadOnSave').checked,
    downloadOnOpen: document.getElementById('downloadOnOpen').checked,
    concurrency: parseInt(document.getElementById('concurrency').value) || 4,
    ignore: ignore.length > 0 ? ignore : undefined,
    syncOption: {
      smartSync: document.getElementById('smartSync').checked,
      conflictResolution: document.getElementById('conflictResolution').value,
    }
  };
}
function save() { vscode.postMessage({ command: 'save', config: getConfig() }); }
function testConnection() {
  const s = document.getElementById('testStatus');
  s.textContent = '⏳ Подключаюсь...'; s.className = 'status-text testing';
  vscode.postMessage({ command: 'testConnection', config: getConfig() });
}
function openFile() { vscode.postMessage({ command: 'openFile' }); }

// ── File Manager
function fmNavigate(p) {
  fmCurrentPath = p || '/';
  document.getElementById('fm-path-input').value = fmCurrentPath;
  const c = document.getElementById('fm-content');
  c.className = 'fm-loader';
  c.innerHTML = '<div class="spinner"></div><span>Загрузка...</span>';
  vscode.postMessage({ command: 'listDir', remotePath: fmCurrentPath });
}
function fmRefresh() { fmNavigate(document.getElementById('fm-path-input').value.trim() || fmCurrentPath); }
function fmGoUp() {
  const parts = fmCurrentPath.replace(/\\/+$/, '').split('/');
  if (parts.length <= 1) return;
  parts.pop();
  fmNavigate(parts.join('/') || '/');
}
function fmUpload() { vscode.postMessage({ command: 'uploadToDir', remotePath: fmCurrentPath }); }
function fmDownload(rp, isDir) { vscode.postMessage({ command: 'downloadFile', remotePath: rp, isDir }); }
function fmDelete(rp, isDir) { vscode.postMessage({ command: 'deleteRemote', remotePath: rp, isDir }); }
function fmOpen(rp, lp) { vscode.postMessage({ command: 'openLocalFile', remotePath: rp, localPath: lp }); }
function fmOpenBrowser(rp) { vscode.postMessage({ command: 'openInBrowser', remotePath: rp }); }

function formatSize(b) {
  if (!b) return '—';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}
function formatDate(ms) {
  if (!ms) return '—';
  const d = new Date(ms);
  return d.toLocaleDateString('ru') + ' ' + d.toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'});
}
function getIcon(name) {
  const ext = (name.split('.').pop()||'').toLowerCase();
  const m = {php:'🐘',js:'☁',ts:'💙',css:'🎨',html:'🌐',htm:'🌐',json:'📦',md:'📝',txt:'📄',sql:'🗄',zip:'📦',gz:'📦',jpg:'🖼',png:'🖼',gif:'🖼',svg:'🖼',sh:'⚙',py:'🐍',xml:'📋',yml:'⚙',yaml:'⚙'};
  return m[ext]||'📄';
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderFmListing(remotePath, files) {
  fmCurrentPath = remotePath;
  document.getElementById('fm-path-input').value = remotePath;
  const cont = document.getElementById('fm-content');
  if (!files.length) {
    cont.className = 'fm-empty';
    cont.innerHTML = '<div class="em-icon">📂</div><div>Папка пуста</div>';
    return;
  }
  const parentPath = remotePath === '/' ? null : (remotePath.replace(/\\/+$/, '').split('/').slice(0,-1).join('/')||'/');
  const TEXT_RE = /\\.(php|js|ts|css|html|htm|json|xml|txt|md|sh|py|sql|yml|yaml|ini|env|conf|log|csv)$/i;
  let html = '<div class="file-list">';
  if (parentPath !== null) {
    html += '<div class="file-item" onclick="fmNavigate(\\''+parentPath.replace(/'/g,"\\\\'")+'\\')" title="Уровень выше"><div class="fi-icon">📁</div><div class="fi-name dir">..</div><div class="fi-local none">—</div><div class="fi-size"></div><div class="fi-date"></div><div class="fi-actions"></div></div>';
  }
  for (const f of files) {
    const fp = remotePath.replace(/\\/+$/,'') + '/' + f.name;
    const fpE = fp.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");
    const lpE = (f.localPath||'').replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");
    const icon = f.isDir ? '📁' : getIcon(f.name);
    const localEl = f.isDir ? '<div class="fi-local none">—</div>' :
      f.localStatus==='ok' ? '<div class="fi-local ok">✅ Актуален</div>' :
      f.localStatus==='outdated' ? '<div class="fi-local outdated">⚠ Устарел</div>' :
      '<div class="fi-local none">— Нет</div>';
    const nameHtml = f.isDir
      ? '<div class="fi-name dir" onclick="fmNavigate(\\''+fpE+'\\')">' + esc(f.name) + '</div>'
      : '<div class="fi-name file-link" onclick="fmOpen(\\''+fpE+'\\',\\''+lpE+'\\')" title="Открыть локально">' + esc(f.name) + '</div>';
    const dlBtn = f.isDir ? '' : '<button class="sm success" onclick="fmDownload(\\''+fpE+'\\',false)" title="Скачать">⬇</button>';
    const brBtn = (!f.isDir && TEXT_RE.test(f.name)) ? '<button class="sm" onclick="fmOpenBrowser(\\''+fpE+'\\')" title="Открыть в браузере">🌐</button>' : '';
    const delBtn = '<button class="sm danger" onclick="fmDelete(\\''+fpE+'\\','+f.isDir+')" title="Удалить">🗑</button>';
    html += '<div class="file-item">' +
      '<div class="fi-icon">'+icon+'</div>' + nameHtml + localEl +
      '<div class="fi-size">'+formatSize(f.size)+'</div>' +
      '<div class="fi-date">'+formatDate(f.mtime)+'</div>' +
      '<div class="fi-actions">'+dlBtn+brBtn+delBtn+'</div></div>';
  }
  html += '</div>';
  cont.className = 'file-list';
  cont.innerHTML = html;
}

// ── Logs
function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.log-filter button').forEach(b => b.classList.remove('active'));
  document.getElementById('filter-'+f).classList.add('active');
  renderLogs();
}
function toggleAutoscroll() {
  autoscroll = !autoscroll;
  const btn = document.getElementById('autoscroll-btn');
  btn.textContent = autoscroll ? '📌 Автопрокрутка' : '📌 Вкл. прокрутку';
  btn.classList.toggle('on', autoscroll);
}
function clearLogs() {
  allLogs = []; logCount = 0;
  document.getElementById('log-area').innerHTML = '';
  document.getElementById('log-count').textContent = '0 строк';
  document.getElementById('log-badge').textContent = '';
}
function parseLogLine(raw) {
  const m = raw.match(/^\\[(\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\]\\s+\\[(\\w+)\\]\\s+(.*)$/s);
  if (!m) return { time:'', level:'info', msg:raw };
  return { time:m[1], level:m[2].toLowerCase(), msg:m[3] };
}
function renderLogs() {
  const area = document.getElementById('log-area');
  const filtered = currentFilter === 'all' ? allLogs :
    allLogs.filter(l => {
      if (currentFilter==='conflict') return l.msg.includes('[conflict-check]');
      if (currentFilter==='error') return l.level==='error'||l.level==='critical';
      return l.level===currentFilter;
    });
  area.innerHTML = filtered.map(l => {
    const cls = l.msg.includes('[conflict-check]') ? 'conflict' : l.level;
    return '<div class="log-line '+cls+'"><span class="ll-time">'+esc(l.time)+'</span><span class="ll-level">'+l.level+'</span><span class="ll-msg">'+esc(l.msg)+'</span></div>';
  }).join('');
  document.getElementById('log-count').textContent = filtered.length + ' строк';
}
function appendLog(raw) {
  const p = parseLogLine(raw);
  allLogs.push(p); logCount++;
  document.getElementById('log-badge').textContent = logCount > 99 ? '(99+)' : '('+logCount+')';
  const show = currentFilter==='all' || (currentFilter==='conflict'&&p.msg.includes('[conflict-check]')) ||
    (currentFilter==='error'&&(p.level==='error'||p.level==='critical')) || p.level===currentFilter;
  if (show) {
    const area = document.getElementById('log-area');
    const cls = p.msg.includes('[conflict-check]') ? 'conflict' : p.level;
    area.insertAdjacentHTML('beforeend','<div class="log-line '+cls+'"><span class="ll-time">'+esc(p.time)+'</span><span class="ll-level">'+p.level+'</span><span class="ll-msg">'+esc(p.msg)+'</span></div>');
    document.getElementById('log-count').textContent = area.children.length + ' строк';
    if (autoscroll) area.scrollTop = area.scrollHeight;
  }
}

// ── Messages from extension
window.addEventListener('message', e => {
  const msg = e.data;
  const status = document.getElementById('testStatus');
  if (msg.command==='testingConnection') { status.textContent='⏳ Проверяю...'; status.className='status-text testing'; }
  else if (msg.command==='testSuccess') { status.textContent='✅ Соединение OK'; status.className='status-text ok'; }
  else if (msg.command==='testError') { status.textContent='❌ '+msg.message; status.className='status-text err'; }
  else if (msg.command==='dirListing') { renderFmListing(msg.remotePath, msg.files); }
  else if (msg.command==='dirError') {
    const c = document.getElementById('fm-content');
    c.className='fm-empty';
    c.innerHTML='<div class="em-icon">⚠️</div><div style="color:var(--red)">'+esc(msg.message)+'</div><button onclick="fmRefresh()">Повторить</button>';
  }
  else if (msg.command==='deleteRemoteDone'||msg.command==='uploadDone'||msg.command==='downloadDone') { fmRefresh(); }
  else if (msg.command==='log') { appendLog(msg.line); }
});
</script>
</body></html>`;
  }
}
