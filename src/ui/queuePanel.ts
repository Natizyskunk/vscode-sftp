import * as vscode from 'vscode';
import { Task } from '../core/scheduler';

interface QueueItem {
  taskId: string;
  label: string;
  status: 'pending' | 'running' | 'done' | 'error';
  direction: string;
  bytesTransferred?: number;
  totalBytes?: number;
  errorMessage?: string;
}

/**
 * Transfer Queue Panel — Webview-панель с визуальным отображением
 * очереди передачи файлов: список файлов, прогресс, скорость, ошибки.
 */
export class QueuePanel {
  static readonly viewType = 'sftp.queuePanel';
  private static _instance: QueuePanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private _items: Map<string, QueueItem> = new Map();
  private _totalTransferred = 0;
  private _speedSamples: number[] = [];
  private _lastBytesAt = 0;
  private _lastBytesTime = Date.now();

  static createOrShow(extensionUri: vscode.Uri): QueuePanel {
    const column = vscode.ViewColumn.Beside;
    if (QueuePanel._instance) {
      QueuePanel._instance._panel.reveal(column);
      return QueuePanel._instance;
    }

    const panel = vscode.window.createWebviewPanel(
      QueuePanel.viewType,
      '⬆ SFTP: Очередь передачи',
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    QueuePanel._instance = new QueuePanel(panel, extensionUri);
    return QueuePanel._instance;
  }

  static getInstance(): QueuePanel | undefined {
    return QueuePanel._instance;
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._lastBytesTime = Date.now();

    this._panel.onDidDispose(() => {
      QueuePanel._instance = undefined;
    });

    this._panel.webview.onDidReceiveMessage(msg => {
      if (msg.command === 'retryAll') {
        vscode.commands.executeCommand('sftp.retryFailedTransfers');
      } else if (msg.command === 'cancelAll') {
        vscode.commands.executeCommand('sftp.cancelAllTransfer');
      } else if (msg.command === 'clearDone') {
        this._clearCompleted();
      }
    });

    this._render();
  }

  /** Добавить новый файл в очередь */
  addTask(task: Task) {
    if (!task.taskId) return;
    this._items.set(task.taskId, {
      taskId: task.taskId,
      label: task.label || task.taskId,
      status: 'pending',
      direction: task.label?.startsWith('↑') ? 'upload' : 'download',
    });
    this._render();
  }

  /** Отметить задачу как выполняемую */
  markRunning(taskId: string) {
    const item = this._items.get(taskId);
    if (item) {
      item.status = 'running';
      this._render();
    }
  }

  /** Обновить прогресс передачи */
  updateProgress(taskId: string, bytesTransferred: number, totalBytes: number) {
    const item = this._items.get(taskId);
    if (item) {
      const delta = bytesTransferred - (item.bytesTransferred || 0);
      item.bytesTransferred = bytesTransferred;
      item.totalBytes = totalBytes;

      // Подсчёт скорости (байт/сек)
      if (delta > 0) {
        this._totalTransferred += delta;
        const now = Date.now();
        const elapsed = (now - this._lastBytesTime) / 1000;
        if (elapsed > 0.5) {
          const speed = (this._totalTransferred - this._lastBytesAt) / elapsed;
          this._speedSamples.push(speed);
          if (this._speedSamples.length > 5) this._speedSamples.shift();
          this._lastBytesAt = this._totalTransferred;
          this._lastBytesTime = now;
        }
      }
      this._render();
    }
  }

  /** Отметить задачу как завершённую */
  markDone(taskId: string) {
    const item = this._items.get(taskId);
    if (item) {
      item.status = 'done';
      this._render();
    }
  }

  /** Отметить задачу как завершённую с ошибкой */
  markError(taskId: string, errorMessage: string) {
    const item = this._items.get(taskId);
    if (item) {
      item.status = 'error';
      item.errorMessage = errorMessage;
      this._render();
    }
  }

  private _clearCompleted() {
    for (const [id, item] of this._items.entries()) {
      if (item.status === 'done') {
        this._items.delete(id);
      }
    }
    this._render();
  }

  private _getAverageSpeed(): number {
    if (this._speedSamples.length === 0) return 0;
    return this._speedSamples.reduce((a, b) => a + b, 0) / this._speedSamples.length;
  }

  private _formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / 1024 / 1024).toFixed(2)} МБ`;
  }

  private _formatSpeed(bps: number): string {
    if (bps <= 0) return '—';
    return `${this._formatBytes(bps)}/с`;
  }

  private _render() {
    const items = Array.from(this._items.values());
    const pending = items.filter(i => i.status === 'pending').length;
    const running = items.filter(i => i.status === 'running').length;
    const done = items.filter(i => i.status === 'done').length;
    const errors = items.filter(i => i.status === 'error').length;
    const speed = this._getAverageSpeed();

    this._panel.webview.html = this._buildHtml(items, {
      pending, running, done, errors, speed,
      totalTransferred: this._totalTransferred,
    });
  }

  private _buildHtml(items: QueueItem[], stats: {
    pending: number; running: number; done: number; errors: number;
    speed: number; totalTransferred: number;
  }): string {
    const rows = items.map(item => {
      const statusIcon = {
        pending: '⏳',
        running: '🔄',
        done: '✅',
        error: '❌',
      }[item.status];

      const dirIcon = item.direction === 'upload' ? '↑' : '↓';
      const dirClass = item.direction === 'upload' ? 'upload' : 'download';

      let progressHtml = '';
      if (item.status === 'running' && item.totalBytes && item.totalBytes > 0) {
        const pct = Math.min(100, Math.round((item.bytesTransferred! / item.totalBytes) * 100));
        progressHtml = `<div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>`;
      }

      const errorHtml = item.errorMessage
        ? `<span class="error-msg" title="${item.errorMessage}">⚠ ${item.errorMessage.slice(0, 50)}</span>`
        : '';

      return `<tr class="row-${item.status}">
        <td class="status-cell">${statusIcon}</td>
        <td class="dir-cell ${dirClass}">${dirIcon}</td>
        <td class="label-cell" title="${item.label}">${item.label}</td>
        <td class="progress-cell">${progressHtml}${errorHtml}</td>
      </tr>`;
    }).join('');

    const hasErrors = stats.errors > 0;
    const hasDone = stats.done > 0;

    return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<style>
  :root { --bg: #1e1e2e; --surface: #2a2a3d; --border: #3a3a5c; --text: #cdd6f4; --muted: #6c7086; --green: #a6e3a1; --red: #f38ba8; --yellow: #f9e2af; --blue: #89b4fa; --upload: #89dceb; --download: #cba6f7; }
  body { font-family: 'Segoe UI', sans-serif; font-size: 13px; background: var(--bg); color: var(--text); margin: 0; padding: 0; height: 100vh; display: flex; flex-direction: column; }
  .header { background: var(--surface); padding: 10px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .header h2 { margin: 0; font-size: 14px; font-weight: 600; color: var(--blue); }
  .stats { display: flex; gap: 12px; flex: 1; }
  .stat { background: var(--bg); border-radius: 6px; padding: 4px 10px; font-size: 12px; }
  .stat span { color: var(--muted); }
  .stat b { color: var(--text); }
  .speed { color: var(--green); font-weight: 600; }
  .actions { display: flex; gap: 8px; }
  button { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: background 0.15s; }
  button:hover { background: var(--border); }
  button.danger { border-color: var(--red); color: var(--red); }
  button.danger:hover { background: #3d1e2a; }
  .table-wrap { flex: 1; overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; }
  tr { border-bottom: 1px solid var(--border); transition: background 0.1s; }
  tr:hover { background: var(--surface); }
  tr.row-done .label-cell { color: var(--muted); }
  tr.row-error .label-cell { color: var(--red); }
  tr.row-running .label-cell { color: var(--text); font-weight: 500; }
  td { padding: 6px 10px; vertical-align: middle; }
  .status-cell { width: 24px; text-align: center; }
  .dir-cell { width: 20px; text-align: center; font-weight: bold; }
  .dir-cell.upload { color: var(--upload); }
  .dir-cell.download { color: var(--download); }
  .label-cell { max-width: 260px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .progress-cell { width: 180px; }
  .progress-bar { height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .progress-fill { height: 100%; background: var(--blue); border-radius: 2px; transition: width 0.3s; }
  .error-msg { color: var(--red); font-size: 11px; }
  .empty { text-align: center; padding: 48px; color: var(--muted); }
  .footer { padding: 6px 16px; border-top: 1px solid var(--border); font-size: 11px; color: var(--muted); background: var(--surface); }
</style>
</head>
<body>
<div class="header">
  <h2>⬆↓ Очередь передачи файлов SFTP</h2>
  <div class="stats">
    <div class="stat"><span>В очереди</span> <b>${stats.pending + stats.running}</b></div>
    <div class="stat"><span>Готово</span> <b style="color:var(--green)">${stats.done}</b></div>
    ${stats.errors > 0 ? `<div class="stat"><span>Ошибок</span> <b style="color:var(--red)">${stats.errors}</b></div>` : ''}
    <div class="stat speed"><span>Скорость</span> <b>${this._formatSpeed(stats.speed)}</b></div>
    <div class="stat"><span>Передано</span> <b>${this._formatBytes(stats.totalTransferred)}</b></div>
  </div>
  <div class="actions">
    ${hasDone ? `<button onclick="send('clearDone')">Очистить завершённые</button>` : ''}
    ${hasErrors ? `<button onclick="send('retryAll')">↻ Повторить ошибки</button>` : ''}
    <button class="danger" onclick="send('cancelAll')">✕ Отменить всё</button>
  </div>
</div>
<div class="table-wrap">
  ${items.length === 0
    ? `<div class="empty">📭 Очередь пуста</div>`
    : `<table><tbody>${rows}</tbody></table>`}
</div>
<div class="footer">SFTP Transfer Queue · ${new Date().toLocaleTimeString('ru-RU')}</div>
<script>
  const vscode = acquireVsCodeApi();
  function send(command) { vscode.postMessage({ command }); }
</script>
</body>
</html>`;
  }
}
