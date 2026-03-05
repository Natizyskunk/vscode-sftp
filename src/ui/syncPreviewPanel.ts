import * as vscode from 'vscode';
import { FileDiff } from '../core/deltaSync';

/**
 * SyncPreviewPanel — Webview для предварительного просмотра
 * результатов дельта-синхронизации перед её запуском.
 *
 * Показывает таблицу: что будет загружено, скачано, пропущено, конфликты.
 * Пользователь может выбрать действие для каждого файла.
 */
export class SyncPreviewPanel {
  static readonly viewType = 'sftp.syncPreview';
  private static _instance: SyncPreviewPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private _diffs: FileDiff[] = [];
  private _onConfirm?: (selectedDiffs: FileDiff[]) => void;

  static async show(
    diffs: FileDiff[],
    onConfirm: (selectedDiffs: FileDiff[]) => void
  ): Promise<void> {
    if (SyncPreviewPanel._instance) {
      SyncPreviewPanel._instance._panel.dispose();
    }

    const panel = vscode.window.createWebviewPanel(
      SyncPreviewPanel.viewType,
      '🔄 SFTP: Предварительный просмотр синхронизации',
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    SyncPreviewPanel._instance = new SyncPreviewPanel(panel, diffs, onConfirm);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    diffs: FileDiff[],
    onConfirm: (selectedDiffs: FileDiff[]) => void
  ) {
    this._panel = panel;
    this._diffs = diffs;
    this._onConfirm = onConfirm;

    this._panel.onDidDispose(() => {
      SyncPreviewPanel._instance = undefined;
    });

    this._panel.webview.onDidReceiveMessage(msg => {
      switch (msg.command) {
        case 'confirm':
          this._handleConfirm(msg.overrides || {});
          break;
        case 'cancel':
          this._panel.dispose();
          break;
        case 'selectAll':
          this._panel.webview.postMessage({ command: 'selectAll', action: msg.action });
          break;
      }
    });

    this._render();
  }

  private _handleConfirm(overrides: Record<string, 'upload' | 'download' | 'skip'>) {
    const result = this._diffs
      .map(diff => {
        const override = overrides[diff.relativePath];
        return override ? { ...diff, action: override } : diff;
      })
      .filter(diff => diff.action !== 'skip');

    if (this._onConfirm) {
      this._onConfirm(result);
    }
    this._panel.dispose();
  }

  private _formatBytes(bytes?: number): string {
    if (!bytes) return '—';
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / 1048576).toFixed(2)} МБ`;
  }

  private _formatDate(dt?: Date): string {
    if (!dt) return '—';
    return dt.toLocaleString('ru-RU', {
      day: '2-digit', month: '2-digit', year: '2-digit',
      hour: '2-digit', minute: '2-digit'
    });
  }

  private _render() {
    const uploads = this._diffs.filter(d => d.action === 'upload').length;
    const downloads = this._diffs.filter(d => d.action === 'download').length;
    const conflicts = this._diffs.filter(d => d.status === 'conflict').length;
    const total = this._diffs.length;

    const rows = this._diffs.map((diff, idx) => {
      const statusEmoji = {
        new_local: '🆕',
        new_remote: '🆕',
        modified: '✏️',
        conflict: '⚠️',
        identical: '✓',
      }[diff.status];

      return `
<tr data-path="${diff.relativePath}">
  <td class="chk"><input type="checkbox" class="row-check" data-idx="${idx}" ${diff.action !== 'skip' ? 'checked' : ''} onchange="updateAction(this, '${diff.relativePath}')"></td>
  <td class="status">${statusEmoji}</td>
  <td class="path" title="${diff.relativePath}">${diff.relativePath}</td>
  <td class="action-cell">
    <select class="action-select" data-path="${diff.relativePath}" onchange="setOverride(this)">
      <option value="upload" ${diff.action === 'upload' ? 'selected' : ''}>↑ Загрузить</option>
      <option value="download" ${diff.action === 'download' ? 'selected' : ''}>↓ Скачать</option>
      <option value="skip" ${diff.action === 'skip' ? 'selected' : ''}>— Пропустить</option>
    </select>
  </td>
  <td class="size">${this._formatBytes(diff.localSize)}</td>
  <td class="size">${this._formatBytes(diff.remoteSize)}</td>
  <td class="date">${this._formatDate(diff.localMtime)}</td>
  <td class="date">${this._formatDate(diff.remoteMtime)}</td>
</tr>`;
    }).join('');

    this._panel.webview.html = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<style>
  :root { --bg: #1e1e2e; --surface: #2a2a3d; --border: #3a3a5c; --text: #cdd6f4; --muted: #6c7086; --green: #a6e3a1; --red: #f38ba8; --yellow: #f9e2af; --blue: #89b4fa; --upload: #89dceb; --download: #cba6f7; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; font-size: 13px; background: var(--bg); color: var(--text); margin: 0; padding: 0; display: flex; flex-direction: column; height: 100vh; }
  .header { background: var(--surface); padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .header h2 { margin: 0 0 8px; font-size: 15px; color: var(--blue); }
  .stats { display: flex; gap: 16px; font-size: 12px; }
  .badge { padding: 3px 10px; border-radius: 12px; font-weight: 600; }
  .badge.upload { background: #1a3340; color: var(--upload); }
  .badge.download { background: #2a1a3d; color: var(--download); }
  .badge.conflict { background: #3d3519; color: var(--yellow); }
  .badge.total { background: var(--border); color: var(--text); }
  .toolbar { display: flex; gap: 8px; align-items: center; padding: 8px 16px; border-bottom: 1px solid var(--border); }
  .toolbar span { color: var(--muted); font-size: 12px; margin-right: auto; }
  button { padding: 5px 14px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 12px; transition: background 0.15s; }
  button:hover { background: var(--border); }
  button.primary { background: var(--blue); border-color: var(--blue); color: #1e1e2e; font-weight: 600; }
  button.primary:hover { background: #6aa0e8; }
  button.danger { border-color: var(--red); color: var(--red); }
  .table-wrap { flex: 1; overflow: auto; }
  table { width: 100%; border-collapse: collapse; table-layout: auto; }
  thead th { background: var(--surface); padding: 6px 10px; text-align: left; font-weight: 500; color: var(--muted); font-size: 12px; border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 1; }
  td { padding: 5px 10px; border-bottom: 1px solid #2a2a3d; vertical-align: middle; }
  tr:hover td { background: var(--surface); }
  .chk { width: 28px; }
  .status { width: 30px; text-align: center; }
  .path { max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: monospace; font-size: 12px; }
  .action-cell { width: 140px; }
  .action-select { background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; font-size: 12px; cursor: pointer; }
  .size { width: 80px; color: var(--muted); font-size: 12px; }
  .date { width: 110px; color: var(--muted); font-size: 11px; }
  .footer { padding: 8px 16px; border-top: 1px solid var(--border); display: flex; gap: 8px; justify-content: flex-end; background: var(--surface); }
  .empty { text-align: center; padding: 64px; color: var(--muted); }
</style>
</head>
<body>
<div class="header">
  <h2>🔄 Предварительный просмотр синхронизации</h2>
  <div class="stats">
    <span class="badge total">Всего: ${total}</span>
    <span class="badge upload">↑ Загрузить: ${uploads}</span>
    <span class="badge download">↓ Скачать: ${downloads}</span>
    ${conflicts > 0 ? `<span class="badge conflict">⚠ Конфликтов: ${conflicts}</span>` : ''}
  </div>
</div>
<div class="toolbar">
  <span>Проверьте список и нажмите «Синхронизировать»</span>
  <button onclick="selectAll('upload')">Выбрать загрузку</button>
  <button onclick="selectAll('download')">Выбрать скачивание</button>
  <button onclick="selectAll('skip')">Пропустить всё</button>
</div>
<div class="table-wrap">
  ${this._diffs.length === 0
    ? `<div class="empty">✅ Файлы идентичны — синхронизация не требуется</div>`
    : `<table>
  <thead><tr>
    <th></th><th>Статус</th><th>Путь</th><th>Действие</th>
    <th>Локальный</th><th>Удалённый</th><th>Изм. (лок.)</th><th>Изм. (уд.)</th>
  </tr></thead>
  <tbody>${rows}</tbody>
</table>`}
</div>
<div class="footer">
  <button class="danger" onclick="cancel()">Отмена</button>
  <button class="primary" onclick="confirm()">▶ Синхронизировать (${total} файлов)</button>
</div>
<script>
  const vscode = acquireVsCodeApi();
  const overrides = {};

  function setOverride(select) {
    overrides[select.dataset.path] = select.value;
  }

  function selectAll(action) {
    document.querySelectorAll('.action-select').forEach(sel => {
      sel.value = action;
      overrides[sel.dataset.path] = action;
    });
  }

  function confirm() {
    vscode.postMessage({ command: 'confirm', overrides });
  }

  function cancel() {
    vscode.postMessage({ command: 'cancel' });
  }
</script>
</body>
</html>`;
  }
}
