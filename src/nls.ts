/**
 * Централизованный файл NLS-строк для runtime-сообщений расширения.
 *
 * Использование:
 *   import { localize } from './nls';
 *   vscode.window.showErrorMessage(localize('sftp.error.connectionFailed', 'Connection failed: {0}', err.message));
 *
 * vscode-nls автоматически подберёт нужный язык на основе локали VS Code.
 */
import * as nls from 'vscode-nls';

// loadMessageBundle() загружает файл локализации (nls.ru.json и т.д.) автоматически
const localize = nls.loadMessageBundle();

export { localize };

// ============================================================
// Готовые локализованные строки для часто используемых сообщений
// ============================================================

export const Messages = {
  // Ошибки соединения
  connectionFailed: (host: string, reason: string) =>
    localize('sftp.error.connectionFailed', 'SFTP: Ошибка подключения к {0}: {1}', host, reason),

  connectionCancelled: () =>
    localize('sftp.info.connectionCancelled', 'SFTP: Подключение отменено'),

  reconnecting: (attempt: number, max: number) =>
    localize('sftp.info.reconnecting', 'SFTP: Переподключение ({0}/{1})...', attempt, max),

  reconnectFailed: () =>
    localize('sftp.error.reconnectFailed', 'SFTP: Не удалось переподключиться'),

  // Загрузка/скачивание
  uploadSuccess: (file: string) =>
    localize('sftp.info.uploadSuccess', 'SFTP: Файл загружен: {0}', file),

  uploadFailed: (file: string, reason: string) =>
    localize('sftp.error.uploadFailed', 'SFTP: Ошибка загрузки {0}: {1}', file, reason),

  downloadSuccess: (file: string) =>
    localize('sftp.info.downloadSuccess', 'SFTP: Файл скачан: {0}', file),

  downloadFailed: (file: string, reason: string) =>
    localize('sftp.error.downloadFailed', 'SFTP: Ошибка скачивания {0}: {1}', file, reason),

  // Синхронизация
  syncStarted: () =>
    localize('sftp.info.syncStarted', 'SFTP: Синхронизация запущена...'),

  syncCompleted: (count: number) =>
    localize('sftp.info.syncCompleted', 'SFTP: Синхронизация завершена. Передано файлов: {0}', count),

  syncFailed: (reason: string) =>
    localize('sftp.error.syncFailed', 'SFTP: Ошибка синхронизации: {0}', reason),

  // Операции с файлами
  fileNotFound: (path: string) =>
    localize('sftp.error.fileNotFound', 'SFTP: Файл не найден: {0}', path),

  permissionDenied: (path: string) =>
    localize('sftp.error.permissionDenied', 'SFTP: Нет доступа к файлу: {0}', path),

  // Конфигурация
  configNotFound: () =>
    localize('sftp.error.configNotFound', 'Файл конфигурации SFTP не найден. Запустите команду «SFTP: Настройки»'),

  configInvalid: (reason: string) =>
    localize('sftp.error.configInvalid', 'Некорректная конфигурация SFTP: {0}', reason),

  profileUnknown: (name: string) =>
    localize('sftp.error.profileUnknown', 'Неизвестный профиль «{0}». Проверьте настройки профилей.', name),

  // Очередь
  queueCancelled: () =>
    localize('sftp.info.queueCancelled', 'SFTP: Все передачи отменены'),

  // Прочее
  featureNotSupported: (feature: string) =>
    localize('sftp.warn.featureNotSupported', 'SFTP: Функция не поддерживается для данного протокола: {0}', feature),
};

export default localize;
