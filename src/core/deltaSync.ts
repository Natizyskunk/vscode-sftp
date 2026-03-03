/**
 * deltaSync.ts — Умная дельта-синхронизация
 *
 * Вместо загрузки/скачивания ВСЕХ файлов анализирует что реально изменилось
 * и передаёт только необходимые файлы.
 *
 * Стратегия сравнения (в порядке приоритета):
 * 1. size — быстро, но может давать ложные срабатывания
 * 2. mtime — время последнего изменения (основной критерий)
 * 3. Только если нужно — полное сравнение содержимого
 */

import { FileSystem, FileEntry, FileType } from './fs';
import logger from '../logger';

export type DiffStatus = 'new_local' | 'new_remote' | 'modified' | 'conflict' | 'identical';

export interface FileDiff {
  relativePath: string;
  localPath: string;
  remotePath: string;
  status: DiffStatus;
  localSize?: number;
  remoteSize?: number;
  localMtime?: Date;
  remoteMtime?: Date;
  /** Recommended action */
  action: 'upload' | 'download' | 'skip' | 'conflict';
}

export interface DeltaSyncOptions {
  /**
   * Порог разницы mtime в секундах для считания файлов "одинаковыми".
   * Нужен из-за FAT-систем (2с granularity) и clock drift серверов.
   * Default: 2
   */
  mtimeDeltaSeconds: number;
  /**
   * Если true — игнорировать mtime, сравнивать только размер
   * Default: false
   */
  ignoreMtime: boolean;
  /**
   * Направление при конфликте (оба изменены)
   * Default: 'newer' (побеждает более новый файл)
   */
  conflictResolution: 'newer' | 'local' | 'remote' | 'skip';
  /**
   * Функция игнорирования путей (из FileService)
   */
  ignore?: ((fsPath: string) => boolean) | null;
}

export const DEFAULT_DELTA_OPTIONS: DeltaSyncOptions = {
  mtimeDeltaSeconds: 2,
  ignoreMtime: false,
  conflictResolution: 'newer',
  ignore: null,
};

/**
 * Нормализует mtime к секундам, убирая миллисекунды
 */
function toSecondPrecision(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

/**
 * Анализирует два списка файлов и возвращает список различий.
 * Без реального чтения файлов — только по метаданным (size, mtime).
 */
export function computeDiff(
  localEntries: Map<string, FileEntry>,
  remoteEntries: Map<string, FileEntry>,
  localRoot: string,
  remoteRoot: string,
  options: DeltaSyncOptions = DEFAULT_DELTA_OPTIONS
): FileDiff[] {
  const diffs: FileDiff[] = [];
  const allPaths = new Set([...localEntries.keys(), ...remoteEntries.keys()]);

  for (const relPath of allPaths) {
    const localEntry = localEntries.get(relPath);
    const remoteEntry = remoteEntries.get(relPath);

    const localPath = `${localRoot}/${relPath}`;
    const remotePath = `${remoteRoot}/${relPath}`;

    // Файл есть только локально → загрузить
    if (localEntry && !remoteEntry) {
      diffs.push({
        relativePath: relPath,
        localPath,
        remotePath,
        status: 'new_local',
        action: 'upload',
        localSize: localEntry.size,
        localMtime: localEntry.mtime ? new Date(localEntry.mtime * 1000) : undefined,
      });
      continue;
    }

    // Файл есть только на сервере → скачать
    if (!localEntry && remoteEntry) {
      diffs.push({
        relativePath: relPath,
        localPath,
        remotePath,
        status: 'new_remote',
        action: 'download',
        remoteSize: remoteEntry.size,
        remoteMtime: remoteEntry.mtime ? new Date(remoteEntry.mtime * 1000) : undefined,
      });
      continue;
    }

    // Файл есть в обоих местах — сравниваем
    if (localEntry && remoteEntry) {
      // Пропускаем директории
      if (localEntry.type === FileType.Directory || remoteEntry.type === FileType.Directory) {
        continue;
      }

      const localSize = localEntry.size || 0;
      const remoteSize = remoteEntry.size || 0;
      const localMtime = localEntry.mtime ? new Date(localEntry.mtime * 1000) : undefined;
      const remoteMtime = remoteEntry.mtime ? new Date(remoteEntry.mtime * 1000) : undefined;

      // Размеры одинаковы?
      const sameSize = localSize === remoteSize;

      // mtime одинаковы (с учётом дельты)?
      let sameMtime = false;
      if (localMtime && remoteMtime && !options.ignoreMtime) {
        const diff = Math.abs(toSecondPrecision(localMtime) - toSecondPrecision(remoteMtime));
        sameMtime = diff <= options.mtimeDeltaSeconds;
      } else if (options.ignoreMtime) {
        sameMtime = true; // игнорируем mtime
      }

      // Файлы идентичны
      if (sameSize && sameMtime) {
        diffs.push({
          relativePath: relPath,
          localPath,
          remotePath,
          status: 'identical',
          action: 'skip',
          localSize,
          remoteSize,
          localMtime,
          remoteMtime,
        });
        continue;
      }

      // Определяем направление конфликта
      let action: 'upload' | 'download' | 'skip' | 'conflict' = 'conflict';
      let status: DiffStatus = 'conflict';

      if (localMtime && remoteMtime) {
        const localSeconds = toSecondPrecision(localMtime);
        const remoteSeconds = toSecondPrecision(remoteMtime);

        if (localSeconds > remoteSeconds + options.mtimeDeltaSeconds) {
          // Локальный новее → загрузить
          status = 'modified';
          action = options.conflictResolution === 'remote' ? 'download' : 'upload';
        } else if (remoteSeconds > localSeconds + options.mtimeDeltaSeconds) {
          // Удалённый новее → скачать
          status = 'modified';
          action = options.conflictResolution === 'local' ? 'upload' : 'download';
        } else {
          // Примерно одновременно изменены → конфликт
          status = 'conflict';
          action = options.conflictResolution === 'newer'
            ? (localSeconds >= remoteSeconds ? 'upload' : 'download')
            : options.conflictResolution === 'local' ? 'upload'
            : options.conflictResolution === 'remote' ? 'download'
            : 'skip';
        }
      } else {
        // Нет mtime — используем размер
        status = 'modified';
        action = 'upload'; // по умолчанию
      }

      diffs.push({
        relativePath: relPath,
        localPath,
        remotePath,
        status,
        action,
        localSize,
        remoteSize,
        localMtime,
        remoteMtime,
      });
    }
  }

  return diffs.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}

/**
 * Собирает плоский список файлов из файловой системы рекурсивно.
 * Возвращает Map<relativePath, FileEntry>
 */
export async function collectEntries(
  fs: FileSystem,
  rootPath: string,
  ignore?: ((fsPath: string) => boolean) | null
): Promise<Map<string, FileEntry>> {
  const result = new Map<string, FileEntry>();

  async function walk(dirPath: string, relBase: string) {
    let entries: FileEntry[];
    try {
      entries = await fs.list(dirPath);
    } catch (err) {
      logger.warn(`[DeltaSync] Cannot list ${dirPath}: ${(err as Error).message}`);
      return;
    }

    for (const entry of entries) {
      const relPath = relBase ? `${relBase}/${entry.name}` : entry.name;
      const fullPath = `${dirPath}/${entry.name}`;

      if (ignore && ignore(fullPath)) {
        continue;
      }

      result.set(relPath, entry);

      if (entry.type === FileType.Directory) {
        await walk(fullPath, relPath);
      }
    }
  }

  await walk(rootPath, '');
  return result;
}

/**
 * Высокоуровневая функция — сравнивает директории локально и удалённо.
 * Возвращает список различий (только то что нужно передать).
 */
export async function analyzeSync(
  localFs: FileSystem,
  remoteFs: FileSystem,
  localRoot: string,
  remoteRoot: string,
  options: Partial<DeltaSyncOptions> = {}
): Promise<FileDiff[]> {
  const opts = { ...DEFAULT_DELTA_OPTIONS, ...options };

  logger.info(`[DeltaSync] Analyzing ${localRoot} ↔ ${remoteRoot}`);

  const [localEntries, remoteEntries] = await Promise.all([
    collectEntries(localFs, localRoot, opts.ignore),
    collectEntries(remoteFs, remoteRoot, opts.ignore),
  ]);

  logger.info(`[DeltaSync] Local: ${localEntries.size} files, Remote: ${remoteEntries.size} files`);

  const diffs = computeDiff(localEntries, remoteEntries, localRoot, remoteRoot, opts);
  const toTransfer = diffs.filter(d => d.action !== 'skip');

  logger.info(
    `[DeltaSync] Result: ${diffs.filter(d => d.status === 'identical').length} identical, ` +
    `${diffs.filter(d => d.action === 'upload').length} to upload, ` +
    `${diffs.filter(d => d.action === 'download').length} to download, ` +
    `${diffs.filter(d => d.status === 'conflict').length} conflicts`
  );

  return toTransfer;
}
