import { FileEntry, FileSystem, FileType } from '../core';
import { FileHandlerContext } from './createFileHandler';

export type CompareStatus = 'same' | 'modified' | 'localOnly' | 'remoteOnly';

export interface CompareResult {
  relativePath: string;
  name: string;
  type: FileType;
  status: CompareStatus;
  localFsPath: string;
  remoteFsPath: string;
}

function isFileModified(a: FileEntry, b: FileEntry): boolean {
  return Math.floor(a.mtime / 1000) !== Math.floor(b.mtime / 1000) || a.size !== b.size;
}

function toHash(entries: FileEntry[]): { [name: string]: FileEntry } {
  return entries.reduce((hash, entry) => {
    hash[entry.name] = entry;
    return hash;
  }, {} as { [name: string]: FileEntry });
}

async function walk(
  localFs: FileSystem,
  remoteFs: FileSystem,
  localDir: string,
  remoteDir: string,
  relativeDir: string,
  results: CompareResult[]
): Promise<void> {
  const [localEntries, remoteEntries] = await Promise.all([
    localFs.list(localDir).catch(() => []),
    remoteFs.list(remoteDir).catch(() => []),
  ]);

  const localTable = toHash(localEntries);
  const remoteTable = toHash(remoteEntries);
  const names = new Set([...Object.keys(localTable), ...Object.keys(remoteTable)]);

  const subDirs: Array<{ relativePath: string; localFsPath: string; remoteFsPath: string }> = [];

  for (const name of names) {
    const localEntry = localTable[name];
    const remoteEntry = remoteTable[name];
    const relativePath = relativeDir ? `${relativeDir}/${name}` : name;

    if (localEntry && remoteEntry) {
      if (localEntry.type === FileType.Directory && remoteEntry.type === FileType.Directory) {
        subDirs.push({
          relativePath,
          localFsPath: localEntry.fspath,
          remoteFsPath: remoteEntry.fspath,
        });
        continue;
      }

      results.push({
        relativePath,
        name,
        type: localEntry.type,
        status: isFileModified(localEntry, remoteEntry) ? 'modified' : 'same',
        localFsPath: localEntry.fspath,
        remoteFsPath: remoteEntry.fspath,
      });
    } else if (localEntry) {
      results.push({
        relativePath,
        name,
        type: localEntry.type,
        status: 'localOnly',
        localFsPath: localEntry.fspath,
        remoteFsPath: remoteFs.pathResolver.join(remoteDir, name),
      });
    } else if (remoteEntry) {
      results.push({
        relativePath,
        name,
        type: remoteEntry.type,
        status: 'remoteOnly',
        localFsPath: localFs.pathResolver.join(localDir, name),
        remoteFsPath: remoteEntry.fspath,
      });
    }
  }

  for (const dir of subDirs) {
    await walk(localFs, remoteFs, dir.localFsPath, dir.remoteFsPath, dir.relativePath, results);
  }
}

export async function compareFolders(ctx: FileHandlerContext): Promise<CompareResult[]> {
  const remoteFs = await ctx.fileService.getRemoteFileSystem(ctx.config);
  const localFs = ctx.fileService.getLocalFileSystem();
  const { localFsPath, remoteFsPath } = ctx.target;

  const results: CompareResult[] = [];
  await walk(localFs, remoteFs, localFsPath, remoteFsPath, '', results);
  results.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return results;
}
