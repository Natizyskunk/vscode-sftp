# SFTP Extension — Improvements & Roadmap

## Table of Contents

- [1. Critical Bugs](#1-critical-bugs)
- [2. Activation & Workspace Detection Issues](#2-activation--workspace-detection-issues)
- [3. Transfer Progress Feature](#3-transfer-progress-feature)
- [4. Connection Reliability](#4-connection-reliability)
- [5. Error Handling](#5-error-handling)
- [6. Performance Improvements](#6-performance-improvements)
- [7. New Feature Ideas](#7-new-feature-ideas)
- [8. Code Quality & Tech Debt](#8-code-quality--tech-debt)
- [9. Security Hardening](#9-security-hardening)

---

## 1. Critical Bugs

### 1.1 Extension doesn't work when new workspace opens

**Symptoms**: Extension doesn't activate for new workspace folders. Workarounds include saving `sftp.json`, disabling/re-enabling the extension, or restarting VS Code.

**Root Cause**: There is **no listener** for `vscode.workspace.onDidChangeWorkspaceFolders` in `src/extension.ts`. The extension only processes workspace folders once during initial activation. Any folder added after that is completely ignored.

**Fix**: Add a workspace folder change listener in `src/extension.ts`:

```typescript
context.subscriptions.push(
  vscode.workspace.onDidChangeWorkspaceFolders(async event => {
    // Initialize services for newly added folders
    for (const folder of event.added) {
      await setupWorkspaceFolder(folder.uri.fsPath);
    }
    // Dispose services for removed folders
    for (const folder of event.removed) {
      disposeFileServices(folder.uri.fsPath);
    }
    app.remoteExplorer.refresh();
  })
);
```

### 1.2 Config file creation not detected

**Symptoms**: When a user creates `.vscode/sftp.json` for the first time in a workspace that was already open, the extension doesn't detect it. Only saving the file again (after it already exists) triggers the reload.

**Root Cause**: `fileActivityMonitor.ts` only watches `onDidSaveTextDocument` events. A newly created file that was never opened in VS Code may not trigger this event. There's also no `FileSystemWatcher` specifically watching for config file creation.

**Fix**: Add a `vscode.workspace.createFileSystemWatcher` for `**/.vscode/sftp.json`:

```typescript
const configWatcher = vscode.workspace.createFileSystemWatcher(
  '**/sftp.json',
  false, // listen for creates
  false, // listen for changes
  false  // listen for deletes
);
configWatcher.onDidCreate(uri => handleConfigChange(uri));
configWatcher.onDidChange(uri => handleConfigChange(uri));
configWatcher.onDidDelete(uri => handleConfigDelete(uri));
```

### 1.3 Race condition during initialization

**Root Cause**: In `src/extension.ts`, `fileActivityMonitor.init()` starts watching files **before** all FileServices are created (async config loading). If a config save event fires during `tryLoadConfigs()`, `handleConfigSave` executes against incomplete state.

**Fix**: Initialize `fileActivityMonitor` only after all workspace folders are set up, or use a ready flag to defer event processing.

### 1.4 RemoteExplorer created after setup

`RemoteExplorer` is created AFTER `setup()` completes. If config file events fire during setup that call `app.remoteExplorer.refresh()`, it will fail because the explorer doesn't exist yet.

**Fix**: Create `RemoteExplorer` before calling `setup()`, or guard refresh calls.

---

## 2. Activation & Workspace Detection Issues

### 2.1 No cleanup when workspace folders are removed

The Trie-based service manager accumulates dead FileService instances when workspace folders are removed. No automatic cleanup is performed.

**Fix**: Listen for `onDidChangeWorkspaceFolders` removed events and call `disposeFileService()` for each removed folder's services.

### 2.2 No initialization state tracking

There's no flag tracking whether each workspace folder has been initialized, no queue for pending initializations, and no error recovery when config loading fails temporarily.

**Fix**: Add a `Map<string, 'pending' | 'ready' | 'error'>` to track workspace folder initialization state, and retry failed initializations on subsequent config saves.

### 2.3 Config validation happens after FileService creation

In `src/modules/serviceManager/index.ts`, the config validator is set AFTER the FileService is created. Invalid configs create partially initialized services.

**Fix**: Validate config before creating FileService instances.

---

## 3. Transfer Progress Feature

**User Request**: Show file size and upload percentage in the status bar during transfers, along with local-to-remote path.

### Current Behavior

- Status bar shows only a spinner animation (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`) during transfers
- No file name, no file size, no progress percentage
- After transfer: shows path in a temporary message

### Proposed Behavior

During upload:
```
⠋ Uploading file.txt — 2.5 MB / 5.0 MB (50%)
```

During multi-file upload:
```
⠋ Uploading 3/12 files — style.css — 1.2 MB / 3.8 MB (32%)
```

### Implementation Plan

**Step 1 — Add progress tracking to TransferTask** (`src/core/transferTask.ts`):
- Before transfer, call `srcFs.lstat()` to get file size
- Store `totalSize: number` and `bytesTransferred: number` on the task
- Wrap the readable stream with a `PassThrough` that counts bytes:

```typescript
import { PassThrough } from 'stream';

const progress = new PassThrough();
let bytesTransferred = 0;
progress.on('data', (chunk) => {
  bytesTransferred += chunk.length;
  this._onProgress?.(bytesTransferred, this._totalSize);
});
input.pipe(progress);
// Then pipe progress to target instead of input
```

**Step 2 — Add progress events to FileService** (`src/core/fileService.ts`):
- Add `TRANSFER_PROGRESS` event to the event emitter
- Fire on each progress callback from TransferTask (throttled to ~200ms)

**Step 3 — Update StatusBarItem** (`src/ui/statusBarItem.ts`):
- Add `showProgress(filename, bytesTransferred, totalSize)` method
- Format: `⠋ filename — X.X MB / Y.Y MB (Z%)`
- Helper to format bytes: `formatBytes(bytes)` → `"1.2 MB"`, `"456 KB"`, etc.

**Step 4 — Wire up in createFileHandler** (`src/fileHandlers/createFileHandler.ts`):
- Subscribe to FileService progress events
- Update status bar on each progress tick
- Show summary after completion

### File Size Formatting Helper

```typescript
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
```

---

## 4. Connection Reliability

### 4.1 No automatic reconnection

When a connection drops mid-session, `KeepAliveRemoteFs` marks it invalid but doesn't retry. Users must manually trigger a new operation.

**Improvement**: Implement retry with exponential backoff:

```typescript
async function withRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === maxRetries - 1) throw err;
      await delay(Math.pow(2, i) * 1000); // 1s, 2s, 4s
    }
  }
}
```

### 4.2 Hardcoded keep-alive intervals

- SSH: 30-second keep-alive hardcoded in `sshClient.ts`
- FTP: 10-second keep-alive in `ftpClient.ts`

**Improvement**: Make keep-alive interval configurable in `sftp.json`:

```json
{
  "keepAliveInterval": 30,
  "connectionTimeout": 10
}
```

### 4.3 SSH hopping has no timeout protection

The `_makeHopping` promise chain in `sshClient.ts` has no timeout. If a jump host is unreachable, the operation hangs indefinitely.

**Improvement**: Wrap hopping operations with `Promise.race` and a configurable timeout.

### 4.4 No connection health checking

There's no mechanism to proactively check if a connection is still alive before performing an operation.

**Improvement**: Add a lightweight health check (e.g., SFTP `realpath('.')`) before operations, with a fast timeout.

### 4.5 No connection pooling / session reuse

Each concurrent transfer operation may open a new SFTP session. This wastes resources and can hit server limits.

**Improvement**: Implement a connection pool that reuses sessions within the same FileService instance, with configurable pool size.

---

## 5. Error Handling

### 5.1 Silent error suppression

**File**: `src/fileHandlers/createFileHandler.ts`, line 31-34
- Throws empty string `throw ''` which produces cryptic error messages
- Line 34 has a typo: `"Config dssadasd Not Found"` should be `"Config Not Found"`

**Fix**: Throw proper Error objects with descriptive messages.

### 5.2 Swallowed errors in sync operations

**File**: `src/fileHandlers/transfer/transfer.ts`, lines 415-419
- `.catch(err => [])` silently swallows list errors during sync
- If reading source/destination fails, sync proceeds with incomplete info → potential data loss

**Fix**: Log errors and warn the user instead of silently swallowing them.

### 5.3 Missing file path in FTP errors

**File**: `src/core/fs/ftpFileSystem.ts`, line 100
- Throws generic `"file not exist"` without specifying which file

**Fix**: Include the file path in error messages.

### 5.4 Non-actionable error messages

Connection errors don't suggest debugging steps. "Config Not Found" doesn't indicate which workspace folder was checked.

**Improvement**: Add context and suggested actions to error messages:

```
"SFTP connection failed to example.com:22 — check host, port, and credentials in .vscode/sftp.json"
```

---

## 6. Performance Improvements

### 6.1 LRU cache too small

**File**: `src/app.ts` — cache max is only 6 items. With multiple workspace folders, constant cache misses occur.

**Fix**: Increase cache size to 50-100, or make it configurable.

### 6.2 Ignore pattern parsing not cached

**File**: `src/core/ignore.ts` — creates a new `Ignore` instance for every directory listing. Patterns are re-parsed each time.

**Fix**: Cache parsed ignore patterns per workspace folder and invalidate on `.gitignore` / config change.

### 6.3 Remote explorer sorts on every refresh

**File**: `src/modules/remoteExplorer/treeDataProvider.ts` — `localeCompare` sort runs on every refresh for every directory.

**Fix**: Cache sorted results and only re-sort when directory contents change. Add pagination for large directories (100+ items).

### 6.4 No batching for multi-file operations

When uploading many files, each file stat is fetched individually. Remote directory listings are also done one-at-a-time.

**Fix**: Batch stat calls where possible. For SFTP, use `readdir` to get stats for all files in a directory at once.

---

## 7. New Feature Ideas

### 7.1 Transfer progress in status bar (Priority: High)
See [Section 3](#3-transfer-progress-feature) above.

### 7.2 Dry-run mode for sync operations (Priority: High)
Preview what files will be uploaded/downloaded/deleted before executing. Especially important when `syncOption.delete: true` is set.

```
Sync Preview:
  Upload: 5 files (2.3 MB)
  Download: 2 files (800 KB)
  Delete remote: 3 files

  Proceed? [Yes] [No]
```

### 7.3 Transfer speed and ETA display (Priority: Medium)
Track bytes per second during transfer and show estimated time remaining:

```
⠋ Uploading bundle.js — 12.5 MB / 45.0 MB (28%) — 2.1 MB/s — ~15s remaining
```

### 7.4 Operation audit log (Priority: Medium)
Log all upload/download/delete operations to an output channel with timestamps:

```
[14:32:05] Uploaded src/app.ts → /var/www/src/app.ts (2.3 KB, 0.1s)
[14:32:06] Uploaded src/index.ts → /var/www/src/index.ts (1.1 KB, 0.1s)
```

### 7.5 Bandwidth throttling (Priority: Medium)
Allow users to limit transfer speed to avoid saturating their network:

```json
{
  "maxBandwidth": "5MB/s"
}
```

### 7.6 Resume interrupted transfers (Priority: Medium)
For large files, support resuming from where a failed transfer left off instead of restarting from zero. Use temp file + byte offset tracking.

### 7.7 Conflict detection and resolution (Priority: Medium)
Before overwriting, compare local and remote file timestamps/sizes. Show a diff and let the user choose which version to keep.

### 7.8 Quick connect / bookmark management (Priority: Low)
Allow saving and switching between multiple server connections quickly from a dropdown, without editing `sftp.json` manually.

### 7.9 Batch operations with confirmation (Priority: Low)
When uploading/deleting multiple files, show a confirmation dialog listing all files that will be affected:

```
Upload 47 files to example.com:/var/www?
[Show Files] [Upload All] [Cancel]
```

### 7.10 Transfer queue visibility (Priority: Low)
Add a tree view panel showing queued, in-progress, and completed transfers. Allow reordering, pausing, or cancelling individual items.

### 7.11 Remote file search (Priority: Low)
Add a search/filter command for the remote explorer tree view to quickly find files by name pattern.

### 7.12 Multi-server sync (Priority: Low)
Support syncing the same workspace to multiple remote servers simultaneously (e.g., staging + production).

---

## 8. Code Quality & Tech Debt

### 8.1 Typos in codebase

| Location | Current | Should Be |
|----------|---------|-----------|
| Transfer code | `perserveTargetMode` | `preserveTargetMode` |
| `treeDataProvider.ts:32` | `makePreivewUrl` | `makePreviewUrl` |
| `remoteFileSystem.ts:75` | `toRemoteTimeInSecnonds` | `toRemoteTimeInSeconds` |
| `createFileHandler.ts:34` | `"Config dssadasd Not Found"` | `"Config Not Found"` |

### 8.2 Private API usage

**File**: `src/core/remote-client/sshClient.ts`, line 180
- Directly manipulates `sftp._stream.open` (private ssh2 API)
- Will break if `ssh2` library updates its internals
- Used for file descriptor limiting

**Fix**: Use public API or file a feature request with `ssh2` for FD limiting support.

### 8.3 Deprecated Joi API

**File**: `src/modules/config.ts`
- Uses `Joi.validate()` which is deprecated in Joi v17+
- Should use `schema.validate()` instead

### 8.4 Excessive `any` types

Many files use `any` for function parameters and return types, bypassing TypeScript's type checking. This allows bugs to slip through at compile time.

**Fix**: Gradually replace `any` with proper types, especially in public APIs.

### 8.5 Promise anti-patterns

Mix of Promise constructors wrapping callback-based code without proper error propagation. Some `.then()` chains could be simplified with `async/await`.

### 8.6 Commented-out code

**File**: `src/core/fileService.ts`, lines 275-302 — large block of commented-out SSH config parsing code.
**File**: `src/fileHandlers/shared.ts` — blocked explorer refresh code with `NEED_VSCODE_UPDATE` comment.

**Fix**: Remove dead code. If it's needed later, it's in git history.

---

## 9. Security Hardening

### 9.1 Plaintext credentials in config

`sftp.json` can contain passwords in cleartext. There's no warning about committing this file to version control.

**Improvement**:
- Add `.vscode/sftp.json` to `.gitignore` template
- Show warning when password is stored in config
- Support credential provider integration or OS keychain

### 9.2 No host key verification warning

SSH connections may accept unknown hosts silently, making man-in-the-middle attacks possible.

**Improvement**: Prompt user on first connection to verify host key fingerprint, and store it for future verification.

### 9.3 Remote path not validated

No checks that remote paths don't traverse outside the intended directory.

**Improvement**: Validate that resolved remote paths stay within `remotePath` bounds.

### 9.4 Interactive auth answers in config

Pre-defined interactive auth answers stored as plaintext array in config and potentially logged in debug output.

**Improvement**: Mask sensitive values in debug logs.

---

## Priority Summary

| Priority | Item | Impact |
|----------|------|--------|
| **P0** | Fix workspace folder change detection (1.1) | Eliminates main user pain point |
| **P0** | Fix config file creation detection (1.2) | Eliminates need for save/reload workaround |
| **P0** | Fix initialization race conditions (1.3, 1.4) | Prevents random activation failures |
| **P1** | Transfer progress in status bar (3) | Most requested feature |
| **P1** | Automatic reconnection (4.1) | Major reliability improvement |
| **P1** | Fix silent error suppression (5.1, 5.2) | Prevents hidden failures |
| **P2** | Dry-run sync mode (7.2) | Prevents accidental data loss |
| **P2** | Operation audit log (7.4) | Improves debugging experience |
| **P2** | Connection timeout/health (4.3, 4.4) | Prevents hanging operations |
| **P3** | Performance optimizations (6.x) | Better experience at scale |
| **P3** | New features (7.5-7.12) | Nice-to-have enhancements |
| **P3** | Code quality cleanup (8.x) | Maintainability |
