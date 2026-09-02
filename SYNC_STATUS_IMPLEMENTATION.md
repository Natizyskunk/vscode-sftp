# File Sync Status Decoration - Implementation Guide

## Overview

This feature adds visual decorations to files in VS Code's file explorer showing their sync status with the remote server.

## What Was Implemented

### 1. **Configuration Schema** (`schema/definitions.json`)
Added new `syncStatus` configuration object with the following options:

```json
"syncStatus": {
  "enabled": false,              // Enable/disable the feature
  "refreshInterval": 30000,      // Cache refresh interval (ms)
  "showLocalOnly": true,         // Show "↑" for files not uploaded
  "showRemoteOnly": true,        // Show "↓" for files not downloaded
  "showModified": true,          // Show "!" for out-of-sync files
  "showSynced": false,           // Show "✓" for synced files
  "showIgnored": false           // Show "×" for ignored files
}
```

### 2. **Sync Status Manager** (`src/modules/syncStatusManager.ts`)
- **Caching**: Two-level caching system
  - File status cache (30s TTL)
  - Remote folder listing cache (60s TTL)
- **Performance**: Fetches entire folder listings instead of individual files
- **Debouncing**: Groups multiple refresh requests (300ms delay)
- **Periodic cleanup**: Removes expired cache entries every minute

### 3. **File Decoration Provider** (`src/modules/fileDecorationProvider.ts`)
Implements VS Code's `FileDecorationProvider` API to show:
- **↑** Blue - Local only (not uploaded)
- **↓** Green - Remote only (not downloaded)
- **!** Orange - Modified (out of sync)
- **✓** Green - Synced
- **×** Gray - Ignored

### 4. **Integration Points**
Auto-refreshes decorations after:
- Upload operations
- Download operations
- Sync commands
- File changes (debounced)

## How to Use

### Enable in Your SFTP Config

Add to your `.vscode/sftp.json`:

```json
{
  "name": "My Server",
  "host": "example.com",
  "protocol": "sftp",
  "port": 22,
  "username": "user",
  "remotePath": "/var/www",
  
  "syncStatus": {
    "enabled": true,
    "showLocalOnly": true,
    "showRemoteOnly": true,
    "showModified": true,
    "showSynced": false,
    "showIgnored": false
  }
}
```

### What You'll See

**In File Explorer:**
```
📁 project/
  📄 index.html ✓     (synced)
  📄 newfile.css ↑    (local only - needs upload)
  📄 remote.txt ↓     (remote only - needs download)
  📄 modified.js !    (modified - out of sync)
  📄 test.scss ×      (ignored)
```

## Performance Optimizations

### 1. **Folder-Level Caching**
Instead of checking each file individually:
- Fetches entire folder listing once
- Caches all files in that folder
- Reuses cache for other files in same folder

### 2. **TTL (Time-To-Live)**
- Status cache: 30 seconds
- Remote listing cache: 60 seconds
- Expired entries auto-cleaned every minute

### 3. **Debouncing**
- Multiple refresh requests within 300ms are grouped
- Prevents excessive FTP queries

### 4. **Smart Invalidation**
Cache is invalidated and refreshed after:
- Upload/download operations
- Sync commands
- Manual refresh
- Config changes

## Architecture

```
┌─────────────────────────────────────┐
│  VS Code File Explorer              │
│  (Shows decorations)                │
└────────────┬────────────────────────┘
             │
             ↓
┌─────────────────────────────────────┐
│  SftpFileDecorationProvider         │
│  - Provides decoration for each file│
│  - Calls syncStatusManager          │
└────────────┬────────────────────────┘
             │
             ↓
┌─────────────────────────────────────┐
│  SyncStatusManager                  │
│  - Caches status (30s TTL)          │
│  - Caches remote listings (60s TTL) │
│  - Compares local vs remote         │
│  - Debounces refresh requests       │
└────────────┬────────────────────────┘
             │
             ↓
┌─────────────────────────────────────┐
│  FileService                        │
│  - Connects to remote server        │
│  - Lists remote files               │
│  - Gets file stats                  │
└─────────────────────────────────────┘
```

## Configuration Examples

### Minimal (Only show problems):
```json
"syncStatus": {
  "enabled": true,
  "showLocalOnly": true,
  "showRemoteOnly": false,
  "showModified": true,
  "showSynced": false,
  "showIgnored": false
}
```

### Show Everything:
```json
"syncStatus": {
  "enabled": true,
  "showLocalOnly": true,
  "showRemoteOnly": true,
  "showModified": true,
  "showSynced": true,
  "showIgnored": true
}
```

### Conservative (Less FTP queries):
```json
"syncStatus": {
  "enabled": true,
  "refreshInterval": 60000,  // 1 minute
  "showLocalOnly": true,
  "showRemoteOnly": false,
  "showModified": true,
  "showSynced": false,
  "showIgnored": false
}
```

## API Reference

### Programmatic Access

```typescript
import app from './app';

// Manually refresh decorations for a file
app.decorationProvider.refresh(uri);

// Schedule a debounced refresh
app.decorationProvider.scheduleRefresh(uri);

// Invalidate cache and refresh
app.decorationProvider.invalidateAndRefresh(uri);

// Invalidate all caches
app.decorationProvider.invalidateAndRefresh();
```

## Troubleshooting

### Decorations Not Showing
1. Check `syncStatus.enabled` is `true`
2. Reload VS Code window
3. Check SFTP output panel for errors

### Performance Issues
1. Increase `refreshInterval` to 60000 (1 minute)
2. Disable unused indicators (`showSynced`, `showIgnored`)
3. Check network latency to FTP server

### Wrong Status Shown
1. Cache might be stale - wait for auto-refresh
2. Manually invalidate: right-click → SFTP commands
3. Check `remoteTimeOffsetInHours` if server timezone differs

## Future Enhancements

Potential improvements:
- Context menu: "Upload to sync", "Download to sync"
- Batch status checks for visible files only
- WebSocket/push notifications for real-time sync
- Conflict resolution UI
- Sync queue/history view

## Files Modified

- `src/modules/syncStatusManager.ts` (NEW)
- `src/modules/fileDecorationProvider.ts` (UPDATED)
- `src/modules/config.ts` (UPDATED)
- `src/core/fileService.ts` (UPDATED)
- `src/extension.ts` (UPDATED)
- `src/app.ts` (UPDATED)
- `src/fileHandlers/transfer/index.ts` (UPDATED)
- `schema/definitions.json` (UPDATED)
