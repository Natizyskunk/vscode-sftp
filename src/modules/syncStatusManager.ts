import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { FileService } from '../core';
import { getFileService } from './serviceManager';
import logger from '../logger';

export type SyncStatus = 'local-only' | 'remote-only' | 'modified' | 'synced' | 'ignored' | null;

interface CachedStatus {
  status: SyncStatus;
  timestamp: number;
}

interface RemoteFileInfo {
  mtime: number;
  size: number;
  exists: boolean;
}

export class SyncStatusManager {
  private cache: Map<string, CachedStatus> = new Map();
  private remoteListCache: Map<string, { files: Map<string, RemoteFileInfo>, timestamp: number }> = new Map();
  private refreshTimer: NodeJS.Timer | null = null;
  private pendingChecks: Set<string> = new Set();
  private debounceTimer: NodeJS.Timer | null = null;
  private pendingListings: Map<string, Promise<Map<string, RemoteFileInfo>>> = new Map();
  
  private readonly CACHE_TTL = 30000; // 30 seconds
  private readonly REMOTE_LIST_CACHE_TTL = 60000; // 1 minute
  private readonly DEBOUNCE_DELAY = 300; // 300ms

  constructor() {
    this.startPeriodicRefresh();
  }

  /**
   * Get the sync status of a file
   */
  async getStatus(uri: vscode.Uri): Promise<SyncStatus> {
    const filePath = uri.fsPath;
    
    // Check cache first
    const cached = this.cache.get(filePath);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.status;
    }

    // Get file service for this file
    const fileService = getFileService(uri);
    if (!fileService) {
      return null;
    }

    const config = fileService.getConfig();
    
    // Check if sync status is enabled
    if (!config.syncStatus || !config.syncStatus.enabled) {
      return null;
    }

    // Calculate status
    const status = await this.calculateStatus(uri, fileService);
    
    // Cache the result
    this.cache.set(filePath, {
      status,
      timestamp: Date.now(),
    });

    return status;
  }

  /**
   * Get detailed file information for tooltip
   */
  async getDetailedInfo(uri: vscode.Uri): Promise<{ localMtime?: number, remoteMtime?: number, localSize?: number, remoteSize?: number } | null> {
    const filePath = uri.fsPath;
    
    // Get file service for this file
    const fileService = getFileService(uri);
    if (!fileService) {
      return null;
    }

    const config = fileService.getConfig();
    
    // Check if sync status is enabled
    if (!config.syncStatus || !config.syncStatus.enabled) {
      return null;
    }

    try {
      // Get local file info
      const localExists = fs.existsSync(filePath);
      const localStat = localExists ? fs.statSync(filePath) : null;
      
      // Get remote file info
      const remotePath = this.getRemotePath(filePath, fileService);
      const remoteInfo = await this.getRemoteFileInfo(remotePath, fileService);

      return {
        localMtime: localStat ? localStat.mtimeMs : undefined,
        remoteMtime: remoteInfo.exists ? remoteInfo.mtime : undefined,
        localSize: localStat ? localStat.size : undefined,
        remoteSize: remoteInfo.exists ? remoteInfo.size : undefined,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Calculate the actual sync status by comparing local and remote
   */
  private async calculateStatus(uri: vscode.Uri, fileService: FileService): Promise<SyncStatus> {
    try {
      const config = fileService.getConfig();
      const localFsPath = uri.fsPath;
      
      // Check if file is ignored
      if (config.ignore && typeof config.ignore === 'function') {
        if (config.ignore(localFsPath)) {
          logger.info(`[SyncStatus] File ignored: ${localFsPath}`);
          return config.syncStatus.showIgnored ? 'ignored' : null;
        }
      }

      // Get local file info
      const localExists = fs.existsSync(localFsPath);
      const localStat = localExists ? fs.statSync(localFsPath) : null;
      
      console.log(`[SyncStatus] Checking: ${localFsPath}`);
      console.log(`[SyncStatus] Local exists: ${localExists}`);
      logger.info(`[SyncStatus] Checking: ${localFsPath}`);
      logger.info(`[SyncStatus] Local exists: ${localExists}`);
      if (localStat) {
        console.log(`[SyncStatus] Local mtime: ${localStat.mtime.toISOString()} (${localStat.mtimeMs}ms)`);
        console.log(`[SyncStatus] Local size: ${localStat.size} bytes`);
        logger.info(`[SyncStatus] Local mtime: ${localStat.mtime.toISOString()} (${localStat.mtimeMs}ms)`);
        logger.info(`[SyncStatus] Local size: ${localStat.size} bytes`);
      }
      
      // Don't check directories for now
      if (localStat && localStat.isDirectory()) {
        return null;
      }

      // Get remote file info
      const remotePath = this.getRemotePath(localFsPath, fileService);
      console.log(`[SyncStatus] Remote path: ${remotePath}`);
      logger.info(`[SyncStatus] Remote path: ${remotePath}`);
      const remoteInfo = await this.getRemoteFileInfo(remotePath, fileService);
      
      console.log(`[SyncStatus] Remote exists: ${remoteInfo.exists}`);
      logger.info(`[SyncStatus] Remote exists: ${remoteInfo.exists}`);
      if (remoteInfo.exists) {
        const remoteMtimeDate = new Date(remoteInfo.mtime);
        console.log(`[SyncStatus] Remote mtime: ${remoteMtimeDate.toISOString()} (${remoteInfo.mtime}ms)`);
        console.log(`[SyncStatus] Remote size: ${remoteInfo.size} bytes`);
        logger.info(`[SyncStatus] Remote mtime: ${remoteMtimeDate.toISOString()} (${remoteInfo.mtime}ms)`);
        logger.info(`[SyncStatus] Remote size: ${remoteInfo.size} bytes`);
      }

      // Determine status
      if (!localExists && !remoteInfo.exists) {
        logger.info(`[SyncStatus] Result: null (neither exists)`);
        return null;
      }

      if (!localExists && remoteInfo.exists) {
        logger.info(`[SyncStatus] Result: remote-only`);
        return config.syncStatus.showRemoteOnly ? 'remote-only' : null;
      }

      if (localExists && !remoteInfo.exists) {
        logger.info(`[SyncStatus] Result: local-only`);
        return config.syncStatus.showLocalOnly ? 'local-only' : null;
      }

      // Both exist - compare timestamps
      if (localStat && remoteInfo.exists) {
        const timeDiff = Math.abs(localStat.mtimeMs - remoteInfo.mtime);
        console.log(`[SyncStatus] Time difference: ${timeDiff}ms (${(timeDiff / 1000).toFixed(2)}s)`);
        logger.info(`[SyncStatus] Time difference: ${timeDiff}ms (${(timeDiff / 1000).toFixed(2)}s)`);
        
        // Detect if remote timestamp has time precision (not just date)
        const remoteDate = new Date(remoteInfo.mtime);
        const hasTimePrecision = remoteDate.getUTCHours() !== 0 || 
                                  remoteDate.getUTCMinutes() !== 0 || 
                                  remoteDate.getUTCSeconds() !== 0;
        
        // If remote has precise time, use 1 minute tolerance (server truncates seconds)
        // If remote only has date, use loose comparison (24 hour tolerance or configured value)
        const strictTolerance = 60000; // 1 minute (60 seconds)
        const looseTolerance = config.syncStatus.timeTolerance || 86400000; // 24 hours default
        const tolerance = hasTimePrecision ? strictTolerance : looseTolerance;
        
        console.log(`[SyncStatus] Remote time precision: ${hasTimePrecision ? 'precise (HH:MM:SS)' : 'date only (00:00:00)'}`);
        console.log(`[SyncStatus] Using tolerance: ${tolerance}ms (${(tolerance / 1000).toFixed(2)}s)`);
        logger.info(`[SyncStatus] Using tolerance: ${tolerance}ms (precision: ${hasTimePrecision})`);
        
        if (timeDiff > tolerance) {
          console.log(`[SyncStatus] Result: modified (time diff > tolerance)`);
          logger.info(`[SyncStatus] Result: modified (time diff > tolerance)`);
          return config.syncStatus.showModified ? 'modified' : null;
        }
        
        console.log(`[SyncStatus] Result: synced (time diff <= tolerance)`);
        logger.info(`[SyncStatus] Result: synced (time diff <= tolerance)`);
        return config.syncStatus.showSynced ? 'synced' : null;
      }

      logger.info(`[SyncStatus] Result: null (fallthrough)`);
      return null;
    } catch (error) {
      logger.error(`[SyncStatus] Error calculating sync status: ${error.message}`, error);
      return null;
    }
  }

  /**
   * Get remote file info with caching at folder level
   */
  private async getRemoteFileInfo(remotePath: string, fileService: FileService): Promise<RemoteFileInfo> {
    const remoteDir = path.posix.dirname(remotePath);
    const fileName = path.posix.basename(remotePath);
    
    console.log(`[SyncStatus] Getting remote info for: ${remotePath}`);
    console.log(`[SyncStatus] Remote dir: ${remoteDir}, filename: ${fileName}`);
    logger.info(`[SyncStatus] Getting remote info for: ${remotePath}`);
    logger.info(`[SyncStatus] Remote dir: ${remoteDir}, filename: ${fileName}`);
    
    // Check if we have cached the folder listing
    const cached = this.remoteListCache.get(remoteDir);
    if (cached && Date.now() - cached.timestamp < this.REMOTE_LIST_CACHE_TTL) {
      logger.info(`[SyncStatus] Using cached folder listing (age: ${Date.now() - cached.timestamp}ms)`);
      const fileInfo = cached.files.get(fileName);
      if (fileInfo) {
        logger.info(`[SyncStatus] Found file in cache: mtime=${fileInfo.mtime}, size=${fileInfo.size}`);
        return fileInfo;
      }
      logger.info(`[SyncStatus] File not found in cached listing`);
      return { exists: false, mtime: 0, size: 0 };
    }

    // Fetch remote folder listing (one request per folder, even if many files ask at once)
    try {
      const filesMap = await this.fetchRemoteListing(remoteDir, fileService);
      const fileInfo = filesMap.get(fileName);
      logger.debug(`[SyncStatus] ${fileName} ${fileInfo ? 'found' : 'not found'} in fresh listing of ${remoteDir}`);
      return fileInfo || { exists: false, mtime: 0, size: 0 };
    } catch (error) {
      logger.error(`[SyncStatus] Error fetching remote file info: ${error.message}`, error);
      return { exists: false, mtime: 0, size: 0 };
    }
  }

  /**
   * List a remote folder and cache it. Concurrent requests for the same folder share one listing.
   */
  private fetchRemoteListing(remoteDir: string, fileService: FileService): Promise<Map<string, RemoteFileInfo>> {
    const pending = this.pendingListings.get(remoteDir);
    if (pending) {
      return pending;
    }

    const listing = (async () => {
      logger.info(`[SyncStatus] Fetching remote folder listing for: ${remoteDir}`);
      const remoteFs = await fileService.getRemoteFileSystem(fileService.getConfig());
      const entries = await remoteFs.list(remoteDir);
      logger.info(`[SyncStatus] Remote folder ${remoteDir} has ${entries.length} entries`);

      const filesMap = new Map<string, RemoteFileInfo>();
      entries.forEach(entry => {
        logger.debug(`[SyncStatus] Entry: ${entry.name}, type: ${entry.type}, mtime: ${entry.mtime}, size: ${entry.size}`);
        filesMap.set(entry.name, {
          exists: true,
          mtime: entry.mtime,
          size: entry.size,
        });
      });

      this.remoteListCache.set(remoteDir, {
        files: filesMap,
        timestamp: Date.now(),
      });
      return filesMap;
    })();

    this.pendingListings.set(remoteDir, listing);
    const cleanup = () => {
      if (this.pendingListings.get(remoteDir) === listing) {
        this.pendingListings.delete(remoteDir);
      }
    };
    listing.then(cleanup, cleanup);
    return listing;
  }

  /**
   * Convert local path to remote path
   */
  private getRemotePath(localPath: string, fileService: FileService): string {
    const config = fileService.getConfig();
    const relativePath = path.relative(fileService.baseDir, localPath);
    
    // Convert Windows path separators to Unix
    const unixRelativePath = relativePath.split(path.sep).join('/');
    
    return path.posix.join(config.remotePath, unixRelativePath);
  }

  /**
   * Invalidate cache for a specific file or folder
   */
  invalidate(uri: vscode.Uri | string) {
    const filePath = typeof uri === 'string' ? uri : uri.fsPath;
    this.cache.delete(filePath);
    
    // Also invalidate parent folder's remote listing cache
    const parentDir = path.dirname(filePath);
    const fileService = typeof uri === 'string' ? null : getFileService(uri);
    if (fileService) {
      const remotePath = this.getRemotePath(parentDir, fileService);
      this.remoteListCache.delete(remotePath);
    }
  }

  /**
   * Invalidate cache for all files
   */
  invalidateAll() {
    this.cache.clear();
    this.remoteListCache.clear();
  }

  /**
   * Schedule a debounced refresh for a file
   */
  scheduleRefresh(uri: vscode.Uri) {
    this.pendingChecks.add(uri.fsPath);
    
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    
    this.debounceTimer = setTimeout(() => {
      this.processPendingChecks();
    }, this.DEBOUNCE_DELAY);
  }

  /**
   * Process pending refresh checks
   */
  private async processPendingChecks() {
    const checks = Array.from(this.pendingChecks);
    this.pendingChecks.clear();
    
    for (const filePath of checks) {
      this.invalidate(filePath);
    }
  }

  /**
   * Start periodic cache cleanup and refresh
   */
  private startPeriodicRefresh() {
    this.refreshTimer = setInterval(() => {
      this.cleanExpiredCache();
    }, 60000); // Clean every minute
  }

  /**
   * Clean expired cache entries
   */
  private cleanExpiredCache() {
    const now = Date.now();
    
    // Clean status cache
    for (const [key, value] of this.cache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL * 2) {
        this.cache.delete(key);
      }
    }
    
    // Clean remote list cache
    for (const [key, value] of this.remoteListCache.entries()) {
      if (now - value.timestamp > this.REMOTE_LIST_CACHE_TTL * 2) {
        this.remoteListCache.delete(key);
      }
    }
  }

  /**
   * Dispose and clean up
   */
  dispose() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    
    this.cache.clear();
    this.remoteListCache.clear();
    this.pendingChecks.clear();
  }
}

// Singleton instance
export const syncStatusManager = new SyncStatusManager();
