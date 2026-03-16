# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VS Code extension providing SFTP/FTP file synchronization. Users configure connections via `.vscode/sftp.json` and can upload, download, sync, and browse remote files.

## Build & Development Commands

```bash
npm run dev          # Webpack watch mode (development)
npm run compile      # Production build (webpack --mode production)
npm test             # Run Jest tests
npm run package      # Create .vsix package via vsce
```

Launch the extension for debugging with F5 in VS Code (uses `.vscode/launch.json`).

## Architecture

**Entry point**: `src/extension.ts` → activates on `sftp.config` command or when workspace contains `.vscode/sftp.json`. Output bundle: `dist/extension.js`.

**Core layers**:
- `src/core/` — FileSystem abstraction (`fileSystem.ts` base, `sftpFileSystem.ts`, `ftpFileSystem.ts`), remote clients (`sshClient.ts`, `ftpClient.ts`), and `fileService.ts` for orchestration
- `src/commands/` — ~45 commands, dynamically loaded via webpack `require.context` in `initCommands.ts`. Uses factory pattern: `createCommand`, `createFileCommand`, `createFileMultiCommand`
- `src/fileHandlers/` — File operation handlers (upload, download, diff, rename, remove) built via `createFileHandler` factory
- `src/modules/` — Feature modules: config loading/validation (Joi schema), `serviceManager` (Trie-based path→FileService mapping), file watcher, remote explorer tree view
- `src/app.ts` — Global singleton with LRU cache, status bar, state manager

**Service Manager** uses a Trie to match file paths to the correct FileService instance, supporting multiple workspace folders and contexts.

**Remote Explorer** is a VS Code TreeView (`remoteExplorer` view ID) using `remote://` URI scheme.

## Code Style

- TypeScript with TSLint (not ESLint/Prettier)
- `strictNullChecks` enabled, `noUnusedLocals` enabled
- Single quotes, semicolons, trailing commas for multiline
- Target: ES6, Module: CommonJS

## Config Schema

User configuration lives in `.vscode/sftp.json`. Validation uses Joi in `src/modules/config.ts`. JSON Schema at `schema/config.schema.json`. Supports single config, arrays (multiple contexts), and `profiles` for named configurations.

## Key Dependencies

- `ssh2` — SFTP/SSH connections (externalized from webpack bundle, not bundled)
- `ftp` — FTP connections
- `joi` — Config validation
- `p-queue` — Concurrent transfer queue
- `lru-cache` — Filesystem caching
