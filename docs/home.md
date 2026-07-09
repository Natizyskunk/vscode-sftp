<!-- Source of the GitHub wiki Home page. Published automatically by .github/workflows/sync-wiki.yml on every push to develop that touches this file. -->

# SFTPresso — Complete Wiki

> **SFTPresso** — SFTP/FTP sync for Visual Studio Code. Actively maintained fork of `vscode-sftp`.
>
> - **Publisher:** `jmwerk` · **Current version:** 1.16.9 · **License:** MIT
> - **Repository:** https://github.com/jmwerk/vscode-sftp
> - **Requires:** VS Code `^1.64.2`
> - **Lineage:** forked from [Natizyskunk/vscode-sftp](https://github.com/Natizyskunk/vscode-sftp), which continued [liximomo's original SFTP plugin](https://github.com/liximomo/vscode-sftp) after it went unmaintained.

---

## Table of Contents

1. [Overview](#1-overview)
   - [Primary purposes](#primary-purposes)
   - [Key features](#key-features)
2. [Installation and Setup](#2-installation-and-setup)
   - [Installing the extension](#installing-the-extension)
   - [First-time setup](#first-time-setup)
   - [Verifying your connection](#verifying-your-connection)
3. [Command Reference](#3-command-reference)
   - [Configuration and connection commands](#configuration-and-connection-commands)
   - [Upload commands](#upload-commands)
   - [Download commands](#download-commands)
   - [Sync commands](#sync-commands)
   - [Diff and compare commands](#diff-and-compare-commands)
   - [Remote Explorer and file commands](#remote-explorer-and-file-commands)
   - [Transfer management commands](#transfer-management-commands)
   - [Force (Alt) commands](#force-alt-commands)
   - [Commands with keybinding arguments](#commands-with-keybinding-arguments)
   - [Default keybindings](#default-keybindings)
4. [Configuration Reference (`sftp.json`)](#4-configuration-reference-sftpjson)
   - [Common options](#common-options)
   - [SFTP-only options](#sftp-only-options)
   - [FTP(S)-only options](#ftps-only-options)
   - [VS Code extension settings](#vs-code-extension-settings)
5. [Usage Examples and Common Workflows](#5-usage-examples-and-common-workflows)
   - [Simple single-server setup](#simple-single-server-setup)
   - [Start from a remote project](#start-from-a-remote-project)
   - [Upload on save](#upload-on-save)
   - [Profiles (dev / prod)](#profiles-dev--prod)
   - [Multiple contexts (array config)](#multiple-contexts-array-config)
   - [Connection hopping (SSH proxy / bastion)](#connection-hopping-ssh-proxy--bastion)
   - [Two-way automatic sync with the watcher](#two-way-automatic-sync-with-the-watcher)
   - [Uploading a folder's contents without the folder itself](#uploading-a-folders-contents-without-the-folder-itself)
   - [Configuration in User Settings (remote-fs)](#configuration-in-user-settings-remote-fs)
   - [Using the Remote Explorer](#using-the-remote-explorer)
   - [Monitoring and cancelling transfers](#monitoring-and-cancelling-transfers)
   - [Comparing folders with the remote](#comparing-folders-with-the-remote)
6. [Best Practices](#6-best-practices)
7. [Troubleshooting and Known Issues](#7-troubleshooting-and-known-issues)
   - [Enabling debug logs](#enabling-debug-logs)
   - [SSH connection error messages](#ssh-connection-error-messages)
   - [Error: Failure](#error-failure)
   - [Error: Connection closed](#error-connection-closed)
   - [ENFILE: file table overflow (macOS)](#enfile-file-table-overflow-macos)
   - [Upload Changed Files does nothing](#upload-changed-files-does-nothing)
   - [Remote Explorer not refreshing after delete](#remote-explorer-not-refreshing-after-delete)
   - [Known issues fixed in this fork](#known-issues-fixed-in-this-fork)
8. [Frequently Asked Questions](#8-frequently-asked-questions)
9. [Development and Contributing](#9-development-and-contributing)
10. [Credits](#10-credits)

---

## 1. Overview

SFTPresso lets you add, edit, or delete files in a local directory and have those changes sync to a remote server directory over **SFTP (SSH)** or **FTP/FTPS**. The most basic setup requires only a few lines of configuration, while a wide array of options covers advanced needs — multiple servers, switchable profiles, SSH connection hopping, file watchers, and atomic uploads.

### Primary purposes

- **Remote deployment while editing locally** — keep a familiar local editor and environment and mirror your work to a web server, staging box, or embedded device on every save.
- **Remote file management** — browse, view, edit, create, and delete files on the server directly from the SFTP sidebar without leaving VS Code.
- **Directory synchronization** — one-shot or continuous sync in either (or both) directions, with fine-grained control over deletes, creates, and overwrites.
- **Multi-environment workflows** — one config with named profiles (e.g. `dev`, `prod`) or several configs mapped to different subfolders of the same workspace.

### Key features

| Feature | Where to find it | Details |
| --- | --- | --- |
| Remote Explorer | SFTP icon in the Activity Bar | Browse remote files, multi-select download/upload — see [Using the Remote Explorer](#using-the-remote-explorer) |
| Transfers view | SFTP sidebar → **Transfers** | Live per-file status (queued / transferring / failed) with per-file cancel — see [Monitoring and cancelling transfers](#monitoring-and-cancelling-transfers) |
| Status-bar progress | Status bar during bulk transfers | "Transferring X/Y files" counter; click to cancel all |
| Diff local ↔ remote | `SFTP: Diff with Remote` | Opens VS Code's diff view against the remote copy |
| Compare Folders | `SFTP: Compare Folders with Remote` | Recursive local/remote diff with per-file actions — see [Comparing folders](#comparing-folders-with-the-remote) |
| Test Connection | `SFTP: Test Connection` / CodeLens on `sftp.json` | Verifies the active profile can connect |
| Upload on save | [`uploadOnSave`](#uploadonsave) | Mirrors every VS Code save to the server |
| File watcher | [`watcher`](#watcher) | Reacts to changes made *outside* VS Code (build tools, git checkout, …) |
| Multiple configurations | [Array config](#multiple-contexts-array-config) | Different servers per workspace subfolder |
| Switchable profiles | [`profiles`](#profiles) + `SFTP: Set Profile` | One config, many targets |
| Temp-file / atomic uploads | [`useTempFile`](#usetempfile), [`openSsh`](#openssh) | Avoid serving half-written files |
| Connection hopping | [`hop`](#connection-hopping-ssh-proxy--bastion) | Reach a target server through one or more SSH bastions |
| Upload to all profiles | `SFTP: Upload … To All Profiles` | Push one file/folder/project to every profile at once |

---

## 2. Installation and Setup

### Installing the extension

SFTPresso is **not yet published to the VS Code Marketplace** under its new name. Until it is, install from a VSIX package:

1. Grab a `.vsix` from [GitHub Releases](https://github.com/jmwerk/vscode-sftp/releases) — or build one from source (see [Development and Contributing](#9-development-and-contributing)).
2. In VS Code, open the Extensions view (`Ctrl+Shift+X` / `Cmd+Shift+X`).
3. If you still have an older `sftp` extension installed (from `@liximomo` or `@Natizyskunk`), uninstall it first to avoid command conflicts.
4. Open the **⋯ (More Actions)** menu at the top of the Extensions view and choose **Install from VSIX…**.
5. Locate the `.vsix` file and select it.
6. Reload VS Code.

To build the VSIX yourself:

```sh
git clone https://github.com/jmwerk/vscode-sftp.git
cd vscode-sftp
npm install          # also applies bundled patches via patch-package
npm run package      # produces sftpresso-<version>.vsix via vsce
```

### First-time setup

1. Open the local folder you want to sync (`File → Open Folder…`).
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run **`SFTP: Config`**.
3. The extension creates `.vscode/sftp.json` with a starter template. Edit it with your server details:

```json
{
    "name": "My Server",
    "host": "server.example.com",
    "protocol": "sftp",
    "port": 22,
    "username": "user1",
    "remotePath": "/var/www/project",
    "uploadOnSave": false
}
```

4. Save and close `sftp.json`. The extension activates automatically whenever a workspace contains `.vscode/sftp.json`.
5. Type `SFTP` in the Command Palette to see all available commands (see the [Command Reference](#3-command-reference)). Many are also available from the file explorer and editor context menus.

Notes:

- `password` is optional — if omitted you'll be prompted when a connection is made. If you do store it, be aware it is **plain text** (see [Best Practices](#6-best-practices)).
- Backslashes and other special characters in JSON values must be escaped with a backslash.
- `sftp.json` gets schema-validated in the editor, so you get completions and warnings for unknown or mistyped option names.

### Verifying your connection

Run **`SFTP: Test Connection`** from the Command Palette, or click the **Test Connection** CodeLens shown at the top of `sftp.json`. It connects using the active profile's settings and reports success or failure with an actionable message (see [SSH connection error messages](#ssh-connection-error-messages)).

---

## 3. Command Reference

All commands live under the **SFTP** category in the Command Palette. Most are also exposed via context menus (file explorer, editor, editor title, SCM view, Remote Explorer). Commands are only available when the extension is active (workspace contains `.vscode/sftp.json`).

### Configuration and connection commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Config` | `sftp.config` | Create a new `sftp.json` configuration file for the workspace. |
| `SFTP: Set Profile` | `sftp.setProfile` | Switch the active [profile](#profiles-dev--prod). |
| `SFTP: Test Connection` | `sftp.testConnection` | Connect to the active profile's remote and report success/failure. Also available as a CodeLens on `sftp.json`. |
| `SFTP: Open SSH in Terminal` | `sftp.openConnectInTerminal` | Open a VS Code terminal auto-logged-in to the server. Extra CLI flags can be added via [`sshCustomParams`](#sshcustomparams). |

### Upload commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Upload Active File` | `sftp.upload.activeFile` | Upload the file currently open in the editor. |
| `SFTP: Upload Active Folder` | `sftp.upload.activeFolder` | Upload the folder containing the current file. |
| `SFTP: Upload Project` | `sftp.upload.project` | Upload the whole project (respecting [`ignore`](#ignore) rules). |
| `SFTP: Upload Changed Files` | `sftp.upload.changedFiles` | Upload all files changed or created since the last Git commit (including deletions). Default keybinding `Ctrl+Alt+U`; also shown in the Source Control view. |
| Upload File / Upload Folder | `sftp.upload.file` / `sftp.upload.folder` | Context-menu variants that act on the right-clicked explorer item. |
| `SFTP: Upload … To All Profiles` | `sftp.upload.activeFile.to.allProfiles`, `sftp.upload.activeFolder.to.allProfiles`, `sftp.upload.project.to.allProfiles`, `sftp.upload.file.to.allProfiles`, `sftp.upload.folder.to.allProfiles` | Same as above but pushes to **every** profile defined in the config, not just the active one. |

### Download commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Download Active File` | `sftp.download.activeFile` | Download the remote version of the current file, overwriting the local copy. |
| `SFTP: Download Active Folder` | `sftp.download.activeFolder` | Download the folder containing the current file. |
| `SFTP: Download Project` | `sftp.download.project` | Download everything under [`remotePath`](#remotepath) into the workspace. |
| Download File / Download Folder | `sftp.download.file` / `sftp.download.folder` | Context-menu variants (explorer and Remote Explorer). |

### Sync commands

Sync compares timestamps and transfers only what differs; behavior is tuned with [`syncOption`](#syncoption).

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Sync Local -> Remote` | `sftp.sync.localToRemote` | Copies files that differ by timestamp, plus files that exist only locally. |
| `SFTP: Sync Remote -> Local` | `sftp.sync.remoteToLocal` | Same, in the opposite direction. |
| `SFTP: Sync Both Directions` | `sftp.sync.bothDirections` | Compares modification times and always keeps the **newest** version on both sides. Only `syncOption.skipCreate` and `syncOption.ignoreExisting` apply to this command. |

> If local and remote clocks disagree (server in another timezone, clock drift), set [`remoteTimeOffsetInHours`](#remotetimeoffsetinhours) so timestamp comparison stays accurate.

### Diff and compare commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Diff Active File with Remote` | `sftp.diff.activeFile` | Open VS Code's diff view: current file vs. its remote counterpart. |
| Diff with Remote | `sftp.diff` | Context-menu variant for any explorer file. |
| `SFTP: Compare Folders with Remote` | `sftp.compareFolders` | Recursively diffs a local folder against its remote counterpart; results (new-local / new-remote / modified) are listed in a QuickPick with per-file actions to open a diff, upload, or download. |

### Remote Explorer and file commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: List` / `SFTP: List Active Folder` / `SFTP: List All` | `sftp.list` / `sftp.listActiveFolder` / `sftp.listAll` | List remote directory contents in a QuickPick. `List All` includes ignored files. |
| Delete | `sftp.delete.remote` | Delete the selected file/folder **on the remote** (Remote Explorer context menu). |
| Create Folder / Create File | `sftp.create.folder` / `sftp.create.file` | Create a remote folder or file from the Remote Explorer. |
| Edit in Local | `sftp.remoteExplorer.editInLocal` | Download the remote file into the workspace so it can be edited (Remote Explorer opens files read-only by default). |
| View Content | `sftp.viewContent` | Open a read-only view of a remote file. |
| Reveal in Explorer | `sftp.revealInExplorer` | Jump from a remote file to its local counterpart in the file explorer. |
| Reveal in Remote Explorer | `sftp.revealInRemoteExplorer` | Jump from a local file to its remote counterpart in the Remote Explorer. |
| Refresh | `sftp.remoteExplorer.refresh` | Refresh the Remote Explorer tree. |
| Refresh Active Remote File | `sftp.remoteExplorer.refreshActiveFile` | Re-fetch the remote file open in the editor. |

### Transfer management commands

| Command | ID | Description |
| --- | --- | --- |
| `SFTP: Cancel All Transfers` | `sftp.cancelAllTransfer` | Stop every in-flight upload/download. Also triggered by clicking the status-bar progress counter, and from the Transfers view title bar. |
| Cancel Transfer | `sftp.cancelTransfer` | Cancel a single in-flight file — the inline ✕ button on items in the [Transfers view](#monitoring-and-cancelling-transfers). |

### Force (Alt) commands

Hold **Alt** while a context menu is open to reveal the force variants, which **disregard [`ignore`](#ignore) rules**:

| Command | ID | Description |
| --- | --- | --- |
| Force Upload | `sftp.forceUpload` | Upload even files matched by ignore rules. |
| Force Download | `sftp.forceDownload` | Download even files matched by ignore rules. |
| Force Upload To All Profiles | `sftp.forceUpload.to.allProfiles` | Force-upload to every profile. |

### Commands with keybinding arguments

These accept arguments when bound in `keybindings.json` or invoked from `tasks.json`:

| Command | Signature |
| --- | --- |
| `sftp.setProfile` | `func(profileName: string)` |
| `sftp.upload` | `func(fspaths: string[])` — upload the given files/folders |
| `sftp.download` | `func(fspaths: string[])` — download the given files/folders |

Example — a keybinding that switches straight to the `prod` profile:

```json
{
  "key": "ctrl+alt+p",
  "command": "sftp.setProfile",
  "args": "prod"
}
```

### Default keybindings

| Keys | Command | When |
| --- | --- | --- |
| `Ctrl+Alt+U` | `SFTP: Upload Changed Files` | Extension active |

---

## 4. Configuration Reference (`sftp.json`)

Configuration lives in `<workspace>/.vscode/sftp.json` — either a single object, or an **array of objects** for [multiple contexts](#multiple-contexts-array-config). Open it any time via `SFTP: Config`.

### Common options

Apply to both SFTP and FTP unless noted.

#### name
A string to identify your configuration. Shown in pickers when multiple configs exist. **Required when using an array (multi-context) config.**

| Key | Type | Default |
| --- | --- | --- |
| `name` | string | — |

```json
{ "name": "My Server" }
```

#### context
A path relative to the workspace root. Use it to map a **subfolder** (rather than the whole workspace) to `remotePath`. Only available at the root level of a config (not inside profiles).

| Key | Type | Default |
| --- | --- | --- |
| `context` | string | workspace root |

```json
{ "context": "./build" }
```

#### protocol
Transfer protocol.

| Key | Type | Default |
| --- | --- | --- |
| `protocol` | `"sftp"` \| `"ftp"` | `"sftp"` |

#### host
Hostname or IP address of the server.

| Key | Type |
| --- | --- |
| `host` | string |

#### port
Server port. Typically `22` for SFTP, `21` for FTP, `990` for implicit FTPS.

| Key | Type |
| --- | --- |
| `port` | integer |

#### username
Username for authentication.

| Key | Type |
| --- | --- |
| `username` | string |

#### password
Password for password-based authentication. **Optional** — omit it to be prompted at connect time.

> ⚠️ **Warning:** passwords in `sftp.json` are stored as **plain text**. Prefer [`privateKeyPath`](#privatekeypath) or [`agent`](#agent), and keep `sftp.json` out of version control. See [Best Practices](#6-best-practices).

| Key | Type |
| --- | --- |
| `password` | string |

#### remotePath
The absolute path on the remote host that maps to your local [`context`](#context). This is what `SFTP: Download Project` downloads.

| Key | Type | Default |
| --- | --- | --- |
| `remotePath` | string | `/` |

#### filePerm
Octal permissions applied to newly created remote files.

| Key | Type | Default |
| --- | --- | --- |
| `filePerm` | number | unset |

```json
{ "filePerm": 644 }
```

#### dirPerm
Octal permissions applied to newly created remote directories.

| Key | Type | Default |
| --- | --- | --- |
| `dirPerm` | number | unset |

```json
{ "dirPerm": 750 }
```

#### uploadOnSave
Upload the file on every VS Code save. See the [Upload on save](#upload-on-save) workflow.

| Key | Type | Default |
| --- | --- | --- |
| `uploadOnSave` | boolean | `false` |

#### useTempFile
Upload to a temporary file first, then move it into place — avoids serving a half-written file to visitors while the upload is in progress.

| Key | Type | Default |
| --- | --- | --- |
| `useTempFile` | boolean | `false` |

#### openSsh
Enable **atomic** file uploads (rename-into-place). Only supported by OpenSSH servers.

> 💡 If `openSsh` is `true`, [`useTempFile`](#usetempfile) must also be `true`.

| Key | Type | Default |
| --- | --- | --- |
| `openSsh` | boolean | `false` |

```json
{ "openSsh": true, "useTempFile": true }
```

#### downloadOnOpen
Download the remote version of a file whenever it is opened locally.

| Key | Type | Default |
| --- | --- | --- |
| `downloadOnOpen` | boolean | `false` |

#### syncOption
Tunes the [Sync commands](#sync-commands).

| Key | Type | Default |
| --- | --- | --- |
| `syncOption` | object | `{}` |

| Sub-option | Type | Effect |
| --- | --- | --- |
| `syncOption.delete` | boolean | Delete extraneous files from the destination. |
| `syncOption.skipCreate` | boolean | Don't create files that are new to the destination. |
| `syncOption.ignoreExisting` | boolean | Don't update files that already exist on the destination. |
| `syncOption.update` | boolean | Only overwrite the destination if the source copy is newer. |

```json
{
  "syncOption": {
    "delete": true,
    "skipCreate": false,
    "ignoreExisting": false,
    "update": true
  }
}
```

> `Sync Both Directions` honors only `skipCreate` and `ignoreExisting`.

#### ignore
Files/folders excluded from transfers and sync. Gitignore-style patterns (wildcards with `*`), relative to the config's [`context`](#context). Bypass with the [Force commands](#force-alt-commands).

| Key | Type | Default |
| --- | --- | --- |
| `ignore` | string[] | `[]` |

```json
{
  "ignore": [
    "/.vscode",
    "/.git",
    ".DS_Store",
    "*.log"
  ]
}
```

#### ignoreFile
Path to an ignore file (e.g. `.gitignore`-style list) — absolute, or relative to the workspace root.

| Key | Type |
| --- | --- |
| `ignoreFile` | string |

```json
{ "ignoreFile": ".gitignore" }
```

#### watcher
Watches for file changes made **outside** the VS Code editor (build output, `git checkout`, external tools) and reacts automatically. Only available at the root level of a config (not inside profiles). See [Two-way automatic sync](#two-way-automatic-sync-with-the-watcher).

| Key | Type | Default |
| --- | --- | --- |
| `watcher` | object | `{}` |

| Sub-option | Type | Effect |
| --- | --- | --- |
| `watcher.files` | string (glob) | Which files to watch (required). |
| `watcher.autoUpload` | boolean | Upload when a watched file changes. |
| `watcher.autoDelete` | boolean | Delete on the remote when a watched file is removed locally. |

> 💡 Set [`uploadOnSave`](#uploadonsave) to `false` when watching everything (`"**/*"`) — otherwise every save triggers both mechanisms.

```json
{
  "watcher": {
    "files": "dist/*.{js,css}",
    "autoUpload": true,
    "autoDelete": false
  }
}
```

#### remoteTimeOffsetInHours
Hours of clock difference between the remote server and your machine (**remote minus local**). Needed for accurate timestamp-based [sync](#sync-commands) when the server is in another timezone or its clock drifts.

| Key | Type | Default |
| --- | --- | --- |
| `remoteTimeOffsetInHours` | number | `0` |

#### remoteExplorer
Tunes the [Remote Explorer](#using-the-remote-explorer) view.

| Key | Type | Default |
| --- | --- | --- |
| `remoteExplorer` | object | `{}` |

| Sub-option | Type | Effect |
| --- | --- | --- |
| `remoteExplorer.filesExclude` | string[] | Patterns for files/folders to hide in the Remote Explorer. |
| `remoteExplorer.order` | number | Sort position of this config among Remote Explorer roots (default `0`). |

```json
{
  "remoteExplorer": {
    "filesExclude": ["**/node_modules"],
    "order": 1
  }
}
```

#### concurrency
Maximum simultaneous transfers. Lower it if your server limits concurrent connections/operations.

| Key | Type | Default |
| --- | --- | --- |
| `concurrency` | number | `4` |

#### connectTimeout
Maximum time (ms) to wait when establishing a connection.

| Key | Type | Default |
| --- | --- | --- |
| `connectTimeout` | number | `10000` |

#### limitOpenFilesOnRemote
Cap the number of file descriptors opened on the remote server. Set `true` for the default limit (222), or a number for a custom limit. Use it if transfers fail with the generic [`Error: Failure`](#error-failure) because the server runs out of descriptors.

> 💡 **Do not set this unless you have to.**

| Key | Type | Default |
| --- | --- | --- |
| `limitOpenFilesOnRemote` | boolean \| number | `false` |

#### profiles
A collection of named profiles keyed by profile name. Each profile is merged over the top-level config; switch with `SFTP: Set Profile`. See [Profiles (dev / prod)](#profiles-dev--prod).

| Key | Type |
| --- | --- |
| `profiles` | object |
| `defaultProfile` | string — profile activated by default |

#### remote
Reference a connection defined in User Settings under `remotefs.remote` instead of repeating host details per project. See [Configuration in User Settings](#configuration-in-user-settings-remote-fs).

| Key | Type |
| --- | --- |
| `remote` | string |

### SFTP-only options

#### agent
Path to the ssh-agent UNIX socket for agent-based authentication (usually `$SSH_AUTH_SOCK`). Windows users: set to `pageant` to authenticate with Pageant, or the path to a Cygwin "UNIX socket".

| Key | Type |
| --- | --- |
| `agent` | string |

```json
{ "agent": "/run/user/1000/ssh-agent.socket" }
```

#### privateKeyPath
Absolute path to your private key file.

| Key | Type |
| --- | --- |
| `privateKeyPath` | string |

```json
{ "privateKeyPath": "/Users/me/.ssh/id_rsa" }
```

#### passphrase
Passphrase for an encrypted private key. Set the string itself, or set `true` to be prompted with a dialog (keeps the passphrase out of the config file — recommended).

| Key | Type |
| --- | --- |
| `passphrase` | string \| boolean |

```json
{ "passphrase": true }
```

#### interactiveAuth
Enable keyboard-interactive authentication (e.g. multi-factor / Google Authenticator). Set `true` for a verification-code dialog, or pass an array of predefined responses to answer prompts automatically.

> 💡 Requires the server to have keyboard-interactive authentication enabled.

| Key | Type | Default |
| --- | --- | --- |
| `interactiveAuth` | boolean \| string[] | `false` |

```json
{ "interactiveAuth": true }
```

#### algorithms
Explicit overrides for the SSH transport-layer algorithms. Mainly needed for older servers — see [Error: Connection closed](#error-connection-closed).

Default:

```json
{
  "algorithms": {
    "kex": [
      "ecdh-sha2-nistp256",
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp521",
      "diffie-hellman-group-exchange-sha256"
    ],
    "cipher": [
      "aes128-gcm",
      "aes128-gcm@openssh.com",
      "aes256-gcm",
      "aes256-gcm@openssh.com",
      "aes128-cbc",
      "aes192-cbc",
      "aes256-cbc",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr"
    ],
    "serverHostKey": [
      "ssh-rsa",
      "ssh-dss",
      "ssh-ed25519",
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256"
    ],
    "hmac": [
      "hmac-sha2-256",
      "hmac-sha2-512"
    ]
  }
}
```

#### sshConfigPath
Path to your OpenSSH client config file; matching `Host` entries contribute settings to the connection.

| Key | Type | Default |
| --- | --- | --- |
| `sshConfigPath` | string | `~/.ssh/config` |

#### sshCustomParams
Extra parameters appended to the `ssh` command used by `SFTP: Open SSH in Terminal`.

| Key | Type |
| --- | --- |
| `sshCustomParams` | string |

```json
{ "sshCustomParams": "-g" }
```

#### hop
Connect through one or more intermediate SSH hosts. A single object for one hop, or an array for multiple. See [Connection hopping](#connection-hopping-ssh-proxy--bastion). Each hop accepts the same host/auth options (`host`, `port`, `username`, `privateKeyPath`, …).

> Variable substitution does not work inside a hop configuration.

| Key | Type |
| --- | --- |
| `hop` | object \| object[] |

### FTP(S)-only options

#### secure
Connection encryption mode:

- `true` — encrypt both control and data connections (explicit FTPS)
- `"control"` — encrypt the control connection only
- `"implicit"` — implicitly encrypted control connection (legacy; usually port 990)

| Key | Type | Default |
| --- | --- | --- |
| `secure` | boolean \| `"control"` \| `"implicit"` | `false` |

```json
{ "protocol": "ftp", "port": 21, "secure": true }
```

#### secureOptions
Extra options passed straight to Node's [`tls.connect()`](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback) — e.g. to accept a self-signed certificate.

| Key | Type |
| --- | --- |
| `secureOptions` | object |

```json
{ "secureOptions": { "rejectUnauthorized": false } }
```

### VS Code extension settings

These are regular VS Code settings (`File → Preferences → Settings`, or `settings.json`), separate from `sftp.json`:

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `sftp.debug` | boolean | `false` | Print debug output to the `sftp` Output channel. **Reload VS Code after changing.** |
| `sftp.printDebugLog` | boolean | `false` | Legacy alias for the same debug output. |
| `sftp.downloadWhenOpenInRemoteExplorer` | boolean | `false` | When opening a file in the Remote Explorer, download it ("Edit in Local") instead of showing a read-only "View Content". |

---

## 5. Usage Examples and Common Workflows

### Simple single-server setup

The minimum viable config — SFTP on port 22, prompted for the password:

```json
{
  "host": "host",
  "username": "username",
  "remotePath": "/remote/workspace"
}
```

### Start from a remote project

If the latest files already live on the server, start with an **empty local folder**:

1. Open the empty folder in VS Code and run `SFTP: Config` (see [First-time setup](#first-time-setup)).
2. Set `remotePath` to the server directory you want.
3. Run **`SFTP: Download Project`** — the remote tree is downloaded into your workspace.
4. From here on, edit locally and upload/sync as needed.

### Upload on save

Mirror every save to the server:

```json
{
  "host": "server.example.com",
  "username": "deploy",
  "remotePath": "/var/www/site",
  "uploadOnSave": true
}
```

If your site is live, add temp-file/atomic uploads so visitors never see a half-written file:

```json
{
  "uploadOnSave": true,
  "useTempFile": true,
  "openSsh": true
}
```

(See [`useTempFile`](#usetempfile) and [`openSsh`](#openssh).)

### Profiles (dev / prod)

One config, several environments. Profile values merge over the top-level config; switch with **`SFTP: Set Profile`**.

```json
{
  "username": "username",
  "password": "password",
  "remotePath": "/remote/workspace/a",
  "watcher": {
    "files": "dist/*.{js,css}",
    "autoUpload": false,
    "autoDelete": false
  },
  "profiles": {
    "dev": {
      "host": "dev-host",
      "remotePath": "/dev",
      "uploadOnSave": true
    },
    "prod": {
      "host": "prod-host",
      "remotePath": "/prod"
    }
  },
  "defaultProfile": "dev"
}
```

> `context` and `watcher` are only available at the root level, not inside a profile.

To deploy to every environment at once, use the **`… To All Profiles`** [upload commands](#upload-commands).

### Multiple contexts (array config)

Map different workspace subfolders to different servers (or different remote paths). The `context` values must differ, and `name` is **required**:

```json
[
  {
    "name": "server1",
    "context": "project/build",
    "host": "host",
    "username": "username",
    "password": "password",
    "remotePath": "/remote/project/build"
  },
  {
    "name": "server2",
    "context": "project/src",
    "host": "host",
    "username": "username",
    "password": "password",
    "remotePath": "/remote/project/src"
  }
]
```

### Connection hopping (SSH proxy / bastion)

Reach a target server through an intermediate host with the SSH protocol. Note: variable substitution does not work in a hop configuration.

**Single hop** (`local → hop → target`):

```json
{
  "name": "target",
  "remotePath": "/path/in/target",

  "host": "hopHost",
  "username": "hopUsername",
  "privateKeyPath": "/Users/localUser/.ssh/id_rsa",

  "hop": {
    "host": "targetHost",
    "username": "targetUsername",
    "privateKeyPath": "/Users/hopUser/.ssh/id_rsa"
  }
}
```

The top-level `privateKeyPath` is a file **on your local machine**; the one inside `hop` is a file **on the hop host**.

**Multiple hops** (`local → hopA → hopB → target`): make `hop` an array — each entry authenticates from the previous host, and the last entry is the target:

```json
{
  "name": "target",
  "remotePath": "/path/in/target",

  "host": "hopAHost",
  "username": "hopAUsername",
  "privateKeyPath": "/Users/localUser/.ssh/id_rsa",

  "hop": [
    {
      "host": "hopBHost",
      "username": "hopBUsername",
      "privateKeyPath": "/Users/hopAUser/.ssh/id_rsa"
    },
    {
      "host": "targetHost",
      "username": "targetUsername",
      "privateKeyPath": "/Users/hopBUser/.ssh/id_rsa"
    }
  ]
}
```

### Two-way automatic sync with the watcher

Keep the server updated with **no manual interaction** — including changes made outside VS Code, e.g. when Git checks out a branch or reverts commits:

```json
{
  "name": "My Server",
  "host": "<host_ip_address>",
  "protocol": "sftp",
  "port": 22,
  "username": "user1",
  "remotePath": "/folder1/folder2/folder3",
  "uploadOnSave": false,
  "watcher": {
    "files": "**/*",
    "autoUpload": true,
    "autoDelete": true
  },
  "syncOption": {
    "delete": true
  }
}
```

Keep `uploadOnSave` **false** here — the watcher already covers saves when watching `**/*` (see [`watcher`](#watcher)).

### Uploading a folder's contents without the folder itself

Set [`context`](#context) to the folder — its *contents* then map directly onto `remotePath`. Here everything in `./build` lands in `/folder1/folder2/folder3` (with only JS/HTML auto-uploaded by the watcher):

```json
{
  "name": "My Server",
  "host": "<host_ip_address>",
  "protocol": "sftp",
  "port": 22,
  "username": "user1",
  "remotePath": "/folder1/folder2/folder3",
  "context": "./build",
  "uploadOnSave": false,
  "watcher": {
    "files": "*.{js,html}",
    "autoUpload": true,
    "autoDelete": false
  }
}
```

### Configuration in User Settings (remote-fs)

Define connections once in User Settings (via [remote-fs](https://github.com/liximomo/vscode-remote-fs)) and reference them by name from any project's `sftp.json` with the [`remote`](#remote) option.

In **User Settings**:

```json
"remotefs.remote": {
  "dev": {
    "scheme": "sftp",
    "host": "host",
    "username": "username",
    "rootPath": "/path/to/somewhere"
  },
  "projectX": {
    "scheme": "sftp",
    "host": "host",
    "username": "username",
    "privateKeyPath": "/Users/xx/.ssh/id_rsa",
    "rootPath": "/home/foo/some/projectx"
  }
}
```

In **sftp.json**:

```json
{
  "remote": "dev",
  "remotePath": "/home/xx/",
  "uploadOnSave": false,
  "ignore": [".vscode", ".git", ".DS_Store"]
}
```

### Using the Remote Explorer

Open it by clicking the **SFTP** icon in the Activity Bar, or run `View: Show SFTP`.

- Browsing opens files in a **read-only** view by default. Run **`SFTP: Edit in Local`** (context menu) to download a file into the workspace for editing — or flip the [`sftp.downloadWhenOpenInRemoteExplorer`](#vs-code-extension-settings) setting to make downloading the default.
- **Multi-select** works like the regular explorer: hold `Ctrl`/`Cmd` or `Shift` while clicking to select several files/folders, then upload or download them all at once.
- Create and delete remote files/folders from the context menu ([file commands](#remote-explorer-and-file-commands)).
- Hide noise (e.g. `node_modules`) with [`remoteExplorer.filesExclude`](#remoteexplorer), and control root ordering with `remoteExplorer.order`.
- After a **delete**, manually refresh the parent folder if the tree doesn't update on its own (known issue).

### Monitoring and cancelling transfers

During bulk operations (folder upload/download, sync, project transfers):

- The **status bar** shows a live "Transferring X/Y files" counter — click it to cancel everything.
- The **Transfers** view in the SFTP sidebar lists each file with its status (queued / transferring / failed) and an inline **✕** button to cancel just that file.
- `SFTP: Cancel All Transfers` is also available from the Command Palette and the Transfers view title bar.

### Comparing folders with the remote

Right-click any folder (or run **`SFTP: Compare Folders with Remote`**) to get a recursive diff against its remote counterpart. Results are grouped into **new-local**, **new-remote**, and **modified** files; picking a file offers per-file actions to open a diff, upload, or download. Use it before a sync to preview exactly what would change.

---

## 6. Best Practices

- **Don't commit credentials.** `password` and `passphrase` are stored in plain text in `sftp.json`. Prefer key-based auth ([`privateKeyPath`](#privatekeypath) or [`agent`](#agent)), set `"passphrase": true` for a prompt instead of a stored string, and add `.vscode/sftp.json` to `.gitignore` if it contains secrets.
- **Ignore what you don't deploy.** Add `/.git`, `/.vscode`, `node_modules`, build caches, and OS junk (`.DS_Store`) to [`ignore`](#ignore) — transfers get faster and you avoid clobbering the server with noise. Use the [Force commands](#force-alt-commands) for one-off exceptions.
- **Protect live sites with atomic uploads.** Enable [`useTempFile`](#usetempfile) (plus [`openSsh`](#openssh) on OpenSSH servers) so a visitor never receives a half-uploaded file.
- **Pick one auto-upload mechanism.** Use either [`uploadOnSave`](#uploadonsave) or a broad [`watcher`](#watcher) (`"**/*"` with `autoUpload`), not both — doubling up causes redundant transfers.
- **Be careful with `syncOption.delete` and `watcher.autoDelete`.** They remove files on the destination. Run a [Compare Folders](#comparing-folders-with-the-remote) first if you're unsure what a sync will do.
- **Set `remoteTimeOffsetInHours` when clocks differ** — otherwise timestamp-based sync may copy in the wrong direction (see [`remoteTimeOffsetInHours`](#remotetimeoffsetinhours)).
- **Tune `concurrency` down for picky servers.** Shared hosts often cap concurrent SFTP operations; `"concurrency": 1–3` trades speed for reliability.
- **Verify early.** After editing `sftp.json`, run [`SFTP: Test Connection`](#verifying-your-connection) rather than discovering an auth typo mid-upload.
- **Use profiles for environments** rather than juggling multiple config files — and remember the [`… To All Profiles`](#upload-commands) commands when a release must land everywhere.

---

## 7. Troubleshooting and Known Issues

### Enabling debug logs

1. Open Settings (`File → Preferences → Settings`, or `Code → Preferences → Settings` on macOS).
2. Set `sftp.debug` to `true` and **reload VS Code**.
3. View the logs in `View → Output` and select the **sftp** channel.

If a connection drops mid-session, the underlying error is logged there (since 1.16.5) instead of being silently discarded.

### SSH connection error messages

As of 1.16.5, common SSH failures surface as plain-language messages instead of raw `ssh2` errors:

| Message | Meaning |
| --- | --- |
| **Connection refused** | Nothing is listening on the configured host/port, or a firewall is blocking it. |
| **Connection timed out** | Host unreachable — wrong address, network/VPN issue, or a firewall silently dropping packets. |
| **Host not found** | Hostname couldn't be resolved; check for typos or DNS issues. |
| **Authentication failed** | Username, password, or private key was rejected by the server. |

Check the `sftp` Output channel (see [Enabling debug logs](#enabling-debug-logs)) for the underlying detail.

### Error: Failure

This generic message comes from the **remote** SFTP server when a syscall fails. To pinpoint it, enable debug output on the *server* side and retry. Two common causes:

1. **`remotePath` points at a symlink** — change it to the actual (resolved) path.
2. **The server ran out of file descriptors** — raise the server's descriptor limit, or if you can't, set [`limitOpenFilesOnRemote`](#limitopenfilesonremote) in `sftp.json`.

### Error: Connection closed

On legacy/old servers the connection may keep closing because of a key-exchange algorithm mismatch. Override the [`algorithms`](#algorithms) to drop `diffie-hellman-group-exchange-sha256` from `kex`:

```json
{
  "algorithms": {
    "kex": [
      "ecdh-sha2-nistp256",
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp521"
    ],
    "cipher": [
      "aes128-gcm",
      "aes128-gcm@openssh.com",
      "aes256-gcm",
      "aes256-gcm@openssh.com",
      "aes128-cbc",
      "aes192-cbc",
      "aes256-cbc",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr"
    ],
    "serverHostKey": [
      "ssh-rsa",
      "ssh-dss",
      "ssh-ed25519",
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-256",
      "rsa-sha2-512"
    ],
    "hmac": [
      "hmac-sha2-256",
      "hmac-sha2-512"
    ]
  }
}
```

### ENFILE: file table overflow (macOS)

macOS has a harsh default limit on open files. Raise it:

```sh
echo kern.maxfiles=65536 | sudo tee -a /etc/sysctl.conf
echo kern.maxfilesperproc=65536 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=65536
ulimit -n 65536
```

### Upload Changed Files does nothing

Historically the command was hidden and had no shortcut (see [liximomo/vscode-sftp#854](https://github.com/liximomo/vscode-sftp/issues/854)). It is now visible in the Command Palette and Source Control view and bound to `Ctrl+Alt+U` by default. It requires a Git repository with at least one commit — it uploads files changed or created **since the last commit**.

### Remote Explorer not refreshing after delete

After deleting a remote file, the tree may not update — manually refresh the parent folder (the ↻ button or `sftp.remoteExplorer.refresh`).

### Known issues fixed in this fork

For historical context (these are already fixed on `develop`):

- **`TypeError: isDate is not a function`** from `ssh2/lib/protocol/SFTP.js` on upload/download — Node removed `util.isDate`, which `ssh2@1.13.0` still used. Fixed via `patches/ssh2+1.13.0.patch`, applied automatically by `patch-package` on `npm install`.
- Compile errors on `develop` (missing command-constant imports, `vscode-uri` default-export mismatch, `string`/`URI` type mismatch) — fixed; `npm run compile` succeeds.
- Test-suite breakage under Jest 28+ and `memfs` stream-close bugs — fixed; all suites pass.

---

## 8. Frequently Asked Questions

**Q: How do I upload the contents of a folder, but not the folder itself?**
Set [`context`](#context) to that folder (e.g. `"context": "./build"`) — its contents then map directly to `remotePath`. Full example: [Uploading a folder's contents without the folder itself](#uploading-a-folders-contents-without-the-folder-itself).

**Q: How can I upload files as root?**
A community workaround (may not work everywhere — see [liximomo/vscode-sftp#559](https://github.com/liximomo/vscode-sftp/issues/559)) is:

```json
"sshCustomParams": "sudo su -;"
```

**Q: How do I sync both ways automatically, without any user interaction?**
Use a watcher on `**/*` with `autoUpload`/`autoDelete` plus `syncOption.delete` — full config in [Two-way automatic sync with the watcher](#two-way-automatic-sync-with-the-watcher). This also keeps the server updated when Git changes files (branch checkout, revert).

**Q: Why don't I see dotfiles/hidden files in the Remote Explorer?**
Often a server-side listing setting. With **proftpd**, edit `proftpd.conf` (commonly `/etc/proftpd.conf`, `/etc/proftpd/proftpd.conf`, `/usr/local/etc/proftpd.conf`, or `/usr/local/etc/proftpd/proftpd.conf`) and change `ListOptions "-l"` to `ListOptions "-la"`:

```conf
<Global>
ListOptions "-la"
</Global>
```

**Q: Do I have to store my password in `sftp.json`?**
No — leave `password` out and you'll be prompted on connect. Better yet, use key-based auth (see [Best Practices](#6-best-practices)).

**Q: What do the "Connection refused" / "Connection timed out" / "Host not found" / "Authentication failed" messages mean?**
See [SSH connection error messages](#ssh-connection-error-messages).

**Q: Can I edit files directly in the Remote Explorer?**
Files open read-only by default — use `SFTP: Edit in Local`, or set `sftp.downloadWhenOpenInRemoteExplorer` to make opening a file download it. See [Using the Remote Explorer](#using-the-remote-explorer).

**Q: Sync copies files in the wrong direction / re-uploads unchanged files.**
Sync is timestamp-based; correct clock/timezone differences with [`remoteTimeOffsetInHours`](#remotetimeoffsetinhours).

**Q: Transfers randomly fail on my shared host.**
Lower [`concurrency`](#concurrency) (some servers cap simultaneous operations) and/or set [`limitOpenFilesOnRemote`](#limitopenfilesonremote) if the server runs out of file descriptors.

---

## 9. Development and Contributing

Issues and pull requests are welcome — the project is under active maintenance again at [jmwerk/vscode-sftp](https://github.com/jmwerk/vscode-sftp).

```sh
git clone https://github.com/jmwerk/vscode-sftp.git
cd vscode-sftp
npm install        # applies patches (ssh2, memfs) via patch-package
npm run compile    # production build (webpack)
npm run dev        # watch mode for development
npm test           # jest test suites
npm run package    # build the .vsix
```

Highlights of the codebase:

- `src/extension.ts` / `src/app.ts` — activation and wiring
- `src/commands/` — one module per command
- `src/core/` — config, file system abstractions, transfer scheduling
- `src/modules/remoteExplorer` — the Remote Explorer view
- `schema/` — the JSON schema that validates `.vscode/sftp.json`
- `patches/` — `patch-package` fixes applied on install

See also [CONTRIBUTING.md](../CONTRIBUTING.md) and the [CHANGELOG](../CHANGELOG.md).

## 10. Credits

This project builds on the work of [@Natizyskunk](https://github.com/Natizyskunk) and [@liximomo](https://github.com/liximomo). If their earlier work helped you, their original donation links are in the [upstream README](https://github.com/Natizyskunk/vscode-sftp#donation).
