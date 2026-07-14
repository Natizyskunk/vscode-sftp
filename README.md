# SFTPresso

SFTP/FTP sync extension for VS Code — actively maintained by [@jmwerk](https://github.com/jmwerk). <br>
(Forked from [Natizyskunk's vscode-sftp](https://github.com/Natizyskunk/vscode-sftp), which itself continued [liximomo's original SFTP plugin](https://github.com/liximomo/vscode-sftp.git) after it went unmaintained)

- Repository: https://github.com/jmwerk/vscode-sftp <br>
- VS Code marketplace: not yet published under this name — for now, install from a built VSIX (see [Installation](#installation) below)

✳ Issues and pull requests welcome — this project is under active maintenance again.

## 🔧 Maintenance notes

**2026 — Taken over by [@jmwerk](https://github.com/jmwerk).** Natizyskunk's upstream repo had gone quiet (see their note below), so this fork is now where fixes and updates land going forward.

First fix shipped: a crash in the bundled `ssh2` dependency — `TypeError: isDate is not a function`, thrown from `ssh2/lib/protocol/SFTP.js` when opening a read/write stream (e.g. on file upload/download). Node removed `util.isDate`, which `ssh2@1.13.0` still relies on.

The fix lives in [`patches/ssh2+1.13.0.patch`](patches/ssh2+1.13.0.patch) and is applied automatically via [patch-package](https://github.com/ds300/patch-package) on `npm install` (see the `postinstall` script in `package.json`). No manual `node_modules` edits needed.

`npm run compile` now succeeds on `develop` — fixed a missing import of `COMMAND_UPLOAD_FILE_TO_ALL_PROFILES`/`COMMAND_UPLOAD_FOLDER_TO_ALL_PROFILES`, a `vscode-uri` default-export mismatch, and a `string`/`URI` type mismatch in `getFileSystemPath`.

`npm test` is fixed too — tests now compile through [ts-jest](https://kulshekhar.github.io/ts-jest/) (the old hand-rolled `test/preprocessor.js` is gone), and `memfs` (used only in tests) is patched via `patch-package` for a couple of stream-close bugs that were silently breaking file-transfer tests. 4/4 suites, 42/42 tests passing.

**July 2026 — toolchain modernization.** The extension now builds with [esbuild](https://esbuild.github.io/) (replacing webpack + ts-loader), type-checks on TypeScript 5, and lints with ESLint + typescript-eslint (replacing the long-deprecated TSLint). CI runs on Node 22/24 (16/18 are EOL), the minimum supported VS Code version is 1.75, and command modules are registered from an explicit index instead of webpack's `require.context` (which would silently register zero commands under any other bundler). Development requires Node 22+ (see `.nvmrc`).

The status bar now shows a live transfer progress counter ("Transferring X/Y files") during bulk uploads/downloads — click it to cancel all in-flight transfers. SSH connection failures (auth errors, connection refused, timeouts, unreachable hosts, DNS issues) also now surface actionable messages instead of raw `ssh2` error text.

A new **Transfers** view in the SFTP sidebar shows live per-file status (queued/transferring/failed) during folder upload/download/sync operations, with a cancel button on each in-flight file in addition to the existing `Cancel All Transfers` command.

Passwords can now be kept in VS Code's secret storage (backed by the OS keychain) instead of plaintext `sftp.json`: save one with `SFTP: Save Password`, or accept the "Remember password" offer after a successful password-prompted connection; remove it with `SFTP: Clear Password`. A one-time output-channel warning nudges configs that still contain a plaintext `password`.

<details>
<summary>History from the previous maintainer (Natizyskunk)</summary>

## ℹ INFOS - 2025/03/13
I've tried to keep this extension up-to-date as much as I can and added a lot of new relevant features. Saddly, for the last year and a half I wasn't really able to work on the project because of personal reasons and I'm really not sure if and when I'll be able to get more time to work on it again. So for now consider the [v1.16.3](https://github.com/Natizyskunk/vscode-sftp/releases/tag/v1.16.3) as the latest official stable release available.

## ℹ INFOS - 2023/06/23
This is the main repository for the SFTP extension since [@liximomo](https://github.com/liximomo) has set his own to deprecated in favor of this one in the VSCode marketplace.
There are also other forks that are available. Feel free to try them.

A lot of work as been brought to fix bugs, add new features and more than 50 updates have been released with a lot of improvements and stability fixes for almost two years now. 😎

I've been working hard to fix a lot of things and I've updated more than 50 new releases with a lot of improvements and stability fixes and I've brought new features for almost three years now. 

</details>

---

VSCode-SFTP enables you to add, edit or delete files within a local directory and have it sync to a remote server directory using different transfer protocols like FTP or SSH. The most basic setup requires only a few lines of configuration with a wide array of specific settings also available to meet the needs of any user. Both powerful and fast, it helps developers save time by allowing the use of a familiar editor and environment.

- Features
  - [Browser remote with Remote Explorer](#remote-explorer)
  - Diff local and remote
  - Compare folders (recursive local/remote diff)
  - Test Connection (verify the active profile can connect, from a command or CodeLens on `sftp.json`)
  - Secure password storage (`SFTP: Save Password` / `SFTP: Clear Password`, backed by the OS keychain)
  - Sync directory (with an optional dry-run preview/confirmation via `syncConfirm`)
  - Upload/Download
  - Transfers view with per-file progress and cancellation
  - Upload on save
  - File Watcher
  - Multiple configurations
  - Switchable profiles
  - Temp File support
- [Commands](https://github.com/jmwerk/vscode-sftp/wiki#3-command-reference)
- [Debug](#debug)
- [FAQ](#faq)

## Installation

### Method 1 (Recommended : Auto update)
> SFTPresso isn't published to the VS Code Marketplace yet. Until it is, build/install from source — see [build instructions on the wiki](https://github.com/jmwerk/vscode-sftp/wiki#9-development-and-contributing) — or grab a VSIX from [Releases](https://github.com/jmwerk/vscode-sftp/releases) once available.

### Method 2 (Manual update)
To install just follow these steps from within VSCode:
1. Select Extensions (Ctrl + Shift + X).
2. Uninstall current sftp extension from @liximomo.
3. Open "More Action" menu(ellipsis on the top) and click "Install from VSIX…".
4. Locate VSIX file and select.
5. Reload VSCode.
6. Voilà!

## Documentation
Full documentation lives on the [project wiki](https://github.com/jmwerk/vscode-sftp/wiki), kept in sync from [docs/home.md](docs/home.md) in this repo:
- [Installation and setup](https://github.com/jmwerk/vscode-sftp/wiki#2-installation-and-setup)
- [Command reference](https://github.com/jmwerk/vscode-sftp/wiki#3-command-reference)
- [Configuration reference (`sftp.json`)](https://github.com/jmwerk/vscode-sftp/wiki#4-configuration-reference-sftpjson)
- [Usage examples and common workflows](https://github.com/jmwerk/vscode-sftp/wiki#5-usage-examples-and-common-workflows)
- [Troubleshooting and known issues](https://github.com/jmwerk/vscode-sftp/wiki#7-troubleshooting-and-known-issues)

## Usage
If the latest files are already on a remote server, you can start with an empty local folder,
then download your project, and from that point sync.

1. In `VS Code`, open a local directory you wish to sync to the remote server (or create an empty directory
that you wish to first download the contents of a remote server folder in order to edit locally).
2. `Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on Mac open command palette, run `SFTP: config` command.
3. If no config exists yet, choose how to create it:
   - **Quick setup** — a guided wizard asks for the protocol (sftp/ftp), host, port (pre-filled per protocol), username, authentication method (password prompt at connect, private key with `~` expansion, or ssh-agent), remote path, and whether to upload on save. It validates your answers, writes `sftp.json`, and runs `SFTP: Test Connection` right away so you know the connection works.
   - **Edit JSON** — a basic configuration file will appear named `sftp.json` under the `.vscode` directory, open and edit the configuration parameters with your remote server information.

For instance:
```json
{
    "name": "Profile Name",
    "host": "name_of_remote_host",
    "protocol": "ftp",
    "port": 21,
    "secure": true,
    "username": "username",
    "remotePath": "/public_html/project", // <--- This is the path which will be downloaded if you "Download Project"
    "password": "password",
    "uploadOnSave": false
}
```
The password parameter in `sftp.json` is optional — if left out you will be prompted for a password on sync, with an offer to remember it in VS Code's secret storage (OS keychain). You can also save it ahead of time with the `SFTP: Save Password` command (and remove it with `SFTP: Clear Password`), keeping the password out of `sftp.json` entirely.
_Note：_ backslashes and other special characters must be escaped with a backslash.

`sftp.json` is read as JSONC, so `// line comments`, `/* block comments */`, and trailing commas are allowed.

4. Save and close the `sftp.json` file.
5. `Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on Mac open command palette.
6. Type `sftp` and you'll now see a number of other commands. You can also access many of the commands from the project's file explorer context menus.
7. A good one to start with if you want to sync with a remote folder is `SFTP: Download Project`.  This will download the directory shown in the `remotePath` setting in `sftp.json` to your local open directory.
8. Done - you can now edit locally and after each save it will upload to sync your remote file with the local copy.
9. Enjoy!

For detailed explanations please go to the [wiki](https://github.com/jmwerk/vscode-sftp/wiki).

## Example configurations
You can see the full list of configuration options [here](https://github.com/jmwerk/vscode-sftp/wiki#4-configuration-reference-sftpjson).

### Simple
```json
{
  "host": "host",
  "username": "username",
  "remotePath": "/remote/workspace"
}
```

### Profiles
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

_Note：_ `context` and `watcher` are only available at root level.

Use `SFTP: Set Profile` to switch profile. When profiles are defined, the status bar shows the active one (e.g. `SFTP: dev`) and clicking it opens the profile picker.

### Multiple Context
The context must **not be same**.
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

_Note：_ `name` is required in this mode.

### Connection Hopping
You can connect to a target server through a proxy with ssh protocol.

_Note：_ Variable substitution is not working in a hop configuration.

#### Single Hop
local -> hop -> target
```json
{
  "name": "target",
  "remotePath": "/path/in/target",

  // hop
  "host": "hopHost",
  "username": "hopUsername",
  "privateKeyPath": "/Users/localUser/.ssh/id_rsa", // <-- The key file is assumed on the local.

  "hop": {
    // target
    "host": "targetHost",
    "username": "targetUsername",
    "privateKeyPath": "/Users/hopUser/.ssh/id_rsa", // <-- The key file is assumed on the hop.
  }
}
```

#### Multiple Hop
local -> hopa -> hopb -> target
```json
{
  "name": "target",
  "remotePath": "/path/in/target",

  // hopa
  "host": "hopAHost",
  "username": "hopAUsername",
  "privateKeyPath": "/Users/hopAUsername/.ssh/id_rsa" // <-- The key file is assumed on the local.

  "hop": [
    // hopb
    {
      "host": "hopBHost",
      "username": "hopBUsername",
      "privateKeyPath": "/Users/hopaUser/.ssh/id_rsa" // <-- The key file is assumed on the hopa.
    },

    // target
    {
      "host": "targetHost",
      "username": "targetUsername",
      "privateKeyPath": "/Users/hopbUser/.ssh/id_rsa", // <-- The key file is assumed on the hopb.
    }
  ]
}
```

### Configuration in User Setting
You can use `remote` to tell sftp to get the configuration from [remote-fs](https://github.com/liximomo/vscode-remote-fs).

In User Setting:
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

In sftp.json:
```json
{
  "remote": "dev",
  "remotePath": "/home/xx/",
  "uploadOnSave": false,
  "ignore": [".vscode", ".git", ".DS_Store"]
}
```

## Remote Explorer
![remote-explorer-preview](https://raw.githubusercontent.com/jmwerk/vscode-sftp/develop/assets/showcase/remote-explorer.png)

Remote Explorer lets you explore files in remote. You can open Remote Explorer by:

1. Run Command `View: Show SFTP`.
2. Click SFTP view in Activity Bar.

You can only view a files content with Remote Explorer. Run command `SFTP: Edit in Local` to edit it in local.

### Multiple Select
You are able to select multiple files/folders at once on the remote server to download and upload. You can do it simply by holding down Ctrl or Shift while selecting all desired files, just like on the regular explorer view.

_Note：_ You need to manually refresh the parent folder after you **delete** a file if the explorer isn't correctly updated.

### Order
You can order the remote Explorer by adding the `remoteExplorer.order` parameter inside your `sftp.json` config file.

In sftp.json:
```json
{
  "remoteExplorer": {
    "order": 1 // <-- Default value is 0.
  }
}
```

## Debug
1. Open User Settings.
  - On Windows/Linux - `File > Preferences > Settings`
  - On macOS - `Code > Preferences > Settings`
2. Set `sftp.debug` to `true` and reload vscode.
3. View the logs in `View > Output > sftp`.

## FAQ
You can see all the Frequently Asked Questions [on the wiki](https://github.com/jmwerk/vscode-sftp/wiki#8-frequently-asked-questions), along with [troubleshooting and known issues](https://github.com/jmwerk/vscode-sftp/wiki#7-troubleshooting-and-known-issues).

## Credits

This project builds on the work of [@Natizyskunk](https://github.com/Natizyskunk) and [@liximomo](https://github.com/liximomo). If their earlier work helped you, their original donation links are in the [upstream README](https://github.com/Natizyskunk/vscode-sftp#donation).
