# sftp sync extension for VS Code

Maintained and updated version by [@Natizyskunk](https://github.com/Natizyskunk/) 😀 <br>
(Forked from the no longer maintained [liximomo's SFTP plugin](https://github.com/liximomo/vscode-sftp.git))

- VS Code marketplace : https://marketplace.visualstudio.com/items?itemName=Natizyskunk.sftp <br>
- VSIX release : https://github.com/Natizyskunk/vscode-sftp/releases/

---

VSCode-SFTP enables you to add, edit or delete files within a local directory and have it sync to a remote server directory using different transfer protocols like FTP or SSH. The most basic setup requires only a few lines of configuration with a wide array of specific settings also available to meet the needs of any user. Both powerful and fast, it helps developers save time by allowing the use of a familiar editor and environment.

- Features
  - [Browser remote with Remote Explorer](#remote-explorer) (with file-type icons and file sizes)
  - [Database Manager](#database-manager) — browse and manage MySQL databases with SSH tunneling
  - [Server Log Viewer](#server-log-viewer) — analyze nginx/apache logs with filtering, grouping, and real-time streaming
  - [Post-connect commands](#post-connect-commands) — run shell commands after SSH connection
  - [Transfer progress](#transfer-progress) — real-time percentage, speed, and ETA in the status bar
  - [Idle connection auto-reconnect](#connection-reliability) — no more hanging after idle periods
  - Diff local and remote
  - Sync directory
  - Upload/Download
  - Upload on save
  - File Watcher
  - Multiple configurations
  - Switchable profiles
  - Temp File support
  - Dynamic workspace folder detection
- [Commands](https://github.com/Natizyskunk/vscode-sftp/wiki/Commands)
- [Debug](#debug)
- [FAQ](#FAQ)

## Installation

### Method 1 (Recommended : Auto update)
1. Select Extensions (Ctrl + Shift + X).
2. Uninstall current sftp extension from @liximomo.
3. Install new extension directly from VS Code Marketplace : https://marketplace.visualstudio.com/items?itemName=Natizyskunk.sftp.
4. Voilà!

### Method 2 (Manual update)
To install just follow these steps from within VSCode:
1. Select Extensions (Ctrl + Shift + X).
2. Uninstall current sftp extension from @liximomo.
3. Open "More Action" menu(ellipsis on the top) and click "Install from VSIX…".
4. Locate VSIX file and select.
5. Reload VSCode.
6. Voilà!

## Documentation
- [Home](https://github.com/Natizyskunk/vscode-sftp/wiki)
- [Settings](https://github.com/Natizyskunk/vscode-sftp/wiki/Setting)
- [Common configuration](https://github.com/Natizyskunk/vscode-sftp/wiki/Common-Configuration)
- [SFTP configuration](https://github.com/Natizyskunk/vscode-sftp/wiki/SFTP-only-Configuration)
- [FTP confriguration](https://github.com/Natizyskunk/vscode-sftp/wiki/FTP(s)-only-Configuration)
- [Commands](https://github.com/Natizyskunk/vscode-sftp/wiki/Commands)

## Usage
If the latest files are already on a remote server, you can start with an empty local folder,
then download your project, and from that point sync.

1. In `VS Code`, open a local directory you wish to sync to the remote server (or create an empty directory
that you wish to first download the contents of a remote server folder in order to edit locally).
2. `Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on Mac open command palette, run `SFTP: config` command.
3. A basic configuration file will appear named `sftp.json` under the `.vscode` directory, open and edit the configuration parameters with your remote server information.

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
The password parameter in `sftp.json` is optional, if left out you will be prompted for a password on sync.
_Note：_ backslashes and other special characters must be escaped with a backslash.

4. Save and close the `sftp.json` file.
5. `Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on Mac open command palette.
6. Type `sftp` and you'll now see a number of other commands. You can also access many of the commands from the project's file explorer context menus.
7. A good one to start with if you want to sync with a remote folder is `SFTP: Download Project`.  This will download the directory shown in the `remotePath` setting in `sftp.json` to your local open directory.
8. Done - you can now edit locally and after each save it will upload to sync your remote file with the local copy.
9. Enjoy!

For detailed explanations please go to [wiki](https://github.com/Natizyskunk/vscode-sftp/wiki).

## Example configurations
You can see the full list of configuration options [here](https://github.com/Natizyskunk/vscode-sftp/wiki/configuration).

- [sftp sync extension for VS Code](#sftp-sync-extension-for-vs-code)
  - [Installation](#installation)
    - [Method 1 (Recommended : Auto update)](#method-1-recommended--auto-update)
    - [Method 2 (Manual update)](#method-2-manual-update)
  - [Documentation](#documentation)
  - [Usage](#usage)
  - [Example configurations](#example-configurations)
    - [Simple](#simple)
    - [Profiles](#profiles)
    - [Multiple Context](#multiple-context)
    - [Connection Hopping](#connection-hopping)
      - [Single Hop](#single-hop)
      - [Multiple Hop](#multiple-hop)
    - [Configuration in User Setting](#configuration-in-user-setting)
  - [Post-Connect Commands](#post-connect-commands)
  - [Remote Explorer](#remote-explorer)
    - [Multiple Select](#multiple-select)
    - [Order](#order)
  - [Database Manager](#database-manager)
  - [Server Log Viewer](#server-log-viewer)
  - [Transfer Progress](#transfer-progress)
  - [Connection Reliability](#connection-reliability)
  - [Debug](#debug)
  - [FAQ](#faq)
  - [Donation](#donation)
    - [Buy Me a Coffee](#buy-me-a-coffee)
    - [PayPal](#paypal)

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

Use `SFTP: Set Profile` to switch profile.

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

## Post-Connect Commands
You can run shell commands automatically after an SSH connection is established using the `post_connect` option. This is useful for setting up the environment, sourcing scripts, or running initialization commands on the remote server.

In sftp.json:
```json
{
  "host": "host",
  "username": "username",
  "remotePath": "/remote/workspace",
  "post_connect": "source /etc/profile"
}
```

You can also provide an array of commands:
```json
{
  "host": "host",
  "username": "username",
  "remotePath": "/remote/workspace",
  "post_connect": [
    "source ~/.nvm/nvm.sh",
    "nvm use 18",
    "echo 'Connected!'"
  ]
}
```

Commands run on both programmatic SFTP connections (before the SFTP session starts) and when opening an SSH terminal via `SFTP: Open SSH in Terminal`.

## Remote Explorer
![remote-explorer-preview](https://raw.githubusercontent.com/Natizyskunk/vscode-sftp/master/assets/showcase/remote-explorer.png)

Remote Explorer lets you explore files in remote. You can open Remote Explorer by:

1. Run Command `View: Show SFTP`.
2. Click SFTP view in Activity Bar.

You can only view a files content with Remote Explorer. Run command `SFTP: Edit in Local` to edit it in local.

### File-Type Icons
Files and folders in the Remote Explorer display appropriate icons from your active VS Code icon theme. File icons are automatically resolved by file extension (e.g., `.ts`, `.json`, `.html` each get distinct icons).

### File Sizes
Human-readable file sizes (B, KB, MB, GB) are shown next to each filename. You can toggle this off in settings:

```json
"sftp.remoteExplorer.showFileSize": false
```

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

## Database Manager
The Database Manager lets you browse and manage MySQL databases directly from VS Code. It supports automatic SSH tunneling — if your database is on the remote server, just set the host to `127.0.0.1` and the extension will tunnel through your existing SSH connection.

### Configuration
Add a `database` array to your `.vscode/sftp.json`:
```json
{
  "name": "My Server",
  "host": "example.com",
  "protocol": "sftp",
  "port": 22,
  "username": "user",
  "remotePath": "/var/www",
  "database": [
    {
      "host": "127.0.0.1",
      "port": 3306,
      "username": "db_user",
      "password": "db_password",
      "database": "my_database"
    }
  ]
}
```

### Usage
1. Configure your database connection(s) in `sftp.json` as shown above.
2. Open the SFTP sidebar — a **Database** section appears below the Explorer.
3. Expand a database to see its tables.
4. Click a table to open the Database Manager panel with three tabs:
   - **Structure** — view columns, types, keys, and indexes
   - **Data** — browse rows with pagination (50 rows per page)
   - **Query** — write and execute SQL (Ctrl+Enter / Cmd+Enter to run)

You can also run the command `SFTP: Open Database Manager` from the Command Palette, or right-click a server root in the Remote Explorer.

_Note:_ Non-SELECT queries (INSERT, UPDATE, DELETE, etc.) will prompt for confirmation before executing.

## Server Log Viewer
The Server Log Viewer lets you view, filter, and analyze nginx/apache access and error logs directly from VS Code, with real-time streaming support.

### Opening the Log Viewer
- Run `SFTP: View Server Logs` from the Command Palette.
- Or right-click a server root in the Remote Explorer and select **View Server Logs**.

### Features
- **Auto-discovery** — Automatically finds log files in `/var/log/nginx`, `/var/log/apache2`, and `/var/log/httpd`.
- **Log parsing** — Supports Combined Log Format (access logs) and nginx/apache error log formats with auto-detection.
- **Filtering** — Filter by IP address, URI pattern, status code, user-agent, and date range.
- **Grouping** — Group log entries by IP, URI, User-Agent, or status code to identify patterns.
- **Real-time streaming** — Stream new log entries in real-time via `tail -f`.
- **Color-coded entries** — 2xx (green), 3xx (blue), 4xx (orange), 5xx (red).
- **Stats sidebar** — View total requests, unique IPs, status breakdown, top IPs, top URIs, and suspicious pattern alerts.
- **Security analysis** — Detects potential SQL injection, path traversal, XSS attempts, known scanners, shellshock, WordPress scans, and high request rate IPs.

### Custom Log Paths
You can add custom log file paths in your VS Code settings:
```json
"sftp.logViewer.customLogPaths": [
  "/var/log/myapp/access.log",
  "/home/user/logs/error.log"
]
```

## Transfer Progress
During file uploads and downloads, the status bar displays real-time transfer information including the filename, completion percentage, transfer speed, and estimated time remaining.

```
⠋ style.css 45% | 2.3 MB/s | ~12s
```

Transfer progress is enabled by default. To disable it, add to your `sftp.json`:
```json
{
  "showTransferProgress": false
}
```

## Connection Reliability
The extension automatically handles idle and stale connections:

- **Idle timeout** — Connections idle for more than 5 minutes are automatically reconnected on the next operation, preventing the common issue of hanging transfers after a period of inactivity.
- **Operation timeout** — All SFTP operations (stat, list, mkdir, rename, etc.) have a configurable timeout (default 30 seconds) to prevent indefinite hangs when a server becomes unresponsive.

To customize the operation timeout (in milliseconds):
```json
{
  "operationTimeout": 30000
}
```

## Debug
1. Open User Settings.
  - On Windows/Linux - `File > Preferences > Settings`
  - On macOS - `Code > Preferences > Settings`
2. Set `sftp.debug` to `true` and reload vscode.
3. View the logs in `View > Output > sftp`.

## FAQ
You can see all the Frequently Asked Questions [here](./FAQ.md).

## Donation
If this project helped you reduce development time and you wish to contribute financially

### Buy Me a Coffee
[![Buy Me A Coffee](https://bmc-cdn.nyc3.digitaloceanspaces.com/BMC-button-images/custom_images/orange_img.png)](https://www.buymeacoffee.com/Natizyskunk)

### PayPal
<!-- [![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BY89QD47D7MPS&source=url) -->
[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/donate?business=DELD7APHHM3BC&no_recurring=0&currency_code=EUR)
[![PayPal Me](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/natanfourie)
