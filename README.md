# sftp-dss sync extension for VS Code

This version is a forked and updated version of the SFTP Plugin from [@Natizyskunk](https://github.com/Natizyskunk/).

I used the current master as a baseline to add new functionality. It extends the extension with mutliple Options.

**The first config Option:**

 `"useIgnoreForUpload": [bool]`

This allows the Ignore List to be used when uploading files via command or on Save.
No blocked files are uploaded to the server anymore
**NEW: The delete Option always bypasses the ignore List! ->** Deleting files on the server doenst follow the blocklist

It also adds a new config option for showing synced files status (its fully customizeable)

```json



 "syncStatus": {
        "type": "object",
        "description": "File sync status decoration settings. Shows visual indicators for files that are out of sync with remote.",
        "properties": {
          "enabled": {
            "type": "boolean",
            "description": "Enable file sync status decorations in the file explorer.",
            "default": false
          },
          "refreshInterval": {
            "type": "number",
            "description": "How often to refresh sync status (in milliseconds).",
            "default": 30000
          },
          "showLocalOnly": {
            "type": "boolean",
            "description": "Show indicator for files that exist only locally (not uploaded).",
            "default": true
          },
          "showRemoteOnly": {
            "type": "boolean",
            "description": "Show indicator for files that exist only on remote (not downloaded).",
            "default": true
          },
          "showModified": {
            "type": "boolean",
            "description": "Show indicator for files that are modified and out of sync.",
            "default": true
          },
          "showSynced": {
            "type": "boolean",
            "description": "Show indicator for files that are in sync.",
            "default": false
          },
          "showIgnored": {
            "type": "boolean",
            "description": "Show indicator for files that are ignored.",
            "default": false
          },
          "timeTolerance": {
            "type": "number",
            "description": "Time difference tolerance in milliseconds for date-only timestamps (when server returns 00:00:00). Files with precise timestamps (HH:MM:SS) use 60 second (1 minute) tolerance automatically. Default is 86400000 (24 hours) for FTP servers that truncate old file timestamps.",
            "default": 86400000
          }
        }
      },
```

## Upload Changed Files (Git / SVN)

`SFTP: Upload Changed Files` (default shortcut `Ctrl+Alt+U`) uploads only the files your version control reports as changed.
Git repositories are read through the built-in Git extension, Subversion working copies through the `svn` command line client (`svn status`), so `svn` has to be on your `PATH`.

1. All added, modified, untracked/unversioned and renamed files below your configured SFTP folders are collected.
2. A list shows every change with its status, the version control system and the target profile. Everything is preselected; deselect what you do not want to upload and confirm.
3. Renamed files are renamed on the remote (when the old file exists there) and uploaded afterwards. Conflicted files are always skipped.
4. The result is shown as a notification and in the SFTP output panel.

The command is also available in the Source Control view (title menu and the context menu of the "Changes", "Staged Changes" and "Unversioned" groups). From there it only handles the files of the clicked group.

Settings (VS Code settings, not `sftp.json`):

| Setting | Default | Description |
| --- | --- | --- |
| `sftp.changedFiles.confirm` | `true` | Show the selection list first. When `false` everything except deletions is uploaded right away. |
| `sftp.changedFiles.includeUntracked` | `true` | Include untracked (git) / unversioned (svn) files. |
| `sftp.changedFiles.allowRemoteDelete` | `false` | Also offer locally deleted files for deletion on the remote. They are never preselected. |

`useIgnoreForUpload` is respected: ignored files are listed as skipped.

## Installation

### Method 1 (Recommended : Auto update)

1. Select Extensions (Ctrl + Shift + X).
2. Uninstall current sftp extension from [@Natizyskunk](https://github.com/Natizyskunk/).
3. Install new extension directly from VS Code Marketplace
4. Voila
