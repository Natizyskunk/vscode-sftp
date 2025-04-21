# sftp sync extension for VS Code

New maintained and updated version by [@Natizyskunk](https://github.com/Natizyskunk/), [@thebestbradley](https://github.com/thebestbradley/) and [@zekeduncan](https://github.com/zekeduncan) 😀 <br>
(Forked from the no longer maintained [liximomo's SFTP plugin](https://github.com/liximomo/vscode-sftp.git))

- VS Code marketplace : https://marketplace.visualstudio.com/items?itemName=Natizyskunk.sftp <br>
- VSIX release : https://github.com/Natizyskunk/vscode-sftp/releases/

✳ I would be more than happy to have you participate in one way or another to this project. You can do so by simply following the [templates](https://github.com/Natizyskunk/vscode-sftp/issues/new/choose) when you open a new issue or a new pull request.

## ℹ INFOS - 2025/03/13

I've tried to keep this extension up-to-date as much as I can and added a lot of new relevant features. Saddly, for the last year and a half I wasn't really able to work on the project because of personal reasons and I'm really not sure if and when I'll be able to get more time to work on it again. So for now consider the [v1.16.3](https://github.com/Natizyskunk/vscode-sftp/releases/tag/v1.16.3) as the latest official stable release available.

## ℹ INFOS - 2023/06/23

This is the main repository for the SFTP extension since [@liximomo](https://github.com/liximomo) has set his own to deprecated in favor of this one in the VSCode marketplace.
There are also other forks that are available. Feel free to try them.

A lot of work as been brought to fix bugs, add new features and more than 50 updates have been released with a lot of improvements and stability fixes for almost two years now. 😎

I've been working hard to fix a lot of things and I've updated more than 50 new releases with a lot of improvements and stability fixes and I've brought new features for almost three years now. 

---

## Table of Contents

- [Introduction](#introduction)
- [Documentation](#documentation)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example configurations](#example-configurations)
- [Remote Explorer](#remote-explorer)
- [Debug](#debug)
- [FAQ](#FAQ)
- [Contribution](#contribution)
- [Roadmap](#roadmap)
- [Changelog](#changelog)
- [Support](#support)
- [License](#license)
- [Donation](#donation)

## Introduction

VSCode-SFTP enables you to add, edit or delete files within a local directory and have it sync to a remote server directory using different transfer protocols like FTP or SSH. The most basic setup requires only a few lines of configuration with a wide array of specific settings also available to meet the needs of any user. Both powerful and fast, it helps developers save time by allowing the use of a familiar editor and environment.

## Documentation

- [Home](https://github.com/Natizyskunk/vscode-sftp/wiki)
- [Settings](https://github.com/Natizyskunk/vscode-sftp/wiki/Setting)
- [Common configuration](https://github.com/Natizyskunk/vscode-sftp/wiki/Common-Configuration)
- [SFTP configuration](https://github.com/Natizyskunk/vscode-sftp/wiki/SFTP-only-Configuration)
- [FTP(s) confriguration](https://github.com/Natizyskunk/vscode-sftp/wiki/FTP(s)-only-Configuration)
- [Commands](https://github.com/Natizyskunk/vscode-sftp/wiki/Commands)

## Current Features

- **[Browser remote with Remote Explorer](#remote-explorer)**: Explore remote directories within VSCode.
- **Diff Local and Remote**: Compare local and remote files.
- **Sync Directory**: Synchronize directories between local and remote.
- **Upload/Download**: Transfer files to and from the remote server.
- **Upload on Save**: Automatically upload files upon saving.
- **File Watcher**: Monitor files for changes and act accordingly.
- **Multiple Configurations**: Support for multiple configurations.
- **Switchable Profiles**: Easily switch between different server profiles.
- **Temp File Support**: Handle temporary files efficiently.

## Added Features

- **Enhanced Proxy Options**: Improved Proxy Support for SOCKS5 and HTTP.
- **UI Enhancements**: Settings GUI and more.
- **Enhanced File Sync**: Improved file synchronization capabilities with conflict resolution.
- **Customizable Upload/Download Rules**: Define specific rules for file transfer operations.
- **Performance Improvements**: Faster and more efficient file transfers.
- **Bug Fixes**: Addressed issues from the original repository and added stability enhancements.

For a complete list of features and detailed documentation, please visit our [wiki](https://github.com/Natizyskunk/vscode-sftp/wiki).

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

## Usage

If the latest files are already on a remote server, you can start with an empty local folder, then download your project, and from that point sync.

1. In `VS Code`, open a local directory you wish to sync to the remote server (or create an empty directory that you wish to first download the contents of a remote server folder in order to edit locally).
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
7. A good one to start with if you want to sync with a remote folder is `SFTP: Download Project`. This will download the directory shown in the `remotePath` setting in `sftp.json` to your local open directory.
8. Done - you can now edit locally and after each save it will upload to sync your remote file with the local copy.
9. Enjoy!

## Example configurations

You can see the full list of configuration options [here](https://github.com/Natizyskunk/vscode-sftp/wiki/configuration).

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

## Remote Explorer

![remote-explorer-preview](https://raw.githubusercontent.com/Natizyskunk/vscode-sftp/master/assets/showcase/remote-explorer.png)

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

You can see all the Frequently Asked Questions [here](./FAQ.md).

## Contribution

We welcome contributions from the community! Please read our [contribution guidelines](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes and ensure that the code passes all tests.
4. Submit a pull request to the `develop` branch with a clear description of your changes.

For more details on how to contribute, check out our [wiki](https://github.com/Natizyskunk/vscode-sftp/wiki).

## Roadmap

Coming soon! We are actively planning new features and improvements. Stay tuned for updates.

Proxy support is currently in progress and in testing on branch bradley.

Once testing is complete - To Do:

Update the documentation in README.md and docs/sftp_configuration.md to include information about the new proxy support features.

Add new test cases in the tests directory to cover the proxy functionality for SFTP connections.

Update the CHANGELOG.md file to reflect the addition of proxy support in the upcoming release.

Implement any necessary UI changes in the extension to allow users to input proxy settings through the VS Code interface.

Conduct thorough testing of the new proxy functionality across different scenarios and connection types.

For a detailed roadmap and progress updates, please visit our [wiki](https://github.com/Natizyskunk/vscode-sftp/wiki).

## Changelog

All notable changes to this project will be documented in the [CHANGELOG.md](CHANGELOG.md) file.

## Support

If you encounter any issues or have questions, please use the [GitHub Issues](https://github.com/Natizyskunk/vscode-sftp/issues) to report them.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Donation

If this project helped you reduce development time and you wish to contribute financially

### Buy Me a Coffee

[![Buy Me A Coffee](https://bmc-cdn.nyc3.digitaloceanspaces.com/BMC-button-images/custom_images/orange_img.png)](https://www.buymeacoffee.com/Natizyskunk)

### PayPal

<!-- [![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BY89QD47D7MPS&source=url) -->
[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/donate?business=DELD7APHHM3BC&no_recurring=0&currency_code=EUR)
[![PayPal Me](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/natanfourie)

---

Thank you for using VSCode-SFTP ! We look forward to your contributions and feedback. For more information and documentation, please visit our [wiki](https://github.com/Natizyskunk/vscode-sftp/wiki).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/github/v/release/Natizyskunk/vscode-sftp)](https://github.com/Natizyskunk/vscode-sftp/releases)
[![Issues](https://img.shields.io/github/issues/Natizyskunk/vscode-sftp)](https://github.com/Natizyskunk/vscode-sftp/issues)
[![Forks](https://img.shields.io/github/forks/Natizyskunk/vscode-sftp)](https://github.com/Natizyskunk/vscode-sftp/network/members)
[![Stars](https://img.shields.io/github/stars/Natizyskunk/vscode-sftp)](https://github.com/Natizyskunk/vscode-sftp/stargazers)
