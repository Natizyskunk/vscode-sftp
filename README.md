# sftp+ sync Extension for VS Code

New maintained and updated version by [@thebestbradley](https://github.com/thebestbradley/) and [@zekeduncan](https://github.com/zekeduncan)<br>
(Forked from the no longer maintained [Natizyskunk SFTP plugin](https://github.com/Natizyskunk/vscode-sftp.git))

<!-- - VS Code marketplace : https://marketplace.visualstudio.com/items?itemName=Natizyskunk.sftp <br>
- VSIX release : https://github.com/Natizyskunk/vscode-sftp/releases/ -->

<hr>

# SFTP+ Sync

Welcome to the SFTP+ Sync repository! This is a fork of the actively maintained [SFTP extension](https://github.com/Natizyskunk/vscode-sftp) by [@Natizyskunk](https://github.com/Natizyskunk) and [@satiromarra](https://github.com/satiromarra). Our goal is to enhance and add new features while maintaining compatibility with the original project. We will push our improvements back to the original repo when they are ready and beneficial to the broader community. [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contribution](#contribution)
- [Roadmap](#roadmap)
- [Changelog](#changelog)
- [Support](#support)
- [License](#license)

## Introduction

SFTP+ Sync is an extension for Visual Studio Code that allows you to upload and download files from your remote servers. This fork aims to provide additional functionality and improvements over the original extension. [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki)

## Current Features

- **Browser Remote with Remote Explorer**: Explore remote directories within VSCode.
- **Diff Local and Remote**: Compare local and remote files.
- **Sync Directory**: Synchronize directories between local and remote.
- **Upload/Download**: Transfer files to and from the remote server.
- **Upload on Save**: Automatically upload files upon saving.
- **File Watcher**: Monitor files for changes and act accordingly.
- **Multiple Configurations**: Support for multiple configurations.
- **Switchable Profiles**: Easily switch between different server profiles.
- **Temp File Support**: Handle temporary files efficiently.
- **Enhanced File Sync**: Improved file synchronization capabilities with conflict resolution.
- **Customizable Upload/Download Rules**: Define specific rules for file transfer operations.
- **Performance Improvements**: Faster and more efficient file transfers.
- **Bug Fixes**: Addressed issues from the original repository and added stability enhancements.

### Added Features

- **Enhanced Proxy Options**: Improved Proxy Support for SOCKS5 and HTTP.
- **UI Enhancements**: Settings GUI and more.
- **Enhanced File Sync**: Improved file synchronization capabilities with conflict resolution.
- **Customizable Upload/Download Rules**: Define specific rules for file transfer operations.
- **Performance Improvements**: Faster and more efficient file transfers.
- **Bug Fixes**: Addressed issues from the original repository and added stability enhancements.

For a complete list of features and detailed documentation, please visit our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

## Extension Installation

### Method 1 (Manual Installation)

1. Download the latest VSIX file from the [Releases](https://github.com/thebestbradley/vscode-sftp-plus/releases) page.
2. Open Visual Studio Code.
3. Go to the Extensions view by clicking on the Extensions icon in the Activity Bar on the side of the window.
4. Click the ellipsis icon (More Actions) on the top right and select "Install from VSIX…".
5. Locate the downloaded VSIX file and select it.
6. Reload Visual Studio Code.

For more detailed installation instructions and troubleshooting, please refer to our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

### Method 2 (VS Code Extension Marketplace Installation)

We will add this extension to the VS Code Marketplace in the near future once we have a stable and feature-rich extension to do so.

For more detailed installation instructions and troubleshooting, please refer to our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

## Quick Configuration

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

For detailed explanations please go to [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

## Contribution

We welcome contributions from the community! Please read our [contribution guidelines](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes and ensure that the code passes all tests.
4. Submit a pull request to the `develop` branch with a clear description of your changes.

For more details on how to contribute, check out our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

## Roadmap

Coming soon! We are actively planning new features and improvements. Stay tuned for updates.

Proxy support is currently in progress and in testing on branch bradley.

Once testing is complete - To Do:

Update the documentation in README.md and docs/sftp_configuration.md to include information about the new proxy support features.

Add new test cases in the tests directory to cover the proxy functionality for SFTP connections.

Update the CHANGELOG.md file to reflect the addition of proxy support in the upcoming release.

Implement any necessary UI changes in the extension to allow users to input proxy settings through the VS Code interface.

Conduct thorough testing of the new proxy functionality across different scenarios and connection types.

For a detailed roadmap and progress updates, please visit our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

## Changelog

All notable changes to this project will be documented in the [CHANGELOG.md](CHANGELOG.md) file.

## Support

If you encounter any issues or have questions, please use the [GitHub Issues](https://github.com/thebestbradley/vscode-sftp-plus/issues) to report them.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Thank you for using SFTP+ Sync! We look forward to your contributions and feedback. For more information and documentation, please visit our [wiki](https://github.com/thebestbradley/vscode-sftp-plus/wiki).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/github/v/release/thebestbradley/vscode-sftp-plus)](https://github.com/thebestbradley/vscode-sftp-plus/releases)
[![Issues](https://img.shields.io/github/issues/thebestbradley/vscode-sftp-plus)](https://github.com/thebestbradley/vscode-sftp-plus/issues)
[![Forks](https://img.shields.io/github/forks/thebestbradley/vscode-sftp-plus)](https://github.com/thebestbradley/vscode-sftp-plus/network/members)
[![Stars](https://img.shields.io/github/stars/thebestbradley/vscode-sftp-plus)](https://github.com/thebestbradley/vscode-sftp-plus/stargazers)
