# CCD SFTP for VS Code

Reliable SFTP/FTP sync for VS Code, maintained by CCD.

This extension helps you edit files locally and keep them in sync with remote servers over SFTP or FTP, with support for profiles, remote explorer operations, diffing, and folder/project sync workflows.

## Project Status

This repository is the actively maintained continuation of the long-running VS Code SFTP plugin line.

Current active fork and maintenance owner:
- CCD: https://github.com/ChrisCurdDesign/vscode-sftp

Lineage (for continuity):
- Kreare fork: https://github.com/Kreare/vscode-sftp
- Natizyskunk fork: https://github.com/Natizyskunk/vscode-sftp
- Original upstream: https://github.com/liximomo/vscode-sftp

## Install

- VS Code Marketplace: https://marketplace.visualstudio.com/items?itemName=CCD-Studios.ccd-sftp
- Source repository: https://github.com/ChrisCurdDesign/vscode-sftp
- Issues and bug reports: https://github.com/ChrisCurdDesign/vscode-sftp/issues

## What You Can Do

- Upload/download files, folders, or full projects
- Sync local to remote, remote to local, or both directions
- Diff local files against remote versions
- Browse remote files in the SFTP Activity Bar view
- Use multiple profiles and switch between them
- Upload changed files from Git changes
- Watch files and auto-upload/delete
- Open SSH sessions in the integrated terminal

## Quick Start

1. Open your local project folder in VS Code.
2. Run `SFTP: Config` from the Command Palette.
3. Edit `.vscode/sftp.json` with your server details.
4. Run `SFTP: Download Project` if you want to pull remote files first.
5. Start editing and run upload/sync commands as needed.

Minimal example (`.vscode/sftp.json`):

```json
{
  "name": "My Server",
  "host": "example.com",
  "protocol": "sftp",
  "port": 22,
  "username": "deploy",
  "remotePath": "/var/www/project",
  "uploadOnSave": false
}
```

Notes:
- `password` is optional. If omitted, you will be prompted.
- SFTP is the default protocol.
- `uploadOnSave` defaults to `false`.

## Common Commands

- `SFTP: Config`
- `SFTP: Set Profile`
- `SFTP: Upload Active File`
- `SFTP: Upload Changed Files`
- `SFTP: Download Active File`
- `SFTP: Download Project`
- `SFTP: Sync Local -> Remote`
- `SFTP: Sync Remote -> Local`
- `SFTP: Sync Both Directions`
- `SFTP: Diff with Remote`
- `SFTP: List Active Folder`
- `SFTP: Cancel All Transfers`
- `SFTP: Open SSH in Terminal`
- `SFTP: Delete Remote File`
- `SFTP: Delete Local and Remote File`

## Multiple Profiles Example

```json
{
  "username": "deploy",
  "remotePath": "/remote/workspace",
  "profiles": {
    "dev": {
      "host": "dev.example.com",
      "remotePath": "/var/www/dev",
      "uploadOnSave": true
    },
    "prod": {
      "host": "prod.example.com",
      "remotePath": "/var/www/prod"
    }
  },
  "defaultProfile": "dev"
}
```

Switch profiles with `SFTP: Set Profile`.

## Documentation

1. [Settings](./docs/settings.md)
2. [Config](./docs/configuration.md)
    - [Common](./docs/common_configuration.md)
    - [SFTP](./docs/sftp_configuration.md)
    - [FTP(s)](./docs/ftp_configuration.md)
3. [Commands](./docs/commands.md)
4. [FAQ](./docs/../FAQ.md)


## Debugging

To enable extension debug logs:
1. Open VS Code Settings.
2. Set `sftp.debug` to `true`.
3. Reload VS Code.
4. Open `View -> Output` and select `SFTP`.

## Contributing

Contributions are welcome.

- Please open issues for bugs and feature requests.
- For pull requests, include clear reproduction steps or rationale.
- See contribution guidelines: ./CONTRIBUTING.md

## License

MIT. See ./LICENSE.

### Buy Me a Coffee
[![Buy Me A Coffee](https://bmc-cdn.nyc3.digitaloceanspaces.com/BMC-button-images/custom_images/orange_img.png)](https://buymeacoffee.com/benbeckford)
