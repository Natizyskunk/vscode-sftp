import * as vscode from 'vscode';
import * as fse from 'fs-extra';
import * as path from 'path';
import app from '../app';
import { COMMAND_TEST_CONNECTION } from '../constants';
import { replaceHomePath, reportError } from '../helper';
import { executeCommand, showErrorMessage, showTextDocument } from '../host';
import { getConfigPath, readConfigsFromFile, validateConfig } from './config';
import { createFileService, disposeFileService, findAllFileService } from './serviceManager';

const AUTH_PASSWORD = 'Password';
const AUTH_PRIVATE_KEY = 'Private Key';
const AUTH_AGENT = 'SSH Agent';

async function pickProtocol(): Promise<'sftp' | 'ftp' | undefined> {
  const picked = await vscode.window.showQuickPick(
    [
      { label: 'sftp', description: 'SSH File Transfer Protocol (default port 22)' },
      { label: 'ftp', description: 'File Transfer Protocol (default port 21)' },
    ],
    { placeHolder: 'Select the transfer protocol', ignoreFocusOut: true }
  );
  return picked && (picked.label as 'sftp' | 'ftp');
}

function inputHost() {
  return vscode.window.showInputBox({
    prompt: 'Host',
    placeHolder: 'example.com',
    ignoreFocusOut: true,
    validateInput: value => (value.trim() ? undefined : 'Host is required.'),
  });
}

async function inputPort(defaultPort: number): Promise<number | undefined> {
  const port = await vscode.window.showInputBox({
    prompt: 'Port',
    value: String(defaultPort),
    ignoreFocusOut: true,
    validateInput: value => {
      const num = Number(value.trim());
      return Number.isInteger(num) && num >= 1 && num <= 65535
        ? undefined
        : 'Port must be an integer between 1 and 65535.';
    },
  });
  return port !== undefined ? Number(port.trim()) : undefined;
}

function inputUsername() {
  return vscode.window.showInputBox({
    prompt: 'Username',
    ignoreFocusOut: true,
    validateInput: value => (value.trim() ? undefined : 'Username is required.'),
  });
}

function inputPrivateKeyPath(basePath: string) {
  return vscode.window.showInputBox({
    prompt: 'Private key path ("~" points to your home folder)',
    value: '~/.ssh/id_rsa',
    ignoreFocusOut: true,
    validateInput: value => {
      if (!value.trim()) {
        return 'Private key path is required.';
      }
      const keyPath = path.resolve(basePath, replaceHomePath(value.trim()));
      return fse.existsSync(keyPath) ? undefined : `No file found at ${keyPath}.`;
    },
  });
}

function inputAgent() {
  return vscode.window.showInputBox({
    prompt: 'SSH agent socket ("$VARNAME" reads from an environment variable)',
    value: process.platform === 'win32' ? 'pageant' : '$SSH_AUTH_SOCK',
    ignoreFocusOut: true,
    validateInput: value => (value.trim() ? undefined : 'Agent is required.'),
  });
}

function inputRemotePath() {
  return vscode.window.showInputBox({
    prompt: 'Remote path to sync with this folder',
    value: '/',
    ignoreFocusOut: true,
    validateInput: value => (value.trim() ? undefined : 'Remote path is required.'),
  });
}

async function pickUploadOnSave(): Promise<boolean | undefined> {
  const picked = await vscode.window.showQuickPick(
    [
      { label: 'No', description: 'Upload files manually', value: false },
      { label: 'Yes', description: 'Upload a file every time it is saved', value: true },
    ],
    { placeHolder: 'Upload files automatically on save?', ignoreFocusOut: true }
  );
  return picked && picked.value;
}

// Collect connection settings step by step. Returns undefined if the user
// dismisses any step, which cancels the whole wizard.
async function collectConfig(basePath: string): Promise<object | undefined> {
  const protocol = await pickProtocol();
  if (protocol === undefined) return;

  const host = await inputHost();
  if (host === undefined) return;

  const port = await inputPort(protocol === 'sftp' ? 22 : 21);
  if (port === undefined) return;

  const username = await inputUsername();
  if (username === undefined) return;

  const config: any = {
    name: 'My Server',
    protocol,
    host: host.trim(),
    port,
    username: username.trim(),
  };

  if (protocol === 'sftp') {
    const authMethod = await vscode.window.showQuickPick(
      [
        { label: AUTH_PASSWORD, description: 'Prompt for the password when connecting' },
        { label: AUTH_PRIVATE_KEY, description: 'Authenticate with a private key file' },
        { label: AUTH_AGENT, description: 'Authenticate through a running ssh-agent' },
      ],
      { placeHolder: 'Select an authentication method', ignoreFocusOut: true }
    );
    if (authMethod === undefined) return;

    // Password needs no config: with no credential keys set, the extension
    // prompts at connect time and offers to save it in secret storage.
    if (authMethod.label === AUTH_PRIVATE_KEY) {
      const privateKeyPath = await inputPrivateKeyPath(basePath);
      if (privateKeyPath === undefined) return;
      config.privateKeyPath = path.resolve(basePath, replaceHomePath(privateKeyPath.trim()));
    } else if (authMethod.label === AUTH_AGENT) {
      const agent = await inputAgent();
      if (agent === undefined) return;
      config.agent = agent.trim();
    }
  }

  const remotePath = await inputRemotePath();
  if (remotePath === undefined) return;
  config.remotePath = remotePath.trim();

  const uploadOnSave = await pickUploadOnSave();
  if (uploadOnSave === undefined) return;
  config.uploadOnSave = uploadOnSave;

  return config;
}

// The file services are normally (re)created when sftp.json is saved from the
// editor. The wizard writes the file directly, so recreate them here to make
// the config usable (and testable) right away.
async function reloadFileServices(basePath: string, configPath: string) {
  findAllFileService(service => service.workspace === basePath).forEach(disposeFileService);

  const configs = await readConfigsFromFile(configPath);
  configs.forEach(config => createFileService(config, basePath));

  if (app.remoteExplorer) {
    app.remoteExplorer.refresh();
  }
}

export async function quickSetupConfig(basePath: string) {
  try {
    const config = await collectConfig(basePath);
    if (config === undefined) {
      return;
    }

    const validationError = validateConfig(config);
    if (validationError) {
      showErrorMessage(`Config is invalid: ${validationError.message}`);
      return;
    }

    const configPath = getConfigPath(basePath);
    await fse.outputJson(configPath, config, { spaces: 4 });
    await reloadFileServices(basePath, configPath);
    await showTextDocument(vscode.Uri.file(configPath));
    await executeCommand(COMMAND_TEST_CONNECTION, vscode.Uri.file(configPath));
  } catch (error) {
    reportError(error);
  }
}
