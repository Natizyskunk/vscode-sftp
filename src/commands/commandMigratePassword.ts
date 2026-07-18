import { JSONPath } from 'jsonc-parser';
import { window } from 'vscode';
import { COMMAND_MIGRATE_PASSWORD } from '../constants';
import { showConfirmMessage, showErrorMessage, showInformationMessage } from '../host';
import { connectionToken, storePassword, ConnectIdentity } from '../credentialStore';
import { getConfigPath, removeConfigValue } from '../modules/config';
import { getAllFileService } from '../modules/serviceManager';
import { checkCommand } from './abstract/createCommand';

// a plaintext password sitting in an sftp.json config (or one of its profiles)
// that can be moved into secret storage
interface PlaintextEntry {
  label: string;
  identity: ConnectIdentity;
  password: string;
  configPath: string;
  keyPath: JSONPath;
  matchConfig: (config: any) => boolean;
}

function identityFrom(config: any): ConnectIdentity {
  return {
    protocol: config.protocol,
    host: config.host,
    port: config.port,
    username: config.username,
  };
}

// picks out the array element in an sftp.json that belongs to `raw`, so a
// multi-config file gets the right entry edited (mirrors the matcher used by
// the Toggle Upload on Save command)
function matchServiceConfig(raw: any) {
  return (config: any) =>
    config.host === raw.host &&
    (raw.name === undefined || config.name === raw.name) &&
    (raw.context === undefined || config.context === raw.context);
}

// scan every configured remote (and its profiles) for a plaintext `password`
function collectPlaintextEntries(): PlaintextEntry[] {
  const entries: PlaintextEntry[] = [];
  for (const service of getAllFileService()) {
    const raw: any = service.getRawConfig();
    const configPath = getConfigPath(service.workspace);
    const matchConfig = matchServiceConfig(raw);

    if (typeof raw.password === 'string' && raw.password.length > 0) {
      const identity = identityFrom(raw);
      entries.push({
        label: connectionToken(identity),
        identity,
        password: raw.password,
        configPath,
        keyPath: ['password'],
        matchConfig,
      });
    }

    const profiles = raw.profiles;
    if (profiles) {
      for (const name of Object.keys(profiles)) {
        const profile = profiles[name];
        if (profile && typeof profile.password === 'string' && profile.password.length > 0) {
          const identity = identityFrom({ ...raw, ...profile });
          entries.push({
            label: `${connectionToken(identity)} (profile: ${name})`,
            identity,
            password: profile.password,
            configPath,
            keyPath: ['profiles', name, 'password'],
            matchConfig,
          });
        }
      }
    }
  }
  return entries;
}

async function selectPlaintextEntry(): Promise<PlaintextEntry | undefined> {
  const entries = collectPlaintextEntries();
  if (entries.length <= 0) {
    showInformationMessage('No plaintext password found in sftp.json.');
    return;
  }

  if (entries.length === 1) {
    return entries[0];
  }

  const picked = await window.showQuickPick(
    entries.map(entry => ({ label: entry.label, entry })),
    { placeHolder: 'Select a plaintext password to migrate...' }
  );
  return picked ? picked.entry : undefined;
}

export default checkCommand({
  id: COMMAND_MIGRATE_PASSWORD,

  async handleCommand() {
    const entry = await selectPlaintextEntry();
    if (!entry) {
      return;
    }

    const confirmed = await showConfirmMessage(
      `Move the plaintext password for ${entry.label} into VS Code's secret storage` +
        ' and remove it from sftp.json?',
      'Migrate',
      'Cancel'
    );
    if (!confirmed) {
      return;
    }

    try {
      await storePassword(entry.identity, entry.password);
    } catch (error) {
      showErrorMessage(`Failed to save password to secret storage: ${error.message}`);
      return;
    }

    try {
      await removeConfigValue(entry.configPath, entry.keyPath, entry.matchConfig);
    } catch (error) {
      showErrorMessage(
        `Password saved to secret storage, but failed to remove it from ${entry.configPath}: ${error.message}`
      );
      return;
    }

    showInformationMessage(
      `Password for ${entry.label} moved to secret storage and removed from sftp.json.`
    );
  },
});
