import * as vscode from 'vscode';
import * as fse from 'fs-extra';
import * as path from 'path';
import * as Joi from 'joi';
import {
  parse as parseJsonc,
  parseTree,
  modify,
  applyEdits,
  printParseErrorCode,
  ParseError,
  JSONPath,
} from 'jsonc-parser';
import { CONFIG_PATH, COMMAND_MIGRATE_PASSWORD } from '../constants';
import logger from '../logger';
import { reportError } from '../helper';
import { showTextDocument, showWarningMessage, executeCommand } from '../host';

const nullable = schema => schema.optional().allow(null);

const configScheme = Joi.object({
  name: Joi.string(),

  context: Joi.string(),
  protocol: Joi.any().valid('sftp', 'ftp', 'local'),

  host: Joi.string().required(),
  port: Joi.number().integer(),
  connectTimeout: Joi.number().integer(),
  username: Joi.string().required(),
  password: nullable(Joi.string()),

  agent: nullable(Joi.string()),
  privateKeyPath: nullable(Joi.string()),
  passphrase: nullable(Joi.string().allow(true)),
  interactiveAuth: Joi.alternatives()
    .try(Joi.boolean(), Joi.array().items(Joi.string()))
    .optional(),
  algorithms: Joi.any(),
  sshConfigPath: Joi.string(),
  sshCustomParams: Joi.string(),

  secure: Joi.any().valid(true, false, 'control', 'implicit'),
  secureOptions: nullable(Joi.object()),
  passive: Joi.boolean(),

  remotePath: Joi.string().required(),
  uploadOnSave: Joi.boolean(),
  useTempFile: Joi.boolean(),
  openSsh: Joi.boolean(),
  downloadOnOpen: Joi.boolean().allow('confirm'),

  ignore: Joi.array()
    .min(0)
    .items(Joi.string()),
  ignoreFile: Joi.string(),
  watcher: {
    files: Joi.string().allow(false, null),
    autoUpload: Joi.boolean(),
    autoDelete: Joi.boolean(),
  },
  concurrency: Joi.number().integer(),

  syncOption: {
    delete: Joi.boolean(),
    skipCreate: Joi.boolean(),
    ignoreExisting: Joi.boolean(),
    update: Joi.boolean(),
  },
  syncConfirm: Joi.boolean(),
  conflictCheck: Joi.boolean(),
  remoteTimeOffsetInHours: Joi.number(),

  remoteExplorer: {
    filesExclude: Joi.array()
      .min(0)
      .items(Joi.string()),
    order: Joi.number(),
  },
});

const defaultConfig = {
  // common
  // name: undefined,
  remotePath: './',
  uploadOnSave: false,
  useTempFile: false,
  openSsh: false,
  downloadOnOpen: false,
  conflictCheck: false,
  ignore: [],
  // ignoreFile: undefined,
  // watcher: {
  //   files: false,
  //   autoUpload: false,
  //   autoDelete: false,
  // },
  concurrency: 4,
  // limitOpenFilesOnRemote: false

  protocol: 'sftp',

  // server common
  // host,
  // port,
  // username,
  // password,
  connectTimeout: 10 * 1000,

  // sftp
  // agent,
  // privateKeyPath,
  // passphrase,
  interactiveAuth: false,
  // algorithms,

  // ftp
  secure: false,
  // secureOptions,
  // passive: false,
  remoteTimeOffsetInHours: 0,

  remoteExplorer: {
    order: 0,
  },
};

function mergedDefault(config) {
  return {
    ...defaultConfig,
    ...config,
  };
}

export function getConfigPath(basePath) {
  return path.join(basePath, CONFIG_PATH);
}

export function validateConfig(config) {
  const { error } = configScheme.validate(config, {
    allowUnknown: true,
    convert: false,
  });
  return error;
}

const plaintextPasswordWarned = new Set<string>();

function hasPlaintextPassword(config): boolean {
  if (typeof config.password === 'string' && config.password.length > 0) {
    return true;
  }

  const profiles = config.profiles;
  return (
    !!profiles &&
    Object.keys(profiles).some(name => {
      const profile = profiles[name];
      return profile && typeof profile.password === 'string' && profile.password.length > 0;
    })
  );
}

function warnPlaintextPassword(configPath: string, configs: any[]) {
  if (plaintextPasswordWarned.has(configPath) || !configs.some(hasPlaintextPassword)) {
    return;
  }

  plaintextPasswordWarned.add(configPath);
  logger.warn(
    `A plaintext password was found in ${configPath}.` +
      ' Consider running the "SFTP: Migrate Plaintext Password" command' +
      " to move it into VS Code's secret storage instead."
  );

  showWarningMessage(
    `A plaintext password was found in ${configPath}.`,
    'Migrate Password'
  ).then(choice => {
    if (choice === 'Migrate Password') {
      executeCommand(COMMAND_MIGRATE_PASSWORD);
    }
  });
}

function offsetToLineColumn(text: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

// the config is read as JSONC, so comments and trailing commas are allowed
export async function readConfigsFromFile(configPath): Promise<any[]> {
  const content = await fse.readFile(configPath, 'utf8');
  const errors: ParseError[] = [];
  const config = parseJsonc(content, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  if (errors.length > 0) {
    const { error, offset } = errors[0];
    const { line, column } = offsetToLineColumn(content, offset);
    throw new Error(
      `Failed to parse ${configPath}: ${printParseErrorCode(error)} at line ${line}, column ${column}.`
    );
  }
  if (config === undefined) {
    throw new Error(`Failed to parse ${configPath}: the file is empty.`);
  }

  const configs = Array.isArray(config) ? config : [config];
  warnPlaintextPassword(configPath, configs);
  return configs.map(mergedDefault);
}

// Edits a single property in an sftp.json file without disturbing the
// surrounding comments or formatting (jsonc-parser rewrites only the edited
// span). Passing `value === undefined` removes the property. `keyPath` is the
// path within a config object (e.g. `['password']` or
// `['profiles', 'dev', 'password']`); when the file holds an array of configs,
// `matchConfig` selects which element to edit, defaulting to the first one when
// nothing matches (or no matcher is given).
async function editConfigProperty(
  configPath: string,
  keyPath: JSONPath,
  value: any,
  matchConfig?: (config: any) => boolean
): Promise<void> {
  const text = await fse.readFile(configPath, 'utf8');
  const root = parseTree(text, [], { allowTrailingComma: true });
  if (!root) {
    throw new Error(`Failed to parse ${configPath}.`);
  }

  let jsonPath: JSONPath = keyPath;
  if (root.type === 'array') {
    const configs = parseJsonc(text, [], { allowTrailingComma: true });
    let index = 0;
    if (matchConfig && Array.isArray(configs)) {
      const found = configs.findIndex(matchConfig);
      if (found >= 0) {
        index = found;
      }
    }
    jsonPath = [index, ...keyPath];
  }

  const edits = modify(text, jsonPath, value, {
    formattingOptions: { insertSpaces: true, tabSize: 4 },
  });
  const updated = applyEdits(text, edits);
  await fse.writeFile(configPath, updated, 'utf8');
}

// Writes a top-level option into an sftp.json file. See `editConfigProperty`.
export function writeConfigValue(
  configPath: string,
  key: string,
  value: any,
  matchConfig?: (config: any) => boolean
): Promise<void> {
  return editConfigProperty(configPath, [key], value, matchConfig);
}

// Removes a property from an sftp.json file. `keyPath` may point at a nested
// property (e.g. a profile's password). See `editConfigProperty`.
export function removeConfigValue(
  configPath: string,
  keyPath: JSONPath,
  matchConfig?: (config: any) => boolean
): Promise<void> {
  return editConfigProperty(configPath, keyPath, undefined, matchConfig);
}

// appends `entry` to a config's `ignore` array, skipping if it's already present
export async function addConfigIgnoreEntry(
  configPath: string,
  entry: string,
  matchConfig?: (config: any) => boolean
): Promise<boolean> {
  const text = await fse.readFile(configPath, 'utf8');
  const root = parseTree(text, [], { allowTrailingComma: true });
  if (!root) {
    throw new Error(`Failed to parse ${configPath}.`);
  }

  const configs = parseJsonc(text, [], { allowTrailingComma: true });
  const config = Array.isArray(configs)
    ? configs[matchConfig ? Math.max(configs.findIndex(matchConfig), 0) : 0]
    : configs;

  const existing: string[] = Array.isArray(config.ignore) ? config.ignore : [];
  if (existing.includes(entry)) {
    return false;
  }

  await writeConfigValue(configPath, 'ignore', [...existing, entry], matchConfig);
  return true;
}

export function tryLoadConfigs(workspace): Promise<any[]> {
  const configPath = getConfigPath(workspace);
  return fse.pathExists(configPath).then(
    exist => {
      if (exist) {
        return readConfigsFromFile(configPath);
      }
      return [];
    },
    _ => []
  );
}

// export function getConfig(activityPath: string) {
//   const config = configTrie.findPrefix(normalizePath(activityPath));
//   if (!config) {
//     throw new Error(`(${activityPath}) config file not found`);
//   }

//   return normalizeConfig(config);
// }

export function newConfig(basePath) {
  const configPath = getConfigPath(basePath);

  return fse
    .pathExists(configPath)
    .then(exist => {
      if (exist) {
        return showTextDocument(vscode.Uri.file(configPath));
      }

      return fse
        .outputJson(
          configPath,
          {
            name: 'My Server',
            host: 'localhost',
            protocol: 'sftp',
            port: 22,
            username: 'username',
            remotePath: '/',
            uploadOnSave: false,
            useTempFile: false,
            openSsh: false,
          },
          { spaces: 4 }
        )
        .then(() => showTextDocument(vscode.Uri.file(configPath)));
    })
    .catch(reportError);
}
