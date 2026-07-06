const Joi = require('joi');

const nullable = schema => schema.optional().allow(null);

const configScheme = Joi.object({
  context: Joi.string(),
  protocol: Joi.any().valid('sftp', 'ftp', 'test'),

  host: Joi.string().required(),
  port: Joi.number().integer(),
  username: Joi.string().required(),
  password: nullable(Joi.string()),

  agent: nullable(Joi.string()),
  privateKeyPath: nullable(Joi.string()),
  passphrase: nullable(Joi.string().allow(true)),
  interactiveAuth: Joi.alternatives()
    .try(Joi.boolean(), Joi.array().items(Joi.string()))
    .optional(),

  secure: Joi.any().valid(true, false, 'control', 'implicit').optional(),
  secureOptions: nullable(Joi.object()),
  passive: Joi.boolean().optional(),

  remotePath: Joi.string().required(),
  uploadOnSave: Joi.boolean().optional(),
  useTempFile: Joi.boolean().optional(),
  openSsh: Joi.boolean().optional(),
  syncMode: Joi.any().valid('update', 'full'),
  ignore: Joi.array()
    .min(0)
    .items(Joi.string()),
  watcher: {
    files: Joi.string()
      .allow(false, null)
      .optional(),
    autoUpload: Joi.boolean().optional(),
    autoDelete: Joi.boolean().optional(),
  },
});

// joi >=16 returns `error: undefined` (not null) when a value is valid.
const validate = config => configScheme.validate(config, { convert: false });

describe("validation config", () => {
  test("default config", () => {
    const config = {
      host: 'host',
      port: 22,
      username: 'username',
      password: null,
      protocol: 'sftp',
      agent: null,
      privateKeyPath: null,
      passive: false,
      interactiveAuth: false,

      remotePath: '/',
      uploadOnSave: false,

      useTempFile: false,
      openSsh: false,

      syncMode: 'update',

      watcher: {
        files: false,
        autoUpload: false,
        autoDelete: false,
      },

      ignore: [
        '**/.vscode',
        '**/.git',
        '**/.DS_Store',
      ],
    };

    expect(validate(config).error).toBeUndefined();
  });

  test("partial config", () => {
    const config = {
      host: 'host',
      port: 22,
      username: 'username',
      protocol: 'sftp',

      remotePath: '/',

      syncMode: 'update',

      watcher: {},

      ignore: [
        '**/.vscode',
        '**/.git',
        '**/.DS_Store',
      ],
    };

    expect(validate(config).error).toBeUndefined();

    delete config.watcher;
    expect(validate(config).error).toBeUndefined();
  });

  describe("key validaiton", () => {
    test("protocol must be one of ['sftp', 'ftp']", () => {
      const config = {
        host: 'host',
        port: 22,
        username: 'username',
        protocol: 'unknown',
        passive: false,
        interactiveAuth: false,

        remotePath: '/',
        uploadOnSave: false,

        useTempFile: false,
        openSsh: false,

        syncMode: 'update',

        watcher: {
          files: false,
          autoUpload: false,
          autoDelete: false,
        },

        ignore: [
          '**/.vscode',
          '**/.git',
          '**/.DS_Store',
        ],
      };

      expect(validate(config).error).toBeDefined();
    });

    test("watcher files must be false or string", () => {
      const config = {
        host: 'host',
        port: 22,
        username: 'username',
        protocol: 'sftp',
        passive: false,
        interactiveAuth: false,

        remotePath: '/',
        uploadOnSave: false,

        useTempFile: false,
        openSsh: false,

        syncMode: 'update',

        watcher: {
          files: false,
          autoUpload: false,
          autoDelete: false,
        },

        ignore: [
          '**/.vscode',
          '**/.git',
          '**/.DS_Store',
        ],
      };

      expect(validate(config).error).toBeUndefined();

      config.watcher.files = '**/*.js';
      expect(validate(config).error).toBeUndefined();

      config.watcher.files = null;
      expect(validate(config).error).toBeUndefined();

      config.watcher.files = true;
      expect(validate(config).error).toBeDefined();

      delete config.watcher;
      expect(validate(config).error).toBeUndefined();
    });

    test("ignore must be an array of string", () => {
      const config = {
        host: 'host',
        port: 22,
        username: 'username',
        protocol: 'sftp',
        passive: false,
        interactiveAuth: false,

        remotePath: '/',
        uploadOnSave: false,

        useTempFile: false,
        openSsh: false,

        syncMode: 'update',

        watcher: {
          files: false,
          autoUpload: false,
          autoDelete: false,
        },

        ignore: [
          1,
          '**/.git',
          '**/.DS_Store',
        ],
      };

      expect(validate(config).error).toBeDefined();

      config.ignore = [];
      expect(validate(config).error).toBeUndefined();
    });

    test("pass", () => {
      const config = {
        host: 'host',
        port: 22,
        username: 'username',
        protocol: 'sftp',
        passive: false,
        interactiveAuth: false,
        passphrase: 'true',

        remotePath: '/',
        uploadOnSave: false,

        useTempFile: false,
        openSsh: false,

        syncMode: 'update',

        watcher: {
          files: false,
          autoUpload: false,
          autoDelete: false,
        },

        ignore: [
          '**/.git',
          '**/.DS_Store',
        ],
      };

      expect(validate(config).error).toBeUndefined();

      config.passphrase = false;
      expect(validate(config).error).toBeDefined();
    });
  });
});
