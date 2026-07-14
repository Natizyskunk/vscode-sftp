// Integration-only jest config. Kept separate from the unit config in
// package.json so `npm test` never touches Docker: it only matches
// test/**/*.spec.js + src/**/__tests__/*.ts, none of which live here
// (the integration specs are test/integration/**/*.spec.ts).
//
// Run with: npm run test:integration  (requires the compose stack to be up).
module.exports = {
  rootDir: '../..',
  moduleFileExtensions: ['ts', 'js'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  testMatch: ['<rootDir>/test/integration/**/*.spec.ts'],
  // `vscode` isn't installed as a package; the transitive logger import needs
  // it stubbed, exactly like the unit suite does via the same manual mock.
  moduleNameMapper: {
    '^vscode$': '<rootDir>/__mocks__/vscode.js',
  },
  // Real network + TLS + a few-MB transfer: generous per-test budget.
  testTimeout: 60000,
  // FTP servers are shared mutable state; run specs serially.
  maxWorkers: 1,
};
