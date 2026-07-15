import { validateConfig } from '../config';

const base = { host: 'h', username: 'u', remotePath: '/r' };

describe('validateConfig — conflictCheck', () => {
  it('accepts the option', () => {
    expect(validateConfig({ ...base, conflictCheck: true })).toBeUndefined();
    expect(validateConfig({ ...base, conflictCheck: false })).toBeUndefined();
  });

  it('accepts a config that omits it', () => {
    expect(validateConfig(base)).toBeUndefined();
  });

  it('rejects a non-boolean', () => {
    expect(validateConfig({ ...base, conflictCheck: 'yes' })).toBeDefined();
  });
});
