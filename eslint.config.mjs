import tseslint from 'typescript-eslint';

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    rules: {
      // "smart" allows the legacy `== null` idiom used throughout
      eqeqeq: ['error', 'smart'],
      curly: ['error', 'multi-line'],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { args: 'none', caughtErrors: 'none', varsIgnorePattern: '^_' },
      ],
      // permits `import x = require('y')` for callable CommonJS exports (e.g. lru-cache@4)
      '@typescript-eslint/no-require-imports': ['error', { allowAsImport: true }],
      // Legacy-codebase relaxations; tighten these as the code gets typed properly.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-this-alias': 'off',
      'prefer-rest-params': 'off',
    },
  },
  {
    files: ['test/**', '__mocks__/**'],
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    ignores: ['dist/**', 'out/**', 'node_modules/**', '_debug/**'],
  }
);
