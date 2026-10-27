const tsc = require('typescript');
const tsConfig = require('../tsconfig.json');

module.exports = {
  process(src, path) {
    if (path.endsWith('.ts')) {
      return { code: tsc.transpile(src, tsConfig.compilerOptions, path, []) };
    }
    return { code: src };
  },
};
