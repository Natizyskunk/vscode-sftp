const tsc = require('typescript');

// Jest 28+ requires transformer.process() to return { code: string }, not just a string
module.exports = {
  process(src, path) {
    if (path.endsWith('.ts')) {
      const compilerOptions = {
        module: tsc.ModuleKind.CommonJS,
        target: tsc.ScriptTarget.ES2020,
        esModuleInterop: true,
        strict: false,
        noUnusedLocals: false,
        strictNullChecks: true,
      };
      const result = tsc.transpileModule(src, {
        compilerOptions,
        fileName: path,
      });
      return { code: result.outputText };
    }
    return { code: src };
  },
};
