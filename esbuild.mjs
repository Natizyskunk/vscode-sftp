import esbuild from 'esbuild';

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

const ctx = await esbuild.context({
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'dist/extension.js',
  external: ['vscode', 'ssh2'],
  // jsonc-parser's CJS entry is a UMD wrapper whose inner require() calls
  // esbuild can't inline, so the bundle would fail to load at runtime;
  // bundle its ESM build instead
  alias: { 'jsonc-parser': 'jsonc-parser/lib/esm/main.js' },
  format: 'cjs',
  platform: 'node',
  // matches the minimum VS Code engine's extension-host runtime
  target: 'node16',
  sourcemap: !production,
  minify: production,
  logLevel: 'info',
});

if (watch) {
  await ctx.watch();
} else {
  await ctx.rebuild();
  await ctx.dispose();
}
