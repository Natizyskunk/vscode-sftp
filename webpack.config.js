//@ts-check

'use strict';

const path = require('path');
const webpack = require('webpack');

/**@type {import('webpack').Configuration}*/
const config = {
  target: 'node',

  entry: './src/extension.ts',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'extension.js',
    libraryTarget: 'commonjs2',
    devtoolModuleFilenameTemplate: '../[resource-path]',
  },
  devtool: 'source-map',
  // Only `vscode` is provided by the host. `ssh2` is bundled so the .vsix is
  // self-contained (no node_modules to ship). ssh2's optional native crypto
  // accelerator (cpu-features / *.node) is ignored — it falls back to pure JS.
  externals: {
    vscode: 'commonjs vscode',
  },
  plugins: [
    new webpack.IgnorePlugin({ resourceRegExp: /^cpu-features$/ }),
    new webpack.IgnorePlugin({ resourceRegExp: /\.node$/ }),
  ],
  resolve: {
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'ts-loader',
          },
        ],
      },
    ],
  },
};

module.exports = config;
