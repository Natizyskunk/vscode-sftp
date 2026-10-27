const { fs } = require('memfs');

// memfs ignores `autoClose: false` once Node destroys the stream after 'finish'
// (autoDestroy), closing an fd the caller still owns. Node's fs ties the two.
const createWriteStream = fs.createWriteStream;
fs.createWriteStream = function(path, options) {
  if (options && typeof options === 'object' && options.autoClose === false && options.autoDestroy === undefined) {
    options = Object.assign({}, options, { autoDestroy: false });
  }
  return createWriteStream.call(this, path, options);
};

// fs-extra expects the native variants to exist
fs.realpath.native = fs.realpath;
fs.realpathSync.native = fs.realpathSync;

fs.__mock__ = true;
module.exports = fs;
