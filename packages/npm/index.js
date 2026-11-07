'use strict';

// Nothing to export yet. Exists so `require('elira')` doesn't throw
// in code that checks for the module before the server lands.
module.exports = { version: require('./package.json').version };
