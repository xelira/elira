#!/usr/bin/env node
'use strict';

const pkg = require('../package.json');
const args = process.argv.slice(2);

if (args.includes('-v') || args.includes('--version')) {
  console.log(pkg.version);
  process.exit(0);
}

console.error('elira: nothing to run yet.');
console.error('The name is reserved; the server is coming. https://github.com/xelira/elira');
process.exit(1);
