#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const args = process.argv.slice(2);

function realpath(file) {
  try {
    return fs.realpathSync(file);
  } catch {
    return file;
  }
}

const self = realpath(__filename);

function isExecutable(file) {
  try {
    if (!fs.statSync(file).isFile()) return false;
    if (process.platform !== 'win32') {
      fs.accessSync(file, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function fromEnv() {
  const file = process.env.ELIRA_BIN;
  if (!file) return null;
  if (!isExecutable(file)) {
    fail(`elira: ELIRA_BIN is set to "${file}", but that is not an executable file.`);
  }
  if (realpath(file) === self) {
    fail('elira: ELIRA_BIN points at the launcher itself.');
  }
  return file;
}

// Platform packages, when published, expose the native binary as
// @elira/<platform>-<arch>.
function fromPackage() {
  const name = `@elira/${process.platform}-${process.arch}`;
  const exe = process.platform === 'win32' ? 'elira.exe' : 'elira';

  let dir;
  try {
    dir = path.dirname(require.resolve(`${name}/package.json`));
  } catch {
    return null;
  }

  const candidates = [];
  try {
    const meta = require(path.join(dir, 'package.json'));
    const bin = typeof meta.bin === 'string' ? meta.bin : meta.bin && meta.bin.elira;
    if (bin) candidates.push(path.resolve(dir, bin));
  } catch {
    // A broken package.json is treated as a package without a binary.
  }
  candidates.push(path.join(dir, 'bin', exe), path.join(dir, exe));

  for (const candidate of candidates) {
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

function fromPath() {
  // npm's shims are named elira and elira.cmd on Windows; looking for
  // elira.exe avoids finding the shim and starting the launcher again.
  const exe = process.platform === 'win32' ? 'elira.exe' : 'elira';
  const dirs = (process.env.PATH || '').split(path.delimiter);

  for (const dir of dirs) {
    if (!dir) continue;
    const candidate = path.join(dir, exe);
    if (!isExecutable(candidate)) continue;
    if (realpath(candidate) === self) continue;
    return candidate;
  }
  return null;
}

const binary = fromEnv() || fromPackage() || fromPath();

if (!binary) {
  fail(
    [
      'elira: no elira binary found.',
      '',
      'The npm package contains the launcher; the server itself is a native executable.',
      '',
      'Install one of:',
      '',
      '  Docker:   build the image from https://github.com/xelira/elira/blob/main/Dockerfile',
      '  Cargo:    cargo install --git https://github.com/xelira/elira elira',
      '  Releases: https://github.com/xelira/elira/releases',
      '',
      'Or set ELIRA_BIN to the path of an existing binary.',
    ].join('\n')
  );
}

const result = spawnSync(binary, args, { stdio: 'inherit' });

if (result.error) {
  fail(`elira: cannot run ${binary}: ${result.error.message}`);
}

if (result.signal) {
  const signal = os.constants.signals[result.signal];
  process.exit(signal ? 128 + signal : 1);
}

process.exit(result.status === null ? 1 : result.status);
