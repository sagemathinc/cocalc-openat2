const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { SandboxRoot } = require('../index.js');

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-test-'));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('basic mkdir/rename/unlink/stat', () => {
  withTempDir((dir) => {
    const sandbox = new SandboxRoot(dir);
    sandbox.mkdir('a/b', true);
    fs.writeFileSync(path.join(dir, 'a/b/file.txt'), 'hello');

    sandbox.copyFile('a/b/file.txt', 'a/b/copy.txt');
    sandbox.truncate('a/b/copy.txt', 2);
    assert.equal(fs.readFileSync(path.join(dir, 'a/b/copy.txt'), 'utf8'), 'he');

    sandbox.rename('a/b/file.txt', 'a/b/file2.txt');
    const stat = sandbox.stat('a/b/file2.txt');
    assert.equal(stat.size, 5);

    sandbox.link('a/b/file2.txt', 'a/b/hard.txt');
    assert.equal(fs.readFileSync(path.join(dir, 'a/b/hard.txt'), 'utf8'), 'hello');

    sandbox.unlink('a/b/file2.txt');
    assert.equal(fs.existsSync(path.join(dir, 'a/b/file2.txt')), false);
  });
});

test('renameNoReplace preserves destination and returns EEXIST', () => {
  withTempDir((dir) => {
    const sandbox = new SandboxRoot(dir);
    fs.writeFileSync(path.join(dir, 'a.txt'), 'a');
    fs.writeFileSync(path.join(dir, 'b.txt'), 'b');
    assert.throws(
      () => sandbox.renameNoReplace('a.txt', 'b.txt'),
      /EEXIST/,
    );
    assert.equal(fs.readFileSync(path.join(dir, 'a.txt'), 'utf8'), 'a');
    assert.equal(fs.readFileSync(path.join(dir, 'b.txt'), 'utf8'), 'b');
  });
});

test('symlink escape is denied', () => {
  withTempDir((dir) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-outside-'));
    try {
      fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
      fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(dir, 'escape-link'));
      const sandbox = new SandboxRoot(dir);

      assert.throws(() => sandbox.stat('escape-link'), /ELOOP|outside|Invalid/);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

test('rm recursive removes tree without escaping symlink targets', () => {
  withTempDir((dir) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-outside-rm-'));
    try {
      fs.mkdirSync(path.join(dir, 'tree', 'nested'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'tree', 'nested', 'x.txt'), 'x');
      fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
      fs.symlinkSync(path.join(outside), path.join(dir, 'tree', 'outside-link'));

      const sandbox = new SandboxRoot(dir);
      sandbox.rm('tree', true, false);

      assert.equal(fs.existsSync(path.join(dir, 'tree')), false);
      assert.equal(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8'), 'secret');
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});
