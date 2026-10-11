const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { SandboxRoot } = require('../index.js');

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-test-'));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function withTempDirAsync(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-test-'));
  try {
    await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('basic mkdir/rename/unlink/stat', async () => {
  await withTempDirAsync(async (dir) => {
    const sandbox = new SandboxRoot(dir);
    sandbox.mkdir('a/b', true);
    fs.writeFileSync(path.join(dir, 'a/b/file.txt'), 'hello');

    await sandbox.copyFile('a/b/file.txt', 'a/b/copy.txt');
    sandbox.truncate('a/b/copy.txt', 2);
    assert.equal(fs.readFileSync(path.join(dir, 'a/b/copy.txt'), 'utf8'), 'he');

    sandbox.rename('a/b/file.txt', 'a/b/file2.txt');
    const stat = sandbox.stat('a/b/file2.txt');
    assert.equal(stat.size, 5);

    sandbox.link('a/b/file2.txt', 'a/b/hard.txt');
    assert.equal(fs.readFileSync(path.join(dir, 'a/b/hard.txt'), 'utf8'), 'hello');
    sandbox.symlink('hard.txt', 'a/b/sym.txt');
    assert.equal(fs.readFileSync(path.join(dir, 'a/b/sym.txt'), 'utf8'), 'hello');

    sandbox.unlink('a/b/file2.txt');
    assert.equal(fs.existsSync(path.join(dir, 'a/b/file2.txt')), false);
  });
});

test('openRead/openWrite expose safe anchored file descriptors', () => {
  withTempDir((dir) => {
    const sandbox = new SandboxRoot(dir);

    const fdWrite1 = sandbox.openWrite('io.txt', true, true, false, 0o644);
    try {
      fs.writeFileSync(fdWrite1, 'one');
    } finally {
      fs.closeSync(fdWrite1);
    }

    const fdWrite2 = sandbox.openWrite('io.txt', true, false, true, 0o644);
    try {
      fs.writeFileSync(fdWrite2, 'two');
    } finally {
      fs.closeSync(fdWrite2);
    }

    const fdRead = sandbox.openRead('io.txt');
    try {
      assert.equal(fs.readFileSync(fdRead, 'utf8'), 'onetwo');
    } finally {
      fs.closeSync(fdRead);
    }
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

test('copyFileNoReplace publishes only a complete new destination', async () => {
  await withTempDirAsync(async (dir) => {
    const sandbox = new SandboxRoot(dir);
    fs.writeFileSync(path.join(dir, 'source.txt'), 'new');

    await sandbox.copyFileNoReplace('source.txt', 'destination.txt');
    assert.equal(
      fs.readFileSync(path.join(dir, 'destination.txt'), 'utf8'),
      'new',
    );

    fs.writeFileSync(path.join(dir, 'source.txt'), 'replacement');
    await assert.rejects(
      sandbox.copyFileNoReplace('source.txt', 'destination.txt'),
      /EEXIST/,
    );
    assert.equal(
      fs.readFileSync(path.join(dir, 'destination.txt'), 'utf8'),
      'new',
    );
    assert.deepEqual(
      fs.readdirSync(dir).sort(),
      ['destination.txt', 'source.txt'],
    );
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

test('rm recursive removes tree without escaping symlink targets', async () => {
  await withTempDirAsync(async (dir) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-outside-rm-'));
    try {
      fs.mkdirSync(path.join(dir, 'tree', 'nested'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'tree', 'nested', 'x.txt'), 'x');
      fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
      fs.symlinkSync(path.join(outside), path.join(dir, 'tree', 'outside-link'));

      const sandbox = new SandboxRoot(dir);
      await sandbox.rm('tree', true, false);

      assert.equal(fs.existsSync(path.join(dir, 'tree')), false);
      assert.equal(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8'), 'secret');
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

test('copyFile rejects same-inode destinations without data loss', async () => {
  await withTempDirAsync(async (dir) => {
    const sandbox = new SandboxRoot(dir);
    fs.writeFileSync(path.join(dir, 'source.txt'), 'preserve me');
    fs.linkSync(path.join(dir, 'source.txt'), path.join(dir, 'alias.txt'));

    await assert.rejects(
      sandbox.copyFile('source.txt', 'source.txt'),
      /EINVAL/,
    );
    await assert.rejects(
      sandbox.copyFile('source.txt', 'alias.txt'),
      /EINVAL/,
    );
    assert.equal(fs.readFileSync(path.join(dir, 'source.txt'), 'utf8'), 'preserve me');
    assert.equal(fs.readFileSync(path.join(dir, 'alias.txt'), 'utf8'), 'preserve me');
  });
});

test('rm refuses excessively deep trees and keeps them intact', async () => {
  await withTempDirAsync(async (dir) => {
    const deep = path.join(dir, 'top', ...Array(256).fill('d'));
    fs.mkdirSync(deep, { recursive: true });
    const sandbox = new SandboxRoot(dir);

    await assert.rejects(sandbox.rm('top', true, false), /^Error: ENAMETOOLONG: /);
    assert.equal(fs.existsSync(deep), true);

    fs.rmdirSync(deep);
    await sandbox.rm('top', true, false);
    assert.equal(fs.existsSync(path.join(dir, 'top')), false);
  });
});

test('concurrent deep rm stays within a low descriptor limit', () => {
  // With RLIMIT_NOFILE=256 the traversal budget is 64 descriptors for the
  // whole process. Concurrent removals must fail cleanly instead of taking the
  // process's other descriptors, and must not leak any.
  const addon = path.join(__dirname, '..', 'index.js');
  const script = String.raw`
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const { SandboxRoot } = require(process.argv[2]);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-budget-'));
    const fdCount = () => fs.readdirSync('/proc/self/fd').length;
    const chain = (name, depth) =>
      fs.mkdirSync(path.join(dir, name, ...Array(depth).fill('d')), { recursive: true });
    for (let i = 0; i < 8; i++) chain('t' + i, 50);
    chain('deep', 100);
    fs.writeFileSync(path.join(dir, 'probe'), 'x');
    const sandbox = new SandboxRoot(dir);
    const baseline = fdCount();
    const names = ['deep', ...Array.from({ length: 8 }, (_, i) => 't' + i)];
    let unrelatedEmfile = 0;
    let settled = false;
    const results = Promise.all(
      names.map((name) =>
        sandbox.rm(name, true, false).then(() => 'ok', (err) => String(err.message)),
      ),
    ).finally(() => { settled = true; });
    const probe = () => {
      try {
        fs.closeSync(fs.openSync(path.join(dir, 'probe'), 'r'));
      } catch (err) {
        if (err.code === 'EMFILE') unrelatedEmfile++;
      }
      if (!settled) setImmediate(probe);
    };
    probe();
    results.then(async (concurrent) => {
      const sequential = [];
      for (const name of names) {
        if (!fs.existsSync(path.join(dir, name))) continue;
        sequential.push(
          await sandbox.rm(name, true, false).then(() => name + ':ok', (err) => name + ':' + err.message),
        );
      }
      const leaked = fdCount() - baseline;
      fs.rmSync(dir, { recursive: true, force: true });
      console.log(JSON.stringify({ concurrent, sequential, unrelatedEmfile, leaked }));
    });
  `;
  const scriptPath = path.join(os.tmpdir(), `openat2-budget-${process.pid}.cjs`);
  fs.writeFileSync(scriptPath, script);
  try {
    const result = spawnSync(
      'sh',
      ['-c', 'ulimit -n 256 && exec "$0" "$1" "$2"', process.execPath, scriptPath, addon],
      { encoding: 'utf8', timeout: 30_000 },
    );
    assert.equal(result.status, 0, result.stderr);
    const out = JSON.parse(result.stdout.trim().split('\n').pop());
    const budgetError = /^EMFILE: directory traversal descriptor budget of 64 is in use/;
    for (const r of out.concurrent) {
      assert.ok(r === 'ok' || budgetError.test(r), r);
    }
    // The 100-level tree exceeds the whole 64-descriptor budget on its own.
    assert.match(out.concurrent[0], budgetError);
    assert.ok(out.sequential.every((r) => r.endsWith(':ok') || r.startsWith('deep:EMFILE')), out.sequential.join());
    assert.ok(out.sequential.some((r) => r.startsWith('deep:EMFILE')));
    assert.equal(out.unrelatedEmfile, 0);
    assert.equal(out.leaked, 0);
  } finally {
    fs.rmSync(scriptPath, { force: true });
  }
});

test('special files report specific error codes', async () => {
  await withTempDirAsync(async (dir) => {
    spawnSync('mkfifo', [path.join(dir, 'fifo')], { stdio: 'inherit' });
    const sandbox = new SandboxRoot(dir);

    assert.throws(() => sandbox.openRead('fifo'), /^Error: EINVAL: /);
    assert.throws(() => sandbox.openWrite('fifo'), /^Error: ENXIO: /);
    assert.throws(() => sandbox.truncate('fifo', 0), /^Error: ENXIO: /);
    await assert.rejects(sandbox.copyFile('fifo', 'copy'), /^Error: EINVAL: /);
    sandbox.chmod('fifo', 0o600);
    assert.equal(fs.statSync(path.join(dir, 'fifo')).mode & 0o7777, 0o600);
  });
});

test('FIFO operations return without blocking the Node process', () => {
  const addon = path.join(__dirname, '..', 'index.js');
  const operations = [
    'openRead',
    'openWrite',
    'chmod',
    'truncate',
    'utimes',
    'copyFile',
    'copyFileNoReplace',
  ];
  const script = String.raw`
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const { spawnSync } = require('node:child_process');
    const { SandboxRoot } = require(process.argv[1]);
    const operation = process.argv[2];
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openat2-fifo-'));
    spawnSync('mkfifo', [path.join(dir, 'fifo')], { stdio: 'inherit' });
    const sandbox = new SandboxRoot(dir);
    (async () => {
      try {
        switch (operation) {
          case 'openRead': sandbox.openRead('fifo'); break;
          case 'openWrite': sandbox.openWrite('fifo', false, false, false, 0o600); break;
          case 'chmod': sandbox.chmod('fifo', 0o600); break;
          case 'truncate': sandbox.truncate('fifo', 0); break;
          case 'utimes': sandbox.utimes('fifo', 0, 0); break;
          case 'copyFile': await sandbox.copyFile('fifo', 'copy'); break;
          case 'copyFileNoReplace': await sandbox.copyFileNoReplace('fifo', 'copy'); break;
        }
      } catch {}
      fs.rmSync(dir, { recursive: true, force: true });
    })();
  `;

  for (const operation of operations) {
    const result = spawnSync(process.execPath, ['-e', script, addon, operation], {
      encoding: 'utf8',
      timeout: 2_000,
    });
    assert.notEqual(result.error?.code, 'ETIMEDOUT', `${operation} blocked`);
    assert.equal(result.status, 0, result.stderr);
  }
});
