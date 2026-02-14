# @cocalc/openat2

Linux-only `napi-rs` addon that exposes `openat2`-anchored filesystem operations for race-safe sandbox mutation.

## Why this exists

`path -> validate -> mutate(path)` is vulnerable to TOCTOU races if a path component is swapped between validation and the operation.

This package keeps all sensitive path resolution inside kernel-checked `openat2(..., RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` flows and performs mutations via `*at` syscalls on validated dirfds.

## Current API

```ts
import { SandboxRoot } from '@cocalc/openat2'

const root = new SandboxRoot('/srv/project')
root.mkdir('a/b', true)
root.rename('a/b/file.txt', 'a/b/file2.txt')
root.unlink('a/b/file2.txt')
const st = root.stat('a/b')
```

Methods implemented now:

- `mkdir(path, recursive?, mode?)`
- `unlink(path)`
- `rmdir(path)`
- `rename(oldPath, newPath)`
- `chmod(path, mode)`
- `utimes(path, atimeNs, mtimeNs)`
- `stat(path)`

## Security model

- Absolute paths are rejected.
- `..` traversal is rejected.
- Symlink traversal is blocked by `openat2` resolve flags.
- Operations are anchored to a root dirfd opened once in constructor.

## Build

```bash
pnpm install
pnpm build
```

Requirements:

- Linux kernel with `openat2` support (>=5.6)
- Rust toolchain
- Node 18+

## Test

```bash
pnpm run test:rust
```

## Packaging notes

This repository is prepared for `napi-rs` prebuilds for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

## Planned next steps

1. Add `openRead`/`openWrite` fd-returning APIs for efficient file-content paths.
2. Add `copyFile` (`copy_file_range`/fallback) and recursive remove helpers.
3. Add deterministic Node integration tests reproducing symlink-swap races.
4. Integrate into CoCalc backend sandbox safe mode behind a feature flag.
