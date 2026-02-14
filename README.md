# @cocalc/openat2

Linux-only `napi-rs` addon that exposes `openat2`-anchored filesystem operations for race-safe sandbox mutation.

## Why this exists

In CoCalc safe mode, we need a strong guarantee:

- filesystem operations for a project stay inside that project root
- even if the project owner (or another process) is changing paths concurrently

The subtle failure mode is a classic race:

1. We validate a string path (e.g. `a/b/file.txt`) and it looks safe.
2. Before the actual mutation syscall runs, an attacker swaps an intermediate path component (or leaf) to a symlink.
3. The mutation then lands outside the sandbox.

That `validate(path) -> mutate(path)` pattern is fundamentally fragile under concurrency, because validation and mutation happen at different times on a mutable namespace.

`openat2` changes the model from string-based trust to descriptor-based trust:

- we first open a **root directory handle** (`dirfd`) for the sandbox root
- each operation resolves relative paths under that root via `openat2`
- kernel-enforced resolve rules (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`) prevent escaping during resolution
- we then mutate via `*at` syscalls (`mkdirat`, `renameat`, `unlinkat`, etc.) anchored to validated dirfds

This is closer to a capability model: possession of the root `dirfd` defines the authority boundary, and every derived operation stays constrained to that boundary. In practice, this removes dependence on ad-hoc deny/allow path filtering as the primary safety mechanism.

Why not just use Node `fs` + file descriptors?

- File descriptors help for **existing-file content I/O** (`read`/`write` on an already opened inode), and we do use that pattern.
- But many dangerous operations are **path mutators** (`mkdir`, `rename`, `unlink`, `rmdir`, `chmod`, `utimes`, create paths) that still require pathname resolution at operation time.
- In plain Node, those mutators are path-based. You can pre-check with `realpath`/`lstat`, but that is still a user-space check followed by a later path syscall, so there is still a race window.
- For create flows, there may be no target inode yet to pin with an fd. The critical security question is whether parent-chain resolution stayed inside the sandbox at the exact syscall boundary.
- Node does not currently expose a complete `openat2`/`*at` capability API that lets us anchor all resolution to a sandbox dirfd with kernel-enforced constraints.

So fd-only hardening in Node is necessary but not sufficient: it meaningfully improves read/write safety, but it cannot fully eliminate TOCTOU escape classes for path-mutating operations. `openat2` + `*at` is the piece that closes that remaining gap.

Tradeoffs:

- implementation is more tedious than plain Node `fs` path calls
- Linux-specific (`openat2` is a Linux syscall)
- existing path-oriented code needs adapter layers for migration

For our situation, that tradeoff is worth it: mutators become fail-closed under symlink/path-swap races, which is exactly the remaining hardening gap in backend sandbox safe mode.

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
- `renameNoReplace(oldPath, newPath)`
- `link(oldPath, newPath)`
- `symlink(target, newPath)`
- `chmod(path, mode)`
- `truncate(path, len)`
- `copyFile(src, dest, mode?)`
- `rm(path, recursive?, force?)`
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
