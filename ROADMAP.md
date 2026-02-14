# cocalc-openat2 Roadmap

## Goal

Provide a Linux-native, `openat2`-anchored API that can replace remaining path-based safe-mode mutators in
[../cocalc-lite4/src/packages/backend/sandbox/index.ts](../cocalc-lite4/src/packages/backend/sandbox/index.ts)
without TOCTOU windows.

## Integration target methods (from lite4 sandbox)

Primary candidates to migrate first:

1. `mkdir`
2. `unlink`
3. `rmdir`
4. `rename`
5. `move` (through rename/fallback)
6. `copyFile` and `cp`
7. `chmod`
8. `utimes`
9. `truncate`
10. `rm`
11. `link`
12. `symlink`

## Milestones

### M1: Foundation (in this repo)

- [x] napi-rs crate scaffold
- [x] root dirfd anchor object (`SandboxRoot`)
- [x] `openat2` wrapper with strict resolve flags
- [x] mutator subset (`mkdir`, `unlink`, `rmdir`, `rename`)
- [x] additional mutators (`renameNoReplace`, `link`, `symlink`, recursive `rm`)
- [x] metadata subset (`chmod`, `utimes`, `stat`)
- [x] rust tests covering traversal/symlink escape regression

### M2: File content primitives

- [ ] `open_read(path) -> fd`
- [ ] `open_write(path, flags...) -> fd`
- [ ] `open_parent(path) -> (dirfd, leaf)` optional internal helper only
- [ ] Node fd handoff design (`napi::External` or numeric fd + ownership contract)

### M3: Copy and delete completeness

- [ ] `copy_file(src, dst, reflink?)`
- [ ] recursive delete (`rm -r`) implemented natively without unsafe path joins
- [ ] better errno/code mapping for all expected Node-style errors

### M4: CoCalc integration (lite4)

- [ ] Add backend adapter module in lite4 (e.g. `sandbox/openat2.ts`)
- [ ] Feature flag env var: `COCALC_SANDBOX_OPENAT2=1`
- [ ] Route safe-mode mutators through addon when enabled
- [ ] Keep existing TypeScript path as fallback initially

### M5: Security regression tests in lite4

- [ ] Convert openat2 motivation test from fail-expected to pass-expected when feature enabled
- [ ] Add deterministic symlink-swap tests for `mkdir/rename/unlink/copyFile/rm`
- [ ] Ensure watcher behavior remains unchanged

### M6: Packaging and release

- [ ] GitHub Actions prebuilds for linux-x64 and linux-arm64
- [ ] Publish npm package `@cocalc/openat2`
- [ ] Add to project-host bundling manifest
- [ ] Add smoke check in CI that addon loads in runtime images

## Non-goals

- macOS/Windows support
- generic virtual filesystem abstraction
- changing unsafe-mode semantics in lite4

## Notes on semantics

- The addon should remain conservative: fail closed on any uncertain path/descriptor condition.
- CoCalc user-facing behavior should stay Node-like (error codes/messages) where practical.
- For methods where strict race-free behavior cannot be preserved with old API shape, prefer explicit error over fallback path mutation.
