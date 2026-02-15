# Release Guide

Manual release flow for `@cocalc/openat2` with Linux prebuilt binaries for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

This avoids GitHub Actions publishing and uses an interactive npm session login.

## Prerequisites

- Node + pnpm installed
- Rust toolchain installed
- npm account with publish rights for:
  - `@cocalc/openat2`
  - `@cocalc/openat2-linux-x64-gnu`
  - `@cocalc/openat2-linux-arm64-gnu`

## One-Time Host Prerequisite (for arm64 cross-build)

```bash
sudo apt-get update
sudo apt-get install -y gcc-aarch64-linux-gnu
```

## Release Steps

```bash
cd /home/wstein/build/cocalc-openat2

pnpm install --frozen-lockfile

# Bump version before publishing (choose one):
# npm version patch
# npm version minor
# npm version major

pnpm run create-npm-dirs

pnpm exec napi build --platform --release --target x86_64-unknown-linux-gnu
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
  pnpm exec napi build --platform --release --target aarch64-unknown-linux-gnu

cp cocalc_openat2.linux-x64-gnu.node npm/linux-x64-gnu/
cp cocalc_openat2.linux-arm64-gnu.node npm/linux-arm64-gnu/

# Optional validation
pnpm test
npm pack --dry-run

# Session-based auth (no long-lived classic token needed)
npm login

# Publish root package.
# prepublishOnly will publish platform packages first, then root.
npm publish --access public
```

## Notes

- Do not publish the same version twice.
- If `npm publish` fails due to auth/session expiry, run `npm login` again.
- If you want to inspect what `prepublishOnly` does:

```bash
pnpm run create-npm-dirs
napi prepublish -t npm --tagstyle npm --skip-gh-release --dry-run
```
