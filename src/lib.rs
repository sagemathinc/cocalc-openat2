#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("@cocalc/openat2 currently only supports Linux");

mod core;

use core::{FileStat, Sandbox, SandboxError};
use napi::{Error, Result, Status};
use napi_derive::napi;

#[napi(object)]
pub struct StatResult {
  pub dev: i64,
  pub ino: i64,
  pub mode: u32,
  pub nlink: i64,
  pub uid: u32,
  pub gid: u32,
  pub rdev: i64,
  pub size: i64,
  pub blksize: i64,
  pub blocks: i64,
  pub atime_ns: i64,
  pub mtime_ns: i64,
  pub ctime_ns: i64,
}

impl From<FileStat> for StatResult {
  fn from(value: FileStat) -> Self {
    Self {
      dev: value.dev as i64,
      ino: value.ino as i64,
      mode: value.mode,
      nlink: value.nlink as i64,
      uid: value.uid,
      gid: value.gid,
      rdev: value.rdev as i64,
      size: value.size,
      blksize: value.blksize,
      blocks: value.blocks,
      atime_ns: value.atime_ns,
      mtime_ns: value.mtime_ns,
      ctime_ns: value.ctime_ns,
    }
  }
}

#[napi]
pub struct SandboxRoot {
  inner: Sandbox,
}

#[napi]
impl SandboxRoot {
  #[napi(constructor)]
  pub fn new(root: String) -> Result<Self> {
    Ok(Self {
      inner: Sandbox::new(&root).map_err(map_error)?,
    })
  }

  #[napi]
  pub fn mkdir(&self, path: String, recursive: Option<bool>, mode: Option<u32>) -> Result<()> {
    self
      .inner
      .mkdir(&path, recursive.unwrap_or(false), mode.unwrap_or(0o755))
      .map_err(map_error)
  }

  #[napi]
  pub fn unlink(&self, path: String) -> Result<()> {
    self.inner.unlink(&path).map_err(map_error)
  }

  #[napi]
  pub fn rmdir(&self, path: String) -> Result<()> {
    self.inner.rmdir(&path).map_err(map_error)
  }

  #[napi]
  pub fn rename(&self, old_path: String, new_path: String) -> Result<()> {
    self.inner.rename(&old_path, &new_path).map_err(map_error)
  }

  #[napi]
  pub fn chmod(&self, path: String, mode: u32) -> Result<()> {
    self.inner.chmod(&path, mode).map_err(map_error)
  }

  #[napi]
  pub fn utimes(&self, path: String, atime_ns: i64, mtime_ns: i64) -> Result<()> {
    self
      .inner
      .utimes(&path, atime_ns, mtime_ns)
      .map_err(map_error)
  }

  #[napi]
  pub fn stat(&self, path: String) -> Result<StatResult> {
    let stat = self.inner.stat(&path).map_err(map_error)?;
    Ok(stat.into())
  }
}

fn map_error(err: SandboxError) -> Error {
  let mut message = err.to_string();
  if let Some(errno) = err.raw_os_error() {
    let code = errno_to_code(errno);
    message = format!("{code}: {message}");
  }
  Error::new(Status::GenericFailure, message)
}

fn errno_to_code(errno: i32) -> &'static str {
  match errno {
    libc::EACCES => "EACCES",
    libc::EPERM => "EPERM",
    libc::ENOENT => "ENOENT",
    libc::ENOTDIR => "ENOTDIR",
    libc::EISDIR => "EISDIR",
    libc::EINVAL => "EINVAL",
    libc::EEXIST => "EEXIST",
    libc::ENOSYS => "ENOSYS",
    libc::EXDEV => "EXDEV",
    libc::ELOOP => "ELOOP",
    _ => "EIO",
  }
}
