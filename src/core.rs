use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
  #[error("path must be relative: {0}")]
  AbsolutePath(String),

  #[error("path may not contain '..': {0}")]
  ParentTraversal(String),

  #[error("path must not be empty")]
  EmptyPath,

  #[error("invalid path component in '{0}'")]
  InvalidPathComponent(String),

  #[error("invalid path: {0}")]
  InvalidPath(String),

  #[error(transparent)]
  Io(#[from] io::Error),
}

impl SandboxError {
  pub fn raw_os_error(&self) -> Option<i32> {
    match self {
      Self::Io(err) => err.raw_os_error(),
      _ => None,
    }
  }
}

#[derive(Debug, Clone)]
pub struct FileStat {
  pub dev: u64,
  pub ino: u64,
  pub mode: u32,
  pub nlink: u64,
  pub uid: u32,
  pub gid: u32,
  pub rdev: u64,
  pub size: i64,
  pub blksize: i64,
  pub blocks: i64,
  pub atime_ns: i64,
  pub mtime_ns: i64,
  pub ctime_ns: i64,
}

#[derive(Debug)]
pub struct Sandbox {
  root_fd: OwnedFd,
  resolve_flags: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct OpenHow {
  flags: u64,
  mode: u64,
  resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

impl Sandbox {
  pub fn new(root: &str) -> Result<Self, SandboxError> {
    let canonical = std::fs::canonicalize(root)?;
    let c_root = cstring_from_os(canonical.as_os_str())?;
    let fd = unsafe {
      libc::open(
        c_root.as_ptr(),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
      )
    };
    if fd < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    Ok(Self {
      root_fd: unsafe { OwnedFd::from_raw_fd(fd) },
      resolve_flags: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    })
  }

  pub fn mkdir(
    &self,
    path: &str,
    recursive: bool,
    mode: u32,
  ) -> Result<(), SandboxError> {
    let components = normalize_relative_components(path)?;
    if components.is_empty() {
      return Err(SandboxError::EmptyPath);
    }

    if recursive {
      self.mkdir_recursive(&components, mode)
    } else {
      let (parent, leaf) = split_parent_leaf(&components)?;
      let parent_fd = self.open_dir_from_root(parent.as_path())?;
      mkdirat(parent_fd.as_raw_fd(), &leaf, mode)
    }
  }

  pub fn unlink(&self, path: &str) -> Result<(), SandboxError> {
    let components = normalize_relative_components(path)?;
    let (parent, leaf) = split_parent_leaf(&components)?;
    let parent_fd = self.open_dir_from_root(parent.as_path())?;
    unlinkat(parent_fd.as_raw_fd(), &leaf, 0)
  }

  pub fn rmdir(&self, path: &str) -> Result<(), SandboxError> {
    let components = normalize_relative_components(path)?;
    let (parent, leaf) = split_parent_leaf(&components)?;
    let parent_fd = self.open_dir_from_root(parent.as_path())?;
    unlinkat(parent_fd.as_raw_fd(), &leaf, libc::AT_REMOVEDIR)
  }

  pub fn rename(&self, old_path: &str, new_path: &str) -> Result<(), SandboxError> {
    let old_components = normalize_relative_components(old_path)?;
    let new_components = normalize_relative_components(new_path)?;

    let (old_parent, old_leaf) = split_parent_leaf(&old_components)?;
    let (new_parent, new_leaf) = split_parent_leaf(&new_components)?;

    let old_parent_fd = self.open_dir_from_root(old_parent.as_path())?;
    let new_parent_fd = self.open_dir_from_root(new_parent.as_path())?;

    let rc = unsafe {
      libc::renameat(
        old_parent_fd.as_raw_fd(),
        old_leaf.as_ptr(),
        new_parent_fd.as_raw_fd(),
        new_leaf.as_ptr(),
      )
    };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn rename_noreplace(&self, old_path: &str, new_path: &str) -> Result<(), SandboxError> {
    let old_components = normalize_relative_components(old_path)?;
    let new_components = normalize_relative_components(new_path)?;

    let (old_parent, old_leaf) = split_parent_leaf(&old_components)?;
    let (new_parent, new_leaf) = split_parent_leaf(&new_components)?;

    let old_parent_fd = self.open_dir_from_root(old_parent.as_path())?;
    let new_parent_fd = self.open_dir_from_root(new_parent.as_path())?;

    let rc = unsafe {
      libc::renameat2(
        old_parent_fd.as_raw_fd(),
        old_leaf.as_ptr(),
        new_parent_fd.as_raw_fd(),
        new_leaf.as_ptr(),
        libc::RENAME_NOREPLACE,
      )
    };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn link(&self, old_path: &str, new_path: &str) -> Result<(), SandboxError> {
    let old_components = normalize_relative_components(old_path)?;
    let new_components = normalize_relative_components(new_path)?;

    let (old_parent, old_leaf) = split_parent_leaf(&old_components)?;
    let (new_parent, new_leaf) = split_parent_leaf(&new_components)?;

    let old_parent_fd = self.open_dir_from_root(old_parent.as_path())?;
    let new_parent_fd = self.open_dir_from_root(new_parent.as_path())?;

    let rc = unsafe {
      libc::linkat(
        old_parent_fd.as_raw_fd(),
        old_leaf.as_ptr(),
        new_parent_fd.as_raw_fd(),
        new_leaf.as_ptr(),
        0,
      )
    };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn symlink(&self, target: &str, new_path: &str) -> Result<(), SandboxError> {
    let new_components = normalize_relative_components(new_path)?;
    let (new_parent, new_leaf) = split_parent_leaf(&new_components)?;
    let new_parent_fd = self.open_dir_from_root_readable(new_parent.as_path())?;
    let c_target = CString::new(target.as_bytes())
      .map_err(|_| SandboxError::InvalidPath("symlink target contains NUL byte".to_string()))?;

    let rc = unsafe { libc::symlinkat(c_target.as_ptr(), new_parent_fd.as_raw_fd(), new_leaf.as_ptr()) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn remove(&self, path: &str, recursive: bool, force: bool) -> Result<(), SandboxError> {
    let components = normalize_relative_components(path)?;
    let (parent, leaf) = split_parent_leaf(&components)?;
    let parent_fd = self.open_dir_from_root_readable(parent.as_path())?;
    remove_entry(
      parent_fd.as_raw_fd(),
      &leaf,
      recursive,
      force,
      self.resolve_flags,
    )
  }

  pub fn chmod(&self, path: &str, mode: u32) -> Result<(), SandboxError> {
    let fd = self.open_existing(path, libc::O_RDONLY)?;
    let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn truncate(&self, path: &str, len: i64) -> Result<(), SandboxError> {
    let fd = self.open_existing(path, libc::O_WRONLY)?;
    let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn copy_file(&self, src: &str, dest: &str, mode: u32) -> Result<(), SandboxError> {
    let src_fd = self.open_existing(src, libc::O_RDONLY)?;
    let src_stat = self.stat(src)?;
    let dst_fd = self.open_for_create(dest, true, mode)?;

    let mut src_file: File = src_fd.into();
    let mut dst_file: File = dst_fd.into();
    std::io::copy(&mut src_file, &mut dst_file)?;
    dst_file.flush()?;

    // Match source permissions as best-effort parity with copy behavior.
    let rc = unsafe { libc::fchmod(dst_file.as_raw_fd(), src_stat.mode as libc::mode_t) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    Ok(())
  }

  pub fn utimes(&self, path: &str, atime_ns: i64, mtime_ns: i64) -> Result<(), SandboxError> {
    let fd = self.open_existing(path, libc::O_RDONLY)?;
    let atime = ns_to_timespec(atime_ns);
    let mtime = ns_to_timespec(mtime_ns);
    let times = [atime, mtime];
    let rc = unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn stat(&self, path: &str) -> Result<FileStat, SandboxError> {
    let fd = self.open_existing(path, libc::O_PATH)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(stat_from_libc(unsafe { &st.assume_init() }))
  }

  fn mkdir_recursive(&self, components: &[OsString], mode: u32) -> Result<(), SandboxError> {
    let mut current_fd = dup_fd(self.root_fd.as_raw_fd())?;

    for component in components {
      let c_component = cstring_from_os(component.as_os_str())?;
      let rc = unsafe {
        libc::mkdirat(
          current_fd.as_raw_fd(),
          c_component.as_ptr(),
          mode as libc::mode_t,
        )
      };
      if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
          return Err(SandboxError::Io(err));
        }
      }

      let next_fd = openat2_fd(
        current_fd.as_raw_fd(),
        &c_component,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
        self.resolve_flags,
      )?;
      current_fd = next_fd;
    }

    Ok(())
  }

  fn open_existing(&self, path: &str, flags: i32) -> Result<OwnedFd, SandboxError> {
    let components = normalize_relative_components(path)?;
    if components.is_empty() {
      return Err(SandboxError::EmptyPath);
    }
    let rel = components_to_pathbuf(&components);
    let c_rel = cstring_from_os(rel.as_os_str())?;
    openat2_fd(
      self.root_fd.as_raw_fd(),
      &c_rel,
      flags | libc::O_CLOEXEC,
      0,
      self.resolve_flags,
    )
  }

  fn open_for_create(
    &self,
    path: &str,
    truncate: bool,
    mode: u32,
  ) -> Result<OwnedFd, SandboxError> {
    let components = normalize_relative_components(path)?;
    let (parent, leaf) = split_parent_leaf(&components)?;
    let parent_fd = self.open_dir_from_root(parent.as_path())?;

    let mut flags = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if truncate {
      flags |= libc::O_TRUNC;
    }

    let fd = unsafe {
      libc::openat(
        parent_fd.as_raw_fd(),
        leaf.as_ptr(),
        flags,
        mode as libc::mode_t,
      )
    };
    if fd < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
  }

  fn open_dir_from_root(&self, rel_dir: &Path) -> Result<OwnedFd, SandboxError> {
    if rel_dir.as_os_str().is_empty() {
      return dup_fd(self.root_fd.as_raw_fd());
    }

    let c_rel = cstring_from_os(rel_dir.as_os_str())?;
    openat2_fd(
      self.root_fd.as_raw_fd(),
      &c_rel,
      libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
      0,
      self.resolve_flags,
    )
  }

  fn open_dir_from_root_readable(&self, rel_dir: &Path) -> Result<OwnedFd, SandboxError> {
    let rel = if rel_dir.as_os_str().is_empty() {
      CString::new(".")
        .map_err(|_| SandboxError::InvalidPath("invalid root path".to_string()))?
    } else {
      cstring_from_os(rel_dir.as_os_str())?
    };
    openat2_fd(
      self.root_fd.as_raw_fd(),
      &rel,
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
      0,
      self.resolve_flags,
    )
  }
}

fn normalize_relative_components(path: &str) -> Result<Vec<OsString>, SandboxError> {
  let p = Path::new(path);
  if p.is_absolute() {
    return Err(SandboxError::AbsolutePath(path.to_string()));
  }

  let mut components = Vec::new();
  for component in p.components() {
    match component {
      Component::Normal(seg) => {
        if seg.as_bytes().contains(&0) {
          return Err(SandboxError::InvalidPathComponent(path.to_string()));
        }
        components.push(seg.to_os_string());
      }
      Component::CurDir => {}
      Component::ParentDir => {
        return Err(SandboxError::ParentTraversal(path.to_string()));
      }
      Component::RootDir | Component::Prefix(_) => {
        return Err(SandboxError::AbsolutePath(path.to_string()));
      }
    }
  }

  Ok(components)
}

fn split_parent_leaf(components: &[OsString]) -> Result<(PathBuf, CString), SandboxError> {
  if components.is_empty() {
    return Err(SandboxError::EmptyPath);
  }

  let mut parent = PathBuf::new();
  for component in &components[..components.len() - 1] {
    parent.push(component);
  }

  let leaf = cstring_from_os(components[components.len() - 1].as_os_str())?;
  Ok((parent, leaf))
}

fn components_to_pathbuf(components: &[OsString]) -> PathBuf {
  let mut path = PathBuf::new();
  for component in components {
    path.push(component);
  }
  path
}

fn cstring_from_os(value: &OsStr) -> Result<CString, SandboxError> {
  CString::new(value.as_bytes()).map_err(|_| SandboxError::InvalidPath("path contains NUL byte".to_string()))
}

fn openat2_fd(
  dirfd: RawFd,
  path: &CString,
  flags: i32,
  mode: u32,
  resolve_flags: u64,
) -> Result<OwnedFd, SandboxError> {
  let how = OpenHow {
    flags: flags as u64,
    mode: mode as u64,
    resolve: resolve_flags,
  };

  let fd = unsafe {
    libc::syscall(
      libc::SYS_openat2,
      dirfd,
      path.as_ptr(),
      &how as *const OpenHow,
      std::mem::size_of::<OpenHow>(),
    )
  };

  if fd < 0 {
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }

  Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn dup_fd(fd: RawFd) -> Result<OwnedFd, SandboxError> {
  let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
  if new_fd < 0 {
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }
  Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

fn mkdirat(parent_fd: RawFd, leaf: &CString, mode: u32) -> Result<(), SandboxError> {
  let rc = unsafe { libc::mkdirat(parent_fd, leaf.as_ptr(), mode as libc::mode_t) };
  if rc < 0 {
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }
  Ok(())
}

fn unlinkat(parent_fd: RawFd, leaf: &CString, flags: i32) -> Result<(), SandboxError> {
  let rc = unsafe { libc::unlinkat(parent_fd, leaf.as_ptr(), flags) };
  if rc < 0 {
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }
  Ok(())
}

fn remove_entry(
  parent_fd: RawFd,
  leaf: &CString,
  recursive: bool,
  force: bool,
  resolve_flags: u64,
) -> Result<(), SandboxError> {
  if !recursive {
    return match unlinkat(parent_fd, leaf, 0) {
      Ok(()) => Ok(()),
      Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => Ok(()),
      Err(err) => Err(err),
    };
  }

  match unlinkat(parent_fd, leaf, 0) {
    Ok(()) => return Ok(()),
    Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => {
      return Ok(());
    }
    Err(SandboxError::Io(err))
      if matches!(err.raw_os_error(), Some(libc::EISDIR) | Some(libc::EPERM)) => {}
    Err(err) => return Err(err),
  }

  let child_dir_fd = openat2_fd(
    parent_fd,
    leaf,
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    0,
    resolve_flags,
  )?;
  remove_dir_contents(child_dir_fd.as_raw_fd(), force, resolve_flags)?;

  match unlinkat(parent_fd, leaf, libc::AT_REMOVEDIR) {
    Ok(()) => Ok(()),
    Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => Ok(()),
    Err(err) => Err(err),
  }
}

fn remove_dir_contents(dir_fd: RawFd, force: bool, resolve_flags: u64) -> Result<(), SandboxError> {
  let iter_fd = dup_fd(dir_fd)?;
  let raw_fd = iter_fd.into_raw_fd();
  let dir_ptr = unsafe { libc::fdopendir(raw_fd) };
  if dir_ptr.is_null() {
    let _ = unsafe { libc::close(raw_fd) };
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }

  loop {
    unsafe {
      *libc::__errno_location() = 0;
    }
    let entry = unsafe { libc::readdir(dir_ptr) };
    if entry.is_null() {
      let errno = io::Error::last_os_error();
      let closed = unsafe { libc::closedir(dir_ptr) };
      if closed < 0 {
        return Err(SandboxError::Io(io::Error::last_os_error()));
      }
      if errno.raw_os_error() == Some(0) {
        return Ok(());
      }
      return Err(SandboxError::Io(errno));
    }

    let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
    if name.to_bytes() == b"." || name.to_bytes() == b".." {
      continue;
    }
    let c_name = CString::new(name.to_bytes())
      .map_err(|_| SandboxError::InvalidPath("directory entry contains NUL byte".to_string()))?;

    match unlinkat(dir_fd, &c_name, 0) {
      Ok(()) => continue,
      Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => {
        continue;
      }
      Err(SandboxError::Io(err))
        if matches!(err.raw_os_error(), Some(libc::EISDIR) | Some(libc::EPERM)) => {}
      Err(err) => {
        let _ = unsafe { libc::closedir(dir_ptr) };
        return Err(err);
      }
    }

    let child_dir_fd = match openat2_fd(
      dir_fd,
      &c_name,
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
      0,
      resolve_flags,
    ) {
      Ok(fd) => fd,
      Err(err) => {
        let _ = unsafe { libc::closedir(dir_ptr) };
        return Err(err);
      }
    };

    if let Err(err) = remove_dir_contents(child_dir_fd.as_raw_fd(), force, resolve_flags) {
      let _ = unsafe { libc::closedir(dir_ptr) };
      return Err(err);
    }

    if let Err(err) = unlinkat(dir_fd, &c_name, libc::AT_REMOVEDIR) {
      let _ = unsafe { libc::closedir(dir_ptr) };
      return Err(err);
    }
  }
}

fn ns_to_timespec(ns: i64) -> libc::timespec {
  let sec = ns.div_euclid(1_000_000_000);
  let nsec = ns.rem_euclid(1_000_000_000);
  libc::timespec {
    tv_sec: sec as libc::time_t,
    tv_nsec: nsec as libc::c_long,
  }
}

fn stat_from_libc(st: &libc::stat) -> FileStat {
  FileStat {
    dev: st.st_dev as u64,
    ino: st.st_ino as u64,
    mode: st.st_mode as u32,
    nlink: st.st_nlink as u64,
    uid: st.st_uid,
    gid: st.st_gid,
    rdev: st.st_rdev as u64,
    size: st.st_size,
    blksize: st.st_blksize,
    blocks: st.st_blocks,
    atime_ns: st.st_atime.saturating_mul(1_000_000_000) + st.st_atime_nsec,
    mtime_ns: st.st_mtime.saturating_mul(1_000_000_000) + st.st_mtime_nsec,
    ctime_ns: st.st_ctime.saturating_mul(1_000_000_000) + st.st_ctime_nsec,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use tempfile::tempdir;

  #[test]
  fn rejects_parent_traversal() {
    let err = normalize_relative_components("../x").unwrap_err();
    assert!(matches!(err, SandboxError::ParentTraversal(_)));
  }

  #[test]
  fn blocks_symlink_escape_for_stat() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::os::unix::fs::symlink(
      outside.path().join("secret.txt"),
      root.path().join("escape-link"),
    )
    .unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.stat("escape-link").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
  }

  #[test]
  fn rename_stays_inside_root() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.rename("a.txt", "b.txt").unwrap();

    assert!(!root.path().join("a.txt").exists());
    assert!(root.path().join("b.txt").exists());
  }

  #[test]
  fn rename_noreplace_returns_eexist_when_destination_exists() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();
    fs::write(root.path().join("b.txt"), b"y").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.rename_noreplace("a.txt", "b.txt").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));

    assert_eq!(fs::read(root.path().join("a.txt")).unwrap(), b"x");
    assert_eq!(fs::read(root.path().join("b.txt")).unwrap(), b"y");
  }

  #[test]
  fn copy_and_truncate_work() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"abcdef").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.copy_file("a.txt", "b.txt", 0o644).unwrap();
    sandbox.truncate("b.txt", 3).unwrap();

    let value = fs::read(root.path().join("b.txt")).unwrap();
    assert_eq!(&value, b"abc");
  }

  #[test]
  fn link_stays_inside_root() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.link("a.txt", "b.txt").unwrap();

    assert_eq!(fs::read(root.path().join("a.txt")).unwrap(), b"x");
    assert_eq!(fs::read(root.path().join("b.txt")).unwrap(), b"x");
  }

  #[test]
  fn symlink_creates_link() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.symlink("a.txt", "s.txt").unwrap();

    let link_target = fs::read_link(root.path().join("s.txt")).unwrap();
    assert_eq!(link_target, PathBuf::from("a.txt"));
  }

  #[test]
  fn remove_recursive_removes_tree() {
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("d1/d2")).unwrap();
    fs::write(root.path().join("d1/d2/f.txt"), b"x").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.remove("d1", true, false).unwrap();

    assert!(!root.path().join("d1").exists());
  }

  #[test]
  fn remove_recursive_does_not_follow_symlink() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::create_dir_all(root.path().join("d1")).unwrap();
    fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::os::unix::fs::symlink(
      outside.path(),
      root.path().join("d1/outside-link"),
    )
    .unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.remove("d1", true, false).unwrap();

    assert!(outside.path().join("secret.txt").exists());
    assert!(!root.path().join("d1").exists());
  }
}
