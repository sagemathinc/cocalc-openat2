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

  #[error("directory nesting exceeds {0} levels")]
  TooDeep(usize),

  #[error(transparent)]
  Io(#[from] io::Error),
}

impl SandboxError {
  pub fn raw_os_error(&self) -> Option<i32> {
    match self {
      Self::Io(err) => err.raw_os_error(),
      Self::TooDeep(_) => Some(libc::ENAMETOOLONG),
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

/// Deepest directory nesting that recursive removal descends into. Removal
/// holds one directory descriptor per level, so this also bounds descriptor
/// use; path-based tools stop far earlier at PATH_MAX.
pub const MAX_REMOVE_DEPTH: usize = 1024;

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

    let sandbox = Self {
      root_fd: unsafe { OwnedFd::from_raw_fd(fd) },
      resolve_flags: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };

    // Fail construction when the kernel or syscall policy does not actually
    // support the confinement primitive this type promises.
    let dot = CString::new(".").expect("static string has no NUL byte");
    drop(openat2_fd(
      sandbox.root_fd.as_raw_fd(),
      &dot,
      libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
      0,
      sandbox.resolve_flags,
    )?);

    Ok(sandbox)
  }

  pub fn try_clone(&self) -> Result<Self, SandboxError> {
    Ok(Self {
      root_fd: dup_fd(self.root_fd.as_raw_fd())?,
      resolve_flags: self.resolve_flags,
    })
  }

  pub fn mkdir(&self, path: &str, recursive: bool, mode: u32) -> Result<(), SandboxError> {
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

    let rc = unsafe {
      libc::symlinkat(
        c_target.as_ptr(),
        new_parent_fd.as_raw_fd(),
        new_leaf.as_ptr(),
      )
    };
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
    // An O_PATH handle never opens the inode itself, so this needs no read
    // permission and has no FIFO or device open side effects. The magic link
    // refers to exactly this inode.
    let fd = self.open_existing(path, libc::O_PATH)?;
    let proc_path = proc_fd_path(fd.as_raw_fd());
    let rc = unsafe { libc::chmod(proc_path.as_ptr(), mode as libc::mode_t) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn truncate(&self, path: &str, len: i64) -> Result<(), SandboxError> {
    let fd = self.open_existing(path, libc::O_WRONLY | libc::O_NONBLOCK)?;
    ensure_regular_file(fd.as_raw_fd())?;
    let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
  }

  pub fn copy_file(&self, src: &str, dest: &str, mode: u32) -> Result<(), SandboxError> {
    let src_fd = self.open_existing(src, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let src_stat = ensure_regular_file(src_fd.as_raw_fd())?;
    let dst_fd = self.open_for_create(dest, false, mode)?;
    let dst_stat = ensure_regular_file(dst_fd.as_raw_fd())?;

    if src_stat.st_dev == dst_stat.st_dev && src_stat.st_ino == dst_stat.st_ino {
      return Err(SandboxError::Io(io::Error::from_raw_os_error(libc::EINVAL)));
    }

    let truncate_rc = unsafe { libc::ftruncate(dst_fd.as_raw_fd(), 0) };
    if truncate_rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    let mut src_file: File = src_fd.into();
    let mut dst_file: File = dst_fd.into();
    std::io::copy(&mut src_file, &mut dst_file)?;
    dst_file.flush()?;

    // Match source permissions as best-effort parity with copy behavior.
    let rc = unsafe {
      libc::fchmod(
        dst_file.as_raw_fd(),
        (src_stat.st_mode & 0o7777) as libc::mode_t,
      )
    };
    if rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    Ok(())
  }

  pub fn copy_file_noreplace(&self, src: &str, dest: &str) -> Result<(), SandboxError> {
    let src_fd = self.open_existing(src, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let src_stat = ensure_regular_file(src_fd.as_raw_fd())?;

    let dest_components = normalize_relative_components(dest)?;
    let (dest_parent, dest_leaf) = split_parent_leaf(&dest_components)?;
    let dest_parent_fd = self.open_dir_from_root(dest_parent.as_path())?;
    let dot = CString::new(".").expect("static string has no NUL byte");
    let temp_fd = unsafe {
      libc::openat(
        dest_parent_fd.as_raw_fd(),
        dot.as_ptr(),
        libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC,
        (src_stat.st_mode & 0o7777) as libc::mode_t,
      )
    };
    if temp_fd < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    let mut src_file: File = src_fd.into();
    let mut temp_file = unsafe { File::from_raw_fd(temp_fd) };
    std::io::copy(&mut src_file, &mut temp_file)?;
    temp_file.flush()?;

    let chmod_rc = unsafe {
      libc::fchmod(
        temp_file.as_raw_fd(),
        (src_stat.st_mode & 0o7777) as libc::mode_t,
      )
    };
    if chmod_rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    let empty = CString::new("").expect("static string has no NUL byte");
    let link_rc = unsafe {
      libc::linkat(
        temp_file.as_raw_fd(),
        empty.as_ptr(),
        dest_parent_fd.as_raw_fd(),
        dest_leaf.as_ptr(),
        libc::AT_EMPTY_PATH,
      )
    };
    if link_rc < 0 {
      return Err(SandboxError::Io(io::Error::last_os_error()));
    }

    Ok(())
  }

  pub fn open_read_fd(&self, path: &str) -> Result<RawFd, SandboxError> {
    let fd = self.open_existing(path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    ensure_regular_file(fd.as_raw_fd())?;
    Ok(fd.into_raw_fd())
  }

  pub fn open_write_fd(
    &self,
    path: &str,
    create: bool,
    truncate: bool,
    append: bool,
    mode: u32,
  ) -> Result<RawFd, SandboxError> {
    if truncate && append {
      return Err(SandboxError::InvalidPath(
        "open_write may not set both truncate and append".to_string(),
      ));
    }
    let components = normalize_relative_components(path)?;
    let (parent, leaf) = split_parent_leaf(&components)?;
    let parent_fd = self.open_dir_from_root(parent.as_path())?;

    let mut flags = libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if create {
      flags |= libc::O_CREAT;
    }
    if truncate {
      flags |= libc::O_TRUNC;
    }
    if append {
      flags |= libc::O_APPEND;
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
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    ensure_regular_file(fd.as_raw_fd())?;
    Ok(fd.into_raw_fd())
  }

  pub fn utimes(&self, path: &str, atime_ns: i64, mtime_ns: i64) -> Result<(), SandboxError> {
    // Same O_PATH pattern as chmod.
    let fd = self.open_existing(path, libc::O_PATH)?;
    let proc_path = proc_fd_path(fd.as_raw_fd());
    let atime = ns_to_timespec(atime_ns);
    let mtime = ns_to_timespec(mtime_ns);
    let times = [atime, mtime];
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, proc_path.as_ptr(), times.as_ptr(), 0) };
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

    let mut flags =
      libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
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
      CString::new(".").map_err(|_| SandboxError::InvalidPath("invalid root path".to_string()))?
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
  CString::new(value.as_bytes())
    .map_err(|_| SandboxError::InvalidPath("path contains NUL byte".to_string()))
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

fn ensure_regular_file(fd: RawFd) -> Result<libc::stat, SandboxError> {
  let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
  let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
  if rc < 0 {
    return Err(SandboxError::Io(io::Error::last_os_error()));
  }
  let stat = unsafe { stat.assume_init() };
  if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
    let errno = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
      libc::EISDIR
    } else {
      libc::EINVAL
    };
    return Err(SandboxError::Io(io::Error::from_raw_os_error(errno)));
  }
  Ok(stat)
}

fn proc_fd_path(fd: RawFd) -> CString {
  CString::new(format!("/proc/self/fd/{fd}")).expect("formatted path has no NUL byte")
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

  let child_dir_fd = open_child_dir(parent_fd, leaf, resolve_flags)?;
  remove_dir_contents(child_dir_fd, force, resolve_flags)?;

  match unlinkat(parent_fd, leaf, libc::AT_REMOVEDIR) {
    Ok(()) => Ok(()),
    Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => Ok(()),
    Err(err) => Err(err),
  }
}

fn open_child_dir(
  parent_fd: RawFd,
  leaf: &CString,
  resolve_flags: u64,
) -> Result<OwnedFd, SandboxError> {
  openat2_fd(
    parent_fd,
    leaf,
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    0,
    resolve_flags,
  )
}

/// A readdir stream that owns its directory descriptor.
struct DirStream {
  dir: *mut libc::DIR,
}

impl DirStream {
  fn new(fd: OwnedFd) -> Result<Self, SandboxError> {
    let raw_fd = fd.into_raw_fd();
    let dir = unsafe { libc::fdopendir(raw_fd) };
    if dir.is_null() {
      let err = io::Error::last_os_error();
      let _ = unsafe { libc::close(raw_fd) };
      return Err(SandboxError::Io(err));
    }
    Ok(Self { dir })
  }

  fn fd(&self) -> RawFd {
    unsafe { libc::dirfd(self.dir) }
  }

  fn next_name(&mut self) -> Result<Option<CString>, SandboxError> {
    loop {
      unsafe {
        *libc::__errno_location() = 0;
      }
      let entry = unsafe { libc::readdir(self.dir) };
      if entry.is_null() {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(0) {
          return Ok(None);
        }
        return Err(SandboxError::Io(err));
      }
      let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
      if name.to_bytes() == b"." || name.to_bytes() == b".." {
        continue;
      }
      return Ok(Some(name.to_owned()));
    }
  }
}

impl Drop for DirStream {
  fn drop(&mut self) {
    unsafe {
      libc::closedir(self.dir);
    }
  }
}

/// Removes everything below `dir_fd` without recursion: one heap frame and one
/// descriptor per directory level, capped at MAX_REMOVE_DEPTH levels.
fn remove_dir_contents(
  dir_fd: OwnedFd,
  force: bool,
  resolve_flags: u64,
) -> Result<(), SandboxError> {
  // Each frame is an open directory and its name in the parent frame.
  let mut stack: Vec<(DirStream, Option<CString>)> = vec![(DirStream::new(dir_fd)?, None)];

  while let Some((dir, _)) = stack.last_mut() {
    let current_fd = dir.fd();
    let Some(name) = dir.next_name()? else {
      let (finished, name) = stack.pop().expect("stack is not empty");
      drop(finished);
      if let (Some(name), Some((parent, _))) = (name, stack.last()) {
        unlinkat(parent.fd(), &name, libc::AT_REMOVEDIR)?;
      }
      continue;
    };

    match unlinkat(current_fd, &name, 0) {
      Ok(()) => continue,
      Err(SandboxError::Io(err)) if force && err.raw_os_error() == Some(libc::ENOENT) => {
        continue;
      }
      Err(SandboxError::Io(err))
        if matches!(err.raw_os_error(), Some(libc::EISDIR) | Some(libc::EPERM)) => {}
      Err(err) => return Err(err),
    }

    if stack.len() >= MAX_REMOVE_DEPTH {
      return Err(SandboxError::TooDeep(MAX_REMOVE_DEPTH));
    }
    let child = DirStream::new(open_child_dir(current_fd, &name, resolve_flags)?)?;
    stack.push((child, Some(name)));
  }

  Ok(())
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
    size: st.st_size as i64,
    blksize: st.st_blksize as i64,
    blocks: st.st_blocks as i64,
    atime_ns: (st.st_atime as i64).saturating_mul(1_000_000_000) + st.st_atime_nsec as i64,
    mtime_ns: (st.st_mtime as i64).saturating_mul(1_000_000_000) + st.st_mtime_nsec as i64,
    ctime_ns: (st.st_ctime as i64).saturating_mul(1_000_000_000) + st.st_ctime_nsec as i64,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use std::io::{Read, Write};
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
  fn copy_file_rejects_same_path_without_truncating() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"abcdef").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.copy_file("a.txt", "a.txt", 0o644).unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    assert_eq!(fs::read(root.path().join("a.txt")).unwrap(), b"abcdef");
  }

  #[test]
  fn copy_file_rejects_hard_link_alias_without_truncating() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"abcdef").unwrap();
    fs::hard_link(root.path().join("a.txt"), root.path().join("b.txt")).unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.copy_file("a.txt", "b.txt", 0o644).unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    assert_eq!(fs::read(root.path().join("a.txt")).unwrap(), b"abcdef");
    assert_eq!(fs::read(root.path().join("b.txt")).unwrap(), b"abcdef");
  }

  #[test]
  fn copy_file_noreplace_creates_destination() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"abcdef").unwrap();
    let mut permissions = fs::metadata(root.path().join("a.txt"))
      .unwrap()
      .permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o751);
    fs::set_permissions(root.path().join("a.txt"), permissions).unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.copy_file_noreplace("a.txt", "b.txt").unwrap();

    assert_eq!(fs::read(root.path().join("b.txt")).unwrap(), b"abcdef");
    assert_eq!(
      fs::metadata(root.path().join("b.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777,
      0o751
    );
  }

  #[test]
  fn copy_file_noreplace_preserves_existing_destination() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"new").unwrap();
    fs::write(root.path().join("b.txt"), b"existing").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.copy_file_noreplace("a.txt", "b.txt").unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    assert_eq!(fs::read(root.path().join("b.txt")).unwrap(), b"existing");
  }

  #[test]
  fn concurrent_copy_file_noreplace_has_one_complete_winner() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let root = tempdir().unwrap();
    let first = vec![b'a'; 2 * 1024 * 1024];
    let second = vec![b'b'; 2 * 1024 * 1024];
    fs::write(root.path().join("a.txt"), &first).unwrap();
    fs::write(root.path().join("b.txt"), &second).unwrap();

    let root_path = root.path().to_str().unwrap().to_string();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = ["a.txt", "b.txt"]
      .into_iter()
      .map(|source| {
        let root_path = root_path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
          let sandbox = Sandbox::new(&root_path).unwrap();
          barrier.wait();
          sandbox.copy_file_noreplace(source, "destination.txt")
        })
      })
      .collect();

    let results: Vec<_> = handles
      .into_iter()
      .map(|handle| handle.join().unwrap())
      .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
      results
        .iter()
        .filter(|result| {
          result.as_ref().err().and_then(SandboxError::raw_os_error) == Some(libc::EEXIST)
        })
        .count(),
      1
    );

    let destination = fs::read(root.path().join("destination.txt")).unwrap();
    assert!(destination == first || destination == second);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
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
    std::os::unix::fs::symlink(outside.path(), root.path().join("d1/outside-link")).unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.remove("d1", true, false).unwrap();

    assert!(outside.path().join("secret.txt").exists());
    assert!(!root.path().join("d1").exists());
  }

  fn nested_dirs(top: &Path, levels: usize) -> PathBuf {
    let mut path = top.to_path_buf();
    for _ in 0..levels {
      path.push("d");
    }
    fs::create_dir_all(&path).unwrap();
    path
  }

  #[test]
  fn remove_recursive_resumes_parent_after_subdirectories() {
    let root = tempdir().unwrap();
    for dir in ["t/a/b", "t/c", "t/e/f/g"] {
      fs::create_dir_all(root.path().join(dir)).unwrap();
    }
    for file in [
      "t/1",
      "t/a/2",
      "t/a/b/3",
      "t/c/4",
      "t/e/5",
      "t/e/f/g/6",
      "t/z",
    ] {
      fs::write(root.path().join(file), b"x").unwrap();
    }

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.remove("t", true, false).unwrap();

    assert!(!root.path().join("t").exists());
  }

  #[test]
  fn remove_recursive_allows_maximum_depth() {
    let root = tempdir().unwrap();
    let deepest = nested_dirs(&root.path().join("top"), MAX_REMOVE_DEPTH - 1);
    fs::write(deepest.join("f.txt"), b"x").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.remove("top", true, false).unwrap();

    assert!(!root.path().join("top").exists());
  }

  #[test]
  fn remove_recursive_rejects_excessive_depth() {
    let root = tempdir().unwrap();
    nested_dirs(&root.path().join("top"), MAX_REMOVE_DEPTH);

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let err = sandbox.remove("top", true, false).unwrap_err();

    assert!(matches!(err, SandboxError::TooDeep(MAX_REMOVE_DEPTH)));
    assert_eq!(err.raw_os_error(), Some(libc::ENAMETOOLONG));
    assert!(root.path().join("top").exists());
  }

  #[test]
  fn chmod_and_utimes_do_not_require_read_permission() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = tempdir().unwrap();
    let file = root.path().join("locked.txt");
    fs::write(&file, b"x").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox
      .utimes("locked.txt", 1_000_000_000, 2_000_000_000)
      .unwrap();
    sandbox.chmod("locked.txt", 0o640).unwrap();

    let meta = fs::metadata(&file).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o640);
    assert_eq!(meta.mtime(), 2);
  }

  #[test]
  fn chmod_and_utimes_do_not_open_fifos() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = tempdir().unwrap();
    let fifo = cstring_from_os(root.path().join("fifo").as_os_str()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    sandbox.chmod("fifo", 0o600).unwrap();
    sandbox.utimes("fifo", 0, 3_000_000_000).unwrap();

    let meta = fs::metadata(root.path().join("fifo")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert_eq!(meta.mtime(), 3);
  }

  #[test]
  fn open_read_fd_reads_expected_bytes() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"hello").unwrap();

    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();
    let fd = sandbox.open_read_fd("a.txt").unwrap();
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut value = String::new();
    file.read_to_string(&mut value).unwrap();
    assert_eq!(value, "hello");
  }

  #[test]
  fn open_write_fd_create_and_append_work() {
    let root = tempdir().unwrap();
    let sandbox = Sandbox::new(root.path().to_str().unwrap()).unwrap();

    {
      let fd = sandbox
        .open_write_fd("log.txt", true, false, true, 0o644)
        .unwrap();
      let mut file = unsafe { File::from_raw_fd(fd) };
      file.write_all(b"one\n").unwrap();
    }
    {
      let fd = sandbox
        .open_write_fd("log.txt", true, false, true, 0o644)
        .unwrap();
      let mut file = unsafe { File::from_raw_fd(fd) };
      file.write_all(b"two\n").unwrap();
    }

    let data = fs::read_to_string(root.path().join("log.txt")).unwrap();
    assert_eq!(data, "one\ntwo\n");
  }
}
