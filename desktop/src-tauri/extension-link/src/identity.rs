//! Which CipherMoth app a host or app build belongs to, and where its local
//! endpoint is. The browser starts the host with no way to pass settings, so
//! both sides compute the same names from the same inputs. Development and QA
//! builds have their own native-host names, folders and endpoints: a test never
//! reaches the real app (design decision 37).

use std::io;
use std::path::{Path, PathBuf};

const IDENTIFIER: &str = "com.ciphermoth.desktop";
const QA_IDENTIFIER: &str = "com.ciphermoth.desktop.qa";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identity {
    Production,
    Development,
    /// The QA build: everything below an explicit absolute root.
    Qa(PathBuf),
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

#[cfg(unix)]
fn home() -> io::Result<PathBuf> {
    if let Some(home) = env_path("HOME") {
        return Ok(home);
    }
    // SAFETY: getpwuid returns a pointer into static storage or null.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() || (*entry).pw_dir.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no home folder"));
        }
        let dir = std::ffi::CStr::from_ptr((*entry).pw_dir);
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
    }
}

/// The OS application-local data folder, as Tauri's `app_local_data_dir`.
pub fn local_data(identifier: &str) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    return Ok(home()?.join("Library/Application Support").join(identifier));
    #[cfg(all(unix, not(target_os = "macos")))]
    return Ok(env_path("XDG_DATA_HOME")
        .map(Ok)
        .unwrap_or_else(|| home().map(|h| h.join(".local/share")))?
        .join(identifier));
    #[cfg(windows)]
    return env_path("LOCALAPPDATA")
        .map(|p| p.join(identifier))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no LOCALAPPDATA"));
}

impl Identity {
    /// `CIPHERMOTH_QA_ROOT` for QA builds (the browser passes its environment
    /// on to the host it starts).
    pub fn qa_from_env() -> io::Result<Identity> {
        env_path("CIPHERMOTH_QA_ROOT")
            .map(Identity::Qa)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "CIPHERMOTH_QA_ROOT must be absolute",
                )
            })
    }

    pub fn host_name(&self) -> &'static str {
        match self {
            Identity::Production => "com.ciphermoth.desktop",
            Identity::Development => "com.ciphermoth.desktop.dev",
            Identity::Qa(_) => "com.ciphermoth.desktop.qa",
        }
    }

    /// The app's data folder (the core's vault lives in `data/` below it).
    pub fn base(&self) -> io::Result<PathBuf> {
        match self {
            Identity::Production => local_data(IDENTIFIER),
            Identity::Development => Ok(local_data(IDENTIFIER)?.join("development")),
            Identity::Qa(root) => Ok(root.clone()),
        }
    }

    /// Pairings, the switch and the launch target (`0700`).
    pub fn link_dir(&self) -> io::Result<PathBuf> {
        Ok(self.base()?.join("browser-extension"))
    }

    pub fn tauri_identifier(&self) -> &'static str {
        match self {
            Identity::Qa(_) => QA_IDENTIFIER,
            _ => IDENTIFIER,
        }
    }

    #[cfg(unix)]
    pub fn socket_path(&self) -> io::Result<PathBuf> {
        let primary = match (self, runtime_dir()) {
            (Identity::Qa(root), _) => root.join("run").join("extension.sock"),
            (_, Some(runtime)) => runtime.join(self.host_name()).join("extension.sock"),
            (_, None) => self.base()?.join("run").join("extension.sock"),
        };
        Ok(short_enough(primary))
    }

    #[cfg(windows)]
    pub fn pipe_name(&self) -> io::Result<String> {
        let sid = crate::ipc::current_user_sid()?;
        let tag = match self {
            Identity::Production => String::new(),
            Identity::Development => "-dev".into(),
            Identity::Qa(root) => format!(
                "-qa-{}",
                short_hash(root.as_os_str().to_string_lossy().as_bytes())
            ),
        };
        Ok(format!(r"\\.\pipe\ciphermoth-extension{tag}-{sid}"))
    }
}

pub fn short_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `$XDG_RUNTIME_DIR` (or `/run/user/<uid>`) when it is ours and private.
#[cfg(unix)]
fn runtime_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        return None;
    }
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let dir =
        env_path("XDG_RUNTIME_DIR").unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    (meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0).then_some(dir)
}

/// A Unix socket path must fit in `sun_path` (104 bytes on macOS, 108 on
/// Linux). A longer one moves to a private folder in the per-user temporary
/// folder, named after the long path so both sides find it.
#[cfg(unix)]
fn short_enough(primary: PathBuf) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    if primary.as_os_str().as_bytes().len() < 100 {
        return primary;
    }
    temp_dir()
        .join(format!(
            "ciphermoth-{}",
            short_hash(primary.as_os_str().as_bytes())
        ))
        .join("s")
}

#[cfg(target_os = "macos")]
fn temp_dir() -> PathBuf {
    // The per-user folder below /var/folders (0700), not $TMPDIR, which a
    // browser may have changed for the processes it starts.
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most buf.len() bytes, NUL-terminated.
    let n = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n > 0 && n <= buf.len() {
        buf.truncate(n - 1);
        use std::os::unix::ffi::OsStringExt;
        return PathBuf::from(std::ffi::OsString::from_vec(buf));
    }
    PathBuf::from("/tmp")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn temp_dir() -> PathBuf {
    PathBuf::from("/tmp")
}

/// Create `dir` (and parents) and make sure it is a real folder of ours that
/// nobody else can enter.
#[cfg(unix)]
pub fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    if !meta.is_dir() || meta.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "folder is not ours",
        ));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn private_dir(dir: &Path) -> io::Result<()> {
    // Below LocalAppData, whose ACL already admits only this user.
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_never_share_names_or_folders() {
        let qa = Identity::Qa(PathBuf::from("/tmp/qa-root"));
        let names = [
            Identity::Production.host_name(),
            Identity::Development.host_name(),
            qa.host_name(),
        ];
        assert_eq!(
            names.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
        for name in names {
            // Native-messaging host names: lowercase alphanumerics, dots, underscores.
            assert!(name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'));
        }
        assert_eq!(
            qa.link_dir().unwrap(),
            PathBuf::from("/tmp/qa-root/browser-extension")
        );
        assert_ne!(
            Identity::Production.base().unwrap(),
            Identity::Development.base().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn long_socket_paths_move_to_a_short_private_place() {
        let long = Identity::Qa(PathBuf::from(format!("/tmp/{}", "x".repeat(120))));
        let path = long.socket_path().unwrap();
        use std::os::unix::ffi::OsStrExt;
        assert!(path.as_os_str().as_bytes().len() < 100, "{path:?}");
        assert_eq!(
            path,
            long.socket_path().unwrap(),
            "both sides compute the same path"
        );
        let short = Identity::Qa(PathBuf::from("/tmp/q"));
        assert_eq!(
            short.socket_path().unwrap(),
            PathBuf::from("/tmp/q/run/extension.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_tightens_our_folder() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/b");
        private_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = root.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(private_dir(&file).is_err());
    }
}
