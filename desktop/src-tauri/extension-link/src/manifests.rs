//! Native-messaging host manifests (design decision 36): written for every
//! supported browser whose profile folder exists, removed from every location
//! we know. macOS and Linux read a JSON file from a folder per browser; Windows
//! reads a registry value (`HKCU\Software\<vendor>\NativeMessagingHosts\<name>`)
//! naming the JSON file, which lives in the app's link folder.

use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};

use crate::ids::{CHROMIUM_IDS, FIREFOX_IDS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Chromium,
    Firefox,
}

#[derive(Clone, Debug)]
pub struct Location {
    pub browser: &'static str,
    pub family: Family,
    /// The browser's own folder: only when it exists is a manifest written.
    pub profile: PathBuf,
    /// macOS/Linux: the folder for manifests. Windows: the registry key below
    /// HKCU (without the host name).
    pub hosts: Target,
}

#[derive(Clone, Debug)]
pub enum Target {
    Folder(PathBuf),
    Registry(&'static str),
}

/// Where browsers look, below the user's folders. `home` is the home folder
/// (macOS, Linux); `local` and `roaming` are LocalAppData and AppData (Windows).
pub struct Roots {
    pub home: PathBuf,
    pub local: PathBuf,
    pub roaming: PathBuf,
}

impl Roots {
    pub fn of_user() -> io::Result<Roots> {
        let var = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        #[cfg(windows)]
        {
            let missing = || io::Error::new(io::ErrorKind::NotFound, "no user profile folders");
            Ok(Roots {
                home: var("USERPROFILE").ok_or_else(missing)?,
                local: var("LOCALAPPDATA").ok_or_else(missing)?,
                roaming: var("APPDATA").ok_or_else(missing)?,
            })
        }
        #[cfg(unix)]
        {
            let home =
                var("HOME").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no HOME"))?;
            Ok(Roots {
                local: home.clone(),
                roaming: home.clone(),
                home,
            })
        }
    }
}

pub fn locations(roots: &Roots) -> Vec<Location> {
    let mut out = Vec::new();
    #[cfg(target_os = "macos")]
    {
        let support = roots.home.join("Library/Application Support");
        for (browser, folder) in [
            ("Chrome", "Google/Chrome"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Edge", "Microsoft Edge"),
            ("Chromium", "Chromium"),
            ("Vivaldi", "Vivaldi"),
        ] {
            let profile = support.join(folder);
            out.push(Location {
                browser,
                family: Family::Chromium,
                hosts: Target::Folder(profile.join("NativeMessagingHosts")),
                profile,
            });
        }
        out.push(Location {
            browser: "Firefox",
            family: Family::Firefox,
            profile: support.join("Firefox"),
            hosts: Target::Folder(support.join("Mozilla/NativeMessagingHosts")),
        });
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.starts_with(&roots.home))
            .unwrap_or_else(|| roots.home.join(".config"));
        for (browser, folder) in [
            ("Chrome", "google-chrome"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Edge", "microsoft-edge"),
            ("Chromium", "chromium"),
            ("Vivaldi", "vivaldi"),
        ] {
            let profile = config.join(folder);
            out.push(Location {
                browser,
                family: Family::Chromium,
                hosts: Target::Folder(profile.join("NativeMessagingHosts")),
                profile,
            });
        }
        out.push(Location {
            browser: "Firefox",
            family: Family::Firefox,
            profile: roots.home.join(".mozilla/firefox"),
            hosts: Target::Folder(roots.home.join(".mozilla/native-messaging-hosts")),
        });
    }
    #[cfg(windows)]
    {
        for (browser, folder, key) in [
            (
                "Chrome",
                r"Google\Chrome\User Data",
                r"Software\Google\Chrome\NativeMessagingHosts",
            ),
            (
                "Brave",
                r"BraveSoftware\Brave-Browser\User Data",
                r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
            ),
            (
                "Edge",
                r"Microsoft\Edge\User Data",
                r"Software\Microsoft\Edge\NativeMessagingHosts",
            ),
            (
                "Chromium",
                r"Chromium\User Data",
                r"Software\Chromium\NativeMessagingHosts",
            ),
            (
                "Vivaldi",
                r"Vivaldi\User Data",
                r"Software\Vivaldi\NativeMessagingHosts",
            ),
        ] {
            out.push(Location {
                browser,
                family: Family::Chromium,
                profile: roots.local.join(folder),
                hosts: Target::Registry(key),
            });
        }
        out.push(Location {
            browser: "Firefox",
            family: Family::Firefox,
            profile: roots.roaming.join(r"Mozilla\Firefox"),
            hosts: Target::Registry(r"Software\Mozilla\NativeMessagingHosts"),
        });
    }
    out
}

/// Chromium forks on Windows also read Google Chrome's key, so it is written
/// when any Chromium-family profile exists (design decision 36).
#[cfg(windows)]
const CHROME_KEY: &str = r"Software\Google\Chrome\NativeMessagingHosts";

pub fn manifest(family: Family, name: &str, host: &Path) -> serde_json::Value {
    let mut value = json!({
        "name": name,
        "description": "CipherMoth desktop app",
        "path": host.to_string_lossy(),
        "type": "stdio",
    });
    match family {
        Family::Chromium => {
            value["allowed_origins"] = json!(CHROMIUM_IDS
                .iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect::<Vec<_>>())
        }
        Family::Firefox => value["allowed_extensions"] = json!(FIREFOX_IDS),
    }
    value
}

pub struct Installer {
    pub name: String,
    /// The native host binary the manifests point at.
    pub host: PathBuf,
    /// The app's link folder (Windows keeps the JSON files here).
    pub link_dir: PathBuf,
    pub roots: Roots,
}

fn write_private(path: &Path, value: &serde_json::Value) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&partial, path)
}

fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() || meta.file_type().is_symlink() => std::fs::remove_file(path),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl Installer {
    fn file_name(&self) -> String {
        format!("{}.json", self.name)
    }

    #[cfg(windows)]
    fn windows_manifest(&self, family: Family) -> PathBuf {
        let suffix = if family == Family::Firefox {
            "firefox"
        } else {
            "chromium"
        };
        self.link_dir
            .join("native-messaging")
            .join(format!("{}.{suffix}.json", self.name))
    }

    /// Write the manifests; returns the browsers they were written for.
    pub fn install(&self) -> io::Result<Vec<&'static str>> {
        let mut done = Vec::new();
        #[cfg(windows)]
        let mut chromium_seen = false;
        for location in locations(&self.roots) {
            if !location.profile.is_dir() {
                continue;
            }
            let value = manifest(location.family, &self.name, &self.host);
            match &location.hosts {
                Target::Folder(dir) => write_private(&dir.join(self.file_name()), &value)?,
                #[cfg(windows)]
                Target::Registry(key) => {
                    let file = self.windows_manifest(location.family);
                    write_private(&file, &value)?;
                    registry::set(&format!(r"{key}\{}", self.name), &file)?;
                    chromium_seen |= location.family == Family::Chromium;
                }
                #[cfg(not(windows))]
                Target::Registry(_) => unreachable!(),
            }
            done.push(location.browser);
        }
        #[cfg(windows)]
        if chromium_seen {
            registry::set(
                &format!(r"{CHROME_KEY}\{}", self.name),
                &self.windows_manifest(Family::Chromium),
            )?;
        }
        Ok(done)
    }

    /// Remove every manifest of this host name, wherever we may have put one.
    pub fn uninstall(&self) -> io::Result<()> {
        let mut first_error = None;
        for location in locations(&self.roots) {
            let result = match &location.hosts {
                Target::Folder(dir) => remove_file(&dir.join(self.file_name())),
                #[cfg(windows)]
                Target::Registry(key) => registry::delete(&format!(r"{key}\{}", self.name)),
                #[cfg(not(windows))]
                Target::Registry(_) => Ok(()),
            };
            if let Err(e) = result {
                first_error.get_or_insert(e);
            }
        }
        #[cfg(windows)]
        {
            for result in [
                registry::delete(&format!(r"{CHROME_KEY}\{}", self.name)),
                remove_file(&self.windows_manifest(Family::Chromium)),
                remove_file(&self.windows_manifest(Family::Firefox)),
            ] {
                if let Err(e) = result {
                    first_error.get_or_insert(e);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The browsers that currently have our manifest.
    pub fn installed(&self) -> Vec<&'static str> {
        locations(&self.roots)
            .into_iter()
            .filter(|location| match &location.hosts {
                Target::Folder(dir) => dir.join(self.file_name()).is_file(),
                #[cfg(windows)]
                Target::Registry(key) => registry::get(&format!(r"{key}\{}", self.name)).is_some(),
                #[cfg(not(windows))]
                Target::Registry(_) => false,
            })
            .map(|location| location.browser)
            .collect()
    }
}

#[cfg(windows)]
pub mod registry {
    use std::io;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetValueW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn check(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    /// Set the default value of `HKCU\<key>` to `path`.
    pub fn set(key: &str, path: &Path) -> io::Result<()> {
        let key = wide(key);
        let mut handle: HKEY = null_mut();
        // SAFETY: valid strings and out pointer.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                null(),
                &mut handle,
                null_mut(),
            )
        })?;
        let value = wide(&path.to_string_lossy());
        // SAFETY: REG_SZ of the stated byte length, including the NUL.
        let result = check(unsafe {
            RegSetValueExW(
                handle,
                null(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        });
        unsafe { RegCloseKey(handle) };
        result
    }

    pub fn get(key: &str) -> Option<String> {
        let key = wide(key);
        let mut buf = vec![0u16; 2048];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: buffer of the stated size.
        let code = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                null(),
                RRF_RT_REG_SZ,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if code != 0 {
            return None;
        }
        buf.truncate((size as usize / 2).saturating_sub(1));
        Some(String::from_utf16_lossy(&buf))
    }

    /// Delete `HKCU\<key>` (our host's own key; it has no subkeys).
    pub fn delete(key: &str) -> io::Result<()> {
        let key = wide(key);
        // SAFETY: valid string.
        match unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, key.as_ptr()) } {
            0 | 2 => Ok(()), // ERROR_FILE_NOT_FOUND: nothing to remove
            code => check(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installer(dir: &Path) -> Installer {
        Installer {
            name: format!("com.ciphermoth.desktop.test{}", std::process::id()),
            host: dir.join("bin/ciphermoth-native-host"),
            link_dir: dir.join("link"),
            roots: Roots {
                home: dir.join("home"),
                local: dir.join("local"),
                roaming: dir.join("roaming"),
            },
        }
    }

    #[test]
    fn manifests_name_only_our_extensions() {
        let chromium = manifest(
            Family::Chromium,
            "com.ciphermoth.desktop",
            Path::new("/a/host"),
        );
        assert_eq!(
            chromium["allowed_origins"],
            json!(["chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/"])
        );
        assert!(chromium.get("allowed_extensions").is_none());
        let firefox = manifest(
            Family::Firefox,
            "com.ciphermoth.desktop",
            Path::new("/a/host"),
        );
        assert_eq!(
            firefox["allowed_extensions"],
            json!(["ciphermoth@mr-grj.github.io"])
        );
        assert_eq!(firefox["type"], "stdio");
    }

    #[test]
    fn only_present_browsers_get_a_manifest_and_off_removes_all() {
        let dir = tempfile::tempdir().unwrap();
        let installer = installer(dir.path());
        assert!(
            installer.install().unwrap().is_empty(),
            "no browser profile, no manifest"
        );
        let all = locations(&installer.roots);
        let chrome = all.iter().find(|l| l.browser == "Chrome").unwrap();
        let firefox = all.iter().find(|l| l.browser == "Firefox").unwrap();
        std::fs::create_dir_all(&chrome.profile).unwrap();
        std::fs::create_dir_all(&firefox.profile).unwrap();
        let mut done = installer.install().unwrap();
        done.sort();
        assert_eq!(done, ["Chrome", "Firefox"]);
        let mut found = installer.installed();
        found.sort();
        assert_eq!(found, ["Chrome", "Firefox"]);
        #[cfg(unix)]
        if let Target::Folder(hosts) = &chrome.hosts {
            let written: serde_json::Value = serde_json::from_slice(
                &std::fs::read(hosts.join(format!("{}.json", installer.name))).unwrap(),
            )
            .unwrap();
            assert_eq!(written["path"], json!(installer.host.to_string_lossy()));
            assert!(!all
                .iter()
                .find(|l| l.browser == "Brave")
                .unwrap()
                .profile
                .exists());
        }
        installer.install().unwrap(); // idempotent
        installer.uninstall().unwrap();
        assert!(installer.installed().is_empty());
        installer.uninstall().unwrap(); // nothing left to remove is fine
    }
}
