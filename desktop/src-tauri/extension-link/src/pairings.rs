//! The desktop app's own extension settings (not the vault): the "Allow
//! browser extensions" switch and the paired browsers. One JSON file, `0600`
//! in the `0700` link folder, replaced atomically.
//!
//! A pairing key is a secret (design decision 43): it lets a browser ask the
//! unlocked app for logins. Anyone who can read this file runs as the user and
//! could read the browser's memory as well, which the threat model already
//! leaves out (design section 7).

use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::wire::{b64, unb64};

pub const MAX_PAIRINGS: usize = 16;
const VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    pub id: String,
    pub browser: String,
    key: String,
    pub created: u64,
    pub last_used: Option<u64>,
}

impl Pairing {
    pub fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let raw = Zeroizing::new(unb64(&self.key)?);
        let key: [u8; 32] = raw.as_slice().try_into().ok()?;
        Some(Zeroizing::new(key))
    }

    pub fn id_bytes(&self) -> Option<[u8; 16]> {
        unb64(&self.id)?.try_into().ok()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    enabled: bool,
    pairings: Vec<Pairing>,
}

/// What Settings shows; never the key.
#[derive(Clone, Serialize, Debug, PartialEq)]
pub struct PairingInfo {
    pub id: String,
    pub browser: String,
    pub created: u64,
    pub last_used: Option<u64>,
}

pub struct Store {
    path: PathBuf,
    config: Mutex<Config>,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Store {
    /// Open the settings in `dir`. A file this version cannot read is moved
    /// aside (never deleted) and the switch starts off.
    pub fn open(dir: &Path) -> io::Result<Store> {
        crate::identity::private_dir(dir)?;
        let path = dir.join("config.json");
        let config = match std::fs::read(&path) {
            Ok(raw) => match serde_json::from_slice::<Config>(&raw) {
                Ok(config) if config.version == VERSION => config,
                _ => {
                    let aside = dir.join(format!("config.json.unreadable-{}", now()));
                    std::fs::rename(&path, aside)?;
                    Config {
                        version: VERSION,
                        ..Config::default()
                    }
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Config {
                version: VERSION,
                ..Config::default()
            },
            Err(e) => return Err(e),
        };
        Ok(Store {
            path,
            config: Mutex::new(config),
        })
    }

    fn save(&self, config: &Config) -> io::Result<()> {
        let dir = self.path.parent().expect("config has a folder");
        let partial = dir.join(format!(
            ".config.json.{}.partial",
            crate::wire::b64(&crate::channel::random::<6>())
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let result = (|| {
            let mut file = options.open(&partial)?;
            file.write_all(&serde_json::to_vec_pretty(config)?)?;
            file.sync_all()?;
            std::fs::rename(&partial, &self.path)?;
            #[cfg(unix)]
            std::fs::File::open(dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        result
    }

    fn change<T>(&self, f: impl FnOnce(&mut Config) -> T) -> io::Result<T> {
        let mut config = self.config.lock().unwrap();
        let mut next = config.clone();
        let out = f(&mut next);
        if next != *config {
            self.save(&next)?;
            *config = next;
        }
        Ok(out)
    }

    pub fn enabled(&self) -> bool {
        self.config.lock().unwrap().enabled
    }

    pub fn set_enabled(&self, enabled: bool) -> io::Result<()> {
        self.change(|c| c.enabled = enabled)
    }

    /// Store a new pairing and return its id. Past the limit, the pairing used
    /// longest ago is dropped.
    pub fn add(&self, browser: &str, key: &[u8; 32]) -> io::Result<String> {
        let id = b64(&crate::channel::random::<16>());
        self.add_with_id(&id, browser, key)?;
        Ok(id)
    }

    /// Store a pairing under `id`; returns the ids of pairings dropped to make
    /// room (their holders must be disconnected).
    pub fn add_with_id(&self, id: &str, browser: &str, key: &[u8; 32]) -> io::Result<Vec<String>> {
        let pairing = Pairing {
            id: id.to_string(),
            browser: browser.to_string(),
            key: b64(key),
            created: now(),
            last_used: None,
        };
        self.change(|c| {
            let mut evicted = Vec::new();
            while c.pairings.len() >= MAX_PAIRINGS {
                let oldest = (0..c.pairings.len())
                    .min_by_key(|&i| c.pairings[i].last_used.unwrap_or(c.pairings[i].created))
                    .unwrap();
                evicted.push(c.pairings.remove(oldest).id);
            }
            c.pairings.push(pairing);
            evicted
        })
    }

    pub fn find(&self, id: &str) -> Option<Pairing> {
        self.config
            .lock()
            .unwrap()
            .pairings
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }

    /// Record use; written at most once a minute per pairing (every
    /// connection calls it).
    pub fn touch(&self, id: &str) -> io::Result<()> {
        let at = now();
        self.change(|c| {
            if let Some(p) = c.pairings.iter_mut().find(|p| p.id == id) {
                if p.last_used.is_none_or(|last| at.saturating_sub(last) >= 60) {
                    p.last_used = Some(at);
                }
            }
        })
    }

    pub fn remove(&self, id: &str) -> io::Result<bool> {
        self.change(|c| {
            let before = c.pairings.len();
            c.pairings.retain(|p| p.id != id);
            before != c.pairings.len()
        })
    }

    pub fn list(&self) -> Vec<PairingInfo> {
        self.config
            .lock()
            .unwrap()
            .pairings
            .iter()
            .map(|p| PairingInfo {
                id: p.id.clone(),
                browser: p.browser.clone(),
                created: p.created,
                last_used: p.last_used,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairings_persist_privately_and_list_without_keys() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("browser-extension");
        let store = Store::open(&link).unwrap();
        assert!(!store.enabled(), "off by default");
        store.set_enabled(true).unwrap();
        let id = store.add("Chrome", &[7; 32]).unwrap();
        store.touch(&id).unwrap();
        let again = Store::open(&link).unwrap();
        assert!(again.enabled());
        let found = again.find(&id).unwrap();
        assert_eq!(*found.key().unwrap(), [7; 32]);
        assert!(found.last_used.is_some());
        let listed = serde_json::to_string(&again.list()).unwrap();
        assert!(listed.contains("Chrome") && !listed.contains(&b64(&[7; 32])));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(link.join("config.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(again.remove(&id).unwrap());
        assert!(!again.remove(&id).unwrap());
        assert!(Store::open(&link).unwrap().find(&id).is_none());
    }

    #[test]
    fn the_oldest_pairing_makes_room() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let first = store.add("Chrome", &[1; 32]).unwrap();
        for _ in 1..MAX_PAIRINGS {
            let id = store.add("Firefox", &[2; 32]).unwrap();
            store.touch(&id).unwrap();
        }
        store.add("Brave", &[3; 32]).unwrap();
        assert_eq!(store.list().len(), MAX_PAIRINGS);
        assert!(store.find(&first).is_none());
    }

    #[test]
    fn an_unreadable_file_is_kept_aside_and_the_switch_is_off() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            b"{\"enabled\": true, \"surprise\": 1}",
        )
        .unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(!store.enabled());
        let kept: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.json.unreadable-")
            })
            .collect();
        assert_eq!(kept.len(), 1);
    }
}
