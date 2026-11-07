//! Browser extensions in desktop mode (docs/EXTENSION.md, design 4.3).
//!
//! Settings → Browser extension → "Allow browser extensions" (off by default,
//! stored in the app's own folder, not the vault). On: the app records how to
//! start it (`launch.json`), writes the native-host manifests for the browsers
//! it finds and listens on its local endpoint. Off: it stops listening, closes
//! every connection, ends every extension session in the core and removes the
//! manifests. Pairings stay until the user removes them.
//!
//! The link itself (pairing, channel, requests) is in the
//! `ciphermoth-extension-link` crate; this module gives it the window (approval
//! dialog, bring to front, lock) and the core (unlocked?, open a session, call
//! `/api/extension/*`). Locking ends every extension session because it stops
//! the core; the tokens kept here are forgotten at the same moment.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use ciphermoth_extension_link::identity::{private_dir, Identity};
use ciphermoth_extension_link::ipc;
use ciphermoth_extension_link::manifests::{Installer, Roots};
use ciphermoth_extension_link::pairings::Store;
use ciphermoth_extension_link::server::{Desktop, Link, Refusal, Running};
use serde_json::{json, Value};
use tauri::{Emitter, Manager, State};

use crate::sidecar::Supervisor;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const CORE_TIMEOUT: Duration = Duration::from_secs(15);
const HOST: &str = if cfg!(windows) {
    "ciphermoth-native-host.exe"
} else {
    "ciphermoth-native-host"
};

fn identity() -> io::Result<Identity> {
    #[cfg(feature = "gui-test")]
    return Identity::qa_from_env();
    #[cfg(not(feature = "gui-test"))]
    Ok(if cfg!(debug_assertions) {
        Identity::Development
    } else {
        Identity::Production
    })
}

/// QA builds find browsers below their own root (the harness creates the
/// profile folders), so they never write into the runner's real profiles.
fn roots(identity: &Identity) -> io::Result<Roots> {
    match identity {
        Identity::Qa(root) => Ok(Roots {
            home: root.join("home"),
            local: root.join("local"),
            roaming: root.join("roaming"),
        }),
        _ => Roots::of_user(),
    }
}

struct Pending {
    id: u64,
    answer: mpsc::Sender<bool>,
}

pub struct AppDesktop {
    store: Store,
    app: tauri::AppHandle,
    next_approval: AtomicU64,
    pending: Mutex<Option<Pending>>,
}

impl AppDesktop {
    fn core(&self, header: Value, body: Vec<u8>) -> Result<(u16, Value), Refusal> {
        let core = self.app.state::<Arc<Supervisor>>();
        if core.status().state != "ready" {
            return Err(Refusal::Locked);
        }
        let reply = tauri::async_runtime::block_on(core.request(header, body, CORE_TIMEOUT, None));
        let (head, body) = reply.map_err(|_| Refusal::Failed)?;
        let status = head["status"].as_u64().unwrap_or(500) as u16;
        let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Ok((status, body))
    }

    fn cancel_approval(&self) {
        if let Some(pending) = self.pending.lock().unwrap().take() {
            let _ = pending.answer.send(false);
        }
    }

    fn answer(&self, id: u64, allow: bool) {
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|p| p.id == id) {
            let _ = pending.take().unwrap().answer.send(allow);
        }
    }
}

impl Desktop for AppDesktop {
    fn store(&self) -> &Store {
        &self.store
    }

    fn unlocked(&self) -> bool {
        matches!(self.core(json!({"native": "extension_status"}), Vec::new()),
            Ok((200, ref body)) if body["unlocked"] == true)
    }

    fn approve(&self, browser: &str, code: &str) -> bool {
        let id = self.next_approval.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::channel();
        if let Some(previous) = self
            .pending
            .lock()
            .unwrap()
            .replace(Pending { id, answer: tx })
        {
            let _ = previous.answer.send(false);
        }
        self.show();
        let _ = self.app.emit(
            "extension-pairing",
            json!({"id": id, "browser": browser, "code": code}),
        );
        let allowed = rx.recv_timeout(APPROVAL_TIMEOUT).unwrap_or(false);
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|p| p.id == id) {
            pending.take();
        }
        drop(pending);
        let _ = self.app.emit("extension-pairing-closed", json!({"id": id}));
        allowed
    }

    fn open_session(&self, browser: &str, client: &str) -> Result<String, Refusal> {
        let header = json!({"native": "extension_open", "browser": browser, "client": client});
        match self.core(header, Vec::new())? {
            (200, body) => body["session_token"]
                .as_str()
                .map(str::to_string)
                .ok_or(Refusal::Failed),
            (401, _) => Err(Refusal::Locked),
            _ => Err(Refusal::Failed),
        }
    }

    fn api(&self, token: &str, route: &str, body: &Value) -> Result<(u16, Value), Refusal> {
        let header = json!({
            "method": "POST",
            "path": format!("/api/extension/{route}"),
            "query": "",
            "headers": [["content-type", "application/json"], ["x-ciphermoth-session", token]],
        });
        self.core(
            header,
            serde_json::to_vec(body).map_err(|_| Refusal::Failed)?,
        )
    }

    fn end_sessions(&self, client: &str) {
        let _ = self.core(
            json!({"native": "extension_end", "client": client}),
            Vec::new(),
        );
    }

    fn show(&self) {
        if let Some(window) = self.app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }

    fn lock(&self) {
        crate::lock::lock();
    }
}

pub struct Extension {
    identity: Identity,
    link: Arc<Link<AppDesktop>>,
    running: Mutex<Option<Running>>,
    error: Mutex<Option<String>>,
    /// The browsers with a manifest, as of the last enable/disable (Settings
    /// polls the status; the locations are not scanned each time).
    browsers: Mutex<Vec<&'static str>>,
}

fn message(error: io::Error) -> String {
    match error.kind() {
        io::ErrorKind::AddrInUse => {
            "Another CipherMoth window already answers browser extensions.".into()
        }
        _ => format!("Browser extensions could not be set up ({}).", error.kind()),
    }
}

impl Extension {
    pub fn start(app: &tauri::AppHandle) -> io::Result<Arc<Extension>> {
        let identity = identity()?;
        let store = Store::open(&identity.link_dir()?)?;
        let desktop = AppDesktop {
            store,
            app: app.clone(),
            next_approval: AtomicU64::new(0),
            pending: Mutex::new(None),
        };
        let extension = Arc::new(Extension {
            identity,
            link: Link::new(desktop),
            running: Mutex::new(None),
            browsers: Mutex::new(Vec::new()),
            error: Mutex::new(None),
        });
        if extension.link.desktop().store.enabled() {
            // Rewritten on every start: a browser installed since, a moved app.
            if let Err(error) = extension.enable() {
                *extension.error.lock().unwrap() = Some(message(error));
            }
        }
        Ok(extension)
    }

    fn installer(&self) -> io::Result<Installer> {
        Ok(Installer {
            name: self.identity.host_name().to_string(),
            host: self.host()?,
            link_dir: self.identity.link_dir()?,
            roots: roots(&self.identity)?,
        })
    }

    /// The host next to the app's executable; an AppImage's mount path changes
    /// on every start, so it gets a copy in the app's folder (decision 42).
    fn host(&self) -> io::Result<PathBuf> {
        let bundled = std::env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no app folder"))?
            .join(HOST);
        if !bundled.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the native host is missing",
            ));
        }
        #[cfg(target_os = "linux")]
        if std::env::var_os("APPIMAGE").is_some() {
            let dir = self.identity.link_dir()?.join("native-host");
            private_dir(&dir)?;
            let copy = dir.join(HOST);
            let partial = dir.join(format!(".{HOST}.partial"));
            std::fs::copy(&bundled, &partial)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o700))?;
            std::fs::rename(&partial, &copy)?;
            return Ok(copy);
        }
        Ok(bundled)
    }

    /// How the host starts this app ("Open CipherMoth" in the popup).
    fn write_launch(&self) -> io::Result<()> {
        let program = std::env::var_os("APPIMAGE")
            .filter(|_| cfg!(target_os = "linux"))
            .map(PathBuf::from)
            .map_or_else(std::env::current_exe, Ok)?;
        let args: Vec<String> = match &self.identity {
            Identity::Qa(root) => vec!["--qa-root".into(), root.to_string_lossy().into_owned()],
            _ => Vec::new(),
        };
        let dir = self.identity.link_dir()?;
        private_dir(&dir)?;
        let partial = dir.join(".launch.json.partial");
        std::fs::write(
            &partial,
            serde_json::to_vec(&json!({"program": program, "args": args}))?,
        )?;
        std::fs::rename(&partial, dir.join("launch.json"))
    }

    fn enable(&self) -> io::Result<()> {
        self.write_launch()?;
        *self.browsers.lock().unwrap() = self.installer()?.install()?;
        let mut running = self.running.lock().unwrap();
        if running.is_none() {
            *running = Some(self.link.start(&ipc::endpoint(&self.identity)?)?);
        }
        Ok(())
    }

    fn disable(&self) -> io::Result<()> {
        if let Some(running) = self.running.lock().unwrap().take() {
            running.stop();
        }
        self.link.close_connections();
        self.link.forget_sessions();
        self.link.desktop().cancel_approval();
        let _ = self
            .link
            .desktop()
            .core(json!({"native": "extension_end"}), Vec::new());
        let removed = self.installer()?.uninstall();
        *self.browsers.lock().unwrap() = self.installer()?.installed();
        removed
    }

    /// The vault locked (or the core stopped): every token is dead already.
    pub fn on_lock(&self) {
        self.link.forget_sessions();
        self.link.desktop().cancel_approval();
    }

    /// The app quits: stop listening (removes the socket), keep the switch.
    pub fn shutdown(&self) {
        if let Some(running) = self.running.lock().unwrap().take() {
            running.stop();
        }
        self.link.close_connections();
    }

    fn status(&self) -> Value {
        let store = &self.link.desktop().store;
        json!({
            "enabled": store.enabled(),
            "listening": self.running.lock().unwrap().is_some(),
            "browsers": *self.browsers.lock().unwrap(),
            "pairings": store.list(),
            "error": *self.error.lock().unwrap(),
        })
    }
}

#[tauri::command]
pub fn extension_status(extension: State<'_, Arc<Extension>>) -> Value {
    extension.status()
}

#[tauri::command]
pub async fn extension_set_enabled(
    enabled: bool,
    extension: State<'_, Arc<Extension>>,
) -> Result<Value, String> {
    let extension = extension.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = &extension.link.desktop().store;
        let result = if enabled {
            store.set_enabled(true).and_then(|()| extension.enable())
        } else {
            store.set_enabled(false).and_then(|()| extension.disable())
        };
        *extension.error.lock().unwrap() = result.err().map(message);
        extension.status()
    })
    .await
    .map_err(|_| "The setting could not be changed.".to_string())
}

#[tauri::command]
pub async fn extension_unpair(
    id: String,
    extension: State<'_, Arc<Extension>>,
) -> Result<Value, String> {
    let extension = extension.inner().clone();
    // Off the main thread: it waits for the core.
    tauri::async_runtime::spawn_blocking(move || {
        let desktop = extension.link.desktop();
        desktop
            .store
            .remove(&id)
            .map_err(|_| "The browser could not be removed.".to_string())?;
        extension.link.forget_pairing(&id);
        // Its open connection still holds the pairing: close them all (the
        // others reconnect on their next request) and end its session.
        extension.link.close_connections();
        let _ = desktop.core(json!({"native": "extension_end", "client": id}), Vec::new());
        Ok(extension.status())
    })
    .await
    .map_err(|_| "The browser could not be removed.".to_string())?
}

#[tauri::command]
pub fn extension_pairing_answer(id: u64, allow: bool, extension: State<'_, Arc<Extension>>) {
    extension.link.desktop().answer(id, allow);
}
