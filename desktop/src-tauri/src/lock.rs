use crate::{clipboard::Clipboard, sidecar::Supervisor};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};
static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
static POLICY: Mutex<Policy> = Mutex::new(Policy {
    epoch: 0,
    deadline: None,
    hidden_since: None,
    hidden_ms: 60_000,
});

struct Policy {
    epoch: u64,
    deadline: Option<Instant>,
    hidden_since: Option<Instant>,
    hidden_ms: u64,
}

pub fn epoch() -> u64 {
    POLICY.lock().unwrap().epoch
}

pub fn observe(epoch: u64, sent_at: Instant, head: &serde_json::Value, settings: Option<&[u8]>) {
    let mut policy = POLICY.lock().unwrap();
    if policy.epoch != epoch {
        return;
    }
    if let Some(ms) = head["session"]["expires_in_ms"].as_u64() {
        // Anchor conservatively before the request. A delayed response must
        // never extend a native deadline by its transport/queueing delay.
        policy.deadline = Some(sent_at + Duration::from_millis(ms.min(43_200_000)));
    }
    if head["status"].as_u64() == Some(200) {
        if let Some(body) = settings {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                if let Some(ms) = value["hidden_ms"].as_u64() {
                    policy.hidden_ms = ms;
                }
            }
        }
    }
}

impl Policy {
    fn expired(&mut self, now: Instant, hidden: bool) -> bool {
        let Some(deadline) = self.deadline else {
            return false;
        };
        if hidden {
            self.hidden_since.get_or_insert(now);
        } else {
            self.hidden_since = None;
        }
        now >= deadline
            || self.hidden_since.is_some_and(|since| {
                now.duration_since(since).as_millis() >= self.hidden_ms as u128
            })
    }
}
#[cfg(target_os = "macos")]
extern "C" {
    fn cm_observe_lock(callback: extern "C" fn());
}
pub(super) extern "C" fn lock() {
    if let Some(app) = APP.get() {
        reset_renderer(app);
        app.state::<Arc<Clipboard>>().clear();
        // Kill the process that owns all keys and pending KDFs, independent of
        // the renderer event loop. SQLite rolls back any unfinished write.
        app.state::<Arc<Supervisor>>().lock();
        let _ = app.emit("vault-locked", ());
    }
}
pub fn install(app: tauri::AppHandle) {
    let _ = APP.set(app);
    #[cfg(target_os = "macos")]
    unsafe {
        cm_observe_lock(lock);
    }
    // A wall-clock gap also locks on resume if a platform notification was lost.
    std::thread::spawn(|| {
        let mut previous = std::time::SystemTime::now();
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let now = std::time::SystemTime::now();
            if now.duration_since(previous).unwrap_or_default().as_secs() > 8 {
                lock();
            }
            previous = now;
            if let Some(app) = APP.get() {
                let hidden = app.get_webview_window("main").is_some_and(|window| {
                    !window.is_visible().unwrap_or(true) || window.is_minimized().unwrap_or(false)
                });
                let expired = POLICY.lock().unwrap().expired(Instant::now(), hidden);
                if expired {
                    lock();
                }
            }
        }
    });
}

#[tauri::command]
pub fn vault_lock() {
    lock();
}

pub fn reset_renderer(app: &tauri::AppHandle) {
    {
        let mut policy = POLICY.lock().unwrap();
        policy.epoch += 1;
        policy.deadline = None;
        policy.hidden_since = None;
    }
    if let Some(files) = app.try_state::<crate::native::Files>() {
        files.invalidate();
    }
    if let Some(extension) = app.try_state::<Arc<crate::extension::Extension>>() {
        extension.on_lock();
    }
    if let Some(window) = app.get_webview_window("main") {
        // Hide stale decrypted DOM before asking the webview to load a fresh
        // document. No JavaScript callback is needed to remove it from view.
        let _ = window.hide();
        if let Ok(mut url) = window.url() {
            url.set_path("/login");
            url.set_query(None);
            url.set_fragment(None);
            let _ = window.navigate(url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_deadlines_expire_without_renderer_callbacks() {
        let now = Instant::now();
        let mut policy = Policy {
            epoch: 0,
            deadline: Some(now + Duration::from_secs(5)),
            hidden_since: None,
            hidden_ms: 1000,
        };
        assert!(!policy.expired(now, true));
        assert!(policy.expired(now + Duration::from_secs(1), true));
        assert!(!policy.expired(now + Duration::from_secs(2), false));
        assert!(policy.expired(now + Duration::from_secs(5), false));
    }
}
