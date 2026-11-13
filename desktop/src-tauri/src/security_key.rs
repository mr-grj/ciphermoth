//! FIDO2 security keys for the desktop app. The web view has no WebAuthn, so each
//! operation runs the bundled core once in `--security-key` mode, which talks to
//! the key over USB (CTAP2) and answers with what a browser would. The request,
//! including the key's PIN, goes over the child's stdin, never its command line.
//! Cancelling kills the child, which also stops the key from waiting for a touch.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::State;

use crate::sidecar::CoreConfig;

const MAX_REQUEST: usize = 48 * 1024;
const MAX_REPLY: u64 = 64 * 1024;
const MAX_PIN: usize = 255;
// The core gives up on its own (key wait and WebAuthn timeout); this is a backstop.
const DEADLINE: Duration = Duration::from_secs(240);

struct Running {
    child: Child,
    operation: Arc<()>,
}

pub struct SecurityKeys {
    executable: Result<PathBuf, String>,
    args: Vec<PathBuf>,
    env: Vec<(String, String)>,
    working_dir: PathBuf,
    running: Mutex<Option<Running>>,
}

impl SecurityKeys {
    pub fn new(config: CoreConfig) -> Arc<Self> {
        Arc::new(Self {
            executable: config.executable,
            args: config.args,
            env: config.env,
            working_dir: config.data_dir,
            running: Mutex::new(None),
        })
    }

    fn run(self: &Arc<Self>, request: Value) -> Result<Value, String> {
        let body = serde_json::to_vec(&request).map_err(|_| "Invalid request.".to_string())?;
        if body.len() > MAX_REQUEST {
            return Err("Invalid request.".into());
        }
        let executable = self.executable.clone()?;
        let mut command = Command::new(executable);
        command
            .args(&self.args)
            .arg("--security-key")
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(&self.working_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let operation = Arc::new(());
        let mut stdout = {
            let mut running = self.running.lock().unwrap();
            if running.is_some() {
                return Err("Another security key request is still waiting.".into());
            }
            let mut child = command
                .spawn()
                .map_err(|_| "The security key could not be used.".to_string())?;
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            *running = Some(Running {
                child,
                operation: operation.clone(),
            });
            let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
                drop(running);
                self.cancel_operation(&operation);
                return Err("The security key could not be used.".into());
            };
            if stdin.write_all(&body).is_err() {
                drop(running);
                self.cancel_operation(&operation);
                return Err("The security key could not be used.".into());
            }
            stdout
        };
        let watchdog = Arc::downgrade(self);
        let watched_operation = operation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(DEADLINE);
            if let Some(keys) = watchdog.upgrade() {
                keys.cancel_operation(&watched_operation);
            }
        });
        let mut reply = Vec::new();
        let read = (&mut stdout).take(MAX_REPLY + 1).read_to_end(&mut reply);
        drop(stdout);
        if read.is_err() || reply.len() > MAX_REPLY as usize {
            self.cancel_operation(&operation);
            return Err("The security key could not be used.".into());
        }
        let finished = self.finish(&operation);
        let Some(mut child) = finished else {
            return Err("cancelled".into());
        };
        let _ = child.wait();
        let reply: Value =
            serde_json::from_slice(&reply).map_err(|_| "The security key could not be used.")?;
        if let Some(result) = reply.get("ok") {
            return Ok(result.clone());
        }
        Err(match reply["error"].as_str() {
            Some("cancelled") => "cancelled".into(),
            Some("pin-invalid") => "pin-invalid".into(),
            _ => reply["message"]
                .as_str()
                .unwrap_or("The security key could not be used.")
                .chars()
                .take(300)
                .collect(),
        })
    }

    // A cancelled request can finish reading after a replacement has started.
    // Its completion and watchdog must only consume its own child.
    fn finish(&self, operation: &Arc<()>) -> Option<Child> {
        let mut running = self.running.lock().unwrap();
        if running
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.operation, operation))
        {
            running.take().map(|current| current.child)
        } else {
            None
        }
    }

    fn cancel_operation(&self, operation: &Arc<()>) {
        if let Some(mut child) = self.finish(operation) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn cancel(&self) {
        if let Some(Running { mut child, .. }) = self.running.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn checked_pin(pin: Option<String>) -> Result<Option<String>, String> {
    match pin {
        Some(pin) if pin.len() > MAX_PIN => Err("Invalid PIN.".into()),
        Some(pin) if pin.is_empty() => Ok(None),
        other => Ok(other),
    }
}

async fn blocking(keys: Arc<SecurityKeys>, request: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || keys.run(request))
        .await
        .map_err(|_| "The security key could not be used.".to_string())?
}

#[tauri::command]
pub async fn security_key_register(
    options: Value,
    pin: Option<String>,
    keys: State<'_, Arc<SecurityKeys>>,
) -> Result<Value, String> {
    let pin = checked_pin(pin)?;
    blocking(
        keys.inner().clone(),
        json!({"op": "register", "options": options, "pin": pin}),
    )
    .await
}

#[tauri::command]
pub async fn security_key_answer(
    challenge: Value,
    pin: Option<String>,
    keys: State<'_, Arc<SecurityKeys>>,
) -> Result<Value, String> {
    let pin = checked_pin(pin)?;
    blocking(
        keys.inner().clone(),
        json!({"op": "answer", "challenge": challenge, "pin": pin}),
    )
    .await
}

#[tauri::command]
pub fn security_key_cancel(keys: State<'_, Arc<SecurityKeys>>) {
    keys.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn stale_key_request_completion_and_timeout_leave_the_current_child_running() {
        let keys = SecurityKeys::new(CoreConfig {
            executable: Err("unused by this lifecycle test".into()),
            args: vec![],
            env: vec![],
            data_dir: std::env::temp_dir(),
            log_dir: std::env::temp_dir(),
        });
        let old = Arc::new(());
        let current = Arc::new(());
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        *keys.running.lock().unwrap() = Some(Running {
            child,
            operation: current.clone(),
        });
        let stale_completion = keys.finish(&old).is_none();
        keys.cancel_operation(&old);
        let still_running = keys
            .running
            .lock()
            .unwrap()
            .as_mut()
            .is_some_and(|run| run.child.try_wait().unwrap().is_none());
        let matching = keys.finish(&current);
        let matched = matching.is_some();
        // Reap even when an assertion will fail; never leave the test child behind.
        if let Some(mut child) = matching {
            let _ = child.kill();
            let _ = child.wait();
        }
        keys.cancel();
        assert!(stale_completion);
        assert!(still_running, "an old request stopped its replacement");
        assert!(
            matched,
            "the active request could not collect its own child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn oversized_key_replies_are_refused_and_the_child_is_reaped() {
        let keys = SecurityKeys::new(CoreConfig {
            executable: Ok("/bin/sh".into()),
            args: vec!["-c".into(), "head -c 65537 /dev/zero; exec sleep 3".into()],
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            data_dir: std::env::temp_dir(),
            log_dir: std::env::temp_dir(),
        });
        let started = std::time::Instant::now();
        assert!(keys.run(json!({})).is_err());
        assert!(keys.running.lock().unwrap().is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "oversized reply waited for child exit"
        );
    }

    #[test]
    fn pins_are_bounded_and_empty_means_none() {
        assert_eq!(checked_pin(Some(String::new())).unwrap(), None);
        assert_eq!(checked_pin(None).unwrap(), None);
        assert_eq!(
            checked_pin(Some("123456".into())).unwrap().as_deref(),
            Some("123456")
        );
        assert!(checked_pin(Some("1".repeat(256))).is_err());
    }
}
