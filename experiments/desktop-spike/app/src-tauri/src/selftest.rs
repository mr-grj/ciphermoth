use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager, State};

use crate::sidecar::Status;

pub struct Selftest {
    scenario: Option<String>,
    report: Option<PathBuf>,
    launched: Instant,
    app: AppHandle,
    marks: Mutex<Map<String, Value>>,
    triggered: Mutex<bool>,
}

impl Selftest {
    pub fn from_env(app: AppHandle, launched: Instant) -> Self {
        let enabled = cfg!(feature = "selftest");
        Self {
            scenario: std::env::var("CIPHERMOTH_SPIKE_SCENARIO")
                .ok()
                .filter(|_| enabled),
            report: std::env::var_os("CIPHERMOTH_SPIKE_REPORT")
                .map(PathBuf::from)
                .filter(|_| enabled),
            launched,
            app,
            marks: Mutex::new(Map::new()),
            triggered: Mutex::new(false),
        }
    }

    pub fn active(&self) -> bool {
        self.scenario.is_some()
    }

    fn mark(&self, name: &str, value: Value) {
        self.marks.lock().unwrap().insert(name.into(), value);
    }

    fn write(&self, extra: Value) {
        let Some(path) = &self.report else { return };
        let report = json!({
            "scenario": self.scenario,
            "app_pid": std::process::id(),
            "since_launch_ms": self.launched.elapsed().as_millis(),
            "marks": Value::Object(self.marks.lock().unwrap().clone()),
            "result": extra,
        });
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(&report).unwrap()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    pub fn on_core_status(&self, status: &Status) {
        if self.scenario.is_none() {
            return;
        }
        if status.state == "failed" {
            self.mark("core_failed", json!(status.reason));
            self.write(json!({"ok": false, "failed": status.reason}));
            return;
        }
        if status.state == "ready" && !self.marks.lock().unwrap().contains_key("core_ready") {
            self.mark(
                "core_ready",
                json!({
                    "since_launch_ms": self.launched.elapsed().as_millis(),
                    "spawn_to_ready_ms": status.ready_ms,
                    "core_pid": status.info.as_ref().and_then(|i| i.get("pid")).cloned(),
                    "core_startup_ms": status.info.as_ref().and_then(|i| i.get("startup_ms")).cloned(),
                }),
            );
        }
        self.maybe_trigger();
    }

    fn maybe_trigger(&self) {
        let ready = {
            let marks = self.marks.lock().unwrap();
            marks.contains_key("core_ready") && marks.contains_key("ui_ready")
        };
        let scenario = self.scenario.as_deref().unwrap_or("");
        if !ready || scenario == "ipc" {
            return;
        }
        {
            let mut triggered = self.triggered.lock().unwrap();
            if *triggered {
                return;
            }
            *triggered = true;
        }
        self.write(json!({"ok": true}));
        let app = self.app.clone();
        match scenario {
            "quit" => {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    app.exit(0);
                });
            }
            "close" => {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.close();
                    }
                });
            }
            _ => {}
        }
    }
}

#[tauri::command]
pub fn selftest_scenario(selftest: State<'_, Arc<Selftest>>) -> Result<String, String> {
    selftest.scenario.clone().ok_or_else(|| "off".into())
}

#[tauri::command]
pub fn selftest_mark(name: String, ms: f64, selftest: State<'_, Arc<Selftest>>) {
    if selftest.active() && name.len() < 512 {
        selftest.mark(
            &name,
            json!({"js_ms": ms, "since_launch_ms": selftest.launched.elapsed().as_millis()}),
        );
        selftest.maybe_trigger();
        if selftest.scenario.as_deref() == Some("ipc") {
            selftest.write(json!({"partial": true}));
        }
    }
}

#[tauri::command]
pub fn selftest_finish(report: String, selftest: State<'_, Arc<Selftest>>, app: AppHandle) {
    if !selftest.active() {
        return;
    }
    let parsed: Value = serde_json::from_str(&report).unwrap_or(Value::Null);
    selftest.write(parsed);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        app.exit(0);
    });
}
