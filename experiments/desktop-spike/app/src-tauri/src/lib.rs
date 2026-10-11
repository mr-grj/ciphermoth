mod commands;
#[cfg(windows)]
mod job;
mod protocol;
mod selftest;
mod sidecar;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use tauri::{Emitter, Manager, RunEvent};

use crate::sidecar::{CoreConfig, Supervisor};

pub static LAUNCHED: OnceLock<Instant> = OnceLock::new();

const CORE_EXE: &str = if cfg!(windows) {
    "ciphermoth-core.exe"
} else {
    "ciphermoth-core"
};

const PASSTHROUGH_ENV: &[&str] = if cfg!(windows) {
    &[
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "USERPROFILE",
    ]
} else {
    &["HOME", "TMPDIR", "LANG"]
};

const SPIKE_ENV: &[&str] = &[
    "CIPHERMOTH_SPIKE_TEST_HOOKS",
    "CIPHERMOTH_SPIKE_FAIL_STARTUP",
];

fn core_executable(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        if let Ok(path) = std::env::var("CIPHERMOTH_CORE_PATH") {
            return Ok(PathBuf::from(path));
        }
    }
    app.path()
        .resource_dir()
        .map(|dir| dir.join("core").join(CORE_EXE))
        .map_err(|error| format!("cannot locate the bundled core: {error}"))
}

fn core_config(app: &tauri::AppHandle) -> CoreConfig {
    let base = std::env::var_os("CIPHERMOTH_SPIKE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            app.path()
                .app_local_data_dir()
                .expect("app data dir")
                .join("spike-vault")
        });
    let mut env: Vec<(String, String)> = PASSTHROUGH_ENV
        .iter()
        .chain(SPIKE_ENV.iter())
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| (name.to_string(), value))
        })
        .collect();
    env.push((
        "PATH".into(),
        if cfg!(windows) {
            std::env::var("SYSTEMROOT")
                .map(|r| format!("{r}\\System32"))
                .unwrap_or_default()
        } else {
            "/usr/bin:/bin".into()
        },
    ));
    CoreConfig {
        executable: core_executable(app),
        data_dir: base.join("data"),
        log_dir: base.join("logs"),
        env,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let launched = *LAUNCHED.get_or_init(Instant::now);
    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::core_request,
            commands::core_cancel,
            commands::core_status,
            commands::core_restart,
            selftest::selftest_scenario,
            selftest::selftest_mark,
            selftest::selftest_finish,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let selftest = Arc::new(selftest::Selftest::from_env(handle.clone(), launched));
            app.manage(selftest.clone());
            #[cfg(feature = "selftest")]
            if selftest.active() {
                app.add_capability(include_str!("../capabilities/selftest.json"))?;
            }
            let emitter = handle.clone();
            let observer = selftest.clone();
            let supervisor = Supervisor::start(core_config(&handle), launched, move |status| {
                let _ = emitter.emit("core-status", status);
                observer.on_core_status(status);
            });
            app.manage(supervisor);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the app");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(supervisor) = handle.try_state::<Arc<Supervisor>>() {
                supervisor.shutdown();
            }
        }
    });
}
