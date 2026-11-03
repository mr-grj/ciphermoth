mod biometric;
mod clipboard;
mod commands;
#[cfg(windows)]
mod job;
mod lock;
#[cfg(target_os = "linux")]
mod lock_linux;
#[cfg(windows)]
mod lock_windows;
mod menu;
mod native;
mod protocol;
#[cfg(feature = "gui-test")]
mod qa;
mod sidecar;
mod updates;

use sidecar::{CoreConfig, Supervisor};
use std::sync::Arc;
use std::time::Instant;
use tauri::{Emitter, Manager, RunEvent};

fn core_config(app: &tauri::AppHandle) -> Result<CoreConfig, Box<dyn std::error::Error>> {
    #[cfg(all(feature = "gui-test", debug_assertions))]
    let _ = app;
    #[cfg(not(feature = "gui-test"))]
    let base = app.path().app_local_data_dir()?;
    #[cfg(feature = "gui-test")]
    let base = std::path::PathBuf::from(std::env::var("CIPHERMOTH_QA_ROOT")?);
    if !base.is_absolute() {
        return Err("Application data location must be absolute".into());
    }
    // Development has a separate identity and never opens an alpha user vault.
    let base = if cfg!(debug_assertions) {
        base.join("development")
    } else {
        base
    };
    #[cfg(not(debug_assertions))]
    let (executable, args) = {
        let resources = app.path().resource_dir()?.canonicalize()?;
        let executable = resources.join("core").join(if cfg!(windows) {
            "ciphermoth-core.exe"
        } else {
            "ciphermoth-core"
        });
        let executable = executable
            .canonicalize()
            .map_err(|_| "The bundled vault core is missing.".to_string())
            .and_then(|path| {
                if path.starts_with(&resources) {
                    Ok(path)
                } else {
                    Err("The bundled core is outside the application.".into())
                }
            });
        (executable, Vec::new())
    };
    #[cfg(debug_assertions)]
    let (executable, args) = {
        let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../core");
        let python = core.join(if cfg!(windows) {
            "build/venv/Scripts/python.exe"
        } else {
            "build/venv/bin/python"
        });
        (
            if python.is_file() {
                Ok(python)
            } else {
                Err("Run make desktop-setup first.".into())
            },
            vec![core.join("core_main.py")],
        )
    };
    let names = if cfg!(windows) {
        vec![
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "LOCALAPPDATA",
            "USERPROFILE",
        ]
    } else {
        vec!["HOME", "TMPDIR", "LANG"]
    };
    let env = names
        .into_iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.into(), value)))
        .collect();
    Ok(CoreConfig {
        executable,
        args,
        data_dir: base.join("data"),
        log_dir: base.join("logs"),
        env,
    })
}

pub fn run() {
    #[cfg(feature = "gui-test")]
    qa::restore_launch_environment();
    let launched = Instant::now();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(updates::Updates::default());
    #[cfg(not(feature = "gui-test"))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        commands::core_request,
        commands::core_cancel,
        commands::core_status,
        commands::core_restart,
        lock::vault_lock,
        clipboard::clipboard_write,
        clipboard::clipboard_clear,
        native::choose_backup,
        native::backup_export,
        native::backup_import,
        native::save_file,
        native::open_external,
        biometric::biometric_available,
        biometric::biometric_enroll,
        biometric::biometric_derive,
        menu::menu_state,
        updates::update_check,
        updates::update_install,
        updates::update_cancel
    ]);
    #[cfg(feature = "gui-test")]
    let builder = builder.invoke_handler(tauri::generate_handler![
        commands::core_request,
        commands::core_cancel,
        commands::core_status,
        commands::core_restart,
        lock::vault_lock,
        clipboard::clipboard_write,
        clipboard::clipboard_clear,
        native::choose_backup,
        native::backup_export,
        native::backup_import,
        native::save_file,
        native::open_external,
        biometric::biometric_available,
        biometric::biometric_enroll,
        biometric::biometric_derive,
        menu::menu_state,
        updates::update_check,
        updates::update_install,
        updates::update_cancel,
        qa::qa_report,
        qa::qa_backup,
        qa::qa_lock,
        qa::qa_update_step
    ]);
    let app = builder
        .setup(move |app| {
            #[cfg(feature = "gui-test")]
            app.add_capability(
                r#"{"identifier":"qa","windows":["main"],"permissions":["allow-qa-report","allow-qa-lock","allow-qa-backup","allow-qa-update-step"]}"#,
            )?;
            let handle = app.handle().clone();
            let emitter = handle.clone();
            let supervisor = Supervisor::start(core_config(&handle)?, launched, move |status| {
                // "stopped" only follows a shutdown, while the main thread waits for
                // the core in RunEvent::Exit. Resetting the window then needs that
                // same thread, which stalled every quit until the shutdown timed out.
                if status.state == "stopped" {
                    return;
                }
                if status.state != "ready" {
                    lock::reset_renderer(&emitter);
                    if let Some(clipboard) = emitter.try_state::<Arc<clipboard::Clipboard>>() {
                        clipboard.clear();
                    }
                }
                let _ = emitter.emit("core-status", status);
            });
            app.manage(supervisor);
            app.manage(native::Files::default());
            app.manage(clipboard::Clipboard::start());
            #[cfg(target_os = "macos")]
            menu::install(&handle)?;
            lock::install(handle);
            let window =
                tauri::WebviewWindowBuilder::from_config(app, &app.config().app.windows[0])?
                    .on_navigation(|url| {
                        (url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                            || (["http", "https"].contains(&url.scheme())
                                && url.host_str() == Some("tauri.localhost"))
                            || (cfg!(debug_assertions)
                                && url.scheme() == "http"
                                && url.host_str() == Some("127.0.0.1")
                                && url.port() == Some(3000))
                    })
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .on_page_load(|window, payload| {
                    if payload.event() == tauri::webview::PageLoadEvent::Finished { let _ = window.show(); }
                })
                    .build()?;
            #[cfg(windows)]
            lock_windows::install(&window)?;
            #[cfg(target_os = "linux")]
            lock_linux::install();
            let _ = window;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("CipherMoth could not initialize its window");
    app.run(|handle, event| {
        // Hide at once, so quitting looks immediate while the core shuts down.
        if let RunEvent::ExitRequested { .. } = event {
            for window in handle.webview_windows().values() {
                let _ = window.hide();
            }
        }
        if let RunEvent::Exit = event {
            for window in handle.webview_windows().values() {
                let _ = window.hide();
            }
            handle.state::<Arc<clipboard::Clipboard>>().clear();
            if let Some(core) = handle.try_state::<Arc<Supervisor>>() {
                core.shutdown();
            }
        }
    });
}
