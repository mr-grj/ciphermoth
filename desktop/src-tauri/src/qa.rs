//! Compiled only into the separately identified native QA artifact.
pub fn restore_launch_environment() {
    // LaunchServices restarts preserve argv, not the test host's environment.
    // These flags exist only in isolated QA binaries, never production.
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let name = match arg.as_str() {
            "--qa-root" => "CIPHERMOTH_QA_ROOT",
            "--qa-update-endpoint" => "CIPHERMOTH_QA_UPDATE_ENDPOINT",
            "--qa-update-ca" => "CIPHERMOTH_QA_UPDATE_CA",
            _ => continue,
        };
        if let Some(value) = args.next() {
            std::env::set_var(name, value);
        }
    }
}

pub fn update_builder(
    builder: tauri_plugin_updater::UpdaterBuilder,
) -> Result<tauri_plugin_updater::UpdaterBuilder, String> {
    let Ok(endpoint) = std::env::var("CIPHERMOTH_QA_UPDATE_ENDPOINT") else {
        return Ok(builder);
    };
    let url = url::Url::parse(&endpoint).map_err(|_| "Invalid QA endpoint")?;
    if url.scheme() != "https" || url.host_str() != Some("localhost") {
        return Err("QA requires local HTTPS".into());
    }
    let pem = std::fs::read(std::env::var("CIPHERMOTH_QA_UPDATE_CA").map_err(|_| "Missing QA CA")?)
        .map_err(|_| "Missing QA CA")?;
    let cert = reqwest::Certificate::from_pem(&pem).map_err(|_| "Invalid QA CA")?;
    builder
        .endpoints(vec![url])
        .map(|b| {
            b.configure_client(move |c| {
                c.add_root_certificate(cert.clone())
                    .https_only(true)
                    .timeout(std::time::Duration::from_secs(30))
            })
        })
        .map_err(|_| "Invalid QA endpoint".into())
}

pub fn update_download(
    update: &tauri_plugin_updater::Update,
) -> Result<tauri_plugin_updater::Update, String> {
    let mut update = update.clone();
    if let Ok(endpoint) = std::env::var("CIPHERMOTH_QA_UPDATE_ENDPOINT") {
        let mut url = url::Url::parse(&endpoint).map_err(|_| "Invalid QA endpoint")?;
        url.set_path(update.download_url.path());
        update.download_url = url;
    }
    Ok(update)
}

#[tauri::command]
pub async fn qa_update_step(
    result: serde_json::Value,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    use tauri::Manager;
    let root = std::path::PathBuf::from(
        std::env::var("CIPHERMOTH_QA_ROOT").map_err(|_| "Missing QA root")?,
    );
    let id = uuid::Uuid::new_v4().to_string();
    let response = root.join(format!("update-{id}.json"));
    let request = serde_json::json!({"id":id,"version":app.package_info().version.to_string(),"pid":std::process::id(),"core":app.state::<std::sync::Arc<crate::sidecar::Supervisor>>().status(),"result":result});
    std::fs::write(
        root.join("update-request.partial"),
        serde_json::to_vec(&request).unwrap(),
    )
    .map_err(|_| "QA write failed")?;
    // Windows refuses to replace or open a file the harness has open at that
    // moment; both sides poll, so retry briefly instead of failing the run.
    let mut renamed = false;
    for _ in 0..100 {
        if std::fs::rename(
            root.join("update-request.partial"),
            root.join("update-request.json"),
        )
        .is_ok()
        {
            renamed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if !renamed {
        return Err("QA write failed".into());
    }
    for _ in 0..2400 {
        if response.exists() {
            if let Ok(bytes) = std::fs::read(&response) {
                if std::fs::remove_file(&response).is_ok() {
                    return serde_json::from_slice(&bytes)
                        .map_err(|_| "Invalid QA response".into());
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err("QA host timed out".into())
}

#[tauri::command]
pub async fn qa_backup(
    operation: String,
    session: String,
    password: String,
    core: tauri::State<'_, std::sync::Arc<crate::sidecar::Supervisor>>,
) -> Result<serde_json::Value, String> {
    if !["backup_export", "backup_import"].contains(&operation.as_str()) {
        return Err("Invalid QA operation".into());
    }
    let root = std::path::PathBuf::from(
        std::env::var("CIPHERMOTH_QA_ROOT").map_err(|_| "QA root missing")?,
    );
    let path = root.join("transport.cmbackup");
    // Fixed synthetic destination authorized by the test host. This exercises
    // the real native transfer, separately from optional OS-picker automation.
    let result = crate::native::file_request(
        &core,
        &operation,
        path.clone(),
        session,
        serde_json::json!({"master_password": password, "on_conflict": "skip"}),
    )
    .await?;
    Ok(
        serde_json::json!({"result": result, "bytes": std::fs::metadata(path).map_err(|_| "Missing backup")?.len()}),
    )
}

#[tauri::command]
pub async fn qa_report(mut result: serde_json::Value) -> Result<(), String> {
    let root = std::env::var("CIPHERMOTH_QA_ROOT").map_err(|_| "QA root missing")?;
    let root = std::path::Path::new(&root);
    let ack = if cfg!(target_os = "macos")
        && [Some("clipboard_timeout"), Some("clipboard_replaced")]
            .contains(&result["stage"].as_str())
    {
        let nonce = uuid::Uuid::new_v4().to_string();
        result["ack"] = serde_json::json!(nonce);
        Some(root.join(format!("{nonce}.done")))
    } else {
        None
    };
    std::fs::write(
        root.join("webview.partial"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .map_err(|_| "Could not write QA report")?;
    // Windows refuses to replace a file the harness has open at that moment;
    // the harness polls, so retry briefly instead of failing the run.
    let mut renamed = false;
    for _ in 0..100 {
        if std::fs::rename(root.join("webview.partial"), root.join("webview.json")).is_ok() {
            renamed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if !renamed {
        return Err("Could not publish QA report".into());
    }
    if let Some(ack) = ack {
        for _ in 0..600 {
            if ack.exists() {
                std::fs::remove_file(ack).map_err(|_| "Could not consume QA acknowledgement")?;
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        return Err("The host did not acknowledge the clipboard check".into());
    }
    Ok(())
}

#[tauri::command]
pub fn qa_lock(app: tauri::AppHandle) -> Result<(), String> {
    app.run_on_main_thread(|| {
        #[cfg(target_os = "macos")]
        unsafe {
            extern "C" {
                fn cm_test_sleep_notification();
            }
            cm_test_sleep_notification();
        }
        #[cfg(not(target_os = "macos"))]
        crate::lock::vault_lock();
    })
    .map_err(|_| "Could not deliver native lock event".into())
}
