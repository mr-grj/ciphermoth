fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "core_request",
            "core_cancel",
            "core_status",
            "core_restart",
            "selftest_scenario",
            "selftest_mark",
            "selftest_finish",
        ]),
    ))
    .expect("failed to run tauri-build");
}
