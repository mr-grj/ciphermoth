//! The macOS menu bar. Vault actions are forwarded to the renderer as `menu-action`
//! events (only an action name, never vault data) and stay disabled while the vault
//! is locked; the renderer reports that state through `menu_state`. Windows and Linux
//! keep their window chrome without a menu bar.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use tauri::menu::{AboutMetadataBuilder, MenuBuilder, MenuItem, MenuItemBuilder, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, Wry};

const REPOSITORY: &str = "https://github.com/mr-grj/ciphermoth";

/// Menu items that act on an unlocked vault.
pub struct VaultItems(Vec<MenuItem<Wry>>);

/// Help items open fixed public pages in the default browser.
fn help_page(id: &str) -> Option<String> {
    match id {
        "help-website" => Some(REPOSITORY.to_string()),
        "help-releases" => Some(format!("{REPOSITORY}/releases")),
        "help-issue" => Some(format!("{REPOSITORY}/issues/new")),
        _ => None,
    }
}

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let mut vault = Vec::new();
    let mut action = |id: &str, text: &str, accelerator: Option<&str>| {
        let mut builder = MenuItemBuilder::with_id(id, text).enabled(false);
        if let Some(keys) = accelerator {
            builder = builder.accelerator(keys);
        }
        let item = builder.build(app)?;
        vault.push(item.clone());
        Ok::<_, tauri::Error>(item)
    };
    let check_updates = action("check-updates", "Check for Updates…", None)?;
    let settings = action("settings", "Settings…", Some("CmdOrCtrl+,"))?;
    let lock = action("lock", "Lock Vault", Some("CmdOrCtrl+Shift+L"))?;
    let new_login = action("new-login", "New Login", Some("CmdOrCtrl+N"))?;
    let new_note = action("new-note", "New Secure Note", Some("CmdOrCtrl+Shift+N"))?;
    let import = action("import", "Import…", None)?;
    let backup = action("backup", "Back Up Vault…", None)?;
    let find = action("find", "Find…", Some("CmdOrCtrl+F"))?;
    let trash = action("trash", "Trash", None)?;
    let health = action("health", "Vault Health", None)?;
    // The theme can change on the lock screen too.
    let theme = MenuItemBuilder::with_id("toggle-theme", "Switch Light/Dark Theme").build(app)?;

    let package = app.package_info();
    let about = AboutMetadataBuilder::new()
        .name(Some("CipherMoth"))
        .version(Some(package.version.to_string()))
        .comments(Some("Your secrets stay in the dark."))
        .copyright(Some("MIT License"))
        .website(Some(REPOSITORY))
        .build();
    let app_menu = SubmenuBuilder::new(app, "CipherMoth")
        .about(Some(about))
        .separator()
        .item(&check_updates)
        .item(&settings)
        .separator()
        .item(&lock)
        .separator()
        .services()
        .separator()
        .hide()
        .hide_others()
        .show_all()
        .separator()
        .quit()
        .build()?;
    let file = SubmenuBuilder::new(app, "File")
        .item(&new_login)
        .item(&new_note)
        .separator()
        .item(&import)
        .item(&backup)
        .separator()
        .close_window()
        .build()?;
    // The standard items are what make Cmd+C, Cmd+V and friends work in text fields.
    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .separator()
        .item(&find)
        .build()?;
    let view = SubmenuBuilder::new(app, "View")
        .item(&trash)
        .item(&health)
        .separator()
        .item(&theme)
        .separator()
        .fullscreen()
        .build()?;
    let window = SubmenuBuilder::new(app, "Window")
        .minimize()
        .maximize()
        .separator()
        .close_window()
        .build()?;
    let help = SubmenuBuilder::new(app, "Help")
        .text("help-website", "CipherMoth on GitHub")
        .text("help-releases", "Release Notes")
        .separator()
        .text("help-issue", "Report an Issue…")
        .build()?;
    let menu = MenuBuilder::new(app)
        .items(&[&app_menu, &file, &edit, &view, &window, &help])
        .build()?;
    app.set_menu(menu)?;
    #[cfg(target_os = "macos")]
    {
        window.set_as_windows_menu_for_nsapp()?;
        help.set_as_help_menu_for_nsapp()?;
    }
    app.manage(VaultItems(vault));
    app.on_menu_event(|app, event| {
        let id = event.id().as_ref();
        if let Some(url) = help_page(id) {
            let _ = crate::native::open_external(url);
        } else {
            let _ = app.emit_to("main", "menu-action", id);
        }
    });
    Ok(())
}

/// Called by the renderer whenever the vault locks or unlocks.
#[tauri::command]
pub fn menu_state(app: AppHandle, unlocked: bool) {
    if let Some(items) = app.try_state::<VaultItems>() {
        for item in &items.0 {
            let _ = item.set_enabled(unlocked);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_items_open_only_fixed_public_pages() {
        for id in ["help-website", "help-releases", "help-issue"] {
            assert!(help_page(id).unwrap().starts_with(REPOSITORY));
        }
        assert_eq!(help_page("lock"), None);
        assert_eq!(help_page("help-anything"), None);
    }
}
