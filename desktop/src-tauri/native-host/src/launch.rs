//! "Open CipherMoth": start the desktop app the manifests belong to. The app
//! records how it was started in `launch.json` in its private link folder each
//! time it turns the switch on, so this works for every package type
//! (a moved .app, an AppImage, the QA build). The app is started detached: it
//! must outlive the browser's native-host process (and, on Windows, its job).

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ciphermoth_extension_link::identity::Identity;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub fn target(identity: &Identity) -> io::Result<(PathBuf, Vec<String>)> {
    let raw = std::fs::read(identity.link_dir()?.join("launch.json"))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| invalid("launch.json"))?;
    let program = value["program"]
        .as_str()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file());
    let args: Option<Vec<String>> = value["args"].as_array().and_then(|list| {
        list.iter()
            .map(|a| a.as_str().map(str::to_string))
            .collect()
    });
    match (program, args) {
        (Some(program), Some(args)) if args.len() <= 8 => Ok((program, args)),
        _ => Err(invalid("launch.json")),
    }
}

/// The `.app` bundle an executable belongs to.
#[cfg(target_os = "macos")]
fn bundle(program: &Path) -> Option<PathBuf> {
    program
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

pub fn start(identity: &Identity) -> io::Result<()> {
    let (program, args) = target(identity)?;
    #[cfg(target_os = "macos")]
    if let Some(app) = bundle(&program) {
        // LaunchServices starts (or focuses) the app outside our process tree.
        let mut command = Command::new("/usr/bin/open");
        command.arg(app);
        if !args.is_empty() {
            command.arg("--args").args(&args);
        }
        return command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .and_then(|s| {
                if s.success() {
                    Ok(())
                } else {
                    Err(invalid("open failed"))
                }
            });
    }
    detached(&program, &args)
}

#[cfg(unix)]
fn detached(program: &Path, args: &[String]) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe; a new session leaves the browser's
    // process group, so closing the browser does not end the app.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.spawn().map(drop)
}

#[cfg(windows)]
fn detached(program: &Path, args: &[String]) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let spawn = |flags: u32| {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
            .map(drop)
    };
    // Browsers run native hosts in a job that is killed with them; breaking
    // away keeps the app open. A job that forbids it still gets a start.
    spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_target_must_be_a_real_absolute_program() {
        let root = tempfile::tempdir().unwrap();
        let identity = Identity::Qa(root.path().to_path_buf());
        let dir = identity.link_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        assert!(target(&identity).is_err(), "no file");
        let program = root.path().join("app");
        std::fs::write(&program, b"").unwrap();
        for bad in [
            serde_json::json!({"program": "relative/app", "args": []}),
            serde_json::json!({"program": root.path().join("missing").to_string_lossy(), "args": []}),
            serde_json::json!({"program": program.to_string_lossy(), "args": [1]}),
            serde_json::json!({"program": program.to_string_lossy()}),
        ] {
            std::fs::write(dir.join("launch.json"), bad.to_string()).unwrap();
            assert!(target(&identity).is_err(), "{bad}");
        }
        let good =
            serde_json::json!({"program": program.to_string_lossy(), "args": ["--qa-root", "/x"]});
        std::fs::write(dir.join("launch.json"), good.to_string()).unwrap();
        assert_eq!(
            target(&identity).unwrap(),
            (program, vec!["--qa-root".to_string(), "/x".to_string()])
        );
    }
}
