//! The built host binary, as a browser starts it (design 8.4: caller check,
//! framing, app not running), against a stand-in app on a QA socket.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ciphermoth_extension_link::framing;
use ciphermoth_extension_link::identity::Identity;
use serde_json::{json, Value};

const CHROME: &str = "chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/";
const FIREFOX: &str = "ciphermoth@mr-grj.github.io";

fn host(root: &Path, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_native-host"))
        .args(args)
        .env("CIPHERMOTH_QA_ROOT", root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn send(child: &mut Child, value: Value) {
    framing::write_object(child.stdin.as_mut().unwrap(), &value).unwrap();
}

fn receive(child: &mut Child) -> Value {
    Value::Object(framing::read_object(child.stdout.as_mut().unwrap()).unwrap())
}

fn finished(child: &mut Child) -> Option<i32> {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    None
}

fn app_socket(root: &Path) -> UnixListener {
    let path = Identity::Qa(root.to_path_buf()).socket_path().unwrap();
    ciphermoth_extension_link::identity::private_dir(path.parent().unwrap()).unwrap();
    UnixListener::bind(path).unwrap()
}

#[test]
fn a_caller_that_is_not_ours_gets_nothing() {
    let root = tempfile::tempdir().unwrap();
    for args in [
        &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
        &["/manifest.json", "evil@example.com"],
        &[],
    ] {
        let mut child = host(root.path(), args);
        drop(child.stdin.take());
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        assert!(out.is_empty(), "{args:?}");
        assert_eq!(finished(&mut child), Some(2), "{args:?}");
    }
}

#[test]
fn without_the_app_it_says_so_and_bad_frames_end_it() {
    let root = tempfile::tempdir().unwrap();
    let mut child = host(root.path(), &[CHROME]);
    send(&mut child, json!({"t": "hello", "id": "x", "nonce": "y"}));
    assert_eq!(
        receive(&mut child),
        json!({"t": "error", "code": "app_not_running"})
    );
    send(&mut child, json!({"t": "launch"}));
    assert_eq!(
        receive(&mut child),
        json!({"t": "error", "code": "launch_failed"})
    );
    // A length over 64 KiB ends the host before it allocates or reads on.
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&(70_000u32).to_ne_bytes())
        .unwrap();
    assert_eq!(finished(&mut child), Some(1));

    let mut child = host(root.path(), &[CHROME]);
    send(&mut child, json!({"t": "export"}));
    assert_eq!(
        finished(&mut child),
        Some(1),
        "unknown message types are refused"
    );
}

#[test]
fn it_relays_both_ways_and_only_our_message_types() {
    let root = tempfile::tempdir().unwrap();
    let listener = app_socket(root.path());
    let mut child = host(root.path(), &["/x/com.ciphermoth.desktop.qa.json", FIREFOX]);
    send(
        &mut child,
        json!({"t": "hello", "id": "abc", "nonce": "def"}),
    );
    let (mut app, _) = listener.accept().unwrap();
    let hello = framing::read_object(&mut app).unwrap();
    assert_eq!(
        Value::Object(hello),
        json!({"t": "host", "caller": FIREFOX, "version": "1"})
    );
    let forwarded = framing::read_object(&mut app).unwrap();
    assert_eq!(forwarded["t"], "hello");
    framing::write_object(&mut app, &json!({"t": "hello_ok", "nonce": "n"})).unwrap();
    assert_eq!(receive(&mut child)["t"], "hello_ok");
    // The app sending anything but a protocol message ends the relay.
    framing::write_object(&mut app, &json!({"t": "pair_commit"})).unwrap();
    assert_eq!(
        receive(&mut child),
        json!({"t": "error", "code": "app_closed"})
    );
    assert_eq!(finished(&mut child), Some(0));
}

#[test]
fn the_launch_target_is_started() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("started");
    let script = root.path().join("fake-app.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = Identity::Qa(root.path().to_path_buf()).link_dir().unwrap();
    std::fs::create_dir_all(&link).unwrap();
    std::fs::write(
        link.join("launch.json"),
        json!({"program": script, "args": []}).to_string(),
    )
    .unwrap();
    let mut child = host(root.path(), &[CHROME]);
    send(&mut child, json!({"t": "launch"}));
    assert_eq!(receive(&mut child), json!({"t": "launched"}));
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(marker.exists());
    drop(child.stdin.take());
    assert_eq!(finished(&mut child), Some(0));
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Whatever the browser side sends, the host never crashes (exit 0, 1
        /// or 2, never a signal or a panic's 101) and writes only well-formed
        /// frames of the types it may send.
        #[test]
        fn arbitrary_input_never_crashes_the_host(
            frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 0..4),
            tail in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let root = tempfile::tempdir().unwrap();
            let mut child = host(root.path(), &[CHROME]);
            let mut input = Vec::new();
            for frame in &frames {
                input.extend_from_slice(&(frame.len() as u32).to_ne_bytes());
                input.extend_from_slice(frame);
            }
            input.extend_from_slice(&tail);
            let _ = child.stdin.as_mut().unwrap().write_all(&input);
            drop(child.stdin.take());
            let mut out = Vec::new();
            child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
            let code = finished(&mut child);
            prop_assert!(matches!(code, Some(0) | Some(1)), "{code:?}");
            let mut cursor = std::io::Cursor::new(out);
            loop {
                match framing::read_object(&mut cursor) {
                    Ok(message) => prop_assert!(
                        matches!(message["t"].as_str(), Some("error" | "launched")),
                        "{message:?}"
                    ),
                    Err(framing::FrameError::Eof) => break,
                    Err(e) => prop_assert!(false, "malformed output: {e}"),
                }
            }
        }
    }
}
