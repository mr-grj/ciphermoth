//! `ciphermoth-native-host`: started by the browser for the CipherMoth
//! extension (native messaging), relays its messages to the running desktop
//! app over the local socket or pipe and back. It holds no secret and decides
//! nothing: the channel between the extension and the app is end-to-end
//! encrypted, the host only checks who started it, frames, sizes and message
//! types. It answers two things itself: `app_not_running` when the app does not
//! listen, and `launch`, which starts the app.

use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use ciphermoth_extension_link::framing::{self, Object};
use ciphermoth_extension_link::identity::Identity;
use ciphermoth_extension_link::ids::{caller_from_args, Caller};
use ciphermoth_extension_link::ipc::{self, Stream};
use ciphermoth_extension_link::wire::kind;
use serde_json::{json, Value};

mod launch;

/// What the extension may send through, and what the app may send back.
const TO_APP: &[&str] = &["pair_commit", "pair_reveal", "hello", "msg"];
const TO_EXTENSION: &[&str] = &["pair_key", "paired", "refused", "hello_ok", "msg"];

/// Release builds are the real app's host and ignore the environment. Debug
/// builds take a QA root when one is set (the host's own tests), else they
/// belong to the development app.
fn identity() -> io::Result<Identity> {
    if cfg!(feature = "qa") {
        Identity::qa_from_env()
    } else if cfg!(debug_assertions) {
        Identity::qa_from_env().or(Ok(Identity::Development))
    } else {
        Ok(Identity::Production)
    }
}

type Out = Arc<Mutex<io::Stdout>>;

fn reply(out: &Out, value: Value) -> io::Result<()> {
    framing::write_object(&mut *out.lock().unwrap(), &value)
}

/// Copy the app's answers to the browser until the app closes the connection.
fn relay_from_app(mut app: Stream, out: Out) {
    loop {
        match framing::read_object(&mut app) {
            Ok(message) if kind(&message).is_some_and(|t| TO_EXTENSION.contains(&t)) => {
                if reply(&out, Value::Object(message)).is_err() {
                    std::process::exit(0);
                }
            }
            _ => {
                let _ = reply(&out, json!({"t": "error", "code": "app_closed"}));
                std::process::exit(0);
            }
        }
    }
}

fn connect(identity: &Identity, caller: &Caller, out: &Out) -> Option<Stream> {
    let mut app = ipc::endpoint(identity)
        .and_then(|endpoint| endpoint.connect())
        .ok()?;
    let hello = json!({"t": "host", "caller": caller.origin(), "version": "1"});
    framing::write_object(&mut app, &hello).ok()?;
    let reader = app.try_clone().ok()?;
    let out = out.clone();
    std::thread::Builder::new()
        .name("from-app".into())
        .spawn(move || relay_from_app(reader, out))
        .ok()?;
    Some(app)
}

fn run(caller: Caller, identity: Identity, mut input: impl Read) -> io::Result<()> {
    let out: Out = Arc::new(Mutex::new(io::stdout()));
    let mut app: Option<Stream> = None;
    loop {
        let message: Object = match framing::read_object(&mut input) {
            Ok(message) => message,
            Err(framing::FrameError::Eof) => return Ok(()),
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame")),
        };
        match kind(&message) {
            Some("launch") if message.len() == 1 => {
                let answer = match launch::start(&identity) {
                    Ok(()) => json!({"t": "launched"}),
                    Err(_) => json!({"t": "error", "code": "launch_failed"}),
                };
                reply(&out, answer)?;
            }
            Some(t) if TO_APP.contains(&t) => {
                if app.is_none() {
                    app = connect(&identity, &caller, &out);
                }
                match app.as_mut() {
                    Some(stream) => framing::write_object(stream, &Value::Object(message))?,
                    None => reply(&out, json!({"t": "error", "code": "app_not_running"}))?,
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown message",
                ))
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(caller) = caller_from_args(&args) else {
        eprintln!("ciphermoth-native-host: not started for the CipherMoth extension");
        return ExitCode::from(2);
    };
    let Ok(identity) = identity() else {
        eprintln!("ciphermoth-native-host: no QA root");
        return ExitCode::from(2);
    };
    match run(caller, identity, io::stdin().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}
