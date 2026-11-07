//! A stand-in for the CipherMoth desktop app in the extension's end-to-end
//! tests (extension/tests/e2e/desktop.spec.ts): the real link server on the QA
//! endpoint, with the vault of a live test backend instead of the core.
//!
//!   CIPHERMOTH_QA_ROOT=/abs/root app_stub --api http://127.0.0.1:PORT/api --password PW
//!
//! stdout (one line each): `listening`, `code <six digits>` when a browser asks
//! to pair, `show`, `locked`. stdin commands: `allow`, `deny`, `lock`,
//! `unlock`, `unpair`, `quit`. Test use only; never shipped.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use ciphermoth_extension_link::identity::Identity;
use ciphermoth_extension_link::ipc;
use ciphermoth_extension_link::pairings::Store;
use ciphermoth_extension_link::server::{Desktop, Link, Refusal};
use serde_json::{json, Value};

struct Stub {
    store: Store,
    api: String,
    password: String,
    unlocked: AtomicBool,
    answers: Mutex<mpsc::Receiver<bool>>,
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// POST JSON to the test backend (plain HTTP on 127.0.0.1).
fn post(
    base: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> Result<(u16, Value), Refusal> {
    let rest = base.strip_prefix("http://").ok_or(Refusal::Failed)?;
    let (host, prefix) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    let mut stream = TcpStream::connect(host).map_err(|_| Refusal::Failed)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|_| Refusal::Failed)?;
    let body = body.to_string();
    let session = token
        .map(|t| format!("x-ciphermoth-session: {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST /{prefix}{path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| Refusal::Failed)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|_| Refusal::Failed)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, payload) = text.split_once("\r\n\r\n").ok_or(Refusal::Failed)?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(Refusal::Failed)?;
    Ok((status, serde_json::from_str(payload).unwrap_or(Value::Null)))
}

impl Desktop for Stub {
    fn store(&self) -> &Store {
        &self.store
    }
    fn unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }
    fn approve(&self, _browser: &str, code: &str) -> bool {
        say(&format!("code {code}"));
        self.answers
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(120))
            .unwrap_or(false)
    }
    fn open_session(&self, browser: &str, client: &str) -> Result<String, Refusal> {
        if !self.unlocked() {
            return Err(Refusal::Locked);
        }
        let body = json!({"master_password": self.password, "browser": browser, "client": client});
        match post(&self.api, "/extension/unlock", None, &body)? {
            (200, answer) => answer["session_token"]
                .as_str()
                .map(str::to_string)
                .ok_or(Refusal::Failed),
            _ => Err(Refusal::Failed),
        }
    }
    fn api(&self, token: &str, route: &str, body: &Value) -> Result<(u16, Value), Refusal> {
        if !self.unlocked() {
            return Err(Refusal::Locked);
        }
        post(&self.api, &format!("/extension/{route}"), Some(token), body)
    }
    fn end_sessions(&self, _client: &str) {
        // The test backend ends them at idle; the stub keeps no token itself.
    }
    fn show(&self) {
        say("show");
    }
    fn lock(&self) {
        self.unlocked.store(false, Ordering::SeqCst);
        say("locked");
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut api, mut password) = (String::new(), String::new());
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--api" => api = args.next().expect("--api URL"),
            "--password" => password = args.next().expect("--password"),
            other => panic!("unknown argument {other}"),
        }
    }
    let identity = Identity::qa_from_env().expect("CIPHERMOTH_QA_ROOT");
    let store = Store::open(&identity.link_dir().unwrap()).unwrap();
    store.set_enabled(true).unwrap();
    let (answer, answers) = mpsc::channel();
    let link = Link::new(Stub {
        store,
        api,
        password,
        unlocked: AtomicBool::new(true),
        answers: Mutex::new(answers),
    });
    let running = link
        .start(&ipc::endpoint(&identity).unwrap())
        .expect("listen");
    say("listening");
    for line in std::io::stdin().lock().lines() {
        match line.unwrap_or_default().trim() {
            "allow" => answer.send(true).unwrap(),
            "deny" => answer.send(false).unwrap(),
            "lock" => {
                link.forget_sessions();
                link.desktop().unlocked.store(false, Ordering::SeqCst);
            }
            "unlock" => link.desktop().unlocked.store(true, Ordering::SeqCst),
            "unpair" => {
                for pairing in link.desktop().store.list() {
                    link.desktop().store.remove(&pairing.id).unwrap();
                    link.forget_pairing(&pairing.id);
                }
                link.close_connections();
            }
            "quit" => break,
            _ => {}
        }
    }
    running.stop();
}
