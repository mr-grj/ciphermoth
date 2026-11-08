//! The app's side of the link: accepts the native host's connections, pairs
//! new browsers (with the user's approval) and answers paired ones over the
//! encrypted channel. Generic over [`Desktop`], which the Tauri app implements
//! with its window and the vault core (and tests and the e2e stub with fakes).
//!
//! One connection, in order:
//! 1. host → app `{t:"host", caller, version}`: the extension the browser
//!    started the host for, checked against the pinned ids again.
//! 2. Optionally a pairing: `pair_commit {browser, commit}` → `pair_key {pub,
//!    nonce}` → `pair_reveal {pub, nonce}` → (the user approves the code) →
//!    `paired {id}`, or `refused {code}` at any step.
//! 3. `hello {id, nonce}` → `hello_ok {nonce}`, then only `msg {c, d}` frames:
//!    sealed JSON requests `{id, op, ...}` and answers `{id, ok, ...}`.
//!
//! The extension session token stays here (design decision 40): it is opened
//! from the unlocked vault for a pairing on first use and never sent out.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::channel::{self, Channel, Exchange, Side};
use crate::framing::{self, Object};
use crate::ids::Caller;
use crate::ipc::{Endpoint, Server, Stream};
use crate::pairings::{Pairing, Store};
use crate::wire::{b64, bytes, has_exactly, kind, text, unb64};

pub const MAX_CONNECTIONS: usize = 8;
/// A sealed answer must still fit in one frame after base64 and the envelope.
pub const MAX_PLAINTEXT: usize = 40 * 1024;
const FIRST_MESSAGE: Duration = Duration::from_secs(10);
const PAIRING_STEP: Duration = Duration::from_secs(30);
const IDLE: Duration = Duration::from_secs(10 * 60);
/// Pairing attempts per minute: each one can put a dialog in front of the
/// user, so a local process cannot flood them with requests to approve.
pub const PAIRINGS_PER_MINUTE: usize = 5;

pub const BROWSERS: &[&str] = &[
    "Chrome", "Chromium", "Edge", "Brave", "Opera", "Vivaldi", "Firefox", "Browser",
];
pub const ROUTES: &[&str] = &["matches", "search", "credential", "totp"];

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The vault is locked (or the core is not running).
    Locked,
    Failed,
}

pub trait Desktop: Send + Sync + 'static {
    fn store(&self) -> &Store;
    fn unlocked(&self) -> bool;
    /// Show the approval dialog with `code` and wait for the answer.
    fn approve(&self, browser: &str, code: &str) -> bool;
    /// A new extension session for this pairing (`client` = the pairing id, so
    /// a new one replaces the pairing's previous session).
    fn open_session(&self, browser: &str, client: &str) -> Result<String, Refusal>;
    /// `POST /api/extension/<route>` with the session token.
    fn api(&self, token: &str, route: &str, body: &Value) -> Result<(u16, Value), Refusal>;
    /// End the extension sessions opened for this pairing (`client`).
    fn end_sessions(&self, client: &str);
    /// Bring the window forward (to unlock, or to answer a pairing).
    fn show(&self);
    fn lock(&self);
}

pub struct Link<D: Desktop> {
    desktop: D,
    tokens: Mutex<HashMap<String, String>>,
    generation: AtomicU64,
    pairing: AtomicBool,
    attempts: Mutex<std::collections::VecDeque<std::time::Instant>>,
    live: Mutex<HashMap<u64, Stream>>,
    next_connection: AtomicU64,
    connections: AtomicUsize,
}

enum Flow {
    Continue,
    Closed,
}

fn send(writer: &mut Stream, value: Value) -> io::Result<()> {
    framing::write_object(writer, &value)
}

fn refuse(writer: &mut Stream, code: &str) -> Flow {
    let _ = send(writer, json!({"t": "refused", "code": code}));
    Flow::Closed
}

// Frees the pairing slot before the browser hears the answer: an extension
// that pairs again right after a refusal must not find it still taken.
fn refuse_released(guard: PairingGuard<'_>, writer: &mut Stream, code: &str) -> Flow {
    drop(guard);
    refuse(writer, code)
}

fn failure(id: u64, code: &str, detail: &str) -> Value {
    json!({"id": id, "ok": false, "code": code, "detail": detail})
}

struct PairingGuard<'a>(&'a AtomicBool);
impl Drop for PairingGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct ConnectionGuard<'a, D: Desktop> {
    link: &'a Link<D>,
    id: u64,
}
impl<D: Desktop> Drop for ConnectionGuard<'_, D> {
    fn drop(&mut self) {
        self.link.live.lock().unwrap().remove(&self.id);
        self.link.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Running {
    stopper: crate::ipc::Stopper,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    pub fn stop(mut self) {
        self.stopper.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl<D: Desktop> Link<D> {
    pub fn new(desktop: D) -> Arc<Self> {
        Arc::new(Link {
            desktop,
            tokens: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            pairing: AtomicBool::new(false),
            attempts: Mutex::new(std::collections::VecDeque::new()),
            live: Mutex::new(HashMap::new()),
            next_connection: AtomicU64::new(0),
            connections: AtomicUsize::new(0),
        })
    }

    pub fn desktop(&self) -> &D {
        &self.desktop
    }

    /// Listen at `endpoint` until the returned handle is stopped.
    pub fn start(self: &Arc<Self>, endpoint: &Endpoint) -> io::Result<Running> {
        let server = Server::bind(endpoint)?;
        let stopper = server.stopper();
        let link = self.clone();
        let thread = std::thread::Builder::new()
            .name("extension-link".into())
            .spawn(move || {
                while let Some(stream) = server.accept() {
                    if link.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        link.connections.fetch_sub(1, Ordering::SeqCst);
                        stream.shutdown();
                        continue;
                    }
                    // Registered before its thread starts, so close_connections
                    // always reaches it.
                    let Some(id) = link.register(&stream) else {
                        link.connections.fetch_sub(1, Ordering::SeqCst);
                        stream.shutdown();
                        continue;
                    };
                    let worker = link.clone();
                    let spawned = std::thread::Builder::new()
                        .name("extension-connection".into())
                        .spawn(move || worker.connection(id, stream));
                    if spawned.is_err() {
                        // The connection never started, so its guard never runs.
                        link.live.lock().unwrap().remove(&id);
                        link.connections.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            })?;
        Ok(Running {
            stopper,
            thread: Some(thread),
        })
    }

    /// End every open connection (the switch was turned off).
    pub fn close_connections(&self) {
        for stream in self.live.lock().unwrap().values() {
            stream.shutdown();
        }
    }

    /// Forget every extension session token (the vault locked, the switch was
    /// turned off). Sessions being opened right now are not kept either.
    pub fn forget_sessions(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.tokens.lock().unwrap().clear();
    }

    /// Forget a pairing's token (removed or evicted); a session being opened
    /// for it right now is not kept either.
    pub fn forget_pairing(&self, id: &str) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.tokens.lock().unwrap().remove(id);
    }

    fn register(&self, stream: &Stream) -> Option<u64> {
        let watch = stream.try_clone().ok()?;
        let id = self.next_connection.fetch_add(1, Ordering::SeqCst);
        self.live.lock().unwrap().insert(id, watch);
        Some(id)
    }

    fn connection(&self, id: u64, stream: Stream) {
        let _guard = ConnectionGuard { link: self, id };
        let _ = self.serve(stream);
    }

    /// Remove pairings from the store and end everything they hold.
    fn drop_pairings(&self, ids: &[String]) {
        for id in ids {
            self.forget_pairing(id);
            self.desktop.end_sessions(id);
        }
    }

    fn serve(&self, mut stream: Stream) -> io::Result<()> {
        let mut writer = stream.try_clone()?;
        stream.set_read_timeout(Some(FIRST_MESSAGE))?;
        let host = read(&mut stream)?;
        let caller = (kind(&host) == Some("host") && has_exactly(&host, &["caller", "version"]))
            .then(|| text(&host, "caller", 200).and_then(Caller::from_origin))
            .flatten();
        if caller.is_none() {
            refuse(&mut writer, "caller");
            return Ok(());
        }
        loop {
            let message = read(&mut stream)?;
            match kind(&message) {
                Some("pair_commit") => {
                    if let Flow::Closed = self.pair(&mut stream, &mut writer, &message)? {
                        return Ok(());
                    }
                }
                Some("hello") => return self.session(stream, writer, &message),
                _ => {
                    refuse(&mut writer, "protocol");
                    return Ok(());
                }
            }
        }
    }

    fn pair(&self, stream: &mut Stream, writer: &mut Stream, commit: &Object) -> io::Result<Flow> {
        let browser = text(commit, "browser", 40).filter(|b| BROWSERS.contains(b));
        let committed = bytes::<32>(commit, "commit");
        let (Some(browser), Some(committed), true) = (
            browser,
            committed,
            has_exactly(commit, &["browser", "commit"]),
        ) else {
            return Ok(refuse(writer, "protocol"));
        };
        if !self.desktop.store().enabled() {
            return Ok(refuse(writer, "disabled"));
        }
        if !self.desktop.unlocked() {
            return Ok(refuse(writer, "locked"));
        }
        if !self.may_pair() {
            return Ok(refuse(writer, "busy"));
        }
        if self.pairing.swap(true, Ordering::SeqCst) {
            return Ok(refuse(writer, "busy"));
        }
        let guard = PairingGuard(&self.pairing);
        let app = Exchange::new();
        let app_nonce = channel::random::<16>();
        send(
            writer,
            json!({"t": "pair_key", "pub": b64(&app.public), "nonce": b64(&app_nonce)}),
        )?;
        stream.set_read_timeout(Some(PAIRING_STEP))?;
        let reveal = read(stream)?;
        let public = bytes::<32>(&reveal, "pub");
        let nonce = bytes::<16>(&reveal, "nonce");
        let (Some(public), Some(nonce), true, Some("pair_reveal")) = (
            public,
            nonce,
            has_exactly(&reveal, &["pub", "nonce"]),
            kind(&reveal),
        ) else {
            return Ok(refuse_released(guard, writer, "protocol"));
        };
        if channel::commit(&public, &nonce) != committed {
            return Ok(refuse_released(guard, writer, "protocol"));
        }
        let transcript = channel::transcript(browser, &public, &nonce, &app.public, &app_nonce);
        let Ok(paired) = app.finish(&public, &transcript) else {
            return Ok(refuse_released(guard, writer, "protocol"));
        };
        let approved = self.desktop.approve(browser, &paired.sas);
        // The dialog is answered: the next browser may pair (the store has
        // its own lock).
        drop(guard);
        if !approved {
            return Ok(refuse(writer, "denied"));
        }
        if !self.desktop.store().enabled() {
            return Ok(refuse(writer, "disabled"));
        }
        if !self.desktop.unlocked() {
            return Ok(refuse(writer, "locked"));
        }
        // The browser hears first: one that cancelled or went away meanwhile
        // leaves no pairing behind.
        let id = crate::wire::b64(&channel::random::<16>());
        send(writer, json!({"t": "paired", "id": id}))?;
        let evicted = self
            .desktop
            .store()
            .add_with_id(&id, browser, &paired.key)?;
        self.drop_pairings(&evicted);
        stream.set_read_timeout(Some(FIRST_MESSAGE))?;
        Ok(Flow::Continue)
    }

    fn may_pair(&self) -> bool {
        let now = std::time::Instant::now();
        let mut attempts = self.attempts.lock().unwrap();
        while attempts
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        if attempts.len() >= PAIRINGS_PER_MINUTE {
            return false;
        }
        attempts.push_back(now);
        true
    }

    fn session(&self, mut stream: Stream, mut writer: Stream, hello: &Object) -> io::Result<()> {
        let pairing = text(hello, "id", 40).and_then(|id| self.desktop.store().find(id));
        let extension_nonce = bytes::<16>(hello, "nonce");
        if !has_exactly(hello, &["id", "nonce"]) || extension_nonce.is_none() {
            refuse(&mut writer, "protocol");
            return Ok(());
        }
        let Some((pairing, key, id_bytes)) =
            pairing.and_then(|p| Some((p.key()?, p.id_bytes()?)).map(|(k, i)| (p, k, i)))
        else {
            refuse(&mut writer, "unknown_pairing");
            return Ok(());
        };
        let app_nonce = channel::random::<16>();
        send(
            &mut writer,
            json!({"t": "hello_ok", "nonce": b64(&app_nonce)}),
        )?;
        let key = channel::connection_key(&key, &id_bytes, &extension_nonce.unwrap(), &app_nonce);
        let mut channel = Channel::new(key, Side::App);
        let mut touched = false;
        stream.set_read_timeout(Some(IDLE))?;
        loop {
            let message = read(&mut stream)?;
            let counter = message.get("c").and_then(Value::as_u64);
            let sealed = text(&message, "d", 96 * 1024).and_then(unb64);
            let (Some("msg"), true, Some(counter), Some(sealed)) = (
                kind(&message),
                has_exactly(&message, &["c", "d"]),
                counter,
                sealed,
            ) else {
                return Ok(());
            };
            // A message that is not the next authentic one ends the connection
            // without an answer.
            let Ok(plain) = channel.open(counter, &sealed) else {
                return Ok(());
            };
            // The switch may have been turned off while this connection was
            // being accepted (before close_connections could see it): it ends
            // here instead of opening a session after extension_end.
            if !self.desktop.store().enabled() || self.desktop.store().find(&pairing.id).is_none() {
                return Ok(());
            }
            // Use is recorded once the peer proved it holds the pairing key.
            if !touched {
                touched = true;
                let _ = self.desktop.store().touch(&pairing.id);
            }
            let answer = match serde_json::from_slice::<Value>(&plain) {
                Ok(Value::Object(request)) => self.answer(&pairing, &request),
                _ => return Ok(()),
            };
            let mut encoded = serde_json::to_vec(&answer)?;
            if encoded.len() > MAX_PLAINTEXT {
                let id = answer["id"].as_u64().unwrap_or(0);
                encoded =
                    serde_json::to_vec(&failure(id, "too_large", "The answer is too large."))?;
            }
            let Ok((counter, sealed)) = channel.seal(&encoded) else {
                return Ok(());
            };
            send(
                &mut writer,
                json!({"t": "msg", "c": counter, "d": b64(&sealed)}),
            )?;
        }
    }

    fn answer(&self, pairing: &Pairing, request: &Map<String, Value>) -> Value {
        let Some(id) = request.get("id").and_then(Value::as_u64) else {
            return failure(0, "protocol", "No request id.");
        };
        let exact = |fields: &[&str]| {
            request.len() == fields.len() + 2 && fields.iter().all(|f| request.contains_key(*f))
        };
        match request.get("op").and_then(Value::as_str) {
            Some("status") if exact(&[]) => {
                let state = if self.desktop.unlocked() {
                    "unlocked"
                } else {
                    "locked"
                };
                json!({"id": id, "ok": true, "value": {"state": state}})
            }
            Some("show") if exact(&[]) => {
                self.desktop.show();
                json!({"id": id, "ok": true, "value": {}})
            }
            Some("unpair") if exact(&[]) => {
                let _ = self.desktop.store().remove(&pairing.id);
                self.drop_pairings(std::slice::from_ref(&pairing.id));
                json!({"id": id, "ok": true, "value": {}})
            }
            Some("lock") if exact(&[]) => {
                self.forget_sessions();
                self.desktop.lock();
                json!({"id": id, "ok": true, "value": {}})
            }
            Some("api") if exact(&["route", "body"]) => {
                let route = request["route"].as_str().filter(|r| ROUTES.contains(r));
                match (route, request["body"].is_object()) {
                    (Some(route), true) => self.api(id, pairing, route, &request["body"]),
                    _ => failure(id, "protocol", "Unknown request."),
                }
            }
            _ => failure(id, "protocol", "Unknown request."),
        }
    }

    fn token(&self, pairing: &Pairing) -> Result<String, Refusal> {
        if !self.desktop.store().enabled() {
            return Err(Refusal::Locked);
        }
        if let Some(token) = self.tokens.lock().unwrap().get(&pairing.id) {
            return Ok(token.clone());
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let token = self.desktop.open_session(&pairing.browser, &pairing.id)?;
        let mut tokens = self.tokens.lock().unwrap();
        // The vault locked, the switch turned off or the pairing went while the
        // core opened it: end it instead of using it once.
        if self.generation.load(Ordering::SeqCst) != generation
            || !self.desktop.store().enabled()
            || self.desktop.store().find(&pairing.id).is_none()
        {
            drop(tokens);
            self.desktop.end_sessions(&pairing.id);
            return Err(Refusal::Locked);
        }
        tokens.insert(pairing.id.clone(), token.clone());
        Ok(token)
    }

    fn api(&self, id: u64, pairing: &Pairing, route: &str, body: &Value) -> Value {
        // A token the core stopped accepting (idle timeout, 12 h, a master
        // password change) is replaced once while the vault is unlocked.
        for _ in 0..2 {
            let token = match self.token(pairing) {
                Ok(token) => token,
                Err(Refusal::Locked) => return failure(id, "locked", "CipherMoth is locked."),
                Err(Refusal::Failed) => {
                    return failure(id, "unavailable", "CipherMoth did not answer.")
                }
            };
            match self.desktop.api(&token, route, body) {
                Ok((401, _)) => {
                    let mut tokens = self.tokens.lock().unwrap();
                    if tokens.get(&pairing.id) == Some(&token) {
                        tokens.remove(&pairing.id);
                    }
                }
                Ok((status, body)) if status < 300 => {
                    return json!({"id": id, "ok": true, "value": body})
                }
                Ok((status, body)) => {
                    let code = body.get("code").and_then(Value::as_str).unwrap_or("error");
                    let detail: String = body
                        .get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or("CipherMoth refused the request.")
                        .chars()
                        .take(300)
                        .collect();
                    return json!({"id": id, "ok": false, "status": status, "code": code, "detail": detail});
                }
                Err(Refusal::Locked) => return failure(id, "locked", "CipherMoth is locked."),
                Err(Refusal::Failed) => {
                    return failure(id, "unavailable", "CipherMoth did not answer.")
                }
            }
        }
        failure(id, "locked", "CipherMoth is locked.")
    }
}

fn read(stream: &mut Stream) -> io::Result<Object> {
    framing::read_object(stream).map_err(|e| match e {
        framing::FrameError::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    })
}

#[cfg(all(test, unix))]
mod tests;
