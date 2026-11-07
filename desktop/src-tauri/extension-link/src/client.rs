//! The extension's side of the protocol, in Rust: used by the tests and by the
//! `ipc_probe` example. The real extension implements the same steps in
//! TypeScript (extension/src/background/desktop.ts); both are checked against
//! testdata/vectors/extension-channel.json.

use serde_json::{json, Value};
use std::io::{self, Read, Write};

use crate::channel::{self, Channel, Exchange, Side};
use crate::framing::{self, Object};
use crate::wire::{b64, bytes, kind, unb64};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub fn send<W: Write>(writer: &mut W, value: Value) -> io::Result<()> {
    framing::write_object(writer, &value)
}

pub fn receive<R: Read>(reader: &mut R) -> io::Result<Object> {
    framing::read_object(reader).map_err(|e| invalid(&e.to_string()))
}

/// The `refused` code of a message, if it is a refusal.
pub fn refusal(message: &Object) -> Option<String> {
    (kind(message) == Some("refused")).then(|| message["code"].as_str().unwrap_or("").to_string())
}

pub struct PairingStart {
    exchange: Exchange,
    nonce: [u8; 16],
    browser: String,
}

/// Step 1: commit to a fresh key.
pub fn pair_commit<W: Write>(writer: &mut W, browser: &str) -> io::Result<PairingStart> {
    let exchange = Exchange::new();
    let nonce = channel::random::<16>();
    let commit = channel::commit(&exchange.public, &nonce);
    send(
        writer,
        json!({"t": "pair_commit", "browser": browser, "commit": b64(&commit)}),
    )?;
    Ok(PairingStart {
        exchange,
        nonce,
        browser: browser.to_string(),
    })
}

pub struct Revealed {
    pub sas: String,
    pub key: channel::Key,
}

/// Steps 2 and 3: read the app's key, reveal ours, compute the code to show.
pub fn pair_reveal<S: Read + Write>(
    stream: &mut S,
    start: PairingStart,
) -> io::Result<Result<Revealed, String>> {
    let answer = receive(stream)?;
    if let Some(code) = refusal(&answer) {
        return Ok(Err(code));
    }
    let (Some(public), Some(app_nonce)) =
        (bytes::<32>(&answer, "pub"), bytes::<16>(&answer, "nonce"))
    else {
        return Err(invalid("no pair_key"));
    };
    send(
        stream,
        json!({"t": "pair_reveal", "pub": b64(&start.exchange.public), "nonce": b64(&start.nonce)}),
    )?;
    let transcript = channel::transcript(
        &start.browser,
        &start.exchange.public,
        &start.nonce,
        &public,
        &app_nonce,
    );
    let paired = start
        .exchange
        .finish(&public, &transcript)
        .map_err(|_| invalid("weak key"))?;
    Ok(Ok(Revealed {
        sas: paired.sas,
        key: paired.key,
    }))
}

/// Step 4: wait for the user's answer in the app.
pub fn pair_result<R: Read>(reader: &mut R) -> io::Result<Result<String, String>> {
    let answer = receive(reader)?;
    if let Some(code) = refusal(&answer) {
        return Ok(Err(code));
    }
    match (kind(&answer), answer.get("id").and_then(Value::as_str)) {
        (Some("paired"), Some(id)) => Ok(Ok(id.to_string())),
        _ => Err(invalid("no paired")),
    }
}

pub struct Session {
    pub channel: Channel,
    next_id: u64,
}

pub fn hello<S: Read + Write>(
    stream: &mut S,
    id: &str,
    pairing_key: &[u8; 32],
) -> io::Result<Result<Session, String>> {
    let nonce = channel::random::<16>();
    send(
        stream,
        json!({"t": "hello", "id": id, "nonce": b64(&nonce)}),
    )?;
    let answer = receive(stream)?;
    if let Some(code) = refusal(&answer) {
        return Ok(Err(code));
    }
    let app_nonce = bytes::<16>(&answer, "nonce").ok_or_else(|| invalid("no hello_ok"))?;
    let id_bytes: [u8; 16] = unb64(id)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("bad id"))?;
    let key = channel::connection_key(pairing_key, &id_bytes, &nonce, &app_nonce);
    Ok(Ok(Session {
        channel: Channel::new(key, Side::Extension),
        next_id: 1,
    }))
}

impl Session {
    /// Seal a request and return the frame (tests replay or tamper with it).
    pub fn seal(&mut self, mut request: Value) -> Value {
        request["id"] = json!(self.next_id);
        self.next_id += 1;
        let (counter, sealed) = self
            .channel
            .seal(&serde_json::to_vec(&request).unwrap())
            .unwrap();
        json!({"t": "msg", "c": counter, "d": b64(&sealed)})
    }

    pub fn open(&mut self, frame: &Object) -> io::Result<Value> {
        let counter = frame
            .get("c")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("no counter"))?;
        let sealed = frame
            .get("d")
            .and_then(Value::as_str)
            .and_then(unb64)
            .ok_or_else(|| invalid("no data"))?;
        let plain = self
            .channel
            .open(counter, &sealed)
            .map_err(|_| invalid("not authentic"))?;
        serde_json::from_slice(&plain).map_err(|_| invalid("not JSON"))
    }

    pub fn request<S: Read + Write>(
        &mut self,
        stream: &mut S,
        request: Value,
    ) -> io::Result<Value> {
        let frame = self.seal(request);
        send(stream, frame)?;
        let answer = receive(stream)?;
        self.open(&answer)
    }
}
