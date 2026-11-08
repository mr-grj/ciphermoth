//! The app's side against a Rust extension client over a real Unix socket,
//! with a fake desktop (design 8.4: pairing, SAS mismatch, replay, reorder,
//! tamper, locked).

use super::*;
use crate::client::{self, receive, send};
use crate::ipc::Endpoint;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;

const CHROME: &str = "chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/";

struct Fake {
    store: Store,
    unlocked: AtomicBool,
    approve: AtomicBool,
    codes: Mutex<Vec<String>>,
    sessions: AtomicU32,
    calls: Mutex<Vec<(String, String)>>,
    /// The token the fake core currently accepts.
    accepted: Mutex<Option<String>>,
    shown: AtomicU32,
    locked: AtomicU32,
    ended: Mutex<Vec<String>>,
    /// Turn the switch off while a session is being opened (the race).
    disable_during_open: AtomicBool,
    approve_delay_ms: AtomicU32,
}

impl Desktop for Fake {
    fn store(&self) -> &Store {
        &self.store
    }
    fn unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }
    fn approve(&self, _browser: &str, code: &str) -> bool {
        std::thread::sleep(Duration::from_millis(
            self.approve_delay_ms.load(Ordering::SeqCst) as u64,
        ));
        self.codes.lock().unwrap().push(code.to_string());
        self.approve.load(Ordering::SeqCst)
    }
    fn open_session(&self, _browser: &str, client: &str) -> Result<String, Refusal> {
        if !self.unlocked() {
            return Err(Refusal::Locked);
        }
        if self.disable_during_open.load(Ordering::SeqCst) {
            self.store.set_enabled(false).unwrap();
        }
        let n = self.sessions.fetch_add(1, Ordering::SeqCst);
        let token = format!("token-{client}-{n}");
        *self.accepted.lock().unwrap() = Some(token.clone());
        Ok(token)
    }
    fn api(&self, token: &str, route: &str, body: &Value) -> Result<(u16, Value), Refusal> {
        if !self.unlocked() {
            return Err(Refusal::Locked);
        }
        self.calls
            .lock()
            .unwrap()
            .push((token.to_string(), route.to_string()));
        if self.accepted.lock().unwrap().as_deref() != Some(token) {
            return Ok((
                401,
                json!({"detail": "Session ended.", "code": "invalid_session"}),
            ));
        }
        if route == "credential" && body["id"] == 404 {
            return Ok((404, json!({"detail": "No such login."})));
        }
        Ok((
            200,
            json!({"logins": [], "truncated": false, "route": route}),
        ))
    }
    fn end_sessions(&self, client: &str) {
        self.ended.lock().unwrap().push(client.to_string());
        let mut accepted = self.accepted.lock().unwrap();
        if accepted
            .as_deref()
            .is_some_and(|t| t.starts_with(&format!("token-{client}-")))
        {
            *accepted = None;
        }
    }
    fn show(&self) {
        self.shown.fetch_add(1, Ordering::SeqCst);
    }
    fn lock(&self) {
        self.locked.fetch_add(1, Ordering::SeqCst);
        self.unlocked.store(false, Ordering::SeqCst);
    }
}

struct Rig {
    link: Arc<Link<Fake>>,
    endpoint: Endpoint,
    running: Option<Running>,
    _dir: tempfile::TempDir,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("link")).unwrap();
        store.set_enabled(true).unwrap();
        let link = Link::new(Fake {
            store,
            unlocked: AtomicBool::new(true),
            approve: AtomicBool::new(true),
            codes: Mutex::new(Vec::new()),
            sessions: AtomicU32::new(0),
            calls: Mutex::new(Vec::new()),
            accepted: Mutex::new(None),
            shown: AtomicU32::new(0),
            locked: AtomicU32::new(0),
            ended: Mutex::new(Vec::new()),
            disable_during_open: AtomicBool::new(false),
            approve_delay_ms: AtomicU32::new(0),
        });
        let endpoint = Endpoint(dir.path().join("run/s"));
        let running = link.start(&endpoint).unwrap();
        Rig {
            link,
            endpoint,
            running: Some(running),
            _dir: dir,
        }
    }

    fn fake(&self) -> &Fake {
        self.link.desktop()
    }

    /// A connection as the native host makes it.
    fn connect(&self) -> Stream {
        let mut stream = self.endpoint.connect().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        send(
            &mut stream,
            json!({"t": "host", "caller": CHROME, "version": "test"}),
        )
        .unwrap();
        stream
    }

    fn pair(&self) -> (String, channel::Key, String) {
        let mut stream = self.connect();
        let start = client::pair_commit(&mut stream, "Chrome").unwrap();
        let revealed = client::pair_reveal(&mut stream, start).unwrap().unwrap();
        let id = client::pair_result(&mut stream).unwrap().unwrap();
        // The app stores the pairing just after sending "paired" (so a browser
        // that went away leaves none). The extension goes on over the same
        // connection, which the app reads only after storing; these tests open
        // a new one, which could arrive first on a busy runner.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while self.fake().store.find(&id).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the pairing was never stored"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        (id, revealed.key, revealed.sas)
    }

    fn session(&self, id: &str, key: &[u8; 32]) -> (Stream, client::Session) {
        let mut stream = self.connect();
        let session = client::hello(&mut stream, id, key).unwrap().unwrap();
        (stream, session)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }
}

fn closed(stream: &mut Stream) -> bool {
    receive(stream).is_err()
}

#[test]
fn pairing_shows_the_same_code_on_both_sides_and_then_fills() {
    let rig = Rig::new();
    let (id, key, sas) = rig.pair();
    assert_eq!(
        rig.fake().codes.lock().unwrap().as_slice(),
        std::slice::from_ref(&sas)
    );
    assert_eq!(sas.len(), 6);
    assert!(rig.fake().store.find(&id).is_some());
    let (mut stream, mut session) = rig.session(&id, &key);
    let status = session
        .request(&mut stream, json!({"op": "status"}))
        .unwrap();
    assert_eq!(status["value"]["state"], "unlocked");
    let found = session
        .request(
            &mut stream,
            json!({"op": "api", "route": "matches", "body": {"origin": "https://github.com"}}),
        )
        .unwrap();
    assert_eq!(found["ok"], true);
    assert_eq!(found["value"]["route"], "matches");
    // One session per pairing, reused, and named by the pairing.
    session
        .request(
            &mut stream,
            json!({"op": "api", "route": "search", "body": {"query": "x"}}),
        )
        .unwrap();
    assert_eq!(rig.fake().sessions.load(Ordering::SeqCst), 1);
    let calls = rig.fake().calls.lock().unwrap().clone();
    assert!(calls
        .iter()
        .all(|(token, _)| token == &format!("token-{id}-0")));
}

#[test]
fn a_pairing_on_the_same_connection_goes_straight_to_hello() {
    let rig = Rig::new();
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Firefox").unwrap();
    let revealed = client::pair_reveal(&mut stream, start).unwrap().unwrap();
    let id = client::pair_result(&mut stream).unwrap().unwrap();
    let mut session = client::hello(&mut stream, &id, &revealed.key)
        .unwrap()
        .unwrap();
    assert_eq!(
        session
            .request(&mut stream, json!({"op": "status"}))
            .unwrap()["ok"],
        true
    );
}

#[test]
fn a_denied_pairing_stores_nothing() {
    let rig = Rig::new();
    rig.fake().approve.store(false, Ordering::SeqCst);
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Chrome").unwrap();
    client::pair_reveal(&mut stream, start).unwrap().unwrap();
    assert_eq!(
        client::pair_result(&mut stream).unwrap(),
        Err("denied".to_string())
    );
    assert!(rig.fake().store.list().is_empty());
}

/// A process in the middle relays between the extension and the app with its
/// own keys. Both sides complete an exchange, but the codes differ, so a user
/// who compares them refuses (and the extension's key is not the app's).
#[test]
fn a_middle_that_swaps_keys_shows_a_different_code() {
    let rig = Rig::new();
    rig.fake().approve.store(false, Ordering::SeqCst);
    let mut to_app = rig.connect();
    // The attacker's side toward the app.
    let attacker_start = client::pair_commit(&mut to_app, "Chrome").unwrap();
    let attacker_view = client::pair_reveal(&mut to_app, attacker_start)
        .unwrap()
        .unwrap();
    // The extension's own exchange (with the attacker answering as the app).
    let ext = Exchange::new();
    let ext_nonce = channel::random::<16>();
    let attacker_app = Exchange::new();
    let attacker_nonce = channel::random::<16>();
    let t = channel::transcript(
        "Chrome",
        &ext.public,
        &ext_nonce,
        &attacker_app.public,
        &attacker_nonce,
    );
    let extension_view = ext.finish(&attacker_app.public, &t).unwrap();
    assert_eq!(
        client::pair_result(&mut to_app).unwrap(),
        Err("denied".to_string())
    );
    let shown_by_app = rig.fake().codes.lock().unwrap()[0].clone();
    assert_eq!(shown_by_app, attacker_view.sas);
    assert_ne!(*extension_view.key, *attacker_view.key);
    assert!(rig.fake().store.list().is_empty());
}

#[test]
fn a_reveal_that_breaks_the_commitment_is_refused_before_any_dialog() {
    let rig = Rig::new();
    let mut stream = rig.connect();
    client::pair_commit(&mut stream, "Chrome").unwrap();
    receive(&mut stream).unwrap();
    let other = Exchange::new();
    send(
        &mut stream,
        json!({"t": "pair_reveal", "pub": b64(&other.public), "nonce": b64(&[0; 16])}),
    )
    .unwrap();
    assert_eq!(
        client::refusal(&receive(&mut stream).unwrap()).as_deref(),
        Some("protocol")
    );
    assert!(rig.fake().codes.lock().unwrap().is_empty());
}

#[test]
fn a_low_order_key_is_refused() {
    let rig = Rig::new();
    let mut stream = rig.connect();
    let weak = [0u8; 32];
    let nonce = [9u8; 16];
    let commit = channel::commit(&weak, &nonce);
    send(
        &mut stream,
        json!({"t": "pair_commit", "browser": "Chrome", "commit": b64(&commit)}),
    )
    .unwrap();
    receive(&mut stream).unwrap();
    send(
        &mut stream,
        json!({"t": "pair_reveal", "pub": b64(&weak), "nonce": b64(&nonce)}),
    )
    .unwrap();
    assert_eq!(
        client::refusal(&receive(&mut stream).unwrap()).as_deref(),
        Some("protocol")
    );
    assert!(rig.fake().codes.lock().unwrap().is_empty());
}

#[test]
fn replayed_reordered_and_tampered_messages_end_the_connection() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();

    let (mut stream, mut session) = rig.session(&id, &key);
    let first = session.seal(json!({"op": "status"}));
    send(&mut stream, first.clone()).unwrap();
    session.open(&receive(&mut stream).unwrap()).unwrap();
    send(&mut stream, first).unwrap();
    assert!(closed(&mut stream), "replay");

    let (mut stream, mut session) = rig.session(&id, &key);
    let zero = session.seal(json!({"op": "status"}));
    let one = session.seal(json!({"op": "status"}));
    send(&mut stream, one).unwrap();
    assert!(closed(&mut stream), "reorder");
    drop(zero);

    let (mut stream, mut session) = rig.session(&id, &key);
    let mut frame = session.seal(json!({"op": "status"}));
    let mut sealed = unb64(frame["d"].as_str().unwrap()).unwrap();
    sealed[0] ^= 1;
    frame["d"] = json!(b64(&sealed));
    send(&mut stream, frame).unwrap();
    assert!(closed(&mut stream), "tamper");

    // A frame recorded on one connection is useless on the next.
    let (stream, mut session) = rig.session(&id, &key);
    let recorded = session.seal(json!({"op": "lock"}));
    drop(stream);
    let (mut stream, _) = rig.session(&id, &key);
    send(&mut stream, recorded).unwrap();
    assert!(closed(&mut stream), "cross-connection replay");
    assert_eq!(rig.fake().locked.load(Ordering::SeqCst), 0);
}

#[test]
fn a_wrong_pairing_key_or_unknown_id_gets_nothing() {
    let rig = Rig::new();
    let (id, _key, _) = rig.pair();
    let mut stream = rig.connect();
    assert_eq!(
        client::hello(&mut stream, &b64(&[1; 16]), &[0; 32])
            .unwrap()
            .err()
            .as_deref(),
        Some("unknown_pairing")
    );
    let (mut stream, mut session) = rig.session(&id, &[0; 32]);
    send(&mut stream, session.seal(json!({"op": "status"}))).unwrap();
    assert!(closed(&mut stream));
    assert!(rig.fake().calls.lock().unwrap().is_empty());
}

#[test]
fn locked_vault_and_unknown_requests() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    rig.fake().unlocked.store(false, Ordering::SeqCst);
    let (mut stream, mut session) = rig.session(&id, &key);
    assert_eq!(
        session
            .request(&mut stream, json!({"op": "status"}))
            .unwrap()["value"]["state"],
        "locked"
    );
    let refused = session
        .request(
            &mut stream,
            json!({"op": "api", "route": "credential", "body": {"id": 1}}),
        )
        .unwrap();
    assert_eq!(
        (refused["ok"].clone(), refused["code"].clone()),
        (json!(false), json!("locked"))
    );
    assert_eq!(
        session.request(&mut stream, json!({"op": "show"})).unwrap()["ok"],
        true
    );
    assert_eq!(rig.fake().shown.load(Ordering::SeqCst), 1);
    for bad in [
        json!({"op": "api", "route": "sessions", "body": {}}),
        json!({"op": "api", "route": "matches", "body": "x"}),
        json!({"op": "status", "extra": 1}),
        json!({"op": "export"}),
    ] {
        assert_eq!(
            session.request(&mut stream, bad).unwrap()["code"],
            "protocol"
        );
    }
    // Pairing needs an unlocked vault.
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Chrome").unwrap();
    assert_eq!(
        client::pair_reveal(&mut stream, start)
            .unwrap()
            .err()
            .as_deref(),
        Some("locked")
    );
}

#[test]
fn an_ended_session_is_replaced_once_and_lock_forgets_tokens() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    let call = json!({"op": "api", "route": "matches", "body": {}});
    session.request(&mut stream, call.clone()).unwrap();
    *rig.fake().accepted.lock().unwrap() = None; // the core ended it (idle)
    assert_eq!(
        session.request(&mut stream, call.clone()).unwrap()["ok"],
        true
    );
    assert_eq!(rig.fake().sessions.load(Ordering::SeqCst), 2);
    let missing = session
        .request(
            &mut stream,
            json!({"op": "api", "route": "credential", "body": {"id": 404}}),
        )
        .unwrap();
    assert_eq!(
        (missing["status"].clone(), missing["detail"].clone()),
        (json!(404), json!("No such login."))
    );
    session.request(&mut stream, json!({"op": "lock"})).unwrap();
    assert_eq!(rig.fake().locked.load(Ordering::SeqCst), 1);
    assert!(rig.link.tokens.lock().unwrap().is_empty());
}

#[test]
fn strangers_disabled_switch_and_too_many_connections() {
    let rig = Rig::new();
    let mut stream = rig.endpoint.connect().unwrap();
    send(&mut stream, json!({"t": "host", "caller": "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", "version": "x"}))
        .unwrap();
    assert_eq!(
        client::refusal(&receive(&mut stream).unwrap()).as_deref(),
        Some("caller")
    );

    rig.fake().store.set_enabled(false).unwrap();
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Chrome").unwrap();
    assert_eq!(
        client::pair_reveal(&mut stream, start)
            .unwrap()
            .err()
            .as_deref(),
        Some("disabled")
    );
    rig.fake().store.set_enabled(true).unwrap();

    let (tx, rx) = mpsc::channel();
    let held: Vec<Stream> = (0..MAX_CONNECTIONS).map(|_| rig.connect()).collect();
    std::thread::sleep(Duration::from_millis(200));
    let mut extra = rig.endpoint.connect().unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    tx.send(()).unwrap();
    assert!(closed(&mut extra), "the ninth connection is closed at once");
    drop(held);
    rx.recv().unwrap();
}

#[test]
fn closing_connections_and_stopping() {
    let mut rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, _session) = rig.session(&id, &key);
    rig.link.close_connections();
    assert!(closed(&mut stream));
    rig.running.take().unwrap().stop();
    assert!(rig.endpoint.connect().is_err());
}

// --- adversarial ---------------------------------------------------------------

#[test]
fn pairing_attempts_are_throttled() {
    let rig = Rig::new();
    rig.fake().approve.store(false, Ordering::SeqCst);
    for _ in 0..PAIRINGS_PER_MINUTE {
        let mut stream = rig.connect();
        let start = client::pair_commit(&mut stream, "Chrome").unwrap();
        client::pair_reveal(&mut stream, start).unwrap().unwrap();
        assert_eq!(
            client::pair_result(&mut stream).unwrap(),
            Err("denied".to_string())
        );
    }
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Chrome").unwrap();
    assert_eq!(
        client::pair_reveal(&mut stream, start)
            .unwrap()
            .err()
            .as_deref(),
        Some("busy")
    );
    assert_eq!(rig.fake().codes.lock().unwrap().len(), PAIRINGS_PER_MINUTE);
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    fn field() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<u64>().prop_map(|n| json!(n)),
            "[ -~]{0,40}".prop_map(|s| json!(s)),
            proptest::collection::vec(any::<u8>(), 0..48).prop_map(|b| json!(b64(&b))),
            Just(json!(null)),
            Just(json!({"nested": [1, 2]})),
        ]
    }

    fn envelope() -> impl Strategy<Value = Value> {
        let kinds = prop_oneof![
            Just("host".to_string()),
            Just("pair_commit".to_string()),
            Just("pair_reveal".to_string()),
            Just("hello".to_string()),
            Just("msg".to_string()),
            Just("paired".to_string()),
            Just("refused".to_string()),
            Just("launch".to_string()),
            "[a-z_]{1,12}",
        ];
        let names = prop_oneof![
            Just("caller".to_string()),
            Just("version".to_string()),
            Just("browser".to_string()),
            Just("commit".to_string()),
            Just("pub".to_string()),
            Just("nonce".to_string()),
            Just("id".to_string()),
            Just("c".to_string()),
            Just("d".to_string()),
            "[a-z]{1,6}",
        ];
        (kinds, proptest::collection::btree_map(names, field(), 0..5)).prop_map(|(kind, fields)| {
            let mut object = serde_json::Map::new();
            object.insert("t".into(), json!(kind));
            object.extend(fields);
            Value::Object(object)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

        /// Whatever a local process sends, nothing is paired, no dialog is
        /// shown, no session is opened, no vault call is made, and the app
        /// still serves a real client afterwards.
        #[test]
        fn hostile_message_sequences_reach_nothing(
            host_first in any::<bool>(),
            messages in proptest::collection::vec(envelope(), 0..6),
            raw in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let rig = Rig::new();
            let mut stream = rig.endpoint.connect().unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            if host_first {
                send(&mut stream, json!({"t": "host", "caller": CHROME, "version": "1"})).unwrap();
            }
            for message in &messages {
                if send(&mut stream, message.clone()).is_err() {
                    break;
                }
                let _ = receive(&mut stream);
            }
            use std::io::Write;
            let _ = stream.write_all(&raw);
            drop(stream);
            let fake = rig.fake();
            prop_assert!(fake.store.list().is_empty());
            prop_assert!(fake.codes.lock().unwrap().is_empty() || messages.iter().any(|m| m["t"] == "pair_reveal"));
            prop_assert_eq!(fake.sessions.load(Ordering::SeqCst), 0);
            prop_assert!(fake.calls.lock().unwrap().is_empty());
            // Still alive for a real browser.
            let (id, key, _) = rig.pair();
            let (mut stream, mut session) = rig.session(&id, &key);
            prop_assert_eq!(&session.request(&mut stream, json!({"op": "status"})).unwrap()["ok"], &json!(true));
        }

        /// A paired connection that receives forged or random sealed frames
        /// closes without acting on them.
        #[test]
        fn forged_frames_on_a_paired_connection_do_nothing(
            frames in proptest::collection::vec((any::<u64>(), proptest::collection::vec(any::<u8>(), 0..80)), 1..4),
        ) {
            let rig = Rig::new();
            let (id, key, _) = rig.pair();
            let (mut stream, _session) = rig.session(&id, &key);
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            for (counter, data) in frames {
                if send(&mut stream, json!({"t": "msg", "c": counter, "d": b64(&data)})).is_err() {
                    break;
                }
            }
            prop_assert!(receive(&mut stream).is_err());
            prop_assert_eq!(rig.fake().shown.load(Ordering::SeqCst), 0);
            prop_assert_eq!(rig.fake().locked.load(Ordering::SeqCst), 0);
            prop_assert!(rig.fake().calls.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn a_connection_that_survives_the_switch_turning_off_gets_nothing() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    session
        .request(&mut stream, json!({"op": "status"}))
        .unwrap();
    // Turned off without close_connections reaching this connection (the race
    // of a connection accepted while the switch turns off).
    rig.fake().store.set_enabled(false).unwrap();
    send(
        &mut stream,
        session.seal(json!({"op": "api", "route": "matches", "body": {}})),
    )
    .unwrap();
    assert!(closed(&mut stream));
    assert_eq!(rig.fake().sessions.load(Ordering::SeqCst), 0);
    assert!(rig.fake().calls.lock().unwrap().is_empty());
}

#[test]
fn a_session_opened_while_the_switch_turns_off_is_ended_not_used() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    rig.fake().disable_during_open.store(true, Ordering::SeqCst);
    let reply = session
        .request(
            &mut stream,
            json!({"op": "api", "route": "credential", "body": {"id": 1}}),
        )
        .unwrap();
    assert_eq!(reply["code"], "locked");
    assert!(
        rig.fake().calls.lock().unwrap().is_empty(),
        "the token was never used"
    );
    assert_eq!(
        rig.fake().ended.lock().unwrap().as_slice(),
        std::slice::from_ref(&id)
    );
    assert!(rig.link.tokens.lock().unwrap().is_empty());
}

#[test]
fn a_pairing_removed_in_the_app_loses_its_open_connection() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    session
        .request(&mut stream, json!({"op": "status"}))
        .unwrap();
    // Removed (Settings, or evicted by a 17th pairing) without closing this.
    rig.fake().store.remove(&id).unwrap();
    send(
        &mut stream,
        session.seal(json!({"op": "api", "route": "matches", "body": {}})),
    )
    .unwrap();
    assert!(closed(&mut stream));
    assert!(rig.fake().calls.lock().unwrap().is_empty());
}

#[test]
fn an_approval_after_the_browser_left_stores_nothing() {
    let rig = Rig::new();
    rig.fake().approve_delay_ms.store(400, Ordering::SeqCst);
    let mut stream = rig.connect();
    let start = client::pair_commit(&mut stream, "Chrome").unwrap();
    client::pair_reveal(&mut stream, start).unwrap().unwrap();
    stream.shutdown(); // the user cancelled in the popup
    drop(stream);
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(
        rig.fake().codes.lock().unwrap().len(),
        1,
        "the dialog was shown"
    );
    assert!(rig.fake().store.list().is_empty(), "but nothing was paired");
}

#[test]
fn unpairing_from_the_extension_removes_it_in_the_app() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    session
        .request(
            &mut stream,
            json!({"op": "api", "route": "matches", "body": {}}),
        )
        .unwrap();
    assert_eq!(
        session
            .request(&mut stream, json!({"op": "unpair"}))
            .unwrap()["ok"],
        true
    );
    assert!(rig.fake().store.list().is_empty());
    assert!(rig.fake().ended.lock().unwrap().contains(&id));
    assert!(rig.link.tokens.lock().unwrap().is_empty());
    send(&mut stream, session.seal(json!({"op": "status"}))).unwrap();
    assert!(closed(&mut stream));
    let mut again = rig.connect();
    assert_eq!(
        client::hello(&mut again, &id, &key)
            .unwrap()
            .err()
            .as_deref(),
        Some("unknown_pairing")
    );
}

#[test]
fn use_is_recorded_at_most_once_a_minute() {
    let rig = Rig::new();
    let (id, key, _) = rig.pair();
    let (mut stream, mut session) = rig.session(&id, &key);
    session
        .request(&mut stream, json!({"op": "status"}))
        .unwrap();
    let first = rig.fake().store.find(&id).unwrap().last_used;
    assert!(first.is_some());
    let config = rig._dir.path().join("link/config.json");
    let written = std::fs::metadata(&config).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let (mut stream, mut session) = rig.session(&id, &key);
    session
        .request(&mut stream, json!({"op": "status"}))
        .unwrap();
    assert_eq!(
        std::fs::metadata(&config).unwrap().modified().unwrap(),
        written
    );
}
