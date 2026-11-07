//! The paired channel between the extension and the app (vectors:
//! testdata/vectors/extension-channel.json, spec: docs/EXTENSION.md).
//!
//! Pairing is an X25519 exchange in which the extension commits to its key
//! before it sees the app's, so a process in the middle cannot search for keys
//! that make both sides show the same six digits: it gets one guess in a
//! million per attempt, and every attempt needs the user to approve a dialog.
//! The pairing key never encrypts anything itself. Each connection derives its
//! own key from fresh nonces of both sides, so counters restart at zero without
//! ever reusing a nonce, and a message recorded on one connection is useless on
//! another.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const LABEL: &str = "ciphermoth/extension/v1";
pub const TO_APP: u8 = 0x01;
pub const TO_EXTENSION: u8 = 0x02;
/// A connection is closed long before; this keeps counters far from overflow.
pub const MAX_MESSAGES: u64 = 1 << 32;

#[derive(Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// A low-order public key: the shared secret would be predictable.
    WeakKey,
    /// Not the next message, or not authentic.
    Refused,
    Exhausted,
}

pub type Key = Zeroizing<[u8; 32]>;

fn lp(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &str, out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info.as_bytes(), out)
        .expect("HKDF output length is valid");
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("the operating system's random source");
    out
}

pub fn commit(public: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut data = Vec::new();
    lp(&mut data, format!("{LABEL}/commit").as_bytes());
    data.extend_from_slice(public);
    data.extend_from_slice(nonce);
    sha256(&data)
}

pub fn transcript(
    browser: &str,
    extension_public: &[u8; 32],
    extension_nonce: &[u8; 16],
    app_public: &[u8; 32],
    app_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut data = Vec::new();
    lp(&mut data, format!("{LABEL}/pair").as_bytes());
    lp(&mut data, browser.as_bytes());
    data.extend_from_slice(extension_public);
    data.extend_from_slice(extension_nonce);
    data.extend_from_slice(app_public);
    data.extend_from_slice(app_nonce);
    sha256(&data)
}

/// One side of a pairing exchange: a fresh X25519 key.
pub struct Exchange {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl Exchange {
    pub fn new() -> Self {
        Self::from_private(Zeroizing::new(random::<32>()))
    }

    pub fn from_private(private: Zeroizing<[u8; 32]>) -> Self {
        let secret = StaticSecret::from(*private);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// The six-digit code and the pairing key, from the peer's key and the
    /// transcript of the exchange.
    pub fn finish(&self, peer: &[u8; 32], transcript: &[u8; 32]) -> Result<Paired, ChannelError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(ChannelError::WeakKey);
        }
        let mut sas = [0u8; 4];
        hkdf(
            shared.as_bytes(),
            transcript,
            &format!("{LABEL}/sas"),
            &mut sas,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf(
            shared.as_bytes(),
            transcript,
            &format!("{LABEL}/channel"),
            &mut key[..],
        );
        Ok(Paired {
            sas: format!("{:06}", u32::from_be_bytes(sas) % 1_000_000),
            key,
        })
    }
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Paired {
    pub sas: String,
    pub key: Key,
}

pub fn connection_key(
    pairing_key: &[u8; 32],
    pairing_id: &[u8; 16],
    extension_nonce: &[u8; 16],
    app_nonce: &[u8; 16],
) -> Key {
    let mut salt = Vec::new();
    lp(&mut salt, format!("{LABEL}/connection").as_bytes());
    salt.extend_from_slice(pairing_id);
    salt.extend_from_slice(extension_nonce);
    salt.extend_from_slice(app_nonce);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf(
        pairing_key,
        &sha256(&salt),
        &format!("{LABEL}/connection"),
        &mut key[..],
    );
    key
}

fn nonce_and_ad(direction: u8, counter: u64) -> ([u8; 12], [u8; 9]) {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    let mut ad = [0u8; 9];
    ad[0] = direction;
    ad[1..].copy_from_slice(&counter.to_be_bytes());
    (nonce, ad)
}

pub fn seal(key: &[u8; 32], direction: u8, counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let (nonce, ad) = nonce_and_ad(direction, counter);
    Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .expect("AES-GCM encryption of a bounded message")
}

pub fn open(
    key: &[u8; 32],
    direction: u8,
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ChannelError> {
    let (nonce, ad) = nonce_and_ad(direction, counter);
    Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| ChannelError::Refused)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    App,
    Extension,
}

/// One connection's state: the key and both counters. A message is read only
/// if it carries exactly the next counter, so replayed, reordered, dropped or
/// reflected messages all fail.
pub struct Channel {
    key: Key,
    sends: u8,
    receives: u8,
    sent: u64,
    received: u64,
}

impl Channel {
    pub fn new(key: Key, side: Side) -> Self {
        let (sends, receives) = match side {
            Side::App => (TO_EXTENSION, TO_APP),
            Side::Extension => (TO_APP, TO_EXTENSION),
        };
        Self {
            key,
            sends,
            receives,
            sent: 0,
            received: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), ChannelError> {
        if self.sent >= MAX_MESSAGES {
            return Err(ChannelError::Exhausted);
        }
        let counter = self.sent;
        self.sent += 1;
        Ok((counter, seal(&self.key, self.sends, counter, plaintext)))
    }

    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if counter != self.received || self.received >= MAX_MESSAGES {
            return Err(ChannelError::Refused);
        }
        let plaintext = open(&self.key, self.receives, counter, ciphertext)?;
        self.received += 1;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{b64, unb64};
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../testdata/vectors/extension-channel.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn hex32(value: &Value) -> [u8; 32] {
        let text = value.as_str().unwrap();
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn fixed<const N: usize>(value: &Value) -> [u8; N] {
        unb64(value.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_frozen_vectors() {
        let doc = vectors();
        for case in doc["cases"].as_array().unwrap() {
            let ext = Exchange::from_private(Zeroizing::new(hex32(&case["extension_private_hex"])));
            let app = Exchange::from_private(Zeroizing::new(hex32(&case["app_private_hex"])));
            assert_eq!(b64(&ext.public), case["extension_public"]);
            assert_eq!(b64(&app.public), case["app_public"]);
            let (n_x, n_a) = (
                fixed::<16>(&case["extension_nonce"]),
                fixed::<16>(&case["app_nonce"]),
            );
            assert_eq!(b64(&commit(&ext.public, &n_x)), case["commit"]);
            let browser = case["browser"].as_str().unwrap();
            let t = transcript(browser, &ext.public, &n_x, &app.public, &n_a);
            assert_eq!(t, hex32(&case["transcript_hex"]));
            let from_ext = ext.finish(&app.public, &t).unwrap();
            let from_app = app.finish(&ext.public, &t).unwrap();
            assert_eq!(from_ext.sas, case["sas"].as_str().unwrap());
            assert_eq!(from_app.sas, from_ext.sas);
            assert_eq!(*from_ext.key, hex32(&case["pairing_key_hex"]));
            assert_eq!(*from_app.key, *from_ext.key);
            let key = connection_key(
                &from_app.key,
                &fixed::<16>(&case["pairing_id"]),
                &fixed::<16>(&case["hello_extension_nonce"]),
                &fixed::<16>(&case["hello_app_nonce"]),
            );
            assert_eq!(*key, hex32(&case["connection_key_hex"]));
            let mut app_side = Channel::new(key.clone(), Side::App);
            let mut ext_side = Channel::new(key, Side::Extension);
            for message in case["messages"].as_array().unwrap() {
                let plain = message["plaintext"].as_str().unwrap().as_bytes();
                let counter = message["counter"].as_u64().unwrap();
                let sealed = unb64(message["ciphertext"].as_str().unwrap()).unwrap();
                let (sender, receiver) = if message["direction"] == 1 {
                    (&mut ext_side, &mut app_side)
                } else {
                    (&mut app_side, &mut ext_side)
                };
                assert_eq!(sender.seal(plain).unwrap(), (counter, sealed.clone()));
                assert_eq!(receiver.open(counter, &sealed).unwrap(), plain);
            }
        }
    }

    #[test]
    fn refused_vectors_and_low_order_points() {
        let doc = vectors();
        let key = hex32(&doc["cases"][0]["connection_key_hex"]);
        for refused in doc["refused"].as_array().unwrap() {
            let sealed = unb64(refused["ciphertext"].as_str().unwrap()).unwrap();
            let direction = refused["direction"].as_u64().unwrap() as u8;
            let counter = refused["counter"].as_u64().unwrap();
            assert_eq!(
                open(&key, direction, counter, &sealed),
                Err(ChannelError::Refused),
                "{}",
                refused["reason"]
            );
        }
        let app = Exchange::new();
        for point in doc["low_order_points"].as_array().unwrap() {
            let point = fixed::<32>(point);
            assert!(matches!(
                app.finish(&point, &[0; 32]),
                Err(ChannelError::WeakKey)
            ));
        }
    }

    #[test]
    fn a_channel_reads_only_the_next_message() {
        let key = Zeroizing::new(random::<32>());
        let mut ext = Channel::new(key.clone(), Side::Extension);
        let mut app = Channel::new(key, Side::App);
        let (c0, m0) = ext.seal(b"zero").unwrap();
        let (c1, m1) = ext.seal(b"one").unwrap();
        assert_eq!(app.open(c1, &m1), Err(ChannelError::Refused), "reordered");
        assert_eq!(app.open(c0, &m0).unwrap(), b"zero");
        assert_eq!(app.open(c0, &m0), Err(ChannelError::Refused), "replayed");
        assert_eq!(app.open(c1, &m0), Err(ChannelError::Refused), "relabelled");
        assert_eq!(app.open(c1, &m1).unwrap(), b"one");
        // The app's own message reflected back to it.
        let (c, m) = app.seal(b"reply").unwrap();
        assert_eq!(app.open(c, &m), Err(ChannelError::Refused));
        let mut tampered = ext.seal(b"two").unwrap();
        tampered.1[3] ^= 0x80;
        assert_eq!(
            app.open(tampered.0, &tampered.1),
            Err(ChannelError::Refused)
        );
    }

    #[test]
    fn a_middle_that_swaps_keys_shows_different_codes() {
        // Each side completes an exchange with the attacker instead of the other.
        let (ext, app, attacker) = (Exchange::new(), Exchange::new(), Exchange::new());
        let (n_x, n_a) = (random::<16>(), random::<16>());
        let t_ext = transcript("Chrome", &ext.public, &n_x, &attacker.public, &n_a);
        let t_app = transcript("Chrome", &attacker.public, &n_x, &app.public, &n_a);
        let seen_by_ext = ext.finish(&attacker.public, &t_ext).unwrap();
        let seen_by_app = app.finish(&attacker.public, &t_app).unwrap();
        assert_ne!(*seen_by_ext.key, *seen_by_app.key);
        assert_ne!(seen_by_ext.sas, seen_by_app.sas);
    }
}
