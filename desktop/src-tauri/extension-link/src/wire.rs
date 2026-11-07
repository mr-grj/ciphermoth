//! Strict reading of the JSON messages: an envelope has a string `t` and
//! exactly the fields its type names, binary values are unpadded base64url of a
//! fixed length. Anything else is a protocol error and ends the connection.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    if text.len() > 96 * 1024 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// The envelope type, `t`.
pub fn kind(object: &Map<String, Value>) -> Option<&str> {
    object.get("t")?.as_str()
}

pub fn has_exactly(object: &Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() + 1
        && object.contains_key("t")
        && fields.iter().all(|field| object.contains_key(*field))
}

pub fn bytes<const N: usize>(object: &Map<String, Value>, field: &str) -> Option<[u8; N]> {
    let text = object.get(field)?.as_str()?;
    if text.len() > N.div_ceil(3) * 4 {
        return None;
    }
    unb64(text)?.try_into().ok()
}

pub fn text<'a>(object: &'a Map<String, Value>, field: &str, max: usize) -> Option<&'a str> {
    object
        .get(field)?
        .as_str()
        .filter(|value| value.len() <= max)
}

pub fn counter(object: &Map<String, Value>) -> Option<u64> {
    object.get("c")?.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_fields_and_fixed_lengths() {
        let ok = json!({"t": "hello", "id": b64(&[7; 16]), "nonce": b64(&[1; 16])});
        let ok = ok.as_object().unwrap();
        assert!(has_exactly(ok, &["id", "nonce"]));
        assert!(!has_exactly(ok, &["id"]));
        assert!(!has_exactly(ok, &["id", "nonce", "extra"]));
        assert_eq!(bytes::<16>(ok, "id"), Some([7; 16]));
        assert_eq!(bytes::<32>(ok, "id"), None);
        let padded = json!({"t": "x", "id": format!("{}==", b64(&[7; 16]))});
        assert_eq!(bytes::<16>(padded.as_object().unwrap(), "id"), None);
        let std_alphabet = json!({"t": "x", "id": "+/+/+/+/+/+/+/+/+/+/+w"});
        assert_eq!(bytes::<16>(std_alphabet.as_object().unwrap(), "id"), None);
    }
}
