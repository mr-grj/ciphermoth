//! Native-messaging framing, used unchanged on the local socket: a u32 length
//! in the platform's byte order, then that many bytes of a UTF-8 JSON object.
//! Every message is at most 64 KiB in both directions (browsers allow more;
//! nothing CipherMoth sends needs it). A length is checked before anything is
//! allocated, and a stream that sent a bad frame is never read again.

use std::io::{self, Read, Write};

pub const MAX_MESSAGE: usize = 64 * 1024;

pub type Object = serde_json::Map<String, serde_json::Value>;

#[derive(Debug)]
pub enum FrameError {
    /// The stream ended cleanly between two frames.
    Eof,
    /// The stream ended inside a frame.
    Truncated,
    Empty,
    TooLarge(u64),
    NotJson,
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Eof => write!(f, "end of stream"),
            FrameError::Truncated => write!(f, "truncated frame"),
            FrameError::Empty => write!(f, "empty frame"),
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes is over the limit"),
            FrameError::NotJson => write!(f, "frame is not a UTF-8 JSON object"),
            FrameError::Io(e) => write!(f, "{e}"),
        }
    }
}

fn fill<R: Read>(reader: &mut R, buf: &mut [u8], at_boundary: bool) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 && at_boundary => return Err(FrameError::Eof),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0u8; 4];
    fill(reader, &mut prefix, true)?;
    let length = u32::from_ne_bytes(prefix) as u64;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_MESSAGE as u64 {
        return Err(FrameError::TooLarge(length));
    }
    let mut body = vec![0u8; length as usize];
    fill(reader, &mut body, false)?;
    Ok(body)
}

/// A frame that must hold a JSON object (serde_json also refuses invalid UTF-8).
pub fn read_object<R: Read>(reader: &mut R) -> Result<Object, FrameError> {
    let body = read_frame(reader)?;
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err(FrameError::NotJson),
    }
}

pub fn encode(body: &[u8]) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "message size"));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// One write per frame, so two writers sharing a stream never interleave.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    writer.write_all(&encode(body)?)?;
    writer.flush()
}

pub fn write_object<W: Write>(writer: &mut W, value: &serde_json::Value) -> io::Result<()> {
    write_frame(writer, &serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn round_trip_and_clean_end() {
        let mut stream = Vec::new();
        write_object(&mut stream, &serde_json::json!({"t": "hello"})).unwrap();
        write_object(&mut stream, &serde_json::json!({"t": "second"})).unwrap();
        let mut cursor = Cursor::new(stream);
        assert_eq!(read_object(&mut cursor).unwrap()["t"], "hello");
        assert_eq!(read_object(&mut cursor).unwrap()["t"], "second");
        assert!(matches!(read_object(&mut cursor), Err(FrameError::Eof)));
    }

    #[test]
    fn the_limit_is_inclusive_and_checked_before_allocation() {
        let body = format!("\"{}\"", "a".repeat(MAX_MESSAGE - 2));
        assert_eq!(
            read_frame(&mut Cursor::new(framed(body.as_bytes())))
                .unwrap()
                .len(),
            MAX_MESSAGE
        );
        let mut huge = (u32::MAX).to_ne_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame(&mut Cursor::new(huge)),
            Err(FrameError::TooLarge(_))
        ));
        let over = ((MAX_MESSAGE + 1) as u32).to_ne_bytes().to_vec();
        assert!(matches!(
            read_frame(&mut Cursor::new(over)),
            Err(FrameError::TooLarge(_))
        ));
        assert!(encode(&vec![b'x'; MAX_MESSAGE + 1]).is_err());
        assert!(encode(b"").is_err());
    }

    #[test]
    fn truncation_empty_and_non_objects() {
        let whole = framed(br#"{"t":"x"}"#);
        for cut in 1..whole.len() {
            assert!(
                matches!(
                    read_frame(&mut Cursor::new(&whole[..cut])),
                    Err(FrameError::Truncated)
                ),
                "cut at {cut}"
            );
        }
        assert!(matches!(
            read_frame(&mut Cursor::new(framed(b""))),
            Err(FrameError::Empty)
        ));
        for body in [
            &b"[1]"[..],
            b"\"s\"",
            b"42",
            b"{",
            b"\xff\xfe{}",
            b"{\"a\":\"\xc3\x28\"}",
        ] {
            assert!(
                matches!(
                    read_object(&mut Cursor::new(framed(body))),
                    Err(FrameError::NotJson)
                ),
                "{body:?}"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        // Arbitrary bytes never panic, never allocate past the limit and never
        // yield anything but a JSON object.
        #[test]
        fn arbitrary_streams_are_safe(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut cursor = Cursor::new(bytes);
            for _ in 0..8 {
                match read_object(&mut cursor) {
                    Ok(object) => prop_assert!(serde_json::to_vec(&object).unwrap().len() <= MAX_MESSAGE),
                    Err(_) => break,
                }
            }
        }

        #[test]
        fn any_object_round_trips(keys in proptest::collection::btree_map("[a-z]{1,8}", ".{0,40}", 0..12)) {
            let value = serde_json::to_value(&keys).unwrap();
            let mut stream = Vec::new();
            write_object(&mut stream, &value).unwrap();
            let back = read_object(&mut Cursor::new(stream)).unwrap();
            prop_assert_eq!(serde_json::Value::Object(back), value);
        }

        #[test]
        fn lengths_over_the_limit_are_refused(length in (MAX_MESSAGE as u32 + 1)..=u32::MAX) {
            let raw = length.to_ne_bytes().to_vec();
            prop_assert!(matches!(read_frame(&mut Cursor::new(raw)), Err(FrameError::TooLarge(_))));
        }
    }
}
