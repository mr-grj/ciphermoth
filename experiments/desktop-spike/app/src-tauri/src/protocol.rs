use std::io::{self, Read};

pub const MAGIC: [u8; 2] = *b"CM";
pub const VERSION: u8 = 1;
pub const PREFIX_SIZE: usize = 16;
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_BODY: usize = 24 * 1024 * 1024;

pub const REQUEST: u8 = 1;
pub const RESPONSE: u8 = 2;
pub const CANCEL: u8 = 3;
pub const READY: u8 = 4;
pub const ERROR: u8 = 5;
pub const SHUTDOWN: u8 = 6;

#[derive(Debug)]
pub struct Frame {
    pub kind: u8,
    pub id: u32,
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ReadError {
    Eof,
    Io(io::Error),
    Desync(&'static str),
}

pub fn encode(kind: u8, id: u32, header: &[u8], body: &[u8]) -> Result<Vec<u8>, &'static str> {
    if header.len() > MAX_HEADER {
        return Err("header_too_large");
    }
    if body.len() > MAX_BODY {
        return Err("too_large");
    }
    let mut out = Vec::with_capacity(PREFIX_SIZE + header.len() + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    Ok(out)
}

fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    at_boundary: bool,
) -> Result<(), ReadError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 && at_boundary => return Err(ReadError::Eof),
            Ok(0) => return Err(ReadError::Desync("truncated frame")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, ReadError> {
    let mut prefix = [0u8; PREFIX_SIZE];
    read_exact_or_eof(reader, &mut prefix, true)?;
    if prefix[0..2] != MAGIC || prefix[2] != VERSION {
        return Err(ReadError::Desync("bad magic or version"));
    }
    let kind = prefix[3];
    let id = u32::from_be_bytes(prefix[4..8].try_into().unwrap());
    let header_len = u32::from_be_bytes(prefix[8..12].try_into().unwrap()) as usize;
    let body_len = u32::from_be_bytes(prefix[12..16].try_into().unwrap()) as usize;
    if header_len > MAX_HEADER || body_len > MAX_BODY {
        return Err(ReadError::Desync("frame exceeds limits"));
    }
    let mut header = vec![0u8; header_len];
    read_exact_or_eof(reader, &mut header, false)?;
    let mut body = vec![0u8; body_len];
    read_exact_or_eof(reader, &mut body, false)?;
    Ok(Frame {
        kind,
        id,
        header,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_is_binary_safe() {
        let body: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        let encoded = encode(RESPONSE, 7, br#"{"status":200}"#, &body).unwrap();
        let frame = read_frame(&mut Cursor::new(encoded)).unwrap();
        assert_eq!((frame.kind, frame.id), (RESPONSE, 7));
        assert_eq!(frame.body, body);
    }

    #[test]
    fn oversized_lengths_are_refused_before_allocation() {
        let mut raw = Vec::from(MAGIC);
        raw.extend_from_slice(&[VERSION, RESPONSE]);
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            read_frame(&mut Cursor::new(raw)),
            Err(ReadError::Desync(_))
        ));
    }

    #[test]
    fn bad_magic_and_truncation() {
        let mut encoded = encode(READY, 0, b"{}", b"").unwrap();
        encoded[0] = b'X';
        assert!(matches!(
            read_frame(&mut Cursor::new(encoded)),
            Err(ReadError::Desync(_))
        ));
        let encoded = encode(READY, 0, b"{}", b"abc").unwrap();
        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            read_frame(&mut Cursor::new(truncated)),
            Err(ReadError::Desync(_))
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(Vec::new())),
            Err(ReadError::Eof)
        ));
    }

    #[test]
    fn encode_refuses_oversized_bodies() {
        assert_eq!(
            encode(REQUEST, 1, b"{}", &vec![0; MAX_BODY + 1]).unwrap_err(),
            "too_large"
        );
    }
}
