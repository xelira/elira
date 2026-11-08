//! FastCGI record framing and name-value encoding.
//!
//! Everything here is byte-oriented and independent of sockets, which keeps
//! the tricky length arithmetic testable without a server.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Error;

/// The only protocol version this client speaks.
pub(crate) const VERSION: u8 = 1;

/// Request id used for the single request on a connection.
pub(crate) const REQUEST_ID: u16 = 1;

/// FastCGI content lengths are 16-bit.
pub(crate) const MAX_CONTENT: usize = u16::MAX as usize;

/// FastCGI role `RESPONDER`.
const ROLE_RESPONDER: u16 = 1;

/// Record types from the FastCGI specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    UnknownType = 11,
}

impl RecordType {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::BeginRequest),
            2 => Some(Self::AbortRequest),
            3 => Some(Self::EndRequest),
            4 => Some(Self::Params),
            5 => Some(Self::Stdin),
            6 => Some(Self::Stdout),
            7 => Some(Self::Stderr),
            8 => Some(Self::Data),
            9 => Some(Self::GetValues),
            10 => Some(Self::GetValuesResult),
            11 => Some(Self::UnknownType),
            _ => None,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::BeginRequest => "BEGIN_REQUEST",
            Self::AbortRequest => "ABORT_REQUEST",
            Self::EndRequest => "END_REQUEST",
            Self::Params => "PARAMS",
            Self::Stdin => "STDIN",
            Self::Stdout => "STDOUT",
            Self::Stderr => "STDERR",
            Self::Data => "DATA",
            Self::GetValues => "GET_VALUES",
            Self::GetValuesResult => "GET_VALUES_RESULT",
            Self::UnknownType => "UNKNOWN_TYPE",
        }
    }
}

/// Decoded record header. The reserved byte is not part of this struct
/// because the specification requires senders to set it to zero but readers
/// have no reason to reject a peer that does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) record_type: u8,
    pub(crate) request_id: u16,
    pub(crate) content_length: u16,
    pub(crate) padding_length: u8,
}

/// One record read from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) record_type: u8,
    pub(crate) request_id: u16,
    pub(crate) content: Vec<u8>,
}

/// Build the eight-byte header that precedes every record.
pub(crate) fn encode_header(
    record_type: RecordType,
    request_id: u16,
    content_length: u16,
    padding_length: u8,
) -> [u8; 8] {
    let request = request_id.to_be_bytes();
    let content = content_length.to_be_bytes();
    [
        VERSION,
        record_type as u8,
        request[0],
        request[1],
        content[0],
        content[1],
        padding_length,
        0,
    ]
}

/// Parse and validate a record header.
pub(crate) fn decode_header(raw: [u8; 8]) -> Result<Header, Error> {
    if raw[0] != VERSION {
        return Err(Error::Protocol(format!(
            "record version {} is not {VERSION}",
            raw[0]
        )));
    }

    Ok(Header {
        record_type: raw[1],
        request_id: u16::from_be_bytes([raw[2], raw[3]]),
        content_length: u16::from_be_bytes([raw[4], raw[5]]),
        padding_length: raw[6],
    })
}

/// Build a `BEGIN_REQUEST` body with the `FCGI_KEEP_CONN` flag optionally set.
///
/// One-shot requests pass `false` and leave the flags at zero. Pooled
/// requests pass `true` so the responder keeps the connection open after
/// `END_REQUEST`.
///
/// Flag bit 0 is `FCGI_KEEP_CONN`; the rest stay zero because this client
/// never negotiates multiplexing.
pub(crate) fn begin_request_body_with_keep_conn(keep_conn: bool) -> [u8; 8] {
    let mut body = [0u8; 8];
    body[..2].copy_from_slice(&ROLE_RESPONDER.to_be_bytes());
    body[2] = u8::from(keep_conn);
    body
}

/// Read one record, or `None` on a clean end of stream at a record boundary.
///
/// A clean EOF is returned as `None` so the caller can tell "the server
/// simply closed" from "the server closed in the middle of a record". The
/// latter is a protocol error and gets the message a person needs at 2am.
pub(crate) async fn read_record<S>(stream: &mut S) -> Result<Option<Record>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut raw = [0u8; 8];
    let first = stream.read(&mut raw[..1]).await.map_err(read_error)?;
    if first == 0 {
        return Ok(None);
    }

    stream
        .read_exact(&mut raw[1..])
        .await
        .map_err(|source| truncated(source, "record header"))?;
    let header = decode_header(raw)?;

    let mut content = vec![0u8; usize::from(header.content_length)];
    stream
        .read_exact(&mut content)
        .await
        .map_err(|source| truncated(source, "record body"))?;

    if header.padding_length != 0 {
        let mut padding = [0u8; 255];
        stream
            .read_exact(&mut padding[..usize::from(header.padding_length)])
            .await
            .map_err(|source| truncated(source, "record padding"))?;
    }

    Ok(Some(Record {
        record_type: header.record_type,
        request_id: header.request_id,
        content,
    }))
}

/// Encode every parameter as `name-length name value-length value`.
pub(crate) fn encode_params(params: &[(String, String)]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for (name, value) in params {
        encode_length(name.len(), &mut out)?;
        encode_length(value.len(), &mut out)?;
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    Ok(out)
}

/// FastCGI uses one byte below 128 and a high-bit-set four-byte value above.
fn encode_length(length: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    if length <= 0x7f {
        out.push(length as u8);
        return Ok(());
    }

    if length <= 0x7fff_ffff {
        out.extend_from_slice(&((length as u32) | 0x8000_0000).to_be_bytes());
        return Ok(());
    }

    Err(Error::Request(format!(
        "a name or value is {length} bytes; FastCGI allows at most 2147483647"
    )))
}

fn read_error(source: io::Error) -> Error {
    Error::Io {
        context: "reading FastCGI response",
        source,
    }
}

fn truncated(source: io::Error, part: &str) -> Error {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        Error::Protocol(format!("connection closed in the middle of a {part}"))
    } else {
        read_error(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_length(input: &mut &[u8]) -> Result<usize, Error> {
        let Some(&first) = input.first() else {
            return Err(Error::Protocol("truncated name-value length".into()));
        };

        if first & 0x80 == 0 {
            *input = &input[1..];
            return Ok(usize::from(first));
        }

        if input.len() < 4 {
            return Err(Error::Protocol("truncated name-value length".into()));
        }
        let raw = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        *input = &input[4..];
        Ok((raw & 0x7fff_ffff) as usize)
    }

    fn decode_params(mut input: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut params = Vec::new();
        while !input.is_empty() {
            let name_len = decode_length(&mut input)?;
            let value_len = decode_length(&mut input)?;
            if input.len() < name_len + value_len {
                return Err(Error::Protocol("truncated name-value pair".into()));
            }
            let (name, rest) = input.split_at(name_len);
            let (value, rest) = rest.split_at(value_len);
            params.push((
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            ));
            input = rest;
        }
        Ok(params)
    }

    #[test]
    fn header_round_trips() {
        let cases = [
            (RecordType::BeginRequest, 0u16, 0u8),
            (RecordType::Stdout, 65_535, 0),
            (RecordType::Stdin, 1, 255),
            (RecordType::EndRequest, 8, 7),
        ];

        for (record_type, content, padding) in cases {
            let raw = encode_header(record_type, REQUEST_ID, content, padding);
            assert_eq!(raw[0], VERSION);
            assert_eq!(raw[1], record_type as u8);
            assert_eq!(raw[2..4], REQUEST_ID.to_be_bytes());
            assert_eq!(raw[4..6], content.to_be_bytes());
            assert_eq!(raw[6], padding);
            assert_eq!(raw[7], 0);

            let header = decode_header(raw).unwrap();
            assert_eq!(header.record_type, record_type as u8);
            assert_eq!(header.request_id, REQUEST_ID);
            assert_eq!(header.content_length, content);
            assert_eq!(header.padding_length, padding);
        }
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut raw = encode_header(RecordType::Stdout, REQUEST_ID, 0, 0);
        raw[0] = 2;
        let error = decode_header(raw).unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("version")));
    }

    #[test]
    fn length_boundaries_round_trip() {
        for length in [0usize, 1, 127, 128, 255, 16_384] {
            let mut encoded = Vec::new();
            encode_length(length, &mut encoded).unwrap();

            let expected_width = if length <= 127 { 1 } else { 4 };
            assert_eq!(encoded.len(), expected_width, "length {length}");

            let mut cursor = encoded.as_slice();
            assert_eq!(decode_length(&mut cursor).unwrap(), length);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn length_encodings_match_the_specification() {
        let mut encoded = Vec::new();
        encode_length(127, &mut encoded).unwrap();
        assert_eq!(encoded, [0x7f]);

        for (length, bytes) in [
            (128usize, [0x80, 0x00, 0x00, 0x80]),
            (255, [0x80, 0x00, 0x00, 0xff]),
            (16_384, [0x80, 0x00, 0x40, 0x00]),
        ] {
            encoded.clear();
            encode_length(length, &mut encoded).unwrap();
            assert_eq!(encoded, bytes);
        }
    }

    #[test]
    fn params_round_trip_at_boundary_lengths() {
        for length in [127usize, 128, 255, 16_384] {
            let params = vec![
                ("A".repeat(length), "B".repeat(length)),
                ("empty".to_owned(), String::new()),
                ("REQUEST_METHOD".to_owned(), "POST".to_owned()),
            ];
            let encoded = encode_params(&params).unwrap();
            assert_eq!(decode_params(&encoded).unwrap(), params);
        }
    }

    #[test]
    fn begin_request_is_responder_with_expected_flags() {
        let body = begin_request_body_with_keep_conn(false);
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), ROLE_RESPONDER);
        assert_eq!(body[2], 0);
        assert_eq!(&body[3..], &[0; 5]);

        let pooled = begin_request_body_with_keep_conn(true);
        assert_eq!(u16::from_be_bytes([pooled[0], pooled[1]]), ROLE_RESPONDER);
        assert_eq!(pooled[2], 1, "FCGI_KEEP_CONN");
        assert_eq!(&pooled[3..], &[0; 5]);
    }

    #[test]
    fn unknown_record_type_is_none() {
        assert_eq!(RecordType::from_u8(0), None);
        assert_eq!(RecordType::from_u8(12), None);
        assert_eq!(RecordType::from_u8(6), Some(RecordType::Stdout));
    }
}
