use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::app_target::Target;
use crate::cgi_response::Response;

const MAX_PACKET: usize = 8 * 1024;
const MAX_CHUNK: usize = MAX_PACKET - 6;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("ajp: {0}")]
    Io(#[from] std::io::Error),

    #[error("ajp response is larger than the configured cap")]
    TooLarge,

    #[error("ajp: {0}")]
    Bad(String),

    #[error("ajp exchange timed out")]
    Timeout,
}

pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) protocol: String,
    pub(crate) uri: &'a str,
    pub(crate) query: &'a str,
    pub(crate) remote_addr: String,
    pub(crate) server_name: &'a str,
    pub(crate) server_port: u16,
    pub(crate) secure: bool,
    pub(crate) headers: &'a [(String, String)],
    pub(crate) secret: Option<&'a str>,
    pub(crate) body: &'a [u8],
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) async fn execute(
    target: &Target,
    request: &Request<'_>,
    timeout: Duration,
    max_response: usize,
) -> Result<Response, Error> {
    let work = exchange(target, request, max_response);
    if timeout.is_zero() {
        work.await
    } else {
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| Error::Timeout)?
    }
}

async fn exchange(
    target: &Target,
    request: &Request<'_>,
    max_response: usize,
) -> Result<Response, Error> {
    let mut stream: Box<dyn Io> = match target {
        Target::Tcp(authority) => Box::new(TcpStream::connect(authority.as_str()).await?),
        Target::Unix(path) => Box::new(UnixStream::connect(path).await?),
    };

    write_forward_request(&mut stream, request).await?;

    let mut body_position = request.body.len().min(MAX_CHUNK);
    if body_position > 0 {
        write_data(&mut stream, &request.body[..body_position]).await?;
    }

    let mut status = None;
    let mut headers = Vec::new();
    let mut response = Vec::new();

    loop {
        let (kind, payload) = read_packet(&mut stream).await?;
        match kind {
            3 => {
                let mut reader = Reader::new(&payload[1..]);
                let length = reader
                    .u16()
                    .ok_or_else(|| Error::Bad("chunk length".into()))?;
                let chunk = reader
                    .bytes(length as usize)
                    .ok_or_else(|| Error::Bad("truncated body chunk".into()))?;
                response.extend_from_slice(chunk);
                if max_response > 0 && response.len() > max_response {
                    return Err(Error::TooLarge);
                }
            }
            4 => {
                let mut reader = Reader::new(&payload[1..]);
                let code = reader
                    .u16()
                    .ok_or_else(|| Error::Bad("status code".into()))?;
                let _message = reader
                    .string()
                    .ok_or_else(|| Error::Bad("status text".into()))?;
                let count = reader
                    .u16()
                    .ok_or_else(|| Error::Bad("header count".into()))?;
                status = Some(code);
                headers.clear();
                for _ in 0..count {
                    let name = reader
                        .header_name()
                        .ok_or_else(|| Error::Bad("response header name".into()))?;
                    let value = reader
                        .string()
                        .ok_or_else(|| Error::Bad("response header value".into()))?;
                    headers.push((name, value));
                }
            }
            5 => break,
            6 => {
                let mut reader = Reader::new(&payload[1..]);
                let requested = reader.u16().unwrap_or(MAX_CHUNK as u16) as usize;
                let remaining = &request.body[body_position..];
                let take = requested.min(MAX_CHUNK).min(remaining.len());
                write_data(&mut stream, &remaining[..take]).await?;
                body_position += take;
            }
            9 => {}
            other => return Err(Error::Bad(format!("unexpected packet type {other}"))),
        }
    }

    Ok(Response {
        status: status.unwrap_or(200),
        headers,
        body: response,
    })
}

async fn write_forward_request(
    stream: &mut (impl AsyncWrite + Unpin),
    request: &Request<'_>,
) -> Result<(), Error> {
    let mut payload = Vec::new();
    payload.push(2);
    payload.push(method_code(request.method)?);
    put_string(&mut payload, &request.protocol);
    put_string(&mut payload, request.uri);
    put_string(&mut payload, &request.remote_addr);
    put_string(&mut payload, &request.remote_addr);
    put_string(&mut payload, request.server_name);
    payload.extend_from_slice(&request.server_port.to_be_bytes());
    payload.push(u8::from(request.secure));
    let count = u16::try_from(request.headers.len())
        .map_err(|_| Error::Bad("too many request headers".into()))?;
    payload.extend_from_slice(&count.to_be_bytes());
    for (name, value) in request.headers {
        put_header_name(&mut payload, name);
        put_string(&mut payload, value);
    }

    if !request.query.is_empty() {
        payload.push(0x05);
        put_string(&mut payload, request.query);
    }
    if let Some(secret) = request.secret {
        payload.push(0x0C);
        put_string(&mut payload, secret);
    }
    payload.push(0xFF);

    if payload.len() > MAX_PACKET - 4 {
        return Err(Error::Bad("request packet is too large".into()));
    }
    write_packet(stream, &payload).await
}

fn method_code(method: &str) -> Result<u8, Error> {
    Ok(match method {
        "OPTIONS" => 1,
        "GET" => 2,
        "HEAD" => 3,
        "POST" => 4,
        "PUT" => 5,
        "DELETE" => 6,
        "TRACE" => 7,
        "PROPFIND" => 8,
        "PROPPATCH" => 9,
        "MKCOL" => 10,
        "COPY" => 11,
        "MOVE" => 12,
        "LOCK" => 13,
        "UNLOCK" => 14,
        "ACL" => 15,
        "REPORT" => 16,
        "VERSION-CONTROL" => 17,
        "CHECKIN" => 18,
        "CHECKOUT" => 19,
        "UNCHECKOUT" => 20,
        "SEARCH" => 21,
        "MKWORKSPACE" => 22,
        "UPDATE" => 23,
        "LABEL" => 24,
        "MERGE" => 25,
        "BASELINE-CONTROL" => 26,
        "MKACTIVITY" => 27,
        other => return Err(Error::Bad(format!("unsupported AJP method {other}"))),
    })
}

fn header_code(name: &str) -> Option<u16> {
    Some(match name.to_ascii_lowercase().as_str() {
        "accept" => 0xA001,
        "accept-charset" => 0xA002,
        "accept-encoding" => 0xA003,
        "accept-language" => 0xA004,
        "authorization" => 0xA005,
        "connection" => 0xA006,
        "content-type" => 0xA007,
        "content-length" => 0xA008,
        "cookie" => 0xA009,
        "cookie2" => 0xA00A,
        "host" => 0xA00B,
        "pragma" => 0xA00C,
        "referer" => 0xA00D,
        "user-agent" => 0xA00E,
        _ => return None,
    })
}

fn response_header_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "content-type",
        0x02 => "content-language",
        0x03 => "content-length",
        0x04 => "date",
        0x05 => "last-modified",
        0x06 => "location",
        0x07 => "set-cookie",
        0x08 => "set-cookie2",
        0x09 => "servlet-engine",
        0x0A => "status",
        0x0B => "www-authenticate",
        _ => return None,
    })
}

fn put_string(buffer: &mut Vec<u8>, value: &str) {
    buffer.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
    buffer.push(0);
}

fn put_header_name(buffer: &mut Vec<u8>, name: &str) {
    if let Some(code) = header_code(name) {
        buffer.extend_from_slice(&code.to_be_bytes());
    } else {
        put_string(buffer, name);
    }
}

async fn write_packet(stream: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> Result<(), Error> {
    let mut header = [0u8; 4];
    header[0] = 0x12;
    header[1] = 0x34;
    header[2..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_data(stream: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        write_packet(stream, &[]).await
    } else {
        write_packet(stream, data).await
    }
}

async fn read_packet(stream: &mut (impl AsyncRead + Unpin)) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != b'A' || header[1] != b'B' {
        return Err(Error::Bad("bad AJP response prefix".into()));
    }
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if length > MAX_PACKET {
        return Err(Error::Bad("AJP response packet is too large".into()));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    if payload.is_empty() {
        return Err(Error::Bad("empty AJP packet".into()));
    }
    Ok((payload[0], payload))
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let slice = self.data.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn string(&mut self) -> Option<String> {
        let length = self.u16()?;
        if length == 0xFFFF {
            return Some(String::new());
        }
        let bytes = self.bytes(length as usize)?;
        self.bytes(1)?;
        Some(String::from_utf8_lossy(bytes).to_string())
    }

    fn header_name(&mut self) -> Option<String> {
        let marker = self.u16()?;
        if marker & 0xFF00 == 0xA000 {
            let code = (marker & 0xFF) as u8;
            return response_header_name(code)
                .map(str::to_owned)
                .or_else(|| Some(format!("x-ajp-header-{code}")));
        }
        let bytes = self.bytes(marker as usize)?;
        self.bytes(1)?;
        Some(String::from_utf8_lossy(bytes).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trips() {
        let mut buffer = Vec::new();
        put_string(&mut buffer, "hello");
        let mut reader = Reader::new(&buffer);
        assert_eq!(reader.string().as_deref(), Some("hello"));
    }

    #[test]
    fn request_header_codes_are_known() {
        assert_eq!(header_code("Host"), Some(0xA00B));
        assert_eq!(header_code("x-custom"), None);
    }
}
