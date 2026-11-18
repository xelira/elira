use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("response is larger than the configured cap")]
    TooLarge,

    #[error("response: {0}")]
    Bad(String),
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) async fn read(
    stream: &mut (impl AsyncRead + Unpin),
    max_response: usize,
) -> Result<Response, Error> {
    let (status, headers, buffered) = read_head(stream).await?;
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok());

    let body = if chunked {
        let raw = read_to_end(stream, buffered, max_response).await?;
        decode_chunked(&raw)?
    } else if let Some(length) = length {
        if max_response > 0 && length > max_response {
            return Err(Error::TooLarge);
        }
        let mut body = buffered;
        while body.len() < length {
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(Error::Bad("closed before Content-Length bytes".to_owned()));
            }
            body.extend_from_slice(&chunk[..read]);
            if max_response > 0 && body.len() > max_response {
                return Err(Error::TooLarge);
            }
        }
        body.truncate(length);
        body
    } else {
        read_to_end(stream, buffered, max_response).await?
    };

    if max_response > 0 && body.len() > max_response {
        return Err(Error::TooLarge);
    }

    Ok(Response {
        status,
        headers,
        body,
    })
}

async fn read_to_end(
    stream: &mut (impl AsyncRead + Unpin),
    mut body: Vec<u8>,
    max_response: usize,
) -> Result<Vec<u8>, Error> {
    if max_response > 0 && body.len() > max_response {
        return Err(Error::TooLarge);
    }
    loop {
        let mut chunk = [0u8; 8192];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..read]);
        if max_response > 0 && body.len() > max_response {
            return Err(Error::TooLarge);
        }
    }
}

async fn read_head(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    let split = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::Bad(
                "connection closed before the header block".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > 64 * 1024 {
            return Err(Error::Bad("header block is too large".to_owned()));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..split]).to_string();
    let body = buffer[split + 4..].to_vec();
    let mut status = None;
    let mut headers = Vec::new();

    for line in head.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("HTTP/") {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Bad(format!("bad header line {line:?}")));
        };
        if name.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|code| code.parse::<u16>().ok());
        } else {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    let status = status.unwrap_or_else(|| {
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("location"))
        {
            302
        } else {
            200
        }
    });

    Ok((status, headers, body))
}

fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    let mut position = 0;

    loop {
        let line_end = raw[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| Error::Bad("truncated chunk size".to_owned()))?;
        let line = &raw[position..position + line_end];
        let size_text = line.split(|byte| *byte == b';').next().unwrap_or_default();
        let size = std::str::from_utf8(size_text)
            .ok()
            .and_then(|text| usize::from_str_radix(text.trim(), 16).ok())
            .ok_or_else(|| Error::Bad("bad chunk size".to_owned()))?;
        position += line_end + 2;

        if size == 0 {
            break;
        }
        let Some(end) = position
            .checked_add(size)
            .and_then(|end| end.checked_add(2))
        else {
            return Err(Error::Bad("truncated chunk".to_owned()));
        };
        if end > raw.len() {
            return Err(Error::Bad("truncated chunk".to_owned()));
        }
        body.extend_from_slice(&raw[position..position + size]);
        position += size;
        if &raw[position..position + 2] != b"\r\n" {
            return Err(Error::Bad("chunk without CRLF".to_owned()));
        }
        position += 2;
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_is_decoded() {
        let raw = b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw).expect("chunked"), b"wikipedia");
    }

    #[test]
    fn defaults_to_200_and_302_for_location() {
        let (status, headers, body) = parse_head(b"Content-Type: text/plain\r\n\r\nhi");
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(body, b"hi");

        let (status, _, _) = parse_head(b"Location: /next\r\n\r\n");
        assert_eq!(status, 302);
    }

    fn parse_head(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("split");
        let head = String::from_utf8_lossy(&raw[..split]);
        let body = raw[split + 4..].to_vec();
        let mut status = None;
        let mut headers = Vec::new();
        for line in head.split("\r\n") {
            let (name, value) = line.split_once(':').expect("header");
            if name.eq_ignore_ascii_case("status") {
                status = value
                    .split_whitespace()
                    .next()
                    .and_then(|code| code.parse::<u16>().ok());
            } else {
                headers.push((name.to_owned(), value.trim().to_owned()));
            }
        }
        let status = status.unwrap_or(
            if headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("location"))
            {
                302
            } else {
                200
            },
        );
        (status, headers, body)
    }
}
