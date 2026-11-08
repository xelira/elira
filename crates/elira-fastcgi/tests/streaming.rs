//! End-to-end tests for the streaming FastCGI exchange.
//!
//! The fake server implements the wire format independently, like the
//! buffered integration tests, so a client framing mistake cannot hide behind
//! a matching helper.

use std::io;
use std::time::Duration;

use bytes::Bytes;
use elira_fastcgi::{execute_stream, BoxError, Error, StreamResponse, Target};
use futures_util::{stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION: u8 = 1;
const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;

struct Received {
    params: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn next_record<S>(stream: &mut S) -> io::Result<Option<(u8, u16, Vec<u8>)>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    let first = stream.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;

    if header[0] != VERSION {
        return Err(invalid(format!(
            "client used FastCGI version {}",
            header[0]
        )));
    }

    let record_type = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let padding_length = usize::from(header[6]);

    let mut content = vec![0u8; content_length];
    stream.read_exact(&mut content).await?;
    if padding_length != 0 {
        let mut padding = [0u8; 255];
        stream.read_exact(&mut padding[..padding_length]).await?;
    }

    Ok(Some((record_type, request_id, content)))
}

async fn read_request<S>(stream: &mut S) -> io::Result<Received>
where
    S: AsyncRead + Unpin,
{
    let Some((record_type, request_id, begin)) = next_record(stream).await? else {
        return Err(eof("BEGIN_REQUEST"));
    };
    if record_type != BEGIN_REQUEST {
        return Err(unexpected("BEGIN_REQUEST", record_type));
    }
    if request_id != 1 {
        return Err(invalid("BEGIN_REQUEST used the wrong request id"));
    }
    if begin.len() != 8 {
        return Err(invalid("BEGIN_REQUEST body is not eight bytes"));
    }

    let mut encoded_params = Vec::new();
    loop {
        let (record_type, request_id, content) = next_record(stream)
            .await?
            .ok_or_else(|| eof("PARAMS terminator"))?;
        if request_id != 1 {
            return Err(invalid("PARAMS used the wrong request id"));
        }
        if record_type != PARAMS {
            return Err(unexpected("PARAMS", record_type));
        }
        if content.is_empty() {
            break;
        }
        encoded_params.extend_from_slice(&content);
    }

    let mut body = Vec::new();
    loop {
        let (record_type, request_id, content) = next_record(stream)
            .await?
            .ok_or_else(|| eof("STDIN terminator"))?;
        if request_id != 1 {
            return Err(invalid("STDIN used the wrong request id"));
        }
        if record_type != STDIN {
            return Err(unexpected("STDIN", record_type));
        }
        if content.is_empty() {
            break;
        }
        body.extend_from_slice(&content);
    }

    Ok(Received {
        params: decode_params(&encoded_params)?,
        body,
    })
}

fn decode_params(mut input: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut params = Vec::new();
    while !input.is_empty() {
        let name_len = decode_length(&mut input)?;
        let value_len = decode_length(&mut input)?;
        let needed = name_len
            .checked_add(value_len)
            .ok_or_else(|| invalid("name/value length overflow"))?;
        if input.len() < needed {
            return Err(invalid("truncated name-value pair"));
        }
        let (name, rest) = input.split_at(name_len);
        let (value, rest) = rest.split_at(value_len);
        params.push((
            String::from_utf8(name.to_vec()).map_err(|_| invalid("name is not UTF-8"))?,
            String::from_utf8(value.to_vec()).map_err(|_| invalid("value is not UTF-8"))?,
        ));
        input = rest;
    }
    Ok(params)
}

fn decode_length(input: &mut &[u8]) -> io::Result<usize> {
    let first = *input.first().ok_or_else(|| invalid("missing length"))?;
    if first & 0x80 == 0 {
        *input = &input[1..];
        return Ok(usize::from(first));
    }

    let raw = input
        .get(..4)
        .ok_or_else(|| invalid("truncated four-byte length"))?;
    let length = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) & 0x7fff_ffff;
    *input = &input[4..];
    Ok(length as usize)
}

async fn write_record<S>(stream: &mut S, record_type: u8, content: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if content.len() > usize::from(u16::MAX) {
        return Err(invalid("test tried to write an oversized record"));
    }
    let length = (content.len() as u16).to_be_bytes();
    let header = [VERSION, record_type, 0, 1, length[0], length[1], 0, 0];
    stream.write_all(&header).await?;
    stream.write_all(content).await
}

async fn write_stream<S>(stream: &mut S, record_type: u8, data: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    for chunk in data.chunks(usize::from(u16::MAX)) {
        write_record(stream, record_type, chunk).await?;
    }
    write_record(stream, record_type, &[]).await
}

async fn send_end<S>(stream: &mut S, app_status: u32) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut end = [0u8; 8];
    end[..4].copy_from_slice(&app_status.to_be_bytes());
    write_record(stream, END_REQUEST, &end).await?;
    stream.flush().await
}

fn body_from(chunks: Vec<&'static [u8]>) -> elira_fastcgi::BodyStream {
    let items: Vec<Result<Bytes, BoxError>> = chunks
        .into_iter()
        .map(|chunk| Ok(Bytes::from_static(chunk)))
        .collect();
    Box::pin(stream::iter(items))
}

async fn drain(response: StreamResponse) -> (Vec<u8>, Option<BoxError>) {
    let StreamResponse { mut body, .. } = response;
    let mut collected = Vec::new();
    let mut failure = None;

    while let Some(item) = body.next().await {
        match item {
            Ok(chunk) => collected.extend_from_slice(&chunk),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }

    (collected, failure)
}

#[tokio::test]
async fn streams_request_and_response_chunks() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let expected_params = vec![
        ("REQUEST_METHOD".to_owned(), "POST".to_owned()),
        ("SCRIPT_FILENAME".to_owned(), "/srv/www/app.php".to_owned()),
    ];
    let params = expected_params.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.params, expected_params);
        assert_eq!(request.body, b"hello streamed world");

        // STDERR before the headers is captured in the returned response.
        write_stream(&mut stream, STDERR, b"early warning\n")
            .await
            .unwrap();
        write_record(
            &mut stream,
            STDOUT,
            b"Status: 200 OK\r\nContent-Type: text/plain\r\nX-Test: one\r\n\r\n",
        )
        .await
        .unwrap();
        write_record(&mut stream, STDOUT, b"first-").await.unwrap();
        write_record(&mut stream, STDOUT, b"second-").await.unwrap();
        write_record(&mut stream, STDOUT, b"third").await.unwrap();
        send_end(&mut stream, 0).await.unwrap();
    });

    let body = body_from(vec![b"hello ", b"streamed ", b"world"]);
    let response = execute_stream(
        &Target::Tcp(address),
        params,
        body,
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("X-Test".to_owned(), "one".to_owned()),
        ]
    );
    assert_eq!(response.stderr, "early warning\n");

    let (body, failure) = drain(response).await;
    assert!(failure.is_none(), "unexpected stream error: {failure:?}");
    assert_eq!(body, b"first-second-third");

    server.await.unwrap();
}

#[tokio::test]
async fn large_response_is_streamed_with_bounded_channels() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    const RECORD_BYTES: usize = 8 * 1024;
    const RECORDS: usize = 40;
    const PAYLOAD: usize = RECORD_BYTES * RECORDS;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert!(request.body.is_empty());

        write_record(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let block = vec![b'q'; RECORD_BYTES];
        for _ in 0..RECORDS {
            write_record(&mut stream, STDOUT, &block).await.unwrap();
            stream.flush().await.unwrap();
        }
        send_end(&mut stream, 0).await.unwrap();
    });

    let response = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_secs(10),
        2 * 1024 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);

    // Read slowly enough that the bounded response channel is exercised; the
    // server cannot finish writing until the client drains records.
    let mut body = response.body;
    let mut received = 0usize;
    let mut chunks = 0usize;
    while let Some(item) = body.next().await {
        let chunk = item.expect("stream should not fail");
        received += chunk.len();
        chunks += 1;
        if chunks.is_multiple_of(4) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    assert_eq!(received, PAYLOAD);
    assert!(chunks >= RECORDS / 2, "only got {chunks} chunks");
    server.await.unwrap();
}

#[tokio::test]
async fn max_stdout_is_enforced_on_the_body_stream() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        write_record(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\n")
            .await
            .unwrap();
        write_record(&mut stream, STDOUT, &vec![b'x'; 512])
            .await
            .unwrap();
        write_record(&mut stream, STDOUT, &vec![b'y'; 512])
            .await
            .unwrap();
        let _ = send_end(&mut stream, 0).await;
    });

    // The header block itself is 19 bytes, so this leaves room for only a
    // small part of the first body record.
    let response = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_secs(5),
        64,
    )
    .await
    .unwrap();

    let (_, failure) = drain(response).await;
    let failure = failure.expect("the stream must report the limit");
    let error = failure
        .downcast::<Error>()
        .expect("the error keeps its concrete type");
    assert!(
        matches!(*error, Error::Response(ref message) if message.contains("exceeds")),
        "unexpected error: {error:?}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn early_request_stream_end_still_sends_the_terminator() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // `read_request` blocks on the empty STDIN record, so this passes only
        // if the client sends it when the request stream ends.
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.body, b"only-chunk");
        write_record(&mut stream, STDOUT, b"Status: 204 No Content\r\n\r\n")
            .await
            .unwrap();
        send_end(&mut stream, 0).await.unwrap();
    });

    let response = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        body_from(vec![b"only-chunk"]),
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
    .unwrap();

    assert_eq!(response.status, 204);
    let (body, failure) = drain(response).await;
    assert!(body.is_empty());
    assert!(failure.is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn header_timeout_is_reported() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = next_record(&mut stream).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let error = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_millis(100),
        64 * 1024,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, Error::Timeout { duration, .. } if duration == Duration::from_millis(100)),
        "unexpected error: {error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn body_timeout_is_reported_on_the_stream() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        write_record(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\nwaiting")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let response = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_millis(150),
        64 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);

    let (_, failure) = drain(response).await;
    let error = failure
        .expect("the stalled body must produce an error")
        .downcast::<Error>()
        .expect("the error keeps its concrete type");
    assert!(
        matches!(*error, Error::Timeout { .. }),
        "unexpected error: {error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn request_body_error_aborts_the_exchange() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = next_record(&mut stream).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let failure: BoxError = Box::new(io::Error::other("body exploded"));
    let body: elira_fastcgi::BodyStream = Box::pin(stream::iter(vec![Err(failure)]));

    let error = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        body,
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, Error::RequestBody(ref inner) if inner.to_string() == "body exploded"),
        "unexpected error: {error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn dropping_the_body_closes_the_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        write_record(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\nstart")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // The client never reads END_REQUEST; it drops the body instead.
        let closed = tokio::time::timeout(Duration::from_secs(5), next_record(&mut stream)).await;
        assert!(
            matches!(closed, Ok(Ok(None)) | Ok(Err(_))),
            "client did not close the socket: {closed:?}"
        );
    });

    let response = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);

    drop(response.body);
    server.await.unwrap();
}

#[tokio::test]
async fn end_request_before_headers_is_rejected() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        send_end(&mut stream, 0).await.unwrap();
    });

    let error = execute_stream(
        &Target::Tcp(address),
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, Error::Response(ref message) if message.contains("header block")),
        "unexpected error: {error:?}"
    );
    server.await.unwrap();
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unexpected(expected: &str, actual: u8) -> io::Error {
    invalid(format!(
        "expected a {expected} record, got record type {actual}"
    ))
}

fn eof(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("connection closed before {what}"),
    )
}
