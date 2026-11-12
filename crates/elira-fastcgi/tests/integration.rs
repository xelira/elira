use std::io;
use std::time::{Duration, Instant};

use elira_fastcgi::{execute, Error, Request, Response, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};

const VERSION: u8 = 1;
const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;

struct Received {
    role: u16,
    flags: u8,
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("client used FastCGI version {}", header[0]),
        ));
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
        return Err(invalid(format!(
            "BEGIN_REQUEST used request id {request_id}"
        )));
    }
    if begin.len() != 8 {
        return Err(invalid(format!(
            "BEGIN_REQUEST body is {} bytes, expected 8",
            begin.len()
        )));
    }
    let role = u16::from_be_bytes([begin[0], begin[1]]);
    let flags = begin[2];

    let mut encoded_params = Vec::new();
    loop {
        let (record_type, request_id, content) = next_record(stream)
            .await?
            .ok_or_else(|| eof("PARAMS terminator"))?;
        if request_id != 1 {
            return Err(invalid(format!("PARAMS used request id {request_id}")));
        }
        if record_type != PARAMS {
            return Err(unexpected("PARAMS", record_type));
        }
        if content.is_empty() {
            break;
        }
        encoded_params.extend_from_slice(&content);
    }
    let params = decode_params(&encoded_params)?;

    let mut body = Vec::new();
    loop {
        let (record_type, request_id, content) = next_record(stream)
            .await?
            .ok_or_else(|| eof("STDIN terminator"))?;
        if request_id != 1 {
            return Err(invalid(format!("STDIN used request id {request_id}")));
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
        role,
        flags,
        params,
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

async fn send_response<S>(
    stream: &mut S,
    stdout: &[u8],
    stderr: &[u8],
    app_status: u32,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_stream(stream, STDOUT, stdout).await?;
    write_stream(stream, STDERR, stderr).await?;

    let mut end = [0u8; 8];
    end[..4].copy_from_slice(&app_status.to_be_bytes());
    end[4] = 0;
    write_record(stream, END_REQUEST, &end).await?;
    stream.flush().await
}

async fn response_for(stdout: &[u8], stderr: &[u8], app_status: u32) -> Result<Response, Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let stdout = stdout.to_vec();
    let stderr = stderr.to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        send_response(&mut stream, &stdout, &stderr, app_status)
            .await
            .unwrap();
    });

    let result = execute(
        &Target::Tcp(address),
        &Request::default(),
        Duration::from_secs(5),
    )
    .await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn tcp_round_trip() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let params = vec![
        (
            "SCRIPT_FILENAME".to_owned(),
            "/srv/www/index.php".to_owned(),
        ),
        ("REQUEST_METHOD".to_owned(), "POST".to_owned()),
        ("QUERY_STRING".to_owned(), "a=1&b=2".to_owned()),
        ("LONG_NAME".repeat(30), "LONG_VALUE".repeat(40)),
    ];
    let body = b"name=value&other=two".to_vec();
    let expected_params = params.clone();
    let expected_body = body.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.role, 1, "RESPONDER role");
        assert_eq!(request.flags, 0, "BEGIN_REQUEST flags");
        assert_eq!(request.params, expected_params);
        assert_eq!(request.body, expected_body);

        send_response(
            &mut stream,
            b"Status: 201 Created\r\nContent-Type: text/plain\r\n\
              X-Duplicate: one\r\nX-Duplicate: two\r\n\
              Content-Length: 5\r\n\r\nhello",
            b"",
            0,
        )
        .await
        .unwrap();
    });

    let request = Request { params, body };
    let response = execute(&Target::Tcp(address), &request, Duration::from_secs(5))
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"hello");
    assert!(response.stderr.is_empty());
    assert_eq!(
        response.headers,
        vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("X-Duplicate".to_owned(), "one".to_owned()),
            ("X-Duplicate".to_owned(), "two".to_owned()),
            ("Content-Length".to_owned(), "5".to_owned()),
        ]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unix_round_trip() {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "elira-fastcgi-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path).unwrap();

    let expected_params = vec![("REQUEST_METHOD".to_owned(), "GET".to_owned())];
    let params = expected_params.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.role, 1);
        assert_eq!(request.params, expected_params);
        assert!(request.body.is_empty());
        send_response(
            &mut stream,
            b"Status: 200 OK\r\nContent-Type: text/html\r\n\r\nfrom unix",
            b"unix warning\n",
            0,
        )
        .await
        .unwrap();
    });

    let request = Request {
        params,
        body: Vec::new(),
    };
    let response = execute(
        &Target::Unix(path.clone()),
        &request,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    server.await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"from unix");
    assert_eq!(response.stderr, "unix warning\n");
    assert_eq!(
        response.headers,
        vec![("Content-Type".to_owned(), "text/html".to_owned())]
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn large_request_and_response_are_chunked() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    let body = vec![b'z'; 140_000];
    let expected_body = body.clone();

    let mut stdout = b"Status: 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    stdout.extend(vec![b'y'; 140_000]);
    let expected_stdout = stdout.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.body, expected_body);
        send_response(&mut stream, &stdout, b"", 0).await.unwrap();
    });

    let response = execute(
        &Target::Tcp(address),
        &Request {
            params: vec![("CONTENT_LENGTH".to_owned(), "140000".to_owned())],
            body,
        },
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    server.await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        expected_stdout[expected_stdout.len() - 140_000..]
    );
}

#[tokio::test]
async fn location_without_status_is_a_redirect() {
    let response = response_for(b"Location: /login\r\n\r\n", b"", 0)
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers,
        vec![("Location".to_owned(), "/login".to_owned())]
    );
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn explicit_status_wins_over_location() {
    let response = response_for(
        b"Status: 404 Not Found\r\nLocation: /missing\r\n\r\nnot here",
        b"",
        0,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 404);
    assert_eq!(response.body, b"not here");
}

#[tokio::test]
async fn malformed_status_is_rejected() {
    let error = response_for(b"Status: definitely not a status\r\n\r\n", b"", 0)
        .await
        .unwrap_err();
    match error {
        Error::Response(message) => {
            assert!(message.contains("Status"), "unhelpful error: {message}")
        }
        other => panic!("expected a response error, got {other:?}"),
    }
}

#[tokio::test]
async fn stderr_is_captured_and_app_status_is_reported() {
    let response = response_for(
        b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nstill fine",
        b"PHP Warning: something odd\n",
        7,
    )
    .await
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"still fine");
    assert_eq!(
        response.stderr,
        "PHP Warning: something odd\nfastcgi: application exited with status 7\n"
    );
}

#[tokio::test]
async fn timeout_is_reported() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });

    let started = Instant::now();
    let error = execute(
        &Target::Tcp(address),
        &Request::default(),
        Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    server.abort();

    match error {
        Error::Timeout { duration, target } => {
            assert_eq!(duration, Duration::from_millis(100));
            assert!(target.starts_with("tcp://"), "target was {target}");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn zero_timeout_means_no_timeout() {
    let response = response_for(b"Status: 204 No Content\r\n\r\n", b"", 0)
        .await
        .unwrap();
    assert_eq!(response.status, 204);
}

#[tokio::test]
async fn connection_refused_is_reported() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = execute(
        &Target::Tcp(address),
        &Request::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    match error {
        Error::Connect { target, .. } => assert!(target.starts_with("tcp://")),
        other => panic!("expected a connect error, got {other:?}"),
    }
}

#[tokio::test]
async fn truncated_record_body_is_rejected() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();

        let header = [VERSION, STDOUT, 0, 1, 0, 16, 0, 0];
        stream.write_all(&header).await.unwrap();
        stream.write_all(b"oops").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let error = execute(
        &Target::Tcp(address),
        &Request::default(),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    server.await.unwrap();

    match error {
        Error::Protocol(message) => {
            assert!(
                message.contains("record body"),
                "unhelpful error: {message}"
            )
        }
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_end_request_is_rejected() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        write_stream(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let error = execute(
        &Target::Tcp(address),
        &Request::default(),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    server.await.unwrap();

    match error {
        Error::Protocol(message) => assert!(
            message.contains("END_REQUEST"),
            "unhelpful error: {message}"
        ),
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_header_terminator_is_rejected() {
    let error = response_for(b"Status: 200 OK\r\nbody without a blank line", b"", 0)
        .await
        .unwrap_err();
    match error {
        Error::Response(message) => {
            assert!(message.contains("blank line"), "unhelpful error: {message}")
        }
        other => panic!("expected a response error, got {other:?}"),
    }
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
