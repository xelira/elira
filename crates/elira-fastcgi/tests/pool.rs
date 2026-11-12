use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use elira_fastcgi::{execute_stream, BodyStream, BoxError, Error, Pool, Request, Target};
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
    let flags = begin[2];

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
        flags,
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

async fn send_response<S>(stream: &mut S, stdout: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_stream(stream, STDOUT, stdout).await?;
    write_stream(stream, STDERR, b"").await?;

    let mut end = [0u8; 8];
    end[4] = 0;
    write_record(stream, END_REQUEST, &end).await?;
    stream.flush().await
}

async fn send_protocol_error<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_stream(stream, STDOUT, b"Status: 200 OK\r\n\r\npartial").await?;
    let mut end = [0u8; 8];
    end[4] = 3;
    write_record(stream, END_REQUEST, &end).await?;
    stream.flush().await
}

fn body_from(chunks: Vec<&'static [u8]>) -> BodyStream {
    let items: Vec<Result<Bytes, BoxError>> = chunks
        .into_iter()
        .map(|chunk| Ok(Bytes::from_static(chunk)))
        .collect();
    Box::pin(stream::iter(items))
}

async fn drain(response: elira_fastcgi::StreamResponse) -> (Vec<u8>, Option<BoxError>) {
    let mut body = response.body;
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

fn target(listener: &TcpListener) -> Target {
    Target::Tcp(listener.local_addr().unwrap())
}

fn get_request() -> Request {
    Request {
        params: vec![
            ("REQUEST_METHOD".to_owned(), "GET".to_owned()),
            (
                "SCRIPT_FILENAME".to_owned(),
                "/srv/www/index.php".to_owned(),
            ),
        ],
        body: Vec::new(),
    }
}

#[tokio::test]
async fn buffered_requests_reuse_one_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);

        for index in 0..2 {
            let request = read_request(&mut stream).await.unwrap();
            assert_eq!(request.flags, 1, "FCGI_KEEP_CONN must be set");
            assert_eq!(
                request.params,
                vec![
                    ("REQUEST_METHOD".to_owned(), "GET".to_owned()),
                    (
                        "SCRIPT_FILENAME".to_owned(),
                        "/srv/www/index.php".to_owned()
                    ),
                ]
            );
            let response = format!("Status: 200 OK\r\n\r\nresponse-{index}");
            send_response(&mut stream, response.as_bytes())
                .await
                .unwrap();
        }
    });

    let pool = Pool::new(4, Duration::from_secs(30));
    let request = get_request();

    let first = pool
        .execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(first.body, b"response-0");
    assert_eq!(pool.idle_count(), 1);

    let second = pool
        .execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(second.body, b"response-1");
    assert_eq!(pool.idle_count(), 1);

    server.await.unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keep_conn_flag_is_set_only_for_pooled_requests() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.flags, 1, "pooled BEGIN_REQUEST flags");
        send_response(&mut stream, b"Status: 200 OK\r\n\r\nok")
            .await
            .unwrap();
    });

    let pool = Pool::new(1, Duration::from_secs(30));
    let response = pool
        .execute(&target, &get_request(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.body, b"ok");
    server.await.unwrap();
}

#[tokio::test]
async fn streaming_requests_reuse_after_body_consumption() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);

        for index in 0..2 {
            let request = read_request(&mut stream).await.unwrap();
            assert_eq!(request.flags, 1);
            assert_eq!(request.body, b"streamed");
            write_record(
                &mut stream,
                STDOUT,
                b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            )
            .await
            .unwrap();
            write_record(&mut stream, STDOUT, format!("part-{index}-").as_bytes())
                .await
                .unwrap();
            write_record(&mut stream, STDOUT, b"done").await.unwrap();
            let mut end = [0u8; 8];
            end[4] = 0;
            write_record(&mut stream, END_REQUEST, &end).await.unwrap();
            stream.flush().await.unwrap();
        }
    });

    let pool = Pool::new(4, Duration::from_secs(30));

    for index in 0..2 {
        let response = pool
            .execute_stream(
                &target,
                vec![("REQUEST_METHOD".to_owned(), "POST".to_owned())],
                body_from(vec![b"streamed"]),
                Duration::from_secs(5),
                64 * 1024,
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let (body, failure) = drain(response).await;
        assert!(failure.is_none(), "unexpected stream error: {failure:?}");
        assert_eq!(body, format!("part-{index}-done").as_bytes());
        assert_eq!(pool.idle_count(), 1);
    }

    server.await.unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn protocol_error_is_not_pooled_and_next_request_connects_fresh() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);
        read_request(&mut first).await.unwrap();
        send_protocol_error(&mut first).await.unwrap();

        let (mut second, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);
        read_request(&mut second).await.unwrap();
        send_response(&mut second, b"Status: 200 OK\r\n\r\nrecovered")
            .await
            .unwrap();
    });

    let pool = Pool::new(4, Duration::from_secs(30));
    let request = get_request();

    let error = pool
        .execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Protocol(ref message) if message.contains("protocol status")),
        "unexpected error: {error:?}"
    );
    assert_eq!(pool.idle_count(), 0, "a failed exchange must not be pooled");

    let response = pool
        .execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.body, b"recovered");
    assert_eq!(pool.idle_count(), 1);

    server.await.unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn idle_cap_evicts_oldest_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);
        let (mut second, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);

        let (first_request, second_request) =
            tokio::join!(read_request(&mut first), read_request(&mut second));
        first_request.unwrap();
        second_request.unwrap();

        send_response(&mut first, b"Status: 200 OK\r\n\r\nfirst")
            .await
            .unwrap();
        send_response(&mut second, b"Status: 200 OK\r\n\r\nsecond")
            .await
            .unwrap();
    });

    let pool = Pool::new(1, Duration::from_secs(30));
    let request = get_request();
    let (first, second) = tokio::join!(
        pool.execute(&target, &request, Duration::from_secs(5)),
        pool.execute(&target, &request, Duration::from_secs(5))
    );

    let mut bodies = vec![first.unwrap().body, second.unwrap().body];
    bodies.sort();
    assert_eq!(bodies, vec![b"first".to_vec(), b"second".to_vec()]);
    assert_eq!(
        pool.idle_count(),
        1,
        "the per-target cap must keep only one idle socket"
    );

    server.await.unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn idle_ttl_expiry_forces_a_new_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_accepts.fetch_add(1, Ordering::SeqCst);
            read_request(&mut stream).await.unwrap();
            send_response(&mut stream, b"Status: 200 OK\r\n\r\nok")
                .await
                .unwrap();
        }
    });

    let pool = Pool::new(4, Duration::from_millis(50));
    let request = get_request();

    pool.execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(pool.idle_count(), 1);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(pool.idle_count(), 0, "expired idle sockets are pruned");

    let response = pool
        .execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.body, b"ok");

    server.await.unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_requests_never_share_one_socket() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);
    let accepts = Arc::new(AtomicUsize::new(0));
    let server_accepts = Arc::clone(&accepts);

    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);
        read_request(&mut first).await.unwrap();
        send_response(&mut first, b"Status: 200 OK\r\n\r\nwarm")
            .await
            .unwrap();

        let (mut second, _) = listener.accept().await.unwrap();
        server_accepts.fetch_add(1, Ordering::SeqCst);

        let (first_result, second_result) = tokio::join!(
            async {
                read_request(&mut first).await.unwrap();
                send_response(&mut first, b"Status: 200 OK\r\n\r\none").await
            },
            async {
                read_request(&mut second).await.unwrap();
                send_response(&mut second, b"Status: 200 OK\r\n\r\ntwo").await
            }
        );
        first_result.unwrap();
        second_result.unwrap();
    });

    let pool = Pool::new(4, Duration::from_secs(30));
    let request = get_request();

    pool.execute(&target, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(pool.idle_count(), 1);

    let (one, two) = tokio::join!(
        pool.execute(&target, &request, Duration::from_secs(5)),
        pool.execute(&target, &request, Duration::from_secs(5))
    );

    let mut bodies = vec![one.unwrap().body, two.unwrap().body];
    bodies.sort();
    assert_eq!(bodies, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(pool.idle_count(), 2, "both concurrent sockets come back");

    server.await.unwrap();
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "one warm socket plus one new socket"
    );
}

#[tokio::test]
async fn dropping_a_streaming_body_closes_the_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap();
        write_record(&mut stream, STDOUT, b"Status: 200 OK\r\n\r\nstart")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(5), next_record(&mut stream)).await;
        assert!(
            matches!(closed, Ok(Ok(None)) | Ok(Err(_))),
            "client did not close the socket: {closed:?}"
        );
    });

    let pool = Pool::new(4, Duration::from_secs(30));
    let response = pool
        .execute_stream(
            &target,
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
    assert_eq!(pool.idle_count(), 0);
}

#[tokio::test]
async fn one_shot_streaming_api_still_works_and_leaves_no_idle_socket() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let target = target(&listener);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        assert_eq!(request.flags, 0, "one-shot API must not request keep-alive");
        write_record(&mut stream, STDOUT, b"Status: 204 No Content\r\n\r\n")
            .await
            .unwrap();
        let mut end = [0u8; 8];
        end[4] = 0;
        write_record(&mut stream, END_REQUEST, &end).await.unwrap();
        stream.flush().await.unwrap();
    });

    let response = execute_stream(
        &target,
        Vec::new(),
        Box::pin(stream::empty::<Result<Bytes, BoxError>>()),
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
