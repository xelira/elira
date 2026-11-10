//! Opt-in FastCGI multiplexing.
//!
//! One connection carries several requests distinguished by request id. The
//! request body and the response are buffered: multiplexing is selected per
//! route and is meant for applications that advertise `FCGI_MPXS_CONNS`.
//! Servers that do not support it must leave the option off.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::timeout;

use crate::protocol::{self, RecordType};
use crate::socket::{Socket, SocketRead, SocketWrite};
use crate::{decode_end_request, response, Error, Response, Target};

/// A pool of multiplexed FastCGI connections.
#[derive(Clone)]
pub struct MultiplexPool {
    inner: Arc<Inner>,
}

struct Inner {
    targets: Mutex<HashMap<Target, Vec<Arc<Connection>>>>,
    create_lock: AsyncMutex<()>,
    max_connections: usize,
    max_requests: usize,
}

struct Connection {
    writer: AsyncMutex<SocketWrite>,
    pending: Arc<Mutex<HashMap<u16, Pending>>>,
    next_id: AtomicU16,
    in_flight: AtomicUsize,
    closed: Arc<AtomicBool>,
    max_requests: usize,
}

struct Pending {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    max_response: usize,
    result: oneshot::Sender<Result<Response, Error>>,
}

impl MultiplexPool {
    /// `max_connections` bounds sockets per target; each socket accepts up to
    /// sixteen concurrent requests.
    pub fn new(max_connections: usize, max_requests: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                targets: Mutex::new(HashMap::new()),
                create_lock: AsyncMutex::new(()),
                max_connections: max_connections.max(1),
                max_requests: max_requests.max(1),
            }),
        }
    }

    /// Send a buffered request and collect the response.
    pub async fn execute(
        &self,
        target: &Target,
        params: &[(String, String)],
        body: &[u8],
        timeout_duration: Duration,
        max_response: usize,
    ) -> Result<Response, Error> {
        let work = self.exchange(target, params, body, max_response);
        if timeout_duration.is_zero() {
            work.await
        } else {
            timeout(timeout_duration, work)
                .await
                .map_err(|_| Error::Timeout {
                    target: target.to_string(),
                    duration: timeout_duration,
                })?
        }
    }

    async fn exchange(
        &self,
        target: &Target,
        params: &[(String, String)],
        body: &[u8],
        max_response: usize,
    ) -> Result<Response, Error> {
        let connection = self.checkout(target).await?;
        let (request_id, rx) = {
            let mut pending = connection.pending.lock().unwrap();
            let request_id = connection.allocate(&mut pending)?;
            let (tx, rx) = oneshot::channel();
            pending.insert(
                request_id,
                Pending {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    max_response,
                    result: tx,
                },
            );
            (request_id, rx)
        };

        let result = async {
            {
                let mut writer = connection.writer.lock().await;
                write_request(&mut writer, request_id, params, body).await?;
            }
            rx.await.map_err(|_| {
                Error::Protocol("FastCGI connection closed before END_REQUEST".to_owned())
            })?
        }
        .await;

        connection.in_flight.fetch_sub(1, Ordering::Relaxed);
        if result.is_err() {
            connection.closed.store(true, Ordering::Relaxed);
        }
        result
    }

    async fn checkout(&self, target: &Target) -> Result<Arc<Connection>, Error> {
        {
            let mut targets = self.inner.targets.lock().unwrap();
            let list = targets.entry(target.clone()).or_default();
            list.retain(|connection| !connection.closed.load(Ordering::Relaxed));
            if let Some(connection) = list
                .iter()
                .find(|connection| {
                    connection.in_flight.load(Ordering::Relaxed) < connection.max_requests
                })
                .cloned()
            {
                connection.in_flight.fetch_add(1, Ordering::Relaxed);
                return Ok(connection);
            }
            if list.len() >= self.inner.max_connections {
                // All connections are busy. Pick the least loaded one instead
                // of failing; the server still demultiplexes by request id.
                if let Some(connection) = list
                    .iter()
                    .min_by_key(|connection| connection.in_flight.load(Ordering::Relaxed))
                    .cloned()
                {
                    connection.in_flight.fetch_add(1, Ordering::Relaxed);
                    return Ok(connection);
                }
            }
        }

        let _creating = self.inner.create_lock.lock().await;
        {
            let mut targets = self.inner.targets.lock().unwrap();
            let list = targets.entry(target.clone()).or_default();
            list.retain(|connection| !connection.closed.load(Ordering::Relaxed));
            if let Some(connection) = list
                .iter()
                .find(|connection| {
                    connection.in_flight.load(Ordering::Relaxed) < connection.max_requests
                })
                .cloned()
            {
                connection.in_flight.fetch_add(1, Ordering::Relaxed);
                return Ok(connection);
            }
        }

        let socket = Socket::connect(target).await?;
        let (reader, writer) = socket.into_split();
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let connection = Arc::new(Connection {
            writer: AsyncMutex::new(writer),
            pending: pending.clone(),
            next_id: AtomicU16::new(1),
            in_flight: AtomicUsize::new(1),
            closed: closed.clone(),
            max_requests: self.inner.max_requests,
        });
        tokio::spawn(read_loop(reader, pending, closed));

        let mut targets = self.inner.targets.lock().unwrap();
        let list = targets.entry(target.clone()).or_default();
        if list.len() < self.inner.max_connections {
            list.push(connection.clone());
        }
        Ok(connection)
    }
}

impl Connection {
    fn allocate(&self, pending: &mut HashMap<u16, Pending>) -> Result<u16, Error> {
        for _ in 0..u16::MAX {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !pending.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(Error::Protocol(
            "all FastCGI request ids are in use".to_owned(),
        ))
    }
}

async fn write_request(
    writer: &mut SocketWrite,
    request_id: u16,
    params: &[(String, String)],
    body: &[u8],
) -> Result<(), Error> {
    crate::write_record_id(
        writer,
        request_id,
        RecordType::BeginRequest,
        &protocol::begin_request_body_with_keep_conn(true),
    )
    .await?;

    let params = protocol::encode_params(params)?;
    write_stream(writer, request_id, RecordType::Params, &params).await?;
    write_stream(writer, request_id, RecordType::Stdin, body).await?;
    writer.flush().await.map_err(crate::write_error)
}

async fn write_stream(
    writer: &mut SocketWrite,
    request_id: u16,
    record_type: RecordType,
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() {
        return crate::write_record_id(writer, request_id, record_type, data).await;
    }
    for chunk in data.chunks(protocol::MAX_CONTENT) {
        crate::write_record_id(writer, request_id, record_type, chunk).await?;
    }
    crate::write_record_id(writer, request_id, record_type, &[]).await
}

async fn read_loop(
    mut reader: SocketRead,
    pending: Arc<Mutex<HashMap<u16, Pending>>>,
    closed: Arc<AtomicBool>,
) {
    loop {
        let record = match protocol::read_record(&mut reader).await {
            Ok(Some(record)) => record,
            _ => break,
        };
        let request_type = RecordType::from_u8(record.record_type);
        let mut pending = pending.lock().unwrap();
        let Some(entry) = pending.get_mut(&record.request_id) else {
            continue;
        };
        match request_type {
            Some(RecordType::Stdout) => {
                entry.stdout.extend_from_slice(&record.content);
                if entry.max_response > 0 && entry.stdout.len() > entry.max_response {
                    let entry = pending.remove(&record.request_id).unwrap();
                    let _ = entry.result.send(Err(Error::Response(
                        "FastCGI response is larger than the configured cap".to_owned(),
                    )));
                }
            }
            Some(RecordType::Stderr) => entry.stderr.extend_from_slice(&record.content),
            Some(RecordType::EndRequest) => {
                let entry = pending.remove(&record.request_id).unwrap();
                let app_status = decode_end_request(&record.content)
                    .map(|(status, _)| status)
                    .unwrap_or(0);
                let _ =
                    entry
                        .result
                        .send(response::parse(&entry.stdout, &entry.stderr, app_status));
            }
            _ => {}
        }
    }

    closed.store(true, Ordering::Relaxed);
    let mut pending = pending.lock().unwrap();
    for (_, entry) in pending.drain() {
        let _ = entry.result.send(Err(Error::Io {
            context: "reading the FastCGI connection",
            source: io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed"),
        }));
    }
}
