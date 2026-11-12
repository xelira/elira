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

struct ExchangeGuard {
    pending: Arc<Mutex<HashMap<u16, Pending>>>,
    connection: Arc<Connection>,
    id: u16,
    armed: bool,
}

impl ExchangeGuard {
    fn finish(mut self) {
        self.cleanup();
        self.armed = false;
    }

    fn cleanup(&self) {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
        self.connection.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cleanup();
        }
    }
}

impl MultiplexPool {
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
        let guard = ExchangeGuard {
            pending: connection.pending.clone(),
            connection: connection.clone(),
            id: request_id,
            armed: true,
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

        guard.finish();
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
                return Err(Error::Protocol(
                    "FastCGI pool has no free request slots".to_owned(),
                ));
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
        let record =
            match timeout(Duration::from_secs(60), protocol::read_record(&mut reader)).await {
                Ok(Ok(Some(record))) => record,
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
            Some(RecordType::Stderr) => {
                entry.stderr.extend_from_slice(&record.content);
                let cap = if entry.max_response > 0 {
                    entry.max_response
                } else {
                    1024 * 1024
                };
                if entry.stderr.len() > cap {
                    let entry = pending.remove(&record.request_id).unwrap();
                    let _ = entry.result.send(Err(Error::Response(
                        "FastCGI stderr is larger than the configured cap".to_owned(),
                    )));
                }
            }
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
