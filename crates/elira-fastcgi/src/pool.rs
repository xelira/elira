use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::socket::Socket;
use crate::stream::{stream_exchange, StreamResponse};
use crate::{
    read_response, write_request_keep_alive, BodyStream, Error, Request, Response, Target,
};

#[derive(Debug, Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

#[derive(Debug)]
struct PoolInner {
    max_idle: usize,
    idle_ttl: Duration,
    idle: Mutex<HashMap<Target, Vec<Idle>>>,
}

#[derive(Debug)]
struct Idle {
    socket: Socket,
    since: Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct PoolHandle {
    inner: Arc<PoolInner>,
    target: Target,
}

impl PoolHandle {
    fn new(pool: &Pool, target: &Target) -> Self {
        Self {
            inner: Arc::clone(&pool.inner),
            target: target.clone(),
        }
    }

    pub(crate) fn release(&self, socket: Socket) {
        self.inner.release(&self.target, socket);
    }
}

impl Pool {
    pub fn new(max_idle_per_target: usize, idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                max_idle: max_idle_per_target,
                idle_ttl,
                idle: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn idle_count(&self) -> usize {
        let mut map = self.inner.lock();
        let ttl = self.inner.idle_ttl;
        map.retain(|_, entries| {
            entries.retain(|idle| idle.since.elapsed() < ttl);
            !entries.is_empty()
        });
        map.values().map(Vec::len).sum()
    }

    pub async fn execute(
        &self,
        target: &Target,
        request: &Request,
        timeout: Duration,
    ) -> Result<Response, Error> {
        if timeout.is_zero() {
            self.exchange(target, request).await
        } else {
            match tokio::time::timeout(timeout, self.exchange(target, request)).await {
                Ok(result) => result,
                Err(_) => Err(Error::Timeout {
                    target: target.to_string(),
                    duration: timeout,
                }),
            }
        }
    }

    async fn exchange(&self, target: &Target, request: &Request) -> Result<Response, Error> {
        let mut attempted_retry = false;

        loop {
            let (mut socket, reused) = match self.inner.checkout(target) {
                Some(socket) => (socket, true),
                None => (Socket::connect(target).await?, false),
            };

            match exchange_keep_alive(&mut socket, request).await {
                Ok(response) => {
                    self.inner.release(target, socket);
                    return Ok(response);
                }
                Err(failure) => {
                    drop(socket);

                    let retry = reused
                        && !attempted_retry
                        && request.body.is_empty()
                        && failure.written == 0;
                    if retry {
                        attempted_retry = true;
                        continue;
                    }
                    return Err(failure.error);
                }
            }
        }
    }

    pub async fn execute_stream(
        &self,
        target: &Target,
        params: Vec<(String, String)>,
        body: BodyStream,
        timeout: Duration,
        max_stdout: usize,
    ) -> Result<StreamResponse, Error> {
        let target_name = target.to_string();
        let socket = match self.inner.checkout(target) {
            Some(socket) => socket,
            None => {
                crate::stream::with_deadline(timeout, &target_name, Socket::connect(target)).await?
            }
        };

        let handle = PoolHandle::new(self, target);
        stream_exchange(
            socket,
            params,
            body,
            timeout,
            max_stdout,
            target_name,
            true,
            Some(handle),
        )
        .await
    }
}

impl PoolInner {
    fn lock(&self) -> MutexGuard<'_, HashMap<Target, Vec<Idle>>> {
        self.idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn checkout(&self, target: &Target) -> Option<Socket> {
        loop {
            let mut socket = self.take_idle(target)?;
            if socket.is_alive() {
                return Some(socket);
            }
        }
    }

    fn take_idle(&self, target: &Target) -> Option<Socket> {
        let ttl = self.idle_ttl;
        let mut map = self.lock();
        let entries = map.get_mut(target)?;
        entries.retain(|idle| idle.since.elapsed() < ttl);
        let socket = entries.pop().map(|idle| idle.socket);
        if entries.is_empty() {
            map.remove(target);
        }
        socket
    }

    fn release(&self, target: &Target, socket: Socket) {
        if self.max_idle == 0 || self.idle_ttl.is_zero() {
            return;
        }

        let mut map = self.lock();
        let entries = map.entry(target.clone()).or_default();
        entries.push(Idle {
            socket,
            since: Instant::now(),
        });

        while entries.len() > self.max_idle {
            entries.remove(0);
        }
    }
}

struct AttemptError {
    error: Error,
    written: usize,
}

async fn exchange_keep_alive<S>(stream: &mut S, request: &Request) -> Result<Response, AttemptError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (write_result, written) = {
        let mut counted = CountingWriter {
            inner: stream,
            written: 0,
        };
        let result = write_request_keep_alive(&mut counted, request).await;
        (result, counted.written)
    };

    match write_result {
        Err(error) => Err(AttemptError { error, written }),
        Ok(()) => read_response(stream)
            .await
            .map_err(|error| AttemptError { error, written }),
    }
}

struct CountingWriter<'a, S> {
    inner: &'a mut S,
    written: usize,
}

impl<S> AsyncWrite for CountingWriter<'_, S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(count)) = &result {
            this.written = this.written.saturating_add(*count);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.as_mut().get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.as_mut().get_mut().inner).poll_shutdown(context)
    }
}
