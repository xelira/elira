//! Optional idle-connection reuse for FastCGI responders.
//!
//! FastCGI is a request/response protocol on a connection that may stay open
//! after `END_REQUEST` when `FCGI_KEEP_CONN` is set. [`Pool`] takes advantage
//! of that: a connection is returned only after a complete, clean exchange,
//! and is checked again when it is taken out of the pool.
//!
//! The pool is intentionally small and conservative:
//!
//! * one request per connection at a time, so no multiplexing is needed;
//! * entries are keyed by the full [`Target`] and capped per target;
//! * expired entries are dropped on checkout (and while counting);
//! * a connection that produced a protocol error, timed out, lost the peer,
//!   or was abandoned by the caller is never returned to the pool.
//!
//! # Retrying a stale connection
//!
//! A reused connection can have been closed by the responder between the
//! moment it was released and the moment it is checked out. When a bodyless
//! request fails before a single request byte was written, the pool makes one
//! fresh connection and replays the request. A request with STDIN data is
//! never replayed, and neither is a streaming request body: both may have
//! side effects that cannot be undone.

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

/// A pool of idle FastCGI connections.
///
/// `max_idle_per_target` bounds the number of idle sockets kept for each
/// [`Target`]. `idle_ttl` bounds how long a socket may sit in the pool; an
/// expired socket is closed the next time it would be checked out. A limit of
/// zero, or a zero TTL, disables reuse entirely.
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

/// Everything a background streaming task needs to give a socket back.
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
    /// Create a pool with the given per-target idle cap and idle lifetime.
    pub fn new(max_idle_per_target: usize, idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                max_idle: max_idle_per_target,
                idle_ttl,
                idle: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Number of idle sockets currently held, excluding expired entries.
    pub fn idle_count(&self) -> usize {
        let mut map = self.inner.lock();
        let ttl = self.inner.idle_ttl;
        map.retain(|_, entries| {
            entries.retain(|idle| idle.since.elapsed() < ttl);
            !entries.is_empty()
        });
        map.values().map(Vec::len).sum()
    }

    /// Send a buffered request through a pooled connection.
    ///
    /// Timeout handling matches [`execute`](crate::execute): zero disables the
    /// deadline; otherwise the whole exchange is covered, including connecting
    /// and reading until `END_REQUEST`.
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
                    // Any failed attempt invalidates this socket. A retry uses
                    // a brand-new connection, never the one that just failed.
                    drop(socket);

                    // The only replay allowed: a bodyless request on a reused
                    // connection that failed before the first request byte.
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

    /// Send a streaming request through a pooled connection.
    ///
    /// The connection is returned to the pool by the background reader only
    /// after the caller has drained (or polled past) the response body. A
    /// caller that drops the body early closes the connection instead.
    ///
    /// Streaming bodies are never replayed, so a reused connection that turns
    /// out to be stale is simply closed and the error is returned.
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
            // A peer that went away while the socket was idle is normal.
            // Drop it and let the caller open a fresh connection.
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

        // Evict the oldest sockets first when the per-target cap is crossed.
        while entries.len() > self.max_idle {
            entries.remove(0);
        }
    }
}

struct AttemptError {
    error: Error,
    written: usize,
}

/// Perform one buffered exchange on a connection that asked for keep-alive.
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

/// Count bytes handed to the socket, so a failed write can distinguish "the
/// stale connection failed at the first byte" from "the request was on the
/// wire and must not be replayed".
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
