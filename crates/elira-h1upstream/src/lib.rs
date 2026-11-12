use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

use elira_upstream::TlsOptions;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

pub fn empty() -> Body {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: usize,

    pub connect_timeout: Duration,
    pub bind: Option<std::net::IpAddr>,
    pub resolver: elira_upstream::Resolver,
    pub tls: TlsOptions,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 64,
            connect_timeout: Duration::from_secs(10),
            bind: None,
            resolver: elira_upstream::Resolver::default(),
            tls: TlsOptions::default(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request URI has no authority")]
    MissingAuthority,
    #[error("unsupported scheme {0}")]
    Scheme(String),
    #[error("connect {origin}: {source}")]
    Connect {
        origin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS {origin}: {source}")]
    Tls {
        origin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("connect timeout for {origin}")]
    ConnectTimeout { origin: String },
    #[error("HTTP/1.1 handshake with {origin}: {source}")]
    Handshake {
        origin: String,
        #[source]
        source: hyper::Error,
    },
    #[error("HTTP/1.1 request failed: {0}")]
    Request(hyper::Error),
}

pub struct Pool {
    config: PoolConfig,
    origins: Mutex<HashMap<String, Arc<OriginPool>>>,
}

struct OriginPool {
    idle: Mutex<Vec<PooledConn>>,
    permits: Arc<Semaphore>,
}

struct PooledConn {
    sender: http1::SendRequest<Body>,
    _permit: OwnedSemaphorePermit,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

impl Pool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            origins: Mutex::new(HashMap::new()),
        }
    }

    pub async fn request(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
        let origin = Origin::parse(request.uri())?;
        let pool = self.origin(&origin);
        let mut conn = self.acquire(&origin, &pool).await?;

        let response = conn
            .sender
            .send_request(request)
            .await
            .map_err(Error::Request)?;
        Ok(wrap_response(response, pool, conn))
    }

    fn origin(&self, origin: &Origin) -> Arc<OriginPool> {
        let key = origin.key();
        let mut origins = self
            .origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        origins
            .entry(key)
            .or_insert_with(|| {
                Arc::new(OriginPool {
                    idle: Mutex::new(Vec::new()),
                    permits: Arc::new(Semaphore::new(self.config.max_connections.max(1))),
                })
            })
            .clone()
    }

    async fn acquire(&self, origin: &Origin, pool: &Arc<OriginPool>) -> Result<PooledConn, Error> {
        loop {
            let candidate = {
                let mut idle = pool
                    .idle
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                idle.pop()
            };
            match candidate {
                Some(conn) if !conn.sender.is_closed() => return Ok(conn),
                Some(_) => continue,
                None => return self.connect(origin, pool).await,
            }
        }
    }

    async fn connect(&self, origin: &Origin, pool: &Arc<OriginPool>) -> Result<PooledConn, Error> {
        let permit =
            pool.permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::ConnectTimeout {
                    origin: origin.key(),
                })?;
        let timeout = self.config.connect_timeout;
        let name = origin.key();
        let established = tokio::time::timeout(timeout, async {
            let tcp = elira_upstream::tcp_connect(
                &origin.host,
                origin.port,
                self.config.bind,
                Some(&self.config.resolver),
            )
            .await
            .map_err(|source| Error::Connect {
                origin: name.clone(),
                source,
            })?;
            let _ = tcp.set_nodelay(true);

            let io: Box<dyn Io> = if origin.https {
                let config = Arc::new(elira_upstream::client_config(&self.config.tls).map_err(
                    |source| Error::Tls {
                        origin: name.clone(),
                        source: std::io::Error::other(source.to_string()),
                    },
                )?);
                let server_name = self
                    .config
                    .tls
                    .sni
                    .clone()
                    .unwrap_or_else(|| origin.host.clone());
                let server_name = match server_name.parse::<std::net::IpAddr>() {
                    Ok(ip) => ServerName::IpAddress(ip.into()),
                    Err(_) => ServerName::try_from(server_name).map_err(|source| Error::Tls {
                        origin: name.clone(),
                        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
                    })?,
                };
                let connector = TlsConnector::from(config);
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|source| Error::Tls {
                        origin: name.clone(),
                        source,
                    })?;
                Box::new(tls)
            } else {
                Box::new(tcp)
            };

            http1::Builder::new()
                .handshake(TokioIo::new(io))
                .await
                .map_err(|source| Error::Handshake {
                    origin: name.clone(),
                    source,
                })
        })
        .await;

        let (sender, driver) = match established {
            Err(_) => {
                return Err(Error::ConnectTimeout {
                    origin: origin.key(),
                })
            }
            Ok(Err(error)) => return Err(error),
            Ok(Ok(pair)) => pair,
        };
        tokio::spawn(async move {
            let _ = driver.await;
        });

        Ok(PooledConn {
            sender,
            _permit: permit,
        })
    }
}

fn wrap_response(
    response: Response<hyper::body::Incoming>,
    pool: Arc<OriginPool>,
    conn: PooledConn,
) -> Response<Body> {
    let (parts, incoming) = response.into_parts();
    let close = parts
        .headers
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
        || parts.version == http::Version::HTTP_10;
    let body = PooledBody {
        inner: incoming
            .map_err(|err| -> BoxError { Box::new(err) })
            .boxed(),
        conn: Some(conn),
        pool,
        reuse: !close && parts.status != StatusCode::SWITCHING_PROTOCOLS,
    }
    .boxed();
    Response::from_parts(parts, body)
}

struct PooledBody {
    inner: Body,
    conn: Option<PooledConn>,
    pool: Arc<OriginPool>,
    reuse: bool,
}

impl PooledBody {
    fn release(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        if !self.reuse || conn.sender.is_closed() {
            return;
        }
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        idle.push(conn);
    }
}

impl HttpBody for PooledBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                self.release();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.conn = None;
                Poll::Ready(Some(Err(err)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for PooledBody {
    fn drop(&mut self) {
        if self.reuse && self.inner.is_end_stream() {
            self.release();
        } else {
            self.conn = None;
        }
    }
}

struct Origin {
    https: bool,
    host: String,
    port: u16,
}

impl Origin {
    fn parse(uri: &Uri) -> Result<Self, Error> {
        let authority = uri.authority().ok_or(Error::MissingAuthority)?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") | None => false,
            Some(other) => return Err(Error::Scheme(other.to_owned())),
        };
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
        Ok(Self { https, host, port })
    }

    fn key(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.https { "https" } else { "http" },
            self.host,
            self.port
        )
    }
}
