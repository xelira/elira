use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use elira::config::{Config, LogFormat};
use elira::proxy::{BoxError, Proxy};
use elira_accesslog::{request_id, Entry};
use http_body::Body as _;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "elira", version, about = "HTTP server and reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server.
    Run {
        #[arg(short, long, default_value = "elira.toml")]
        config: PathBuf,
    },
    /// Parse the config and exit.
    Check {
        #[arg(short, long, default_value = "elira.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls refuses to guess when more than one crypto backend is compiled
    // in, and quinn pulls in its own feature set. Pick one, once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match Cli::parse().command {
        Command::Check { config } => {
            let cfg = Config::load(&config)?;
            println!(
                "{}: ok, {} route(s), {} upstream(s)",
                config.display(),
                cfg.routes.len(),
                cfg.upstreams.len()
            );
            Ok(())
        }
        Command::Run { config } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .init();
            run(config).await
        }
    }
}

/// Everything that can change on SIGHUP. Connections in flight keep the
/// version they started with.
struct Runtime {
    proxy: Proxy,
    tls: Option<Arc<rustls::ServerConfig>>,
    log: LogFormat,
    health: elira::config::Health,
}

impl Runtime {
    fn build(cfg: &Config) -> anyhow::Result<Self> {
        let tls = match &cfg.tls {
            Some(tls) => Some(Arc::new(elira_tls::server_config(&tls.cert, &tls.key)?)),
            None => None,
        };
        Ok(Self {
            proxy: Proxy::new(cfg)?,
            tls,
            log: cfg.log.format,
            health: cfg.health.clone(),
        })
    }
}

async fn run(path: PathBuf) -> anyhow::Result<()> {
    let cfg = Config::load(&path)?;
    let runtime = Arc::new(ArcSwap::from_pointee(Runtime::build(&cfg)?));

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("cannot bind {}", cfg.listen))?;

    tracing::info!(
        listen = %cfg.listen,
        routes = cfg.routes.len(),
        upstreams = cfg.upstreams.len(),
        tls = cfg.tls.is_some(),
        "listening"
    );

    let max_connections = cfg.limits.max_connections;
    let max_headers = cfg.limits.max_headers;
    let max_buf_size = cfg.limits.max_header_bytes;
    let idle_timeout = Duration::from_secs(cfg.limits.idle_timeout_secs);
    let opts = ConnOptions {
        max_headers,
        max_buf_size,
        idle_timeout,
        h2: false,
        secure: false,
    };
    let semaphore = Arc::new(Semaphore::new(max_connections));

    let (stop_tx, stop_rx) = watch::channel(false);
    let (reload_tx, mut reload_rx) = watch::channel(0u64);
    spawn_signal_task(stop_tx.clone(), reload_tx)?;
    spawn_health_loop(runtime.clone(), stop_rx.clone());

    if let Some(http3) = &cfg.http3 {
        let cfg = elira_h3::Config {
            listen: http3.listen,
            cert: http3.cert.clone(),
            key: http3.key.clone(),
        };
        let current = runtime.load_full();
        let proxy = current.proxy.clone();
        let log = current.log;
        let stop = stop_rx.clone();

        tokio::spawn(async move {
            if let Err(err) = elira_h3::serve(cfg, proxy, log, stop).await {
                tracing::error!(error = %err, "http/3 listener stopped");
            }
        });
    }

    let mut stop_wait = stop_rx.clone();
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = stop_wait.changed() => break,

            changed = reload_rx.changed() => {
                if changed.is_err() {
                    continue;
                }
                reload(&path, &cfg, &runtime, max_connections, max_headers, max_buf_size).await;
            }

            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // EMFILE/ENFILE return immediately and would turn this
                        // loop into a log-flooding spin.
                        tracing::warn!(error = %err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Blocking here would stop the accept loop from noticing
                // SIGTERM or SIGHUP. When the limit is hit, drop the socket.
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!(%peer, "connection limit reached");
                        continue;
                    }
                };

                let runtime = runtime.clone();
                let mut stop = stop_rx.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve(stream, peer, runtime, opts, &mut stop).await;
                });
            }
        }

        while connections.try_join_next().is_some() {}
    }

    tracing::info!("shutting down");
    drop(listener);
    let _ = stop_tx.send(true);

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        tracing::warn!("some connections did not finish in time");
    }

    Ok(())
}

async fn reload(
    path: &Path,
    current: &Config,
    runtime: &ArcSwap<Runtime>,
    max_connections: usize,
    max_headers: usize,
    max_buf_size: usize,
) {
    let next = match Config::load(path) {
        Ok(next) => next,
        Err(err) => {
            tracing::error!(error = %err, "reload failed, keeping the old config");
            return;
        }
    };

    // The listener and the per-connection limits are captured at startup;
    // pretending otherwise would silently ignore the operator's edit.
    if next.listen != current.listen {
        tracing::warn!("listen address changes need a restart");
    }
    if next.limits.max_connections != max_connections
        || next.limits.max_headers != max_headers
        || next.limits.max_header_bytes != max_buf_size
    {
        tracing::warn!("connection and header limits apply after a restart");
    }
    if next.http3.is_some() != current.http3.is_some() {
        tracing::warn!("http/3 listener changes need a restart");
    }

    let built = match Runtime::build(&next) {
        Ok(built) => built,
        Err(err) => {
            tracing::error!(error = %err, "reload failed, keeping the old config");
            return;
        }
    };

    // Probe before publishing, otherwise every server looks healthy again
    // for one interval after reload.
    if built.health.enabled {
        built.proxy.check_health(&built.health).await;
    }

    runtime.store(Arc::new(built));
    tracing::info!("config reloaded");
}

#[cfg(unix)]
fn spawn_signal_task(stop: watch::Sender<bool>, reload: watch::Sender<u64>) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        let mut seq = 0u64;

        loop {
            tokio::select! {
                _ = &mut ctrl_c => { let _ = stop.send(true); return; }
                _ = term.recv() => { let _ = stop.send(true); return; }
                _ = hup.recv() => {
                    seq += 1;
                    let _ = reload.send(seq);
                }
            }
        }
    });

    Ok(())
}

#[cfg(not(unix))]
fn spawn_signal_task(stop: watch::Sender<bool>, _reload: watch::Sender<u64>) -> anyhow::Result<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    });
    Ok(())
}

#[derive(Clone, Copy)]
struct ConnOptions {
    max_headers: usize,
    max_buf_size: usize,
    idle_timeout: Duration,
    h2: bool,
    secure: bool,
}

async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    stop: &mut watch::Receiver<bool>,
) {
    let tls = runtime.load().tls.clone();
    let secure = tls.is_some();

    match tls {
        Some(config) => {
            let acceptor = TlsAcceptor::from(config);
            // A client that never sends ClientHello must not hold a permit,
            // and with it the accept loop, forever.
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                    let opts = ConnOptions { h2, secure, ..opts };
                    serve_conn(stream, peer, runtime, opts, stop).await;
                }
                Ok(Err(err)) => tracing::debug!(%peer, error = %err, "tls handshake failed"),
                Err(_) => tracing::debug!(%peer, "tls handshake timed out"),
            }
        }
        None => serve_conn(stream, peer, runtime, opts, stop).await,
    }
}

async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    stop: &mut watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let idle = Arc::new(tokio::sync::Notify::new());
    let idle_for_service = idle.clone();
    let scheme = if opts.secure { "https" } else { "http" };

    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let runtime = runtime.clone();
        let idle = idle_for_service.clone();
        async move {
            // Reset the keep-alive watchdog: a request means the client is
            // still there, even if the response takes a while.
            idle.notify_one();

            // Load per request, so a reload applies to the next request on
            // an existing keep-alive connection rather than the next one.
            let current = runtime.load_full();

            let started = Instant::now();
            let method = req.method().clone();
            let host = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                // HTTP/2 has no Host header; the value lives in :authority.
                .or_else(|| req.uri().authority().map(|value| value.as_str().to_owned()))
                .unwrap_or_default();
            let version = req.version();
            let path = req
                .uri()
                .path_and_query()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_else(|| "/".to_owned());
            let user_agent = req
                .headers()
                .get(hyper::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let id = request_id();

            let req = req.map(|body| body.map_err(|err| -> BoxError { Box::new(err) }).boxed());
            let response = current.proxy.handle(req, peer, scheme).await;
            let bytes = response.body().size_hint().exact().unwrap_or(0);
            let entry = Entry {
                peer: peer.ip(),
                method,
                version,
                host,
                path,
                status: response.status(),
                bytes,
                duration: started.elapsed(),
                user_agent,
                request_id: id,
            };

            match current.log {
                LogFormat::Text => tracing::info!(target: "access", "{}", entry.line()),
                LogFormat::Json => tracing::info!(target: "access", "{}", entry.json()),
            }

            Ok::<_, std::convert::Infallible>(response)
        }
    });

    if opts.h2 {
        let conn = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(20))
            .max_header_list_size(opts.max_buf_size as u32)
            .serve_connection(TokioIo::new(io), service);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "connection closed");
                }
            }
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
        }
    } else {
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(Duration::from_secs(30)))
            .max_headers(opts.max_headers)
            .max_buf_size(opts.max_buf_size)
            .serve_connection(TokioIo::new(io), service)
            // Without this hyper refuses to hand the socket over and
            // OnUpgrade resolves with "upgrade expected but low level API
            // in use".
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "connection closed");
                }
            }
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
        }
    }
}

/// Let the current request finish, but do not wait forever: a client that
/// trickles a body would otherwise pin the permit until the process dies.
async fn drain<C>(conn: std::pin::Pin<&mut C>, peer: SocketAddr)
where
    C: std::future::Future<Output = Result<(), hyper::Error>>,
{
    if tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .is_err()
    {
        tracing::debug!(%peer, "connection did not drain in time");
    }
}

/// Close a connection that has not seen a request for `timeout`.
/// A zero timeout disables the watchdog.
async fn idle_watch(idle: Arc<tokio::sync::Notify>, timeout: Duration) {
    if timeout.is_zero() {
        std::future::pending::<()>().await;
        return;
    }

    loop {
        match tokio::time::timeout(timeout, idle.notified()).await {
            Ok(()) => continue,
            Err(_) => return,
        }
    }
}

fn spawn_health_loop(runtime: Arc<ArcSwap<Runtime>>, mut stop: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            let current = runtime.load_full();
            let interval = if current.health.enabled {
                Duration::from_secs(current.health.interval_secs)
            } else {
                Duration::from_secs(30)
            };

            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep(interval) => {
                    current.proxy.check_health(&current.health).await;
                }
            }
        }
    });
}
