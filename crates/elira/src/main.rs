use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use elira::config::Config;
use elira::server::{self, Options, Runtime};
use elira_metrics::Metrics;
use tokio::sync::watch;
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
    /// Convert an nginx config into elira TOML.
    Migrate {
        /// nginx config to read.
        input: PathBuf,
        /// Write the TOML here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
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
        Command::Migrate { input, output } => {
            let source = std::fs::read_to_string(&input)
                .with_context(|| format!("cannot read {}", input.display()))?;
            let migration = elira_migrate::migrate(&source)?;

            for warning in &migration.warnings {
                eprintln!("warning: {warning}");
            }

            match output {
                Some(path) => {
                    std::fs::write(&path, &migration.toml)
                        .with_context(|| format!("cannot write {}", path.display()))?;
                    eprintln!("wrote {}", path.display());
                }
                None => print!("{}", migration.toml),
            }
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

async fn run(path: PathBuf) -> anyhow::Result<()> {
    let cfg = Config::load(&path)?;
    let runtime = Arc::new(ArcSwap::from_pointee(Runtime::build(&cfg)?));

    let listener = server::bind_tcp(cfg.listen, cfg.reuse_port)
        .with_context(|| format!("cannot bind {}", cfg.listen))?;

    tracing::info!(
        listen = %cfg.listen,
        routes = cfg.routes.len(),
        upstreams = cfg.upstreams.len(),
        tls = cfg.tls.is_some(),
        "listening"
    );

    let mut options = Options::from_config(&cfg);
    if let Some(acme) = &cfg.acme {
        let started = elira_acme::Acme::start(elira_acme::AcmeConfig {
            domains: acme.domains.clone(),
            contacts: acme.contacts.clone(),
            cache_dir: acme.cache_dir.clone(),
            production: acme.production,
            challenge: match acme.challenge {
                elira::config::AcmeChallenge::TlsAlpn01 => elira_acme::Challenge::TlsAlpn01,
                elira::config::AcmeChallenge::Http01 => elira_acme::Challenge::Http01,
            },
        })
        .await?;
        options.acme = Some(Arc::new(started));
    }
    let metrics = Arc::new(Metrics::new());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (reload_tx, mut reload_rx) = watch::channel(0u64);
    let (restart_tx, mut restart_rx) = watch::channel(0u64);

    spawn_signal_task(stop_tx.clone(), reload_tx.clone(), restart_tx)?;
    server::spawn_health_loop(runtime.clone(), metrics.clone(), stop_rx.clone());

    if let (Some(acme), Some(listen)) = (
        options.acme.clone(),
        cfg.acme.as_ref().and_then(|acme| acme.http01_listen),
    ) {
        let listener = server::bind_tcp(listen, cfg.reuse_port)
            .with_context(|| format!("cannot bind HTTP-01 listener on {listen}"))?;
        tracing::info!(%listen, "http-01 challenge listener");
        server::spawn_http01(listener, acme, stop_rx.clone());
    }

    if let Some(metrics_cfg) = &cfg.metrics {
        let metrics_listener = server::bind_tcp(metrics_cfg.listen, cfg.reuse_port)
            .with_context(|| format!("cannot bind metrics on {}", metrics_cfg.listen))?;
        let admin_auth = match &metrics_cfg.auth_file {
            Some(path) => Some(Arc::new(elira_auth::BasicAuth::from_file(path)?)),
            None => None,
        };
        server::spawn_metrics(
            metrics_listener,
            runtime.clone(),
            metrics.clone(),
            admin_auth,
            reload_tx.clone(),
            stop_tx.clone(),
            stop_rx.clone(),
        );
    }

    let mut h3_task = spawn_h3(
        runtime.clone(),
        metrics.clone(),
        stop_rx.clone(),
        cfg.reuse_port,
        options.body_timeout,
        cfg.proxy_protocol,
    );
    let mut stop_wait = stop_rx.clone();

    let unix_serving = match &cfg.listen_unix {
        Some(path) => {
            let listener = server::bind_unix(path)
                .with_context(|| format!("cannot bind unix socket {}", path.display()))?;
            tracing::info!(path = %path.display(), "listening on a unix socket");
            Some(tokio::spawn(server::serve_unix(
                listener,
                runtime.clone(),
                options.clone(),
                metrics.clone(),
                stop_rx.clone(),
            )))
        }
        None => None,
    };

    let serving = tokio::spawn(server::serve(
        listener,
        runtime.clone(),
        options.clone(),
        metrics.clone(),
        stop_rx.clone(),
    ));

    // Both the readiness file (seen by the old process during SIGUSR2) and
    // the systemd notification mean the same thing: all listeners are bound.
    notify_ready();

    loop {
        tokio::select! {
            _ = stop_wait.changed() => break,

            changed = restart_rx.changed() => {
                if changed.is_err() {
                    break;
                }

                if !cfg.reuse_port {
                    tracing::warn!("SIGUSR2 needs reuse_port = true; ignoring");
                    continue;
                }

                if spawn_replacement() {
                    let _ = stop_tx.send(true);
                    break;
                }
                tracing::error!("replacement did not become ready; keeping this process");
            }

            changed = reload_rx.changed() => {
                if changed.is_err() {
                    break;
                }

                let before = h3_identity(runtime.load().http3());
                reload(&path, &cfg, &runtime, options.clone(), &metrics).await;
                let after = h3_identity(runtime.load().http3());

                // Routes, the proxy and logging load the current Runtime per
                // request, so only a changed certificate or listener needs a
                // new QUIC endpoint. Restarting it drops live HTTP/3 streams.
                if before != after {
                    if let Some(handle) = h3_task.take() {
                        handle.abort();
                        let _ = handle.await;
                    }
                    h3_task = spawn_h3(
                        runtime.clone(),
                        metrics.clone(),
                        stop_rx.clone(),
                        cfg.reuse_port,
                        options.body_timeout,
                        cfg.proxy_protocol,
                    );
                }
            }
        }
    }

    tracing::info!("shutting down");
    let _ = stop_tx.send(true);

    if tokio::time::timeout(Duration::from_secs(15), serving)
        .await
        .is_err()
    {
        tracing::warn!("server did not stop in time");
    }
    if let Some(task) = unix_serving {
        if tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .is_err()
        {
            tracing::warn!("unix listener did not stop in time");
        }
    }

    // The listener got the stop signal and closed its endpoint on its own;
    // this is only a fallback for a stuck task.
    if let Some(handle) = h3_task.take() {
        handle.abort();
    }

    Ok(())
}

fn spawn_h3(
    runtime: Arc<ArcSwap<Runtime>>,
    metrics: Arc<Metrics>,
    stop: watch::Receiver<bool>,
    reuse_port: bool,
    body_timeout: Option<Duration>,
    proxy_protocol: bool,
) -> Option<tokio::task::JoinHandle<()>> {
    let current = runtime.load();
    let http3 = current.http3().cloned()?;
    drop(current);

    // The QUIC listener outlives route reloads; the proxy is loaded per
    // request so new routes take effect without touching live streams.
    let proxy_runtime = runtime.clone();
    let proxy: Arc<dyn Fn() -> elira_proxy::Proxy + Send + Sync> =
        Arc::new(move || proxy_runtime.load().proxy().clone());

    let client_auth = match http3.client_auth {
        elira::config::ClientAuthMode::Off => elira_tls::ClientAuth::Off,
        elira::config::ClientAuthMode::Optional => elira_tls::ClientAuth::Optional,
        elira::config::ClientAuthMode::Required => elira_tls::ClientAuth::Required,
    };

    // The listener restarts on reload, but one log closure keeps using the
    // current runtime, so templates and files stay in sync.
    let log_runtime = runtime.clone();
    let log: Arc<dyn Fn(&elira_accesslog::Entry) + Send + Sync> =
        Arc::new(move |entry| log_runtime.load().write_log(entry));

    Some(tokio::spawn(async move {
        let cfg = elira_h3::Config {
            listen: http3.listen,
            cert: http3.cert,
            key: http3.key,
            reuse_port,
            client_ca: http3.client_ca,
            client_auth,
            proxy_protocol,
        };
        if let Err(err) = elira_h3::serve(cfg, proxy, metrics, body_timeout, log, stop).await {
            tracing::error!(error = %err, "http/3 listener stopped");
        }
    }))
}

/// Identity of the QUIC listener covered by a reload. A different path,
/// address or file timestamp means the endpoint has to be rebuilt.
type H3Identity = (
    std::net::SocketAddr,
    std::path::PathBuf,
    std::path::PathBuf,
    Option<std::path::PathBuf>,
    elira::config::ClientAuthMode,
    u64,
    u64,
    u64,
);

fn h3_identity(http3: Option<&elira::config::Http3>) -> Option<H3Identity> {
    let http3 = http3?;
    let stamp = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|delta| delta.as_nanos() as u64)
            .unwrap_or(0)
    };
    Some((
        http3.listen,
        http3.cert.clone(),
        http3.key.clone(),
        http3.client_ca.clone(),
        http3.client_auth,
        stamp(&http3.cert),
        stamp(&http3.key),
        http3.client_ca.as_deref().map(stamp).unwrap_or(0),
    ))
}

async fn reload(
    path: &Path,
    current: &Config,
    runtime: &ArcSwap<Runtime>,
    options: Options,
    metrics: &Metrics,
) {
    let next = match Config::load(path) {
        Ok(next) => next,
        Err(err) => {
            tracing::error!(error = %err, "reload failed, keeping the old config");
            metrics.reload_failed();
            return;
        }
    };

    // The listener and the per-connection limits are captured at startup;
    // pretending otherwise would silently ignore the operator's edit.
    if next.listen != current.listen {
        tracing::warn!("listen address changes need a restart");
    }
    if next.metrics.as_ref().map(|m| m.listen) != current.metrics.as_ref().map(|m| m.listen) {
        tracing::warn!("metrics listener changes need a restart");
    }
    if next.limits.max_connections != options.max_connections
        || next.limits.max_headers != options.max_headers
        || next.limits.max_header_bytes != options.max_buf_size
    {
        tracing::warn!("connection and header limits apply after a restart");
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
    if built.health().enabled {
        built.proxy().check_health(built.health()).await;
    }

    runtime.store(Arc::new(built));
    metrics.reload_ok();
    tracing::info!("config reloaded");
}

/// Start a new process and wait until it says its listeners are bound. The old
/// process must not drain before that: if the replacement fails to bind, the
/// service would simply stop.
fn spawn_replacement() -> bool {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            tracing::error!(error = %err, "cannot find the executable");
            return false;
        }
    };

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let ready = std::env::temp_dir().join(format!(
        "elira-ready-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let mut child = match std::process::Command::new(exe)
        .args(args)
        .env("ELIRA_READY_FILE", &ready)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            tracing::error!(error = %err, "cannot start a replacement");
            return false;
        }
    };

    let pid = child.id();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if ready.exists() {
            let _ = std::fs::remove_file(&ready);
            tracing::info!(pid, "replacement is ready, draining this one");
            return true;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                tracing::error!(pid, %status, "replacement exited before becoming ready");
                let _ = std::fs::remove_file(&ready);
                return false;
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(pid, error = %err, "cannot poll the replacement");
                let _ = std::fs::remove_file(&ready);
                return false;
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    tracing::error!(pid, "replacement did not become ready in time");
    let _ = child.kill();
    let _ = std::fs::remove_file(&ready);
    false
}

/// Tell the process that started us (and systemd, when present) that the
/// sockets are bound. Called once, after the accept loops are live.
fn notify_ready() {
    let pid = std::process::id();

    if let Ok(path) = std::env::var("ELIRA_READY_FILE") {
        let _ = std::fs::write(path, pid.to_string());
    }

    let Ok(socket) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };

    let message = format!("READY=1\nMAINPID={pid}\n");
    if let Err(err) = send_to_socket(&socket, message.as_bytes()) {
        tracing::debug!(error = %err, "systemd notify failed");
    }
}

#[cfg(unix)]
fn send_to_socket(path: &str, message: &[u8]) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let socket = UnixDatagram::unbound()?;
    // systemd uses the abstract namespace by default; a leading '@' in the
    // environment variable is how it is spelled there.
    if let Some(name) = path.strip_prefix('@') {
        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        socket.send_to_addr(message, &addr)?;
    } else {
        socket.send_to(message, path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_to_socket(_path: &str, _message: &[u8]) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn spawn_signal_task(
    stop: watch::Sender<bool>,
    reload: watch::Sender<u64>,
    restart: watch::Sender<u64>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr2 = signal(SignalKind::user_defined2())?;

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        let mut reload_seq = 0u64;
        let mut restart_seq = 0u64;

        loop {
            tokio::select! {
                _ = &mut ctrl_c => { let _ = stop.send(true); return; }
                _ = term.recv() => { let _ = stop.send(true); return; }
                _ = hup.recv() => {
                    reload_seq += 1;
                    let _ = reload.send(reload_seq);
                }
                _ = usr2.recv() => {
                    restart_seq += 1;
                    let _ = restart.send(restart_seq);
                }
            }
        }
    });

    Ok(())
}

#[cfg(not(unix))]
fn spawn_signal_task(
    stop: watch::Sender<bool>,
    _reload: watch::Sender<u64>,
    _restart: watch::Sender<u64>,
) -> anyhow::Result<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    });
    Ok(())
}
