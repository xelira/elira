use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use elira::config::Config;
use elira::server::{self, Options, Runtime};
use elira_metrics::Metrics;
use tokio::net::TcpListener;
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

    let options = Options::from_config(&cfg);
    let metrics = Arc::new(Metrics::new());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (reload_tx, mut reload_rx) = watch::channel(0u64);

    spawn_signal_task(stop_tx.clone(), reload_tx)?;
    server::spawn_health_loop(runtime.clone(), metrics.clone(), stop_rx.clone());

    if let Some(metrics_cfg) = &cfg.metrics {
        let metrics_listener = TcpListener::bind(metrics_cfg.listen)
            .await
            .with_context(|| format!("cannot bind metrics on {}", metrics_cfg.listen))?;
        server::spawn_metrics(metrics_listener, metrics.clone(), stop_rx.clone());
    }

    let mut h3_task = spawn_h3(runtime.clone(), stop_rx.clone());
    let mut stop_wait = stop_rx.clone();

    let serving = tokio::spawn(server::serve(
        listener,
        runtime.clone(),
        options,
        metrics.clone(),
        stop_rx.clone(),
    ));

    loop {
        tokio::select! {
            _ = stop_wait.changed() => break,

            changed = reload_rx.changed() => {
                if changed.is_err() {
                    break;
                }

                reload(&path, &cfg, &runtime, options).await;

                // The new Runtime carries its own http3 config. Restart the
                // listener against it instead of keeping the old one.
                if let Some(handle) = h3_task.take() {
                    handle.abort();
                    // Wait for the QUIC endpoint to drop before rebinding.
                    let _ = handle.await;
                }
                h3_task = spawn_h3(runtime.clone(), stop_rx.clone());
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

    // The listener got the stop signal and closed its endpoint on its own;
    // this is only a fallback for a stuck task.
    if let Some(handle) = h3_task.take() {
        handle.abort();
    }

    Ok(())
}

fn spawn_h3(
    runtime: Arc<ArcSwap<Runtime>>,
    stop: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let current = runtime.load();
    let http3 = current.http3().cloned()?;
    let proxy = current.proxy().clone();
    let log = current.log();
    drop(current);

    Some(tokio::spawn(async move {
        let cfg = elira_h3::Config {
            listen: http3.listen,
            cert: http3.cert,
            key: http3.key,
        };
        if let Err(err) = elira_h3::serve(cfg, proxy, log, stop).await {
            tracing::error!(error = %err, "http/3 listener stopped");
        }
    }))
}

async fn reload(path: &Path, current: &Config, runtime: &ArcSwap<Runtime>, options: Options) {
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
