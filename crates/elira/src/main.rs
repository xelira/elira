use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use elira::config::Config;
use elira::proxy::Proxy;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
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
    let proxy = Proxy::new(&cfg)?;

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("cannot bind {}", cfg.listen))?;

    tracing::info!(
        listen = %cfg.listen,
        routes = cfg.routes.len(),
        upstreams = cfg.upstreams.len(),
        "listening"
    );

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    let max_headers = cfg.limits.max_headers;
    let max_buf_size = cfg.limits.max_header_bytes;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(error = %err, "accept failed");
                        continue;
                    }
                };

                let proxy = proxy.clone();
                let mut stop = stop_rx.clone();
                connections.spawn(async move {
                    serve(stream, peer, proxy, max_headers, max_buf_size, &mut stop).await;
                });
            }
            _ = shutdown() => break,
        }
    }

    tracing::info!("shutting down");
    drop(listener);
    let _ = stop_tx.send(true);

    let drain = async {
        while connections.join_next().await.is_some() {}
    };
    if tokio::time::timeout(Duration::from_secs(10), drain).await.is_err() {
        tracing::warn!("some connections did not finish in time");
    }

    Ok(())
}

async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    proxy: Proxy,
    max_headers: usize,
    max_buf_size: usize,
    stop: &mut watch::Receiver<bool>,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let proxy = proxy.clone();
        async move { Ok::<_, std::convert::Infallible>(proxy.handle(req, peer).await) }
    });

    let conn = http1::Builder::new()
        .max_headers(max_headers)
        .max_buf_size(max_buf_size)
        .serve_connection(io, service);
    let mut conn = std::pin::pin!(conn);

    tokio::select! {
        result = conn.as_mut() => {
            if let Err(err) = result {
                tracing::debug!(%peer, error = %err, "connection closed");
            }
        }
        _ = stop.changed() => {
            conn.as_mut().graceful_shutdown();
            if let Err(err) = conn.await {
                tracing::debug!(%peer, error = %err, "connection closed during drain");
            }
        }
    }
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut term = match signal(SignalKind::terminate()) {
            Ok(term) => term,
            Err(err) => {
                tracing::warn!(error = %err, "SIGTERM handler unavailable");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
