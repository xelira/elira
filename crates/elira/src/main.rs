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
    /// Internal: host one isolated module process.
    #[command(hide = true)]
    ModuleWorker { module: PathBuf },
    /// Convert an nginx config into elira TOML.
    Migrate {
        /// nginx config to read.
        input: PathBuf,
        /// Write the TOML here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
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
        Command::ModuleWorker { module } => module_worker(&module),
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
            init_tracing();
            let cfg = Config::load(&config)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("cannot build the tokio runtime")?;

            // A child of the supervisor must never supervise again.
            if cfg.workers > 1 && std::env::var_os("ELIRA_WORKER").is_none() {
                runtime.block_on(supervise(config, cfg.workers))
            } else {
                runtime.block_on(run(config))
            }
        }
    }
}

fn module_worker(path: &Path) -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let module = elira_module::Module::load(path)?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    loop {
        let mut length = [0u8; 4];
        match input.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > 16 * 1024 * 1024 {
            anyhow::bail!("module request too large");
        }
        let mut body = vec![0u8; length];
        input.read_exact(&mut body)?;
        let request: elira_module::Request = serde_json::from_slice(&body)?;
        let response = module.call(&request)?;
        let encoded = serde_json::to_vec(&response)?;
        output.write_all(&(encoded.len() as u32).to_be_bytes())?;
        output.write_all(&encoded)?;
        output.flush()?;
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

async fn run(path: PathBuf) -> anyhow::Result<()> {
    let cfg = Config::load(&path)?;
    if std::env::var_os("ELIRA_WORKER").is_none() {
        if let Some(hook) = cfg.tls.as_ref().and_then(|tls| tls.ocsp_hook.as_ref()) {
            run_ocsp_hook(hook).await;
        }
    }
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
                elira::config::AcmeChallenge::Dns01 => elira_acme::Challenge::Dns01,
            },
            dns_hook: acme.dns_hook.clone(),
            dns_cleanup_hook: acme.dns_cleanup_hook.clone(),
            dns_propagation_secs: acme.dns_propagation_secs,
        })
        .await?;
        options.acme = Some(Arc::new(started));
    }
    let metrics = Arc::new(Metrics::new());
    record_certificate_expiry(&cfg, &metrics);
    if let (Ok(path), Ok(index)) = (
        std::env::var("ELIRA_METRICS_SOCKET"),
        std::env::var("ELIRA_WORKER_INDEX"),
    ) {
        spawn_metrics_sender(
            metrics.clone(),
            runtime.clone(),
            PathBuf::from(path),
            index.parse().unwrap_or(0),
        );
    }
    if let Ok(path) = std::env::var("ELIRA_CONTROL_SOCKET") {
        spawn_control_socket(PathBuf::from(path), runtime.clone());
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let (reload_tx, mut reload_rx) = watch::channel(0u64);
    let (restart_tx, mut restart_rx) = watch::channel(0u64);

    spawn_signal_task(stop_tx.clone(), reload_tx.clone(), restart_tx)?;
    if std::env::var_os("ELIRA_WORKER").is_none() {
        if let Some(tls) = &cfg.tls {
            if let Some(hook) = &tls.ocsp_hook {
                let has_ocsp =
                    tls.ocsp.is_some() || tls.certificates.iter().any(|entry| entry.ocsp.is_some());
                if has_ocsp {
                    spawn_ocsp_refresh(hook.clone(), tls.ocsp_refresh_secs, reload_tx.clone());
                }
            }
        }
    }
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
        if std::env::var_os("ELIRA_METRICS_SOCKET").is_some() {
            // The supervisor owns the metrics listener in worker mode.
        } else {
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

    if tokio::time::timeout(
        Duration::from_secs(cfg.limits.shutdown_timeout_secs),
        serving,
    )
    .await
    .is_err()
    {
        tracing::warn!("server did not stop in time");
    }
    if let Some(task) = unix_serving {
        if tokio::time::timeout(Duration::from_secs(cfg.limits.shutdown_timeout_secs), task)
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

fn record_certificate_expiry(cfg: &Config, metrics: &Metrics) {
    let mut paths = Vec::new();
    if let Some(tls) = &cfg.tls {
        paths.push(tls.cert.clone());
    }
    if let Some(http3) = &cfg.http3 {
        paths.push(http3.cert.clone());
    }
    for path in paths {
        if let Ok(expiry) = elira_tls::certificate_expiry(&path) {
            if let Ok(delta) = expiry.duration_since(std::time::UNIX_EPOCH) {
                metrics.set_certificate_expiry(&path.display().to_string(), delta.as_secs() as i64);
            }
        }
    }
}

fn reload_counter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos() as u64)
        .unwrap_or(0)
}

async fn run_ocsp_hook(hook: &Path) {
    match tokio::process::Command::new(hook).status().await {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(%status, "ocsp hook failed"),
        Err(error) => tracing::warn!(%error, "cannot run the ocsp hook"),
    }
}

fn spawn_ocsp_refresh(hook: PathBuf, interval_secs: u64, reload: watch::Sender<u64>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            run_ocsp_hook(&hook).await;
            let _ = reload.send(reload_counter());
            tracing::info!("ocsp hook finished, reloading");
        }
    });
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
            certificates: http3
                .certificates
                .iter()
                .map(|entry| elira_tls::NamedCert {
                    names: entry.names.clone(),
                    cert: entry.cert.clone(),
                    key: entry.key.clone(),
                    ocsp: entry.ocsp.clone(),
                })
                .collect(),
            idle_timeout_secs: http3.idle_timeout_secs,
            early_data: http3.early_data,
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
    record_certificate_expiry(&next, metrics);
    metrics.reload_ok();
    tracing::info!("config reloaded");
}

struct WorkerSlot {
    pid: u32,
    ready: PathBuf,
    control: PathBuf,
}

type StatusMap = Arc<std::sync::Mutex<std::collections::HashMap<usize, String>>>;
type WorkerGauges = Arc<std::sync::Mutex<std::collections::HashMap<usize, (u64, u64, u64)>>>;

/// Supervisor for `workers > 1`. Children share the sockets via SO_REUSEPORT;
/// the parent only starts, watches, reloads and restarts them.
async fn supervise(config: PathBuf, workers: usize) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::sync::mpsc;

    let cfg = Config::load(&config)?;
    if let Some(hook) = cfg.tls.as_ref().and_then(|tls| tls.ocsp_hook.as_ref()) {
        run_ocsp_hook(hook).await;
    }
    let (exit_tx, mut exit_rx) = mpsc::channel::<(usize, std::process::ExitStatus)>(64);
    let (admin_tx, mut admin_rx) = mpsc::channel::<server::AdminCommand>(8);
    let mut slots = Vec::with_capacity(workers);

    // Workers send their counters here; the supervisor owns the public
    // metrics listener in multi-process mode.
    let mut metrics_socket = None;
    let mut gauge_state: Option<(Arc<Metrics>, WorkerGauges)> = None;
    if let Some(metrics_cfg) = cfg.metrics.as_ref() {
        let listener = server::bind_tcp(metrics_cfg.listen, cfg.reuse_port)
            .with_context(|| format!("cannot bind metrics on {}", metrics_cfg.listen))?;
        let path = std::env::temp_dir().join(format!(
            "elira-metrics-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|delta| delta.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        let socket = tokio::net::UnixDatagram::bind(&path)
            .with_context(|| format!("cannot bind {}", path.display()))?;
        let aggregate = Arc::new(Metrics::new());
        let statuses: StatusMap = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let gauges: WorkerGauges =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        gauge_state = Some((aggregate.clone(), gauges.clone()));
        spawn_metrics_receiver(socket, aggregate.clone(), statuses.clone(), gauges);
        let auth = match &metrics_cfg.auth_file {
            Some(path) => Some(Arc::new(elira_auth::BasicAuth::from_file(path)?)),
            None => None,
        };
        server::spawn_metrics_aggregate(listener, aggregate, statuses, auth, admin_tx.clone());
        metrics_socket = Some(path);
    }
    if let Some(path) = &metrics_socket {
        std::env::set_var("ELIRA_METRICS_SOCKET", path);
    }

    let pids: Arc<std::sync::Mutex<Vec<u32>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    if let Some(tls) = &cfg.tls {
        if let (Some(hook), Some(_)) = (&tls.ocsp_hook, &tls.ocsp) {
            let hook = hook.clone();
            let pids = pids.clone();
            let interval = tls.ocsp_refresh_secs;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    run_ocsp_hook(&hook).await;
                    let pids = pids
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    for pid in pids {
                        kill(pid, libc::SIGHUP);
                    }
                    tracing::info!("ocsp hook finished, reloading workers");
                }
            });
        }
    }

    for index in 0..workers {
        let slot = spawn_worker(index, &config)?;
        watch_worker(index, &slot, exit_tx.clone());
        pids.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(slot.pid);
        slots.push(slot);
    }

    for slot in &slots {
        wait_worker_ready(slot)
            .await
            .with_context(|| format!("worker {} did not become ready", slot.pid))?;
    }
    notify_ready();
    tracing::info!(workers, "supervisor is ready");

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            Some(command) = admin_rx.recv() => match command {
                server::AdminCommand::Drain => break,
                server::AdminCommand::Reload => {
                    for slot in &slots {
                        kill(slot.pid, libc::SIGHUP);
                    }
                    tracing::info!("admin reload sent SIGHUP to every worker");
                }
                server::AdminCommand::Purge(prefix) => {
                    let socket = tokio::net::UnixDatagram::unbound();
                    if let Ok(socket) = socket {
                        let message = serde_json::json!({ "purge": prefix }).to_string();
                        for slot in &slots {
                            if socket
                                .send_to(message.as_bytes(), &slot.control)
                                .await
                                .is_err()
                            {
                                tracing::warn!(worker = slot.pid, "cache purge was not delivered");
                            }
                        }
                    }
                }
            },
            _ = sighup.recv() => {
                for slot in &slots {
                    kill(slot.pid, libc::SIGHUP);
                }
                match Config::load(&config) {
                    Ok(next) if next.workers > slots.len() => {
                        let extra = next.workers - slots.len();
                        for _ in 0..extra {
                            let index = slots.len();
                            let slot = spawn_worker(index, &config)?;
                            watch_worker(index, &slot, exit_tx.clone());
                            pids
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .push(slot.pid);
                            slots.push(slot);
                            wait_worker_ready(&slots[index]).await?;
                            tracing::info!(worker = index, "added a worker on reload");
                        }
                    }
                    Ok(next) if next.workers < slots.len() => {
                        tracing::warn!(
                            "reducing worker count needs a restart; keeping {} workers",
                            slots.len()
                        );
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!(error = %err, "cannot read the config for worker scaling");
                    }
                }
                tracing::info!("sent SIGHUP to every worker");
            }
            _ = sigusr2.recv() => {
                tracing::info!("rolling restart of all workers");
                for index in 0..slots.len() {
                    kill(slots[index].pid, libc::SIGTERM);
                    wait_for_exit(&mut exit_rx, index, &mut slots, &config, &exit_tx).await?;
                }
            }
            Some((index, status)) = exit_rx.recv() => {
                if !status.success() {
                    tracing::error!(worker = index, %status, "worker exited, restarting it");
                } else {
                    tracing::warn!(worker = index, %status, "worker exited, restarting it");
                }
                if let Some((aggregate, gauges)) = &gauge_state {
                    remove_worker_gauges(aggregate, gauges, index);
                }
                let slot = spawn_worker(index, &config)?;
                watch_worker(index, &slot, exit_tx.clone());
                {
                    let mut pids = pids
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Some(entry) = pids.get_mut(index) {
                        *entry = slot.pid;
                    }
                }
                slots[index] = slot;
                wait_worker_ready(&slots[index]).await?;
            }
        }
    }

    if let Some(path) = &metrics_socket {
        std::env::remove_var("ELIRA_METRICS_SOCKET");
        let _ = std::fs::remove_file(path);
    }

    for slot in &slots {
        let _ = std::fs::remove_file(&slot.control);
    }

    tracing::info!("stopping workers");
    for slot in &slots {
        kill(slot.pid, libc::SIGTERM);
    }
    let drain = async {
        for _ in 0..slots.len() {
            if exit_rx.recv().await.is_none() {
                break;
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(15), drain)
        .await
        .is_err()
    {
        for slot in &slots {
            kill(slot.pid, libc::SIGKILL);
        }
    }

    Ok(())
}

fn spawn_control_socket(path: PathBuf, runtime: Arc<ArcSwap<Runtime>>) {
    tokio::spawn(async move {
        let _ = std::fs::remove_file(&path);
        let Ok(socket) = tokio::net::UnixDatagram::bind(&path) else {
            tracing::warn!(path = %path.display(), "cannot bind the control socket");
            return;
        };
        let mut buffer = [0u8; 4096];
        loop {
            let Ok(read) = socket.recv(&mut buffer).await else {
                break;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&buffer[..read]) else {
                continue;
            };
            if let Some(prefix) = value.get("purge").and_then(|value| value.as_str()) {
                let removed = runtime.load().proxy().purge_cache_prefix(prefix);
                tracing::info!(removed, "purged the cache prefix");
            }
        }
        let _ = std::fs::remove_file(&path);
    });
}

fn spawn_metrics_sender(
    metrics: Arc<Metrics>,
    runtime: Arc<ArcSwap<Runtime>>,
    path: PathBuf,
    worker: usize,
) {
    tokio::spawn(async move {
        let socket = match tokio::net::UnixDatagram::unbound() {
            Ok(socket) => socket,
            Err(error) => {
                tracing::warn!(%error, "cannot create the metrics socket");
                return;
            }
        };
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let delta = metrics.take_delta();
            let status = runtime.load().proxy().status();
            let message = serde_json::json!({
                "worker": worker,
                "delta": delta,
                "status": status,
            });
            if socket
                .send_to(message.to_string().as_bytes(), &path)
                .await
                .is_err()
            {
                tracing::debug!("metrics supervisor is not reachable");
            }
        }
    });
}

fn spawn_metrics_receiver(
    socket: tokio::net::UnixDatagram,
    aggregate: Arc<Metrics>,
    statuses: StatusMap,
    gauges: WorkerGauges,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let Ok(read) = socket.recv(&mut buf).await else {
                break;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&buf[..read]) else {
                continue;
            };
            let worker = value
                .get("worker")
                .and_then(|value| value.as_u64())
                .unwrap_or(0) as usize;
            if let Some(delta) = value.get("delta") {
                if let Ok(delta) = serde_json::from_value::<elira_metrics::Delta>(delta.clone()) {
                    aggregate.apply_counters(&delta);
                    let mut gauges = gauges
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    gauges.insert(
                        worker,
                        (
                            delta.connections_in_flight,
                            delta.upstreams_up,
                            delta.upstreams_down,
                        ),
                    );
                    let mut total = elira_metrics::Delta::default();
                    for (connections, up, down) in gauges.values() {
                        total.connections_in_flight += connections;
                        total.upstreams_up += up;
                        total.upstreams_down += down;
                    }
                    aggregate.apply_gauges(&total);
                }
            }
            if let Some(status) = value.get("status") {
                let mut statuses = statuses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                statuses.insert(worker, status.to_string());
            }
        }
    });
}

fn remove_worker_gauges(aggregate: &Metrics, gauges: &WorkerGauges, index: usize) {
    let mut gauges = gauges
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    gauges.remove(&index);
    let mut total = elira_metrics::Delta::default();
    for (connections, up, down) in gauges.values() {
        total.connections_in_flight += connections;
        total.upstreams_up += up;
        total.upstreams_down += down;
    }
    aggregate.apply_gauges(&total);
}

fn spawn_worker(index: usize, config: &Path) -> anyhow::Result<WorkerSlot> {
    let exe = std::env::current_exe().context("cannot find the executable")?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let ready = std::env::temp_dir().join(format!(
        "elira-worker-{}-{index}-{stamp}.ready",
        std::process::id()
    ));
    let control = std::env::temp_dir().join(format!(
        "elira-control-{}-{index}-{stamp}.sock",
        std::process::id()
    ));

    let child = tokio::process::Command::new(exe)
        .args(["run", "--config"])
        .arg(config)
        .env("ELIRA_WORKER", "1")
        .env("ELIRA_WORKER_INDEX", index.to_string())
        .env("ELIRA_CONTROL_SOCKET", &control)
        .env("ELIRA_READY_FILE", &ready)
        .spawn()
        .with_context(|| format!("cannot start worker {index}"))?;

    Ok(WorkerSlot {
        pid: child.id().context("worker has no pid")?,
        ready,
        control,
    })
}

fn watch_worker(
    index: usize,
    slot: &WorkerSlot,
    exit: tokio::sync::mpsc::Sender<(usize, std::process::ExitStatus)>,
) {
    // Reap the child in a task. The pid is still valid for signals until then.
    let pid = slot.pid as libc::pid_t;
    tokio::spawn(async move {
        let status = wait_pid(pid).await;
        let _ = exit.send((index, status)).await;
    });
}

async fn wait_pid(pid: libc::pid_t) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return std::process::ExitStatus::from_raw(status);
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return std::process::ExitStatus::from_raw(0);
        }
    }
}

async fn wait_worker_ready(slot: &WorkerSlot) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if slot.ready.exists() {
            let _ = std::fs::remove_file(&slot.ready);
            return Ok(());
        }
        if unsafe { libc::kill(slot.pid as libc::pid_t, 0) } != 0 {
            anyhow::bail!("worker {} exited before becoming ready", slot.pid);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("worker {} readiness timed out", slot.pid);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_exit(
    exits: &mut tokio::sync::mpsc::Receiver<(usize, std::process::ExitStatus)>,
    wanted: usize,
    slots: &mut [WorkerSlot],
    config: &Path,
    exit_tx: &tokio::sync::mpsc::Sender<(usize, std::process::ExitStatus)>,
) -> anyhow::Result<()> {
    loop {
        let Some((index, _)) = exits.recv().await else {
            return Ok(());
        };
        let slot = spawn_worker(index, config)?;
        watch_worker(index, &slot, exit_tx.clone());
        slots[index] = slot;
        wait_worker_ready(&slots[index]).await?;
        if index == wanted {
            return Ok(());
        }
    }
}

fn kill(pid: u32, signal: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
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

    // A worker is not the main PID; the supervisor owns the systemd socket.
    if std::env::var_os("ELIRA_WORKER").is_some() {
        return;
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
