use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use elira::config::Config;
use elira::server::{self, Options, Runtime};
use elira_metrics::Metrics;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const CAP_NET_BIND_SERVICE: u32 = 10;

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
// SAFETY: `capset` is part of the Linux UAPI; `CapHeader`/`CapData` reproduce the
// `_LINUX_CAPABILITY_*` layout used by the kernel.
extern "C" {
    fn capset(header: *const CapHeader, data: *const CapData) -> i32;
}

fn chown_runtime_dir(uid: u32, gid: u32) {
    let dir = runtime_dir();
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return;
    };
    // SAFETY: `path` is a valid NUL-terminated C string for the duration of the call.
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
        tracing::debug!(dir = %dir.display(), "cannot chown runtime dir");
    }
}

fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("ELIRA_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        return dir;
    }
    // SAFETY: `getuid` has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let run = PathBuf::from("/run").join(format!("elira-{uid}"));
    if std::fs::create_dir_all(&run).is_ok() {
        let _ = std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700));
        return run;
    }
    let dir = std::env::temp_dir().join(format!("elira-{uid}"));
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    dir
}

#[derive(Parser)]
#[command(name = "elira", version, about = "HTTP server and reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(short, long, default_value = "elira.toml")]
        config: PathBuf,
    },

    Check {
        #[arg(short, long, default_value = "elira.toml")]
        config: PathBuf,
    },

    #[command(hide = true)]
    ModuleWorker { module: PathBuf },

    Migrate {
        input: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn check_secret_permissions(cfg: &Config, config: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = vec![config.to_path_buf()];
    for route in &cfg.routes {
        if let Some(path) = &route.auth_file {
            paths.push(path.clone());
        }
    }
    if let Some(metrics) = &cfg.metrics {
        if let Some(path) = &metrics.auth_file {
            paths.push(path.clone());
        }
    }

    let mut warnings = Vec::new();
    for path in paths {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.mode() & 0o077 != 0 {
            warnings.push(format!(
                "{} is readable by group or others (mode {:04o}); secrets should be 0600 or 0640",
                path.display(),
                meta.mode() & 0o7777
            ));
        }
    }
    warnings
}

fn worker_scope() -> Option<(usize, usize)> {
    let index = std::env::var("ELIRA_WORKER_INDEX").ok()?.parse().ok()?;
    let workers = std::env::var("ELIRA_WORKERS").ok()?.parse().ok()?;
    Some((index, workers))
}

fn share_limit(value: usize, workers: usize, index: usize) -> usize {
    let base = value / workers;
    let remainder = value % workers;
    (base + usize::from(index < remainder)).max(1)
}

fn apply_shared_limits(cfg: &mut Config, workers: usize, index: usize) {
    if !cfg.limits.shared_limits || workers <= 1 {
        return;
    }
    let share = |value| share_limit(value, workers, index);
    cfg.limits.max_connections = share(cfg.limits.max_connections);
    if cfg.limits.limit_conn_per_ip > 0 {
        cfg.limits.limit_conn_per_ip = share(cfg.limits.limit_conn_per_ip);
    }
    if cfg.limits.requests_per_second > 0 {
        cfg.limits.requests_per_second = share(cfg.limits.requests_per_second as usize) as u32;
    }
    if cfg.limits.burst > 0 {
        cfg.limits.burst = share(cfg.limits.burst as usize) as u32;
    }
    for route in &mut cfg.routes {
        if let Some(rate) = route.requests_per_second {
            route.requests_per_second = Some(share(rate as usize) as u32);
        }
        if let Some(burst) = route.burst {
            route.burst = Some(share(burst as usize) as u32);
        }
        if let Some(limit) = route.limit_conn {
            route.limit_conn = Some(share(limit as usize) as u32);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match Cli::parse().command {
        Command::Check { config } => {
            let cfg = Config::load(&config)?;
            for warning in check_secret_permissions(&cfg, &config) {
                eprintln!("warning: {warning}");
            }
            if cfg.proxy_protocol && cfg.proxy_protocol_trusted.is_empty() {
                eprintln!(
                    "warning: proxy_protocol is enabled without proxy_protocol_trusted; any direct client can spoof its address"
                );
            }
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
            let cpus = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1);
            let threads = if cfg.workers > 1 {
                (cpus / cfg.workers).max(1)
            } else {
                cpus
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .context("cannot build the tokio runtime")?;

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
    let mut cfg = Config::load(&path)?;
    if let Some((index, workers)) = worker_scope() {
        apply_shared_limits(&mut cfg, workers, index);
    }
    if std::env::var_os("ELIRA_WORKER").is_none() {
        for warning in check_secret_permissions(&cfg, &path) {
            tracing::warn!("{warning}");
        }
        if cfg.proxy_protocol && cfg.proxy_protocol_trusted.is_empty() {
            tracing::warn!(
                "proxy_protocol is enabled without proxy_protocol_trusted; any direct client can spoof its address"
            );
        }
    }
    let _pid_guard = if std::env::var_os("ELIRA_WORKER").is_none() {
        match &cfg.pid_file {
            Some(path) => Some(write_pid_file(path)?),
            None => None,
        }
    } else {
        None
    };
    apply_chroot(&cfg)?;
    if let Some(user) = &cfg.user {
        if let Ok((uid, gid)) = resolve_user(user) {
            chown_runtime_dir(uid, gid);
        }
    }
    apply_privileges_mode(&cfg, true)?;
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
    let (reopen_tx, mut reopen_rx) = watch::channel(0u64);

    spawn_signal_task(stop_tx.clone(), reload_tx.clone(), restart_tx, reopen_tx)?;
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
        cfg.proxy_protocol_trusted.clone(),
    );
    let mut stop_wait = stop_rx.clone();

    let unix_serving = match &cfg.listen_unix {
        Some(path) => {
            let listener = server::bind_unix(path)
                .with_context(|| format!("cannot bind unix socket {}", path.display()))?;
            server::configure_unix(path, cfg.listen_unix_mode, cfg.listen_unix_owner.as_deref())
                .with_context(|| format!("cannot configure unix socket {}", path.display()))?;
            tracing::info!(path = %path.display(), "listening on a unix socket");
            let mut unix_options = options.clone();
            unix_options.name = "unix".to_owned();
            Some(tokio::spawn(server::serve_unix(
                listener,
                runtime.clone(),
                unix_options,
                metrics.clone(),
                stop_rx.clone(),
            )))
        }
        None => None,
    };

    let mut stream_bounds = Vec::new();
    for stream in &cfg.streams {
        stream_bounds.push(
            elira::stream::bind(stream)
                .await
                .with_context(|| format!("cannot bind stream listener {}", stream.listen))?,
        );
        tracing::info!(listen = %stream.listen, transport = ?stream.transport, "stream listener");
    }

    apply_cpu_affinity(&cfg)?;
    if std::env::var_os("ELIRA_WORKER").is_none() {
        if let Some(hook) = cfg.tls.as_ref().and_then(|tls| tls.ocsp_hook.as_ref()) {
            run_ocsp_hook(hook).await;
        }
    }

    let mut stream_serving = Vec::new();
    for bound in stream_bounds {
        stream_serving.push(elira::stream::spawn(
            bound,
            runtime.clone(),
            cfg.limits.max_connections,
            metrics.clone(),
            stop_rx.clone(),
        ));
    }

    let mut serving = Vec::new();
    serving.push(tokio::spawn(server::serve(
        listener,
        runtime.clone(),
        options.clone(),
        metrics.clone(),
        stop_rx.clone(),
    )));
    for (index, entry) in cfg.listeners.iter().enumerate() {
        let listener = server::bind_tcp(entry.listen, cfg.reuse_port)
            .with_context(|| format!("cannot bind {}", entry.listen))?;
        let mut listener_options = options.clone();
        listener_options.tls = entry.tls;
        listener_options.name = entry
            .name
            .clone()
            .unwrap_or_else(|| format!("listener-{index}"));
        tracing::info!(listen = %entry.listen, tls = entry.tls, name = %listener_options.name, "additional listener");
        serving.push(tokio::spawn(server::serve(
            listener,
            runtime.clone(),
            listener_options,
            metrics.clone(),
            stop_rx.clone(),
        )));
    }

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

            changed = reopen_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                runtime.load().reopen_logs();
                tracing::info!("access log reopened");
            }
            changed = reload_rx.changed() => {
                if changed.is_err() {
                    break;
                }

                let before = h3_identity(runtime.load().http3());
                reload(&path, &cfg, &runtime, options.clone(), &metrics).await;
                let after = h3_identity(runtime.load().http3());




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
                        cfg.proxy_protocol_trusted.clone(),
                    );
                }
            }
        }
    }

    tracing::info!("shutting down");
    let _ = stop_tx.send(true);

    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(cfg.limits.shutdown_timeout_secs);
    for task in serving {
        if tokio::time::timeout_at(deadline, task).await.is_err() {
            tracing::warn!("server did not stop in time");
            break;
        }
    }
    for task in stream_serving {
        if tokio::time::timeout_at(deadline, task).await.is_err() {
            tracing::warn!("stream listener did not stop in time");
            break;
        }
    }
    if let Some(task) = unix_serving {
        if tokio::time::timeout(Duration::from_secs(cfg.limits.shutdown_timeout_secs), task)
            .await
            .is_err()
        {
            tracing::warn!("unix listener did not stop in time");
        }
    }

    if let Some(mut handle) = h3_task.take() {
        if tokio::time::timeout(
            Duration::from_secs(cfg.limits.shutdown_timeout_secs),
            &mut handle,
        )
        .await
        .is_err()
        {
            tracing::warn!("http/3 listener did not stop in time");
            handle.abort();
        }
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

struct PidFile(PathBuf);

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Ok(current) = std::fs::read_to_string(&self.0) {
            if current.trim() == std::process::id().to_string() {
                let _ = std::fs::remove_file(&self.0);
            }
        }
    }
}

fn write_pid_file(path: &Path) -> anyhow::Result<PidFile> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "elira.pid".to_owned());
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let temp = dir.join(format!(".{name}.{}-{stamp}.tmp", std::process::id()));

    let result = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&temp)
            .with_context(|| format!("cannot write pid file {}", path.display()))?;
        file.write_all(format!("{}\n", std::process::id()).as_bytes())
            .with_context(|| format!("cannot write pid file {}", path.display()))?;
        let _ = file.sync_all();
        std::fs::rename(&temp, path)
            .with_context(|| format!("cannot write pid file {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    Ok(PidFile(path.to_path_buf()))
}

fn bind_unix_datagram(path: &Path) -> std::io::Result<tokio::net::UnixDatagram> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let temp = dir.join(format!(".elira-sock-{}-{stamp}", std::process::id()));
    let socket = tokio::net::UnixDatagram::bind(&temp)?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    Ok(socket)
}

fn resolve_user(value: &str) -> anyhow::Result<(u32, u32)> {
    if let Some((uid, gid)) = value.split_once(':') {
        let uid: u32 = uid
            .parse()
            .map_err(|_| anyhow::anyhow!("bad uid in {value:?}"))?;
        let gid: u32 = gid
            .parse()
            .map_err(|_| anyhow::anyhow!("bad gid in {value:?}"))?;
        return Ok((uid, gid));
    }

    let name = std::ffi::CString::new(value)
        .map_err(|_| anyhow::anyhow!("user name contains a NUL byte"))?;
    // SAFETY: `libc::passwd` is a plain C struct for which an all-zero bit pattern is
    // valid; `getpwnam_r` overwrites it before we read its fields.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: `name` is NUL-terminated, `buffer` and `entry` are writable for the sizes
    // passed, and `result` points to a valid local. The call does not retain any pointer.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        bail!("unknown user {value:?}");
    }
    Ok((entry.pw_uid, entry.pw_gid))
}

fn apply_rlimit(limit: Option<u64>) -> anyhow::Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let limits = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    // SAFETY: `limits` is a fully initialized `rlimit` and `RLIMIT_NOFILE` is a valid
    // resource selector for the current process.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
        bail!(
            "cannot raise RLIMIT_NOFILE to {limit}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn apply_cpu_affinity(cfg: &Config) -> anyhow::Result<()> {
    let Some(cpus) = &cfg.worker_cpu_affinity else {
        return Ok(());
    };
    let index = std::env::var("ELIRA_WORKER_INDEX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let cpu = cpus[index % cpus.len()];

    // SAFETY: an all-zero `cpu_set_t` is a valid empty CPU set; the macros below only
    // write within that initialized value.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid CPU-set pointer and `cpu` was validated against the
    // configured list before this point.
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    // SAFETY: the size matches `cpu_set_t`, `set` is initialized, and PID 0 means the
    // current process.
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) } != 0 {
        bail!(
            "cannot bind worker to CPU {cpu}: {}",
            std::io::Error::last_os_error()
        );
    }
    tracing::info!(cpu, "bound worker to CPU");
    Ok(())
}

fn apply_chroot(cfg: &Config) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let Some(root) = &cfg.chroot else {
        return Ok(());
    };
    let path = std::ffi::CString::new(root.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("chroot path contains a NUL byte"))?;

    // SAFETY: `path` is a valid NUL-terminated C string. After a successful call the
    // process is confined to the new root; the following `chdir` uses a relative path.
    if unsafe { libc::chroot(path.as_ptr()) } != 0 {
        bail!(
            "chroot {}: {}",
            root.display(),
            std::io::Error::last_os_error()
        );
    }
    std::env::set_current_dir("/").context("chdir after chroot")?;
    tracing::info!(root = %root.display(), "entered chroot");
    Ok(())
}

fn apply_privileges_mode(cfg: &Config, keep_bind: bool) -> anyhow::Result<()> {
    apply_rlimit(cfg.worker_rlimit_nofile)?;

    let Some(user) = &cfg.user else {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            tracing::warn!("running as root without user; set user or drop privileges");
        }
        return Ok(());
    };
    let (uid, gid) = resolve_user(user)?;

    // SAFETY: `geteuid`, `getuid` and `getgid` are parameterless POSIX calls.
    let root = unsafe { libc::geteuid() } == 0;
    if !root {
        if unsafe { libc::getuid() } == uid && unsafe { libc::getgid() } == gid {
            return Ok(());
        }
        bail!("only root can switch to user {user:?}");
    }

    #[cfg(target_os = "linux")]
    // SAFETY: `PR_SET_KEEPCAPS` takes the scalar value 1 and ignores the remaining
    // arguments; no pointers are involved.
    if keep_bind && unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
        bail!("prctl keepcaps: {}", std::io::Error::last_os_error());
    }

    // SAFETY: a zero-length group list with a null pointer is the documented way to
    // clear supplementary groups; `uid`/`gid` come from the resolved passwd entry.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        bail!("setgroups: {}", std::io::Error::last_os_error());
    }
    // SAFETY: setgid/setuid take plain numeric IDs and only affect the current process.
    if unsafe { libc::setgid(gid) } != 0 {
        bail!("setgid({gid}): {}", std::io::Error::last_os_error());
    }
    // SAFETY: see the setgid comment above.
    if unsafe { libc::setuid(uid) } != 0 {
        bail!("setuid({uid}): {}", std::io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    if keep_bind {
        retain_bind_capability()?;
    }
    #[cfg(not(target_os = "linux"))]
    if keep_bind {
        tracing::warn!("cannot retain CAP_NET_BIND_SERVICE on this platform");
    }

    tracing::info!(user, uid, gid, keep_bind, "dropped privileges");
    Ok(())
}

#[cfg(target_os = "linux")]
fn retain_bind_capability() -> anyhow::Result<()> {
    let word = (CAP_NET_BIND_SERVICE / 32) as usize;
    let bit = 1u32 << (CAP_NET_BIND_SERVICE % 32);
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    data[word].effective |= bit;
    data[word].permitted |= bit;
    data[word].inheritable |= bit;
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    // SAFETY: `header` and the two-element `data` array match the Linux `capset` ABI
    // (`_LINUX_CAPABILITY_VERSION_3`); the kernel copies the data before returning.
    if unsafe { capset(&header, data.as_ptr()) } != 0 {
        bail!("capset: {}", std::io::Error::last_os_error());
    }
    // SAFETY: `PR_CAP_AMBIENT_RAISE` takes a capability number and integer flags; no
    // pointers are passed and the capability is already in the permitted set.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE,
            CAP_NET_BIND_SERVICE as libc::c_ulong,
            0,
            0,
        )
    } != 0
    {
        bail!(
            "prctl ambient capability: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
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
    proxy_protocol_trusted: Vec<String>,
) -> Option<tokio::task::JoinHandle<()>> {
    let current = runtime.load();
    let http3 = current.http3().cloned()?;
    let max_header_bytes = current.config().limits.max_header_bytes;
    let max_headers_for_h3 = current.config().limits.max_headers;
    let max_connections_for_h3 = current.config().limits.max_connections;
    drop(current);

    let proxy_runtime = runtime.clone();
    let proxy: Arc<dyn Fn() -> elira_proxy::Proxy + Send + Sync> =
        Arc::new(move || proxy_runtime.load().proxy().clone());

    let client_auth = match http3.client_auth {
        elira::config::ClientAuthMode::Off => elira_tls::ClientAuth::Off,
        elira::config::ClientAuthMode::Optional => elira_tls::ClientAuth::Optional,
        elira::config::ClientAuthMode::Required => elira_tls::ClientAuth::Required,
    };

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
            client_crl: http3.client_crl,
            client_auth,
            cipher_suites: http3.cipher_suites,
            curves: http3.curves,
            ticket_key: http3.ticket_key,
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
            max_concurrent_bidi_streams: http3.max_concurrent_bidi_streams,
            stream_receive_window: http3.stream_receive_window,
            receive_window: http3.receive_window,
            send_window: http3.send_window,
            reject_unknown_sni: http3.reject_unknown_sni,
            max_header_bytes,
            max_headers: max_headers_for_h3,
            max_connections: max_connections_for_h3,
            proxy_protocol,
            proxy_protocol_trusted,
        };
        if let Err(err) = elira_h3::serve(cfg, proxy, metrics, body_timeout, log, stop).await {
            tracing::error!(error = %err, "http/3 listener stopped");
        }
    }))
}

#[derive(Debug, PartialEq, Eq)]
struct H3Identity {
    config: elira::config::Http3,
    file_stamps: Vec<u64>,
}

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
    let mut paths = vec![&http3.cert, &http3.key];
    paths.extend(http3.client_ca.as_ref());
    paths.extend(http3.client_crl.as_ref());
    paths.extend(http3.ticket_key.as_ref());
    for entry in &http3.certificates {
        paths.push(&entry.cert);
        paths.push(&entry.key);
        paths.extend(entry.ocsp.as_ref());
    }
    let file_stamps = paths.into_iter().map(|path| stamp(path)).collect();
    Some(H3Identity {
        config: http3.clone(),
        file_stamps,
    })
}

async fn reload(
    path: &Path,
    current: &Config,
    runtime: &ArcSwap<Runtime>,
    options: Options,
    metrics: &Metrics,
) {
    let mut next = match Config::load(path) {
        Ok(next) => next,
        Err(err) => {
            tracing::error!(error = %err, "reload failed, keeping the old config");
            metrics.reload_failed();
            return;
        }
    };

    if let Some((index, workers)) = worker_scope() {
        apply_shared_limits(&mut next, workers, index);
    }

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

    let previous = runtime.load();
    let built = match Runtime::build_with_previous(&next, Some(&previous)) {
        Ok(built) => built,
        Err(err) => {
            tracing::error!(error = %err, "reload failed, keeping the old config");
            metrics.reload_failed();
            return;
        }
    };

    drop(previous);

    if built.health().enabled {
        built.proxy().check_health(built.health()).await;
    }

    runtime.store(Arc::new(built));
    record_certificate_expiry(&next, metrics);
    metrics.reload_ok();
    tracing::info!("config reloaded");
}

fn update_config_json(target: &std::sync::Mutex<String>, config: &Config) {
    *target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = server::redacted_config_json(config);
}

struct WorkerSlot {
    pid: u32,
    ready: PathBuf,
    control: PathBuf,
}

struct ChildGuard {
    pids: Arc<std::sync::Mutex<Vec<u32>>>,
    armed: bool,
}

impl ChildGuard {
    fn new(pids: Arc<std::sync::Mutex<Vec<u32>>>) -> Self {
        Self { pids, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let pids = self
            .pids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for pid in pids {
            kill(pid, libc::SIGKILL);
        }
    }
}

type StatusMap = Arc<std::sync::Mutex<std::collections::HashMap<usize, String>>>;
type WorkerGauges = Arc<std::sync::Mutex<std::collections::HashMap<usize, (u64, u64, u64)>>>;

async fn supervise(config: PathBuf, workers: usize) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::sync::mpsc;

    let cfg = Config::load(&config)?;
    for warning in check_secret_permissions(&cfg, &config) {
        tracing::warn!("{warning}");
    }
    if cfg.proxy_protocol && cfg.proxy_protocol_trusted.is_empty() {
        tracing::warn!(
            "proxy_protocol is enabled without proxy_protocol_trusted; any direct client can spoof its address"
        );
    }
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 && cfg.user.is_none() {
        tracing::warn!("supervisor runs as root without user; set user or drop privileges");
    }
    if let Some(user) = &cfg.user {
        if let Ok((uid, gid)) = resolve_user(user) {
            chown_runtime_dir(uid, gid);
        }
    }
    let _pid_guard = match &cfg.pid_file {
        Some(path) => Some(write_pid_file(path)?),
        None => None,
    };
    apply_rlimit(cfg.worker_rlimit_nofile)?;
    let (exit_tx, mut exit_rx) = mpsc::channel::<(usize, std::process::ExitStatus)>(64);
    let (admin_tx, mut admin_rx) = mpsc::channel::<server::AdminCommand>(8);
    let mut slots = Vec::with_capacity(workers);

    let mut metrics_socket = None;
    let mut gauge_state: Option<(Arc<Metrics>, WorkerGauges)> = None;
    let config_json = Arc::new(std::sync::Mutex::new(server::redacted_config_json(&cfg)));
    if let Some(metrics_cfg) = cfg.metrics.as_ref() {
        let listener = server::bind_tcp(metrics_cfg.listen, cfg.reuse_port)
            .with_context(|| format!("cannot bind metrics on {}", metrics_cfg.listen))?;
        let path = runtime_dir().join(format!(
            "elira-metrics-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|delta| delta.as_nanos())
                .unwrap_or(0)
        ));
        let socket =
            bind_unix_datagram(&path).with_context(|| format!("cannot bind {}", path.display()))?;
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
        server::spawn_metrics_aggregate(
            listener,
            aggregate,
            statuses,
            config_json.clone(),
            auth,
            admin_tx.clone(),
        );
        metrics_socket = Some(path);
    }

    let pids: Arc<std::sync::Mutex<Vec<u32>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut children = ChildGuard::new(pids.clone());
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
        let slot = spawn_worker(index, workers, &config, metrics_socket.as_deref())?;
        watch_worker(index, &slot, exit_tx.clone());
        pids.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(slot.pid);
        slots.push(slot);
    }

    for slot in &slots {
        if let Err(err) = wait_worker_ready(slot).await {
            for slot in &slots {
                kill(slot.pid, libc::SIGTERM);
            }
            return Err(err).with_context(|| format!("worker {} did not become ready", slot.pid));
        }
    }
    if let Err(err) = apply_privileges_mode(&cfg, true) {
        for slot in &slots {
            kill(slot.pid, libc::SIGTERM);
        }
        return Err(err);
    }
    if let Some(hook) = cfg.tls.as_ref().and_then(|tls| tls.ocsp_hook.as_ref()) {
        run_ocsp_hook(hook).await;
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
                    if let Ok(next) = Config::load(&config) {
                        update_config_json(&config_json, &next);
                    }
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
                server::AdminCommand::PurgeTag(tag) => {
                    let socket = tokio::net::UnixDatagram::unbound();
                    if let Ok(socket) = socket {
                        let message = serde_json::json!({ "purge_tag": tag }).to_string();
                        for slot in &slots {
                            if socket
                                .send_to(message.as_bytes(), &slot.control)
                                .await
                                .is_err()
                            {
                                tracing::warn!(worker = slot.pid, "cache purge tag was not delivered");
                            }
                        }
                    }
                }
                server::AdminCommand::Weight {
                    upstream,
                    index,
                    weight,
                } => {
                    let socket = tokio::net::UnixDatagram::unbound();
                    if let Ok(socket) = socket {
                        let message = serde_json::json!({
                            "weight": {
                                "upstream": upstream,
                                "index": index,
                                "weight": weight,
                            }
                        })
                        .to_string();
                        for slot in &slots {
                            if socket
                                .send_to(message.as_bytes(), &slot.control)
                                .await
                                .is_err()
                            {
                                tracing::warn!(worker = slot.pid, "weight update was not delivered");
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
                    Ok(next) => {
                        update_config_json(&config_json, &next);
                        if next.workers > slots.len() {
                            let extra = next.workers - slots.len();
                            for _ in 0..extra {
                                let index = slots.len();
                                let slot = spawn_worker(index, workers, &config, metrics_socket.as_deref())?;
                                watch_worker(index, &slot, exit_tx.clone());
                                pids
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .push(slot.pid);
                                slots.push(slot);
                                wait_worker_ready(&slots[index]).await?;
                                tracing::info!(worker = index, "added a worker on reload");
                            }
                        } else if next.workers < slots.len() {
                            tracing::warn!(
                                "reducing worker count needs a restart; keeping {} workers",
                                slots.len()
                            );
                        }
                    }
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
                    wait_for_exit(
                        &mut exit_rx,
                        index,
                        &mut slots,
                        &config,
                        metrics_socket.as_deref(),
                        &exit_tx,
                    )
                    .await?;
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
                let slot = spawn_worker(index, workers, &config, metrics_socket.as_deref())?;
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

    children.disarm();
    Ok(())
}

fn spawn_control_socket(path: PathBuf, runtime: Arc<ArcSwap<Runtime>>) {
    tokio::spawn(async move {
        let Ok(socket) = bind_unix_datagram(&path) else {
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
            } else if let Some(tag) = value.get("purge_tag").and_then(|value| value.as_str()) {
                let removed = runtime.load().proxy().purge_cache_tag(tag);
                tracing::info!(removed, "purged the cache tag");
            } else if let Some(weight) = value.get("weight") {
                let upstream = weight
                    .get("upstream")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let index = weight
                    .get("index")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0) as usize;
                let weight = weight
                    .get("weight")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(1) as u32;
                let updated = runtime
                    .load()
                    .proxy()
                    .set_upstream_weight(upstream, index, weight);
                tracing::info!(updated, upstream, index, weight, "updated upstream weight");
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

fn spawn_worker(
    index: usize,
    workers: usize,
    config: &Path,
    metrics_socket: Option<&Path>,
) -> anyhow::Result<WorkerSlot> {
    let exe = std::env::current_exe().context("cannot find the executable")?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let ready = runtime_dir().join(format!(
        "elira-worker-{}-{index}-{stamp}.ready",
        std::process::id()
    ));
    let control = runtime_dir().join(format!(
        "elira-control-{}-{index}-{stamp}.sock",
        std::process::id()
    ));

    let mut command = tokio::process::Command::new(exe);
    command
        .args(["run", "--config"])
        .arg(config)
        .env("ELIRA_WORKER", "1")
        .env("ELIRA_WORKER_INDEX", index.to_string())
        .env("ELIRA_WORKERS", workers.to_string())
        .env("ELIRA_CONTROL_SOCKET", &control)
        .env("ELIRA_READY_FILE", &ready);
    if let Some(metrics_socket) = metrics_socket {
        command.env("ELIRA_METRICS_SOCKET", metrics_socket);
    }
    let child = command
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
    let pid = slot.pid as libc::pid_t;
    tokio::task::spawn_blocking(move || {
        let status = wait_pid(pid);
        let _ = exit.blocking_send((index, status));
    });
}

fn wait_pid(pid: libc::pid_t) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    loop {
        let mut status = 0;
        // SAFETY: `pid` is a child of this process and `status` points to a live local.
        // `waitpid` writes at most one `c_int` and does not retain the pointer.
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
        // SAFETY: signal 0 performs only an existence/permission check on the stored
        // child PID; it does not deliver a signal.
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
    metrics_socket: Option<&Path>,
    exit_tx: &tokio::sync::mpsc::Sender<(usize, std::process::ExitStatus)>,
) -> anyhow::Result<()> {
    loop {
        let Some((index, _)) = exits.recv().await else {
            return Ok(());
        };
        let slot = spawn_worker(index, wanted, config, metrics_socket)?;
        watch_worker(index, &slot, exit_tx.clone());
        slots[index] = slot;
        wait_worker_ready(&slots[index]).await?;
        if index == wanted {
            return Ok(());
        }
    }
}

fn kill(pid: u32, signal: libc::c_int) {
    // SAFETY: `pid` is a worker/supervisor PID recorded at spawn time; sending it a signal
    // is the intended shutdown mechanism. The return value is intentionally ignored.
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
}

fn spawn_replacement() -> bool {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            tracing::error!(error = %err, "cannot find the executable");
            return false;
        }
    };

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let ready = runtime_dir().join(format!(
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

fn notify_ready() {
    let pid = std::process::id();

    if let Ok(path) = std::env::var("ELIRA_READY_FILE") {
        let _ = std::fs::write(path, pid.to_string());
    }

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
    reopen: watch::Sender<u64>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut usr2 = signal(SignalKind::user_defined2())?;

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        let mut reload_seq = 0u64;
        let mut restart_seq = 0u64;
        let mut reopen_seq = 0u64;

        loop {
            tokio::select! {
                _ = &mut ctrl_c => { let _ = stop.send(true); return; }
                _ = term.recv() => { let _ = stop.send(true); return; }
                _ = hup.recv() => {
                    reload_seq += 1;
                    let _ = reload.send(reload_seq);
                }
                _ = usr1.recv() => {
                    reopen_seq += 1;
                    let _ = reopen.send(reopen_seq);
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
    _reopen: watch::Sender<u64>,
) -> anyhow::Result<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn shared_limits_are_split_between_workers() {
        let config = Config::parse(
            r#"
listen = "127.0.0.1:0"

[limits]
shared_limits = true
max_connections = 10
limit_conn_per_ip = 8
requests_per_second = 10
burst = 10

[[routes]]
host = "*"
return = { status = 200, body = "ok" }
requests_per_second = 7
burst = 9
limit_conn = 11
"#,
        )
        .expect("config");

        let mut totals = [0u32; 7];
        for index in 0..4 {
            let mut worker = config.clone();
            apply_shared_limits(&mut worker, 4, index);
            totals[0] += worker.limits.max_connections as u32;
            totals[1] += worker.limits.limit_conn_per_ip as u32;
            totals[2] += worker.limits.requests_per_second;
            totals[3] += worker.limits.burst;
            let route = &worker.routes[0];
            totals[4] += route.requests_per_second.expect("rate");
            totals[5] += route.burst.expect("burst");
            totals[6] += route.limit_conn.expect("limit_conn");
        }
        assert_eq!(totals, [10, 8, 10, 10, 7, 9, 11]);
    }

    #[test]
    fn h3_identity_tracks_files_and_transport() {
        let dir = std::env::temp_dir().join(format!("elira-h3-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let named_cert = dir.join("named.pem");
        let named_key = dir.join("named.key");
        for path in [&cert, &key, &named_cert, &named_key] {
            std::fs::write(path, "pem").expect("write");
        }
        let config = |timeout: u64| {
            format!(
                "listen = \"127.0.0.1:8080\"\n\n[[routes]]\nhost = \"*\"\n\
                 return = {{ status = 200, body = \"ok\" }}\n\n[http3]\nlisten = \"127.0.0.1:8443\"\n\
                 cert = \"{}\"\nkey = \"{}\"\nidle_timeout_secs = {timeout}\n\n\
                 [[http3.certificates]]\ncert = \"{}\"\nkey = \"{}\"\nnames = [\"other.local\"]\n",
                cert.display(),
                key.display(),
                named_cert.display(),
                named_key.display(),
            )
        };
        let first = Config::parse(&config(30)).expect("parse");
        let second = Config::parse(&config(60)).expect("parse");
        assert_ne!(
            h3_identity(first.http3.as_ref()),
            h3_identity(second.http3.as_ref())
        );

        let identity = h3_identity(first.http3.as_ref()).expect("identity");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&named_cert, "rotated").expect("rewrite");
        assert_ne!(
            identity,
            h3_identity(first.http3.as_ref()).expect("identity")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn warns_on_group_or_world_readable_secret_files() {
        let dir = std::env::temp_dir().join(format!("elira-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let config_path = dir.join("elira.toml");
        std::fs::write(
            &config_path,
            "listen = \"127.0.0.1:8080\"\n\n[[routes]]\nhost = \"*\"\nroot = \"/tmp\"\n",
        )
        .expect("write config");
        let cfg = Config::parse(&std::fs::read_to_string(&config_path).expect("read"))
            .expect("parse config");

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert!(!check_secret_permissions(&cfg, &config_path).is_empty());

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        assert!(check_secret_permissions(&cfg, &config_path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
