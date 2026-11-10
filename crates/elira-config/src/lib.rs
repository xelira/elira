//! Configuration and validation.
//!
//! Everything here is plain data plus checks. No sockets, no async.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

mod error;
mod load;
mod normalize;
mod types;
mod validate;
pub use error::*;
use load::load_value;
use normalize::expand_locations;
pub use types::*;

fn deserialize_workers<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Count(usize),
        Word(String),
    }

    match Value::deserialize(deserializer)? {
        Value::Count(count) => Ok(count),
        Value::Word(word) if word.eq_ignore_ascii_case("auto") => {
            Ok(std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
                .min(64))
        }
        Value::Word(word) => Err(serde::de::Error::custom(format!(
            "workers must be a number or \"auto\", got {word:?}"
        ))),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,

    /// Optional HTTP/1.1 listener on a unix socket.
    #[serde(default)]
    pub listen_unix: Option<PathBuf>,

    /// Terminate TLS on the unix socket using the `[tls]` settings.
    #[serde(default)]
    pub unix_tls: bool,

    /// Additional TCP listeners. The primary `listen` above stays bound.
    #[serde(default)]
    pub listeners: Vec<Listener>,

    /// Layer-4 TCP/UDP proxy listeners.
    #[serde(default)]
    pub streams: Vec<Stream>,

    /// Server-level path rewrites applied before route selection.
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,

    /// Named variables computed from one source variable and a value table.
    #[serde(default)]
    pub maps: Vec<Map>,

    /// Named variables matched against client IP networks.
    #[serde(default)]
    pub geos: Vec<Geo>,

    /// Named variables bucketed by a deterministic percentage split.
    #[serde(default)]
    pub splits: Vec<Split>,

    /// Permission bits for the unix socket, for example `0o660`.
    #[serde(default)]
    pub listen_unix_mode: Option<u32>,

    /// Numeric owner as `uid:gid` for the unix socket.
    #[serde(default)]
    pub listen_unix_owner: Option<String>,

    /// Accept HTTP/2 with prior knowledge on plain TCP (h2c).
    #[serde(default)]
    pub h2c: bool,

    /// Worker processes sharing the listener via SO_REUSEPORT. One process is
    /// the default; more needs `reuse_port = true`. The string `"auto"` uses
    /// the available CPU count, capped at 64.
    #[serde(
        default = "Config::default_workers",
        deserialize_with = "deserialize_workers"
    )]
    pub workers: usize,

    /// Drop to this user after binding sockets. A name or `uid:gid`.
    #[serde(default)]
    pub user: Option<String>,

    /// Raise RLIMIT_NOFILE for each process.
    #[serde(default)]
    pub worker_rlimit_nofile: Option<u64>,

    /// CPU indices assigned to workers in order. A single process uses the
    /// first entry.
    #[serde(default)]
    pub worker_cpu_affinity: Option<Vec<usize>>,

    /// Write the supervisor (or single-process) PID here.
    #[serde(default)]
    pub pid_file: Option<PathBuf>,

    /// Enter this directory as the filesystem root before loading runtime
    /// files. Every configured path must be valid inside the new root.
    #[serde(default)]
    pub chroot: Option<PathBuf>,
    #[serde(default)]
    pub limits: Limits,
    /// Send our `Server: elira` header and keep the upstream one.
    #[serde(default = "Config::default_server_header")]
    pub server_header: bool,
    #[serde(default)]
    pub cache: Cache,
    #[serde(default)]
    pub resolver: Resolver,
    #[serde(default)]
    pub upstream_tls: UpstreamTls,
    #[serde(default)]
    pub acme: Option<Acme>,
    /// Expect a PROXY protocol header on every accepted connection. Enable
    /// only when the listener is reachable solely through a load balancer.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Let a replacement process bind the same ports. Required for SIGUSR2.
    #[serde(default)]
    pub reuse_port: bool,
    /// Answer simple static GET/HEAD with sendfile(2) before hyper sees the
    /// request. Linux only.
    #[serde(default = "Config::default_sendfile")]
    pub sendfile: bool,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub health: Health,
    #[serde(default)]
    pub connect: Connect,
    #[serde(default)]
    pub compression: Compression,
    /// Global error pages as `STATUS /path`, served from `error_root`.
    #[serde(default)]
    pub error_pages: Vec<String>,
    /// Directory for global `error_pages`.
    #[serde(default)]
    pub error_root: Option<PathBuf>,
    #[serde(default)]
    pub http3: Option<Http3>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    pub routes: Vec<Route>,
}

impl Config {
    fn default_workers() -> usize {
        1
    }

    fn default_server_header() -> bool {
        true
    }

    fn default_sendfile() -> bool {
        true
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let value = load_value(path, 0)?;
        let mut cfg: Config = value.try_into().map_err(Error::Toml)?;
        expand_locations(&mut cfg)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse a self-contained config without includes or environment
    /// substitution. `load` is the operator-facing path.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut cfg: Config = toml::from_str(text).map_err(Error::Toml)?;
        expand_locations(&mut cfg)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod unit_tests;
