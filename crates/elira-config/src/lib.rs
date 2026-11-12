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

    #[serde(default)]
    pub listen_unix: Option<PathBuf>,

    #[serde(default)]
    pub unix_tls: bool,

    #[serde(default)]
    pub listeners: Vec<Listener>,

    #[serde(default)]
    pub streams: Vec<Stream>,

    #[serde(default)]
    pub rewrites: Vec<Rewrite>,

    #[serde(default)]
    pub maps: Vec<Map>,

    #[serde(default)]
    pub geos: Vec<Geo>,

    #[serde(default)]
    pub splits: Vec<Split>,

    #[serde(default)]
    pub listen_unix_mode: Option<u32>,

    #[serde(default)]
    pub listen_unix_owner: Option<String>,

    #[serde(default)]
    pub h2c: bool,

    #[serde(
        default = "Config::default_workers",
        deserialize_with = "deserialize_workers"
    )]
    pub workers: usize,

    #[serde(default)]
    pub user: Option<String>,

    #[serde(default)]
    pub worker_rlimit_nofile: Option<u64>,

    #[serde(default)]
    pub worker_cpu_affinity: Option<Vec<usize>>,

    #[serde(default)]
    pub pid_file: Option<PathBuf>,

    #[serde(default)]
    pub chroot: Option<PathBuf>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub http2: Http2,

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

    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub reuse_port: bool,

    #[serde(default = "Config::default_sendfile")]
    pub sendfile: bool,

    #[serde(default = "Config::default_sendfile_min_bytes")]
    pub sendfile_min_bytes: u64,
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

    #[serde(default)]
    pub error_pages: Vec<String>,

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

    fn default_sendfile_min_bytes() -> u64 {
        64 * 1024
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let value = load_value(path, 0)?;
        let mut cfg: Config = value.try_into().map_err(Error::Toml)?;
        expand_locations(&mut cfg)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut cfg: Config = toml::from_str(text).map_err(Error::Toml)?;
        expand_locations(&mut cfg)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod unit_tests;
