//! Cache and access-log settings.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    /// How long a successful lookup is reused.
    #[serde(default = "Resolver::default_ttl_secs")]
    pub ttl_secs: u64,

    /// How long a failed or empty lookup is reused. Zero disables negative
    /// caching.
    #[serde(default = "Resolver::default_negative_ttl_secs")]
    pub negative_ttl_secs: u64,

    /// Static names that bypass the system resolver.
    #[serde(default)]
    pub hosts: Vec<ResolverHost>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverHost {
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            ttl_secs: Self::default_ttl_secs(),
            negative_ttl_secs: Self::default_negative_ttl_secs(),
            hosts: Vec::new(),
        }
    }
}

impl Resolver {
    fn default_ttl_secs() -> u64 {
        30
    }

    fn default_negative_ttl_secs() -> u64 {
        5
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "Cache::default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "Cache::default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "Cache::default_max_item_bytes")]
    pub max_item_bytes: usize,

    /// Keep response bodies on disk here instead of in memory.
    #[serde(default)]
    pub dir: Option<PathBuf>,

    /// Serve an expired entry for this long while a refresh runs in the
    /// background. Zero disables stale serving.
    #[serde(default)]
    pub stale_secs: u64,

    /// Share `dir` between processes. Entries are read through from disk;
    /// eviction remains per process.
    #[serde(default)]
    pub shared: bool,

    /// Named cache zones referenced by `cache_zone` on a route.
    #[serde(default)]
    pub zones: HashMap<String, CacheZone>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheZone {
    #[serde(default = "Cache::default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "Cache::default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "Cache::default_max_item_bytes")]
    pub max_item_bytes: usize,
    #[serde(default)]
    pub dir: Option<PathBuf>,
    #[serde(default)]
    pub stale_secs: u64,
    #[serde(default)]
    pub shared: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default)]
    pub format: LogFormat,

    /// Append access lines here. Without it they go to stdout via tracing.
    #[serde(default)]
    pub file: Option<PathBuf>,

    /// Rotate after this many bytes.
    #[serde(default = "Log::default_max_bytes")]
    pub max_bytes: usize,

    /// How many rotated files to keep.
    #[serde(default = "Log::default_keep")]
    pub keep: usize,

    /// Fraction of requests to write to the access log. One logs everything.
    #[serde(default = "Log::default_sample")]
    pub sample: f64,

    /// nginx-like template. Overrides `format` when set.
    #[serde(default)]
    pub template: Option<String>,

    /// Also send lines to this Unix datagram socket, usually `/dev/log`.
    #[serde(default)]
    pub syslog: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: Self::default_ttl_secs(),
            max_bytes: Self::default_max_bytes(),
            max_item_bytes: Self::default_max_item_bytes(),
            dir: None,
            stale_secs: 0,
            shared: false,
            zones: HashMap::new(),
        }
    }
}

impl Cache {
    fn default_ttl_secs() -> u64 {
        60
    }

    fn default_max_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_max_item_bytes() -> usize {
        1024 * 1024
    }
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            file: None,
            max_bytes: Self::default_max_bytes(),
            keep: Self::default_keep(),
            sample: Self::default_sample(),
            template: None,
            syslog: None,
        }
    }
}

impl Log {
    fn default_sample() -> f64 {
        1.0
    }

    fn default_max_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_keep() -> usize {
        3
    }
}

impl<'de> Deserialize<'de> for LogFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(serde::de::Error::custom(format!(
                "unknown log format \"{other}\", expected \"text\" or \"json\""
            ))),
        }
    }
}
