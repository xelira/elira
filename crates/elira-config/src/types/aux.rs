use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    #[serde(default = "Resolver::default_ttl_secs")]
    pub ttl_secs: u64,

    #[serde(default = "Resolver::default_negative_ttl_secs")]
    pub negative_ttl_secs: u64,

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

    #[serde(default)]
    pub dir: Option<PathBuf>,

    #[serde(default)]
    pub stale_secs: u64,

    #[serde(default)]
    pub shared: bool,

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

    #[serde(default)]
    pub file: Option<PathBuf>,

    #[serde(default = "Log::default_max_bytes")]
    pub max_bytes: usize,

    #[serde(default = "Log::default_keep")]
    pub keep: usize,

    #[serde(default = "Log::default_sample")]
    pub sample: f64,

    #[serde(default)]
    pub template: Option<String>,

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
