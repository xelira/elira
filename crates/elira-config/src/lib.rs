//! Configuration and validation.
//!
//! Everything here is plain data plus checks. No sockets, no async.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use http::uri::Authority;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub health: Health,
    #[serde(default)]
    pub connect: Connect,
    #[serde(default)]
    pub http3: Option<Http3>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum number of request headers. Guards against header-count floods.
    #[serde(default = "Limits::default_max_headers")]
    pub max_headers: usize,

    /// Read buffer cap. A request with larger headers gets a 431.
    #[serde(default = "Limits::default_max_header_bytes")]
    pub max_header_bytes: usize,

    /// How long to wait for the upstream to answer.
    #[serde(default = "Limits::default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    /// How many client connections may be open at once.
    #[serde(default = "Limits::default_max_connections")]
    pub max_connections: usize,

    /// Close a keep-alive connection after this many seconds without a
    /// request. Zero disables the timer.
    #[serde(default = "Limits::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_headers: Self::default_max_headers(),
            max_header_bytes: Self::default_max_header_bytes(),
            upstream_timeout_secs: Self::default_upstream_timeout_secs(),
            max_connections: Self::default_max_connections(),
            idle_timeout_secs: Self::default_idle_timeout_secs(),
        }
    }
}

impl Limits {
    fn default_max_headers() -> usize {
        64
    }

    fn default_max_header_bytes() -> usize {
        16 * 1024
    }

    fn default_upstream_timeout_secs() -> u64 {
        30
    }

    fn default_max_connections() -> usize {
        1024
    }

    fn default_idle_timeout_secs() -> u64 {
        60
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "Health::default_path")]
    pub path: String,

    #[serde(default = "Health::default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default = "Health::default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            enabled: false,
            path: Self::default_path(),
            interval_secs: Self::default_interval_secs(),
            timeout_secs: Self::default_timeout_secs(),
        }
    }
}

impl Health {
    fn default_path() -> String {
        "/health".to_owned()
    }

    fn default_interval_secs() -> u64 {
        5
    }

    fn default_timeout_secs() -> u64 {
        2
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    /// Off by default: an open CONNECT proxy is an SSRF pivot, and a reverse
    /// proxy has no reason to offer one.
    #[serde(default)]
    pub enabled: bool,
    /// Exact `host:port` destinations the tunnel may reach.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Bind loopback here unless you really mean to expose the counters.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http3 {
    pub listen: SocketAddr,
    // Defaults so a missing field names itself in the error instead of
    // surfacing as a bare serde "missing field".
    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Host to match, case-insensitive. `*` catches everything else.
    pub host: String,

    /// Name of an upstream to proxy to. Exactly one of `upstream` or `root`.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Directory to serve files from. Exactly one of `upstream` or `root`.
    #[serde(default)]
    pub root: Option<PathBuf>,

    /// Files tried for a directory request, in order.
    #[serde(default = "Route::default_index")]
    pub index: Vec<String>,

    /// Serve the first index file for missing paths. For client-side routers.
    #[serde(default)]
    pub spa: bool,
}

impl Route {
    fn default_index() -> Vec<String> {
        vec!["index.html".to_owned()]
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Empty when omitted; `validate` names the missing field instead of
    /// letting serde report a bare "missing field" with no section context.
    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
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

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text).map_err(|e| e.into_parse(path.display().to_string()))
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let cfg: Config = toml::from_str(text).map_err(Error::Toml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.limits.max_header_bytes < 8192 {
            return Err(Error::MaxHeaderBytesTooSmall);
        }
        if self.limits.max_headers == 0 {
            return Err(Error::MaxHeadersZero);
        }
        if self.limits.max_connections == 0 {
            return Err(Error::MaxConnectionsZero);
        }

        if self.health.enabled {
            if !self.health.path.starts_with('/')
                || self.health.path.chars().any(|c| c.is_control() || c == ' ')
            {
                return Err(Error::BadHealthPath);
            }
            if self.health.interval_secs == 0 {
                return Err(Error::BadHealthInterval);
            }
            if self.health.timeout_secs == 0 {
                return Err(Error::BadHealthTimeout);
            }
        }

        if let Some(http3) = &self.http3 {
            if http3.cert.as_os_str().is_empty() {
                return Err(Error::Http3MissingCert);
            }
            if http3.key.as_os_str().is_empty() {
                return Err(Error::Http3MissingKey);
            }
        }

        if self.connect.enabled {
            if self.connect.allow.is_empty() {
                return Err(Error::ConnectEmptyAllow);
            }
            for target in &self.connect.allow {
                let parsed: Authority = target.parse().map_err(|_| Error::BadConnectTarget {
                    target: target.clone(),
                })?;
                if parsed.port_u16().is_none() || target.contains('@') || target.contains('/') {
                    return Err(Error::BadConnectTarget {
                        target: target.clone(),
                    });
                }
            }
        }

        if self.routes.is_empty() {
            return Err(Error::NoRoutes);
        }

        if let Some(tls) = &self.tls {
            if tls.cert.as_os_str().is_empty() {
                return Err(Error::TlsMissingCert);
            }
            if tls.key.as_os_str().is_empty() {
                return Err(Error::TlsMissingKey);
            }
        }

        let mut names = HashSet::new();
        for up in &self.upstreams {
            if up.name.trim().is_empty() {
                return Err(Error::EmptyUpstreamName);
            }
            if !names.insert(up.name.as_str()) {
                return Err(Error::DuplicateUpstream {
                    name: up.name.clone(),
                });
            }
            if up.servers.is_empty() {
                return Err(Error::EmptyUpstream {
                    name: up.name.clone(),
                });
            }
            for addr in &up.servers {
                check_server(addr).map_err(|_| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
            }
        }

        let mut hosts = HashSet::new();
        let mut has_default = false;
        for (index, route) in self.routes.iter().enumerate() {
            let host = route.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(Error::EmptyRouteHost { index });
            }
            if host == "*" {
                if has_default {
                    return Err(Error::DuplicateDefaultRoute);
                }
                has_default = true;
            } else if !hosts.insert(host) {
                return Err(Error::DuplicateRoute {
                    host: route.host.clone(),
                });
            }

            match (&route.upstream, &route.root) {
                (Some(upstream), None) => {
                    if !names.contains(upstream.as_str()) {
                        return Err(Error::UnknownUpstream {
                            index,
                            upstream: upstream.clone(),
                        });
                    }
                }
                (None, Some(root)) => {
                    if root.as_os_str().is_empty() {
                        return Err(Error::EmptyRoot { index });
                    }
                    if route.spa && route.index.is_empty() {
                        return Err(Error::SpaNeedsIndex { index });
                    }
                    for entry in &route.index {
                        if entry.is_empty() || entry.contains('/') || entry.contains("..") {
                            return Err(Error::BadIndexEntry {
                                index,
                                entry: entry.clone(),
                            });
                        }
                    }
                }
                (Some(_), Some(_)) => return Err(Error::RouteHasTwoTargets { index }),
                (None, None) => return Err(Error::RouteNeedsTarget { index }),
            }
        }

        Ok(())
    }
}

fn check_server(addr: &str) -> Result<(), ()> {
    if addr.contains('@') || addr.contains('/') {
        return Err(());
    }
    let authority: Authority = addr.parse().map_err(|_| ())?;
    if authority.port_u16().is_none() {
        return Err(());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("{0}")]
    Toml(#[source] toml::de::Error),

    #[error("no routes configured")]
    NoRoutes,

    #[error("limits.max_header_bytes must be at least 8192, hyper refuses smaller buffers")]
    MaxHeaderBytesTooSmall,

    #[error("limits.max_headers must be greater than zero")]
    MaxHeadersZero,

    #[error("limits.max_connections must be greater than zero")]
    MaxConnectionsZero,

    #[error("health.path must start with '/' and contain no spaces or control characters")]
    BadHealthPath,

    #[error("health.interval_secs must be greater than zero")]
    BadHealthInterval,

    #[error("health.timeout_secs must be greater than zero")]
    BadHealthTimeout,

    #[error("http3.cert must not be empty")]
    Http3MissingCert,

    #[error("http3.key must not be empty")]
    Http3MissingKey,

    #[error("connect.enabled requires a non-empty connect.allow list")]
    ConnectEmptyAllow,

    #[error("connect target \"{target}\" is not host:port")]
    BadConnectTarget { target: String },

    #[error("tls.cert is required when [tls] is set and must not be empty")]
    TlsMissingCert,

    #[error("tls.key is required when [tls] is set and must not be empty")]
    TlsMissingKey,

    #[error("upstream name is empty")]
    EmptyUpstreamName,

    #[error("upstream \"{name}\" is defined twice")]
    DuplicateUpstream { name: String },

    #[error("upstream \"{name}\" has no servers")]
    EmptyUpstream { name: String },

    #[error("upstream \"{upstream}\": \"{addr}\" is not host:port")]
    BadServer { upstream: String, addr: String },

    #[error("route {index} has an empty host")]
    EmptyRouteHost { index: usize },

    #[error("route for host \"{host}\" is defined twice")]
    DuplicateRoute { host: String },

    #[error("only one `host = \"*\"` route is allowed")]
    DuplicateDefaultRoute,

    #[error("route {index} points to unknown upstream \"{upstream}\"")]
    UnknownUpstream { index: usize, upstream: String },

    #[error("route {index} needs exactly one of `upstream` or `root`")]
    RouteNeedsTarget { index: usize },

    #[error("route {index} has both `upstream` and `root`")]
    RouteHasTwoTargets { index: usize },

    #[error("route {index} has an empty `root`")]
    EmptyRoot { index: usize },

    #[error("route {index}: index file \"{entry}\" must be a plain file name")]
    BadIndexEntry { index: usize, entry: String },

    #[error("route {index}: `spa` needs at least one index file")]
    SpaNeedsIndex { index: usize },
}

impl Error {
    fn into_parse(self, path: String) -> Self {
        match self {
            Error::Toml(source) => Error::Parse { path, source },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#;

    #[test]
    fn parses_minimal() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.limits.max_headers, 64);
    }

    #[test]
    fn defaults_log_to_text_and_tls_to_none() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert_eq!(cfg.log.format, LogFormat::Text);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn parses_tls_and_json_log() {
        let text = format!(
            "{MINIMAL}\n[tls]\ncert = \"/etc/elira/cert.pem\"\nkey = \"/etc/elira/key.pem\"\n\n[log]\nformat = \"json\"\n"
        );
        let cfg = Config::parse(&text).expect("valid config");
        let tls = cfg.tls.expect("tls section");
        assert_eq!(tls.cert, PathBuf::from("/etc/elira/cert.pem"));
        assert_eq!(tls.key, PathBuf::from("/etc/elira/key.pem"));
        assert_eq!(cfg.log.format, LogFormat::Json);
    }

    #[test]
    fn rejects_tls_without_key() {
        let text = format!("{MINIMAL}\n[tls]\ncert = \"/etc/elira/cert.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::TlsMissingKey)));
    }

    #[test]
    fn rejects_tls_with_empty_cert() {
        let text = format!("{MINIMAL}\n[tls]\ncert = \"\"\nkey = \"/etc/elira/key.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::TlsMissingCert)));
    }

    #[test]
    fn rejects_unknown_log_format() {
        let text = format!("{MINIMAL}\n[log]\nformat = \"xml\"\n");
        let err = Config::parse(&text).expect_err("unknown format");
        let msg = err.to_string();
        assert!(msg.contains("text"), "{msg}");
        assert!(msg.contains("json"), "{msg}");
    }

    #[test]
    fn rejects_unknown_field() {
        let text = format!("{MINIMAL}\nnonsense = 1\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_route_to_unknown_upstream() {
        let text = MINIMAL.replace("upstream = \"app\"", "upstream = \"nope\"");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::UnknownUpstream { .. })
        ));
    }

    #[test]
    fn rejects_server_without_port() {
        let text = MINIMAL.replace("127.0.0.1:3000", "127.0.0.1");
        assert!(matches!(Config::parse(&text), Err(Error::BadServer { .. })));
    }

    #[test]
    fn rejects_duplicate_host() {
        let text = format!("{MINIMAL}\n[[routes]]\nhost = \"*\"\nupstream = \"app\"\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::DuplicateDefaultRoute)
        ));
    }

    #[test]
    fn rejects_empty_upstream() {
        let text = MINIMAL.replace(r#"servers = ["127.0.0.1:3000"]"#, "servers = []");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::EmptyUpstream { .. })
        ));
    }

    #[test]
    fn rejects_tiny_header_buffer() {
        // hyper asserts on buffers below 8192, and the assert fires inside
        // every spawned connection. Catch it at load time instead.
        let text = format!("{MINIMAL}\n[limits]\nmax_header_bytes = 1024\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::MaxHeaderBytesTooSmall)
        ));
    }

    #[test]
    fn rejects_bad_health_path() {
        let text = format!("{MINIMAL}\n[health]\nenabled = true\npath = \"health\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::BadHealthPath)));
    }

    #[test]
    fn health_is_disabled_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(!cfg.health.enabled);
        assert_eq!(cfg.health.path, "/health");
        assert_eq!(cfg.limits.idle_timeout_secs, 60);
        assert!(cfg.http3.is_none());
    }

    #[test]
    fn rejects_http3_without_key() {
        let text =
            format!("{MINIMAL}\n[http3]\nlisten = \"127.0.0.1:4433\"\ncert = \"cert.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::Http3MissingKey)));
    }

    #[test]
    fn connect_is_off_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(!cfg.connect.enabled);
    }

    #[test]
    fn connect_needs_targets_when_enabled() {
        let text = format!("{MINIMAL}\n[connect]\nenabled = true\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::ConnectEmptyAllow)
        ));
    }

    #[test]
    fn connect_rejects_target_without_port() {
        let text = format!("{MINIMAL}\n[connect]\nenabled = true\nallow = [\"10.0.0.5\"]\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::BadConnectTarget { .. })
        ));
    }

    #[test]
    fn parses_a_static_route() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.upstreams.len(), 0);
        assert_eq!(
            cfg.routes[0].root.as_deref(),
            Some(std::path::Path::new("/var/www"))
        );
        assert_eq!(cfg.routes[0].index, vec!["index.html".to_owned()]);
    }

    #[test]
    fn rejects_a_route_with_two_targets() {
        let text = format!(
            "{MINIMAL}\n[[routes]]\nhost = \"both.example\"\nupstream = \"app\"\nroot = \"/srv\"\n"
        );
        assert!(matches!(
            Config::parse(&text),
            Err(Error::RouteHasTwoTargets { .. })
        ));
    }

    #[test]
    fn rejects_a_route_without_a_target() {
        let text = format!("{MINIMAL}\n[[routes]]\nhost = \"empty.example\"\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::RouteNeedsTarget { .. })
        ));
    }

    #[test]
    fn rejects_an_index_name_with_a_slash() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
index = ["../secret"]
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadIndexEntry { .. })
        ));
    }

    #[test]
    fn spa_needs_an_index() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
index = []
spa = true
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::SpaNeedsIndex { .. })
        ));
    }
}
