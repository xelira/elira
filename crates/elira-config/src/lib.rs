//! Configuration and validation.
//!
//! Everything here is plain data plus checks. No sockets, no async.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use http::uri::Authority;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default)]
    pub limits: Limits,
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
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_headers: Self::default_max_headers(),
            max_header_bytes: Self::default_max_header_bytes(),
            upstream_timeout_secs: Self::default_upstream_timeout_secs(),
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
    pub upstream: String,
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
        if self.routes.is_empty() {
            return Err(Error::NoRoutes);
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
            if !names.contains(route.upstream.as_str()) {
                return Err(Error::UnknownUpstream {
                    index,
                    upstream: route.upstream.clone(),
                });
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
        let text = format!(
            "{MINIMAL}\n[[routes]]\nhost = \"*\"\nupstream = \"app\"\n"
        );
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
}
