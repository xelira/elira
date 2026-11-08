//! Where the FastCGI application lives.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::Error;

/// A listening FastCGI application.
///
/// TCP targets hold a resolved [`SocketAddr`]; host names are not resolved
/// here because the proxy loads configuration synchronously and a blocking
/// DNS lookup in a config parser is a trap. Resolve the name before calling
/// [`Target::parse`] when the upstream uses one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A TCP socket, usually the local machine.
    Tcp(SocketAddr),
    /// A Unix domain socket.
    Unix(PathBuf),
}

impl Target {
    /// Parse `host:port` or `unix:/path`.
    ///
    /// IPv6 addresses must use brackets: `[::1]:9000`.
    pub fn parse(value: &str) -> Result<Self, Error> {
        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                return Err(invalid(value, "the Unix socket path is empty"));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }

        if value.is_empty() {
            return Err(invalid(value, "expected host:port or unix:/path"));
        }

        // SocketAddr accepts IPv4 and bracketed IPv6 literals. Anything else
        // gets a reason aimed at the two mistakes that are actually common.
        match value.parse::<SocketAddr>() {
            Ok(addr) => Ok(Self::Tcp(addr)),
            Err(_) if value.contains("://") => Err(invalid(
                value,
                "URL schemes are not supported; use host:port or unix:/path",
            )),
            Err(_) if !value.contains(':') => Err(invalid(
                value,
                "the port is missing; expected host:port or unix:/path",
            )),
            Err(_) => Err(invalid(
                value,
                "the host must be an IP address and the port must be a number; \
                 resolve host names before building the target",
            )),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

fn invalid(value: &str, reason: &str) -> Error {
    Error::InvalidTarget {
        value: value.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    #[test]
    fn parses_tcp() {
        let target = Target::parse("127.0.0.1:9000").unwrap();
        assert_eq!(
            target,
            Target::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 9000)))
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let target = Target::parse("[::1]:9001").unwrap();
        assert_eq!(
            target,
            Target::Tcp(SocketAddr::from((Ipv6Addr::LOCALHOST, 9001)))
        );
    }

    #[test]
    fn parses_unix_path() {
        assert_eq!(
            Target::parse("unix:/run/php/php-fpm.sock").unwrap(),
            Target::Unix(PathBuf::from("/run/php/php-fpm.sock"))
        );
    }

    #[test]
    fn rejects_invalid_values() {
        let cases = [
            "",
            "unix:",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:http",
            "localhost:9000",
            "tcp://127.0.0.1:9000",
            "[::1]",
        ];

        for value in cases {
            let error = Target::parse(value).unwrap_err();
            assert!(
                matches!(error, Error::InvalidTarget { .. }),
                "{value:?} produced {error:?}"
            );
        }
    }

    #[test]
    fn display_round_trips_user_visible_form() {
        assert_eq!(
            Target::parse("127.0.0.1:9000").unwrap().to_string(),
            "tcp://127.0.0.1:9000"
        );
        assert_eq!(
            Target::parse("unix:/tmp/app.sock").unwrap().to_string(),
            "unix:/tmp/app.sock"
        );
    }
}
