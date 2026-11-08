//! Where the FastCGI application lives.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::Error;

/// A listening FastCGI application.
///
/// A literal address connects immediately; a host name is resolved by the
/// client for each request, so DNS changes do not require a reload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// A TCP socket with a literal address.
    Tcp(SocketAddr),
    /// A TCP host name and port, resolved at request time.
    TcpName(String),
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
            Err(_) => {
                let (host, port) = value
                    .rsplit_once(':')
                    .ok_or_else(|| invalid(value, "the port is missing; expected host:port"))?;
                if host.is_empty() || port.parse::<u16>().is_err() {
                    return Err(invalid(value, "expected host:port with a numeric port"));
                }
                Ok(Self::TcpName(value.to_owned()))
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            Self::TcpName(name) => write!(f, "tcp://{name}"),
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
    fn keeps_a_host_name_for_later_resolution() {
        assert_eq!(
            Target::parse("php.internal:9000").unwrap(),
            Target::TcpName("php.internal:9000".to_owned())
        );
    }

    #[test]
    fn rejects_a_non_numeric_port() {
        assert!(Target::parse("php.internal:http").is_err());
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
