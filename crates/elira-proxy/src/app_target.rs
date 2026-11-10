//! TCP or unix socket target shared by the app protocols.

use std::path::PathBuf;

use http::uri::Authority;

#[derive(Clone, Debug)]
pub(crate) enum Target {
    Tcp(Authority),
    Unix(PathBuf),
}

impl Target {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            return Some(Self::Unix(PathBuf::from(path)));
        }
        value.parse::<Authority>().ok().map(Self::Tcp)
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(authority) => authority.fmt(formatter),
            Self::Unix(path) => write!(formatter, "unix:{}", path.display()),
        }
    }
}
