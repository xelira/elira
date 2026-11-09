//! Request variables and derived maps used by route templates.
//!
//! Everything here is pure data plus string expansion; the request-specific
//! values are filled by the proxy before routing.

use std::borrow::Cow;
use std::collections::HashMap;

use http::header::{HeaderName, AUTHORIZATION, COOKIE};
use http::{HeaderMap, StatusCode};

use elira_config::{Map, RewriteFlag};

#[derive(Clone, Debug)]
pub(crate) enum RequestKey {
    Ip,
    Authorization,
    Header(HeaderName),
    Cookie(String),
    Uri,
}

/// Values available for `$variable` expansion in route templates.
pub(crate) struct RequestVars {
    pub(crate) remote_addr: std::net::IpAddr,
    pub(crate) host: String,
    pub(crate) uri: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) method: String,
    pub(crate) scheme: &'static str,
    pub(crate) port: u16,
    pub(crate) request_id: String,
    pub(crate) headers: HeaderMap,
    pub(crate) mapped: HashMap<String, String>,
}

impl RequestVars {
    pub(crate) fn value<'a>(&'a self, name: &str) -> Option<Cow<'a, str>> {
        match name {
            "remote_addr" => Some(Cow::Owned(self.remote_addr.to_string())),
            "host" => Some(Cow::Borrowed(&self.host)),
            "request_uri" => Some(Cow::Borrowed(&self.uri)),
            "uri" => Some(Cow::Borrowed(&self.path)),
            "query_string" | "args" => Some(Cow::Borrowed(&self.query)),
            "request_method" => Some(Cow::Borrowed(&self.method)),
            "scheme" => Some(Cow::Borrowed(self.scheme)),
            "server_port" => Some(Cow::Owned(self.port.to_string())),
            "request_id" => Some(Cow::Borrowed(&self.request_id)),
            _ => {
                if let Some(value) = self.mapped.get(name) {
                    return Some(Cow::Borrowed(value));
                }
                if let Some(header) = name.strip_prefix("http_") {
                    let header = header.replace('_', "-");
                    return self
                        .headers
                        .get(header)
                        .and_then(|value| value.to_str().ok())
                        .map(Cow::Borrowed);
                }
                if let Some(cookie) = name.strip_prefix("cookie_") {
                    for header in self.headers.get_all(COOKIE) {
                        let Ok(header) = header.to_str() else {
                            continue;
                        };
                        for part in header.split(';') {
                            let Some((key, value)) = part.trim().split_once('=') else {
                                continue;
                            };
                            if key.trim() == cookie {
                                return Some(Cow::Borrowed(value.trim()));
                            }
                        }
                    }
                }
                None
            }
        }
    }

    pub(crate) fn apply_derived(
        &mut self,
        maps: &[Map],
        geos: &[CompiledGeo],
        splits: &[CompiledSplit],
    ) {
        for map in maps {
            let source = map.source.strip_prefix('$').unwrap_or(&map.source);
            let key = self
                .value(source)
                .map(|value| value.into_owned())
                .unwrap_or_default();
            let value = map
                .values
                .get(&key)
                .cloned()
                .or_else(|| map.default.clone())
                .unwrap_or_default();
            self.mapped.insert(map.name.clone(), value);
        }

        for geo in geos {
            let value = geo
                .networks
                .iter()
                .find(|(network, _)| network.contains(&self.remote_addr))
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| geo.default.clone());
            self.mapped.insert(geo.name.clone(), value);
        }

        for split in splits {
            let source = split.source.strip_prefix('$').unwrap_or(&split.source);
            let key = self
                .value(source)
                .map(|value| value.into_owned())
                .unwrap_or_default();
            let bucket = (stable_hash(&key) % 100) as u8;
            let mut cumulative = 0u16;
            let mut value = String::new();
            for (percent, bucket_value) in &split.buckets {
                cumulative = cumulative.saturating_add(u16::from(*percent));
                if u16::from(bucket) < cumulative {
                    value = bucket_value.clone();
                    break;
                }
            }
            self.mapped.insert(split.name.clone(), value);
        }
    }

    pub(crate) fn render(&self, template: &str) -> String {
        let mut out = String::with_capacity(template.len());
        let mut chars = template.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch != '$' {
                out.push(ch);
                continue;
            }
            if chars.peek() == Some(&'$') {
                chars.next();
                out.push('$');
                continue;
            }
            let mut name = String::new();
            if chars.peek() == Some(&'{') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch == '}' {
                        break;
                    }
                    name.push(ch);
                }
            } else {
                while let Some(ch) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || *ch == '_' {
                        name.push(*ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            if name.is_empty() {
                out.push('$');
                continue;
            }
            if let Some(value) = self.value(&name) {
                out.push_str(&value);
            } else {
                out.push('$');
                out.push_str(&name);
            }
        }
        out
    }
}

pub(crate) fn expand_rewrite(template: &str, captures: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'$') {
            chars.next();
            out.push('$');
            continue;
        }
        let mut name = String::new();
        while let Some(ch) = chars.peek() {
            if ch.is_ascii_alphanumeric() || *ch == '_' {
                name.push(*ch);
                chars.next();
            } else {
                break;
            }
        }
        if name.is_empty() {
            out.push('$');
            continue;
        }
        let value = if let Ok(index) = name.parse::<usize>() {
            captures.get(index).map(|capture| capture.as_str())
        } else {
            captures.name(&name).map(|capture| capture.as_str())
        };
        match value {
            Some(value) => out.push_str(value),
            None => {
                out.push('$');
                out.push_str(&name);
            }
        }
    }
    out
}

pub(crate) fn parse_request_key(value: Option<&str>) -> RequestKey {
    match value {
        None | Some("ip") => RequestKey::Ip,
        Some("authorization") => RequestKey::Authorization,
        Some("uri") => RequestKey::Uri,
        Some(value) => {
            if let Some(name) = value.strip_prefix("header:") {
                HeaderName::from_bytes(name.as_bytes())
                    .map(RequestKey::Header)
                    .unwrap_or(RequestKey::Ip)
            } else if let Some(name) = value.strip_prefix("cookie:") {
                RequestKey::Cookie(name.to_owned())
            } else {
                RequestKey::Ip
            }
        }
    }
}

/// The value that identifies one bucket. A missing header or cookie falls
/// back to the peer address, so a client cannot dodge the limiter by omitting
/// it.
pub(crate) fn request_key_value<'a>(
    key: &RequestKey,
    headers: &'a HeaderMap,
    peer: std::net::IpAddr,
    path: &'a str,
) -> Cow<'a, str> {
    let header = |name: &HeaderName| headers.get(name).and_then(|value| value.to_str().ok());
    match key {
        RequestKey::Ip => Cow::Owned(peer.to_string()),
        RequestKey::Authorization => header(&AUTHORIZATION)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Header(name) => header(name)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Cookie(name) => cookie_value(headers, name)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Uri => Cow::Borrowed(path),
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header in headers.get_all(COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for part in header.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            if key.trim() != name {
                continue;
            }
            let value = value.trim();
            return Some(
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value),
            );
        }
    }
    None
}

#[derive(Clone)]
pub(crate) struct CompiledIf {
    pub(crate) variable: String,
    pub(crate) equals: Option<String>,
    pub(crate) regex: Option<regex::Regex>,
    pub(crate) status: StatusCode,
    pub(crate) body: String,
    pub(crate) content_type: Option<String>,
}

pub(crate) struct CompiledRewrite {
    pub(crate) regex: regex::Regex,
    pub(crate) replacement: String,
    pub(crate) flag: RewriteFlag,
}

pub(crate) struct CompiledGeo {
    pub(crate) name: String,
    pub(crate) default: String,
    pub(crate) networks: Vec<(ipnet::IpNet, String)>,
}

pub(crate) struct CompiledSplit {
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) buckets: Vec<(u8, String)>,
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
