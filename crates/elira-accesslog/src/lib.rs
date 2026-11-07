//! Access log formatting.
//!
//! Two renderings are available: a one-line common-log-like format for
//! human-facing logs, and a flat JSON object for machine consumption. Both
//! escape control characters so a hostile request target or User-Agent
//! cannot split or confuse a log line.

use std::fmt::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One finished request.
#[derive(Debug, Clone)]
pub struct Entry {
    pub peer: IpAddr,
    pub method: http::Method,
    pub version: http::Version,
    pub host: String,
    pub path: String,
    pub status: http::StatusCode,
    pub bytes: u64,
    pub duration: Duration,
    pub user_agent: Option<String>,
    pub request_id: String,
}

impl Entry {
    /// Render the entry as a single common-log-like line:
    ///
    /// ```text
    /// <peer> - [<request_id>] "<method> <path> <version>" <status> <bytes> <duration_ms>ms "<user_agent>" host=<host>
    /// ```
    ///
    /// Example:
    ///
    /// ```text
    /// 203.0.113.5 - [a1b2c3d4e5f60718] "GET /path HTTP/1.1" 200 1234 12ms "curl/8.0" host=example.com
    /// ```
    ///
    /// A missing or empty User-Agent is written as `-` inside the quotes,
    /// following the common log convention. Durations are truncated to whole
    /// milliseconds, so sub-millisecond requests show `0ms`.
    ///
    /// Backslashes and double quotes in the path, User-Agent, and host are
    /// backslash-escaped. Control characters are written as `\xNN`, which
    /// keeps the result on one line.
    pub fn line(&self) -> String {
        let mut out = String::with_capacity(160);
        let _ = write!(
            out,
            "{} - [{}] \"{} ",
            self.peer, self.request_id, self.method
        );
        escape_line(&self.path, &mut out);
        let _ = write!(
            out,
            " {}\" {} {} {}ms \"",
            version_str(self.version),
            self.status.as_u16(),
            self.bytes,
            self.duration.as_millis()
        );
        match self.user_agent.as_deref().filter(|ua| !ua.is_empty()) {
            Some(ua) => escape_line(ua, &mut out),
            None => out.push('-'),
        }
        out.push_str("\" host=");
        escape_line(&self.host, &mut out);
        out
    }

    /// Render the entry as a single-line JSON object.
    ///
    /// Keys are `peer`, `method`, `version`, `host`, `path`, `status`,
    /// `bytes`, `duration_ms`, `user_agent` (string or `null`), and
    /// `request_id`. Strings use standard JSON escapes; other control
    /// characters become `\u00XX`.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');

        push_str(&mut out, "peer", &self.peer.to_string());
        push_str(&mut out, "method", self.method.as_str());
        push_str(&mut out, "version", version_str(self.version));
        push_str(&mut out, "host", &self.host);
        push_str(&mut out, "path", &self.path);
        push_num(&mut out, "status", u128::from(self.status.as_u16()));
        push_num(&mut out, "bytes", u128::from(self.bytes));
        push_num(&mut out, "duration_ms", self.duration.as_millis());
        match &self.user_agent {
            Some(ua) => push_str(&mut out, "user_agent", ua),
            None => {
                push_key(&mut out, "user_agent");
                out.push_str("null,");
            }
        }
        push_str(&mut out, "request_id", &self.request_id);

        out.pop();
        out.push('}');
        out
    }
}

/// Build a 16-character lowercase hex identifier for correlating log lines.
///
/// The value mixes a process-wide counter with the wall clock in nanoseconds.
/// It is unique enough to tell concurrent requests apart; it is not a
/// cryptographic token and must not be used for authentication or secrecy.
pub fn request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let mut x = n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ nanos;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;

    format!("{x:016x}")
}

fn version_str(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?.?",
    }
}

fn escape_line(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

fn escape_json(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

fn push_key(out: &mut String, key: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
}

fn push_str(out: &mut String, key: &str, value: &str) {
    push_key(out, key);
    out.push('"');
    escape_json(value, out);
    out.push_str("\",");
}

fn push_num(out: &mut String, key: &str, value: u128) {
    push_key(out, key);
    let _ = write!(out, "{value},");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry() -> Entry {
        Entry {
            peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            method: http::Method::GET,
            version: http::Version::HTTP_11,
            host: "example.com".to_owned(),
            path: "/path".to_owned(),
            status: http::StatusCode::OK,
            bytes: 1234,
            duration: Duration::from_millis(12),
            user_agent: Some("curl/8.0".to_owned()),
            request_id: "a1b2c3d4e5f60718".to_owned(),
        }
    }

    #[test]
    fn line_has_the_documented_shape() {
        assert_eq!(
            entry().line(),
            "203.0.113.5 - [a1b2c3d4e5f60718] \"GET /path HTTP/1.1\" 200 1234 12ms \"curl/8.0\" host=example.com"
        );
    }

    #[test]
    fn line_uses_dash_for_missing_user_agent() {
        let mut e = entry();
        e.user_agent = None;
        assert!(e.line().ends_with("\"-\" host=example.com"));

        e.user_agent = Some(String::new());
        assert!(e.line().ends_with("\"-\" host=example.com"));
    }

    #[test]
    fn line_cannot_be_broken_by_control_characters_or_quotes() {
        let mut e = entry();
        e.path = "/a\"b\\c\nnext".to_owned();
        e.user_agent = Some("agent\"\r\n\ttab\u{7}".to_owned());
        e.host = "bad\"host".to_owned();

        let line = e.line();

        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
        assert!(!line.contains('\t'));
        assert!(line.contains(r#""GET /a\"b\\c\x0anext HTTP/1.1""#));
        assert!(line.contains(r#""agent\"\x0d\x0a\x09tab\x07""#));
        assert!(line.ends_with(r#"host=bad\"host"#));
    }

    #[test]
    fn json_escapes_quotes_backslashes_and_controls() {
        let mut e = entry();
        e.path = "/a\"b\\c\nline\ttab\u{7}".to_owned();
        e.user_agent = Some("ua\"\\\r".to_owned());

        assert_eq!(
            e.json(),
            concat!(
                r#"{"peer":"203.0.113.5","method":"GET","version":"HTTP/1.1","host":"example.com","#,
                r#""path":"/a\"b\\c\nline\ttab\u0007","#,
                r#""status":200,"bytes":1234,"duration_ms":12,"#,
                r#""user_agent":"ua\"\\\r","request_id":"a1b2c3d4e5f60718"}"#
            )
        );
        assert!(!e.json().contains('\n'));
    }

    #[test]
    fn json_writes_null_for_absent_user_agent() {
        let mut e = entry();
        e.user_agent = None;
        assert!(e.json().contains(r#""user_agent":null,"#));
    }

    #[test]
    fn request_id_is_16_lowercase_hex_characters() {
        for _ in 0..64 {
            let id = request_id();
            assert_eq!(id.len(), 16);
            assert!(id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }

    #[test]
    fn request_ids_differ_between_calls() {
        let a = request_id();
        let b = request_id();
        assert_ne!(a, b);
    }
}
