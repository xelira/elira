//! Access log formatting.
//!
//! Two built-in renderings are available: a one-line common-log-like format
//! for human-facing logs, and a flat JSON object for machine consumption.
//! [`Format`] adds configurable nginx-like `$variable` templates, and
//! [`Syslog`] forwards rendered lines to a local Unix syslog socket. All
//! renderings escape control characters so a hostile request target or
//! User-Agent cannot split or confuse a log line.
//!
//! # Time handling
//!
//! The crate deliberately has no time-zone database dependency. `$time_iso8601`
//! is formatted in UTC, and `$time_local` is *also* formatted in UTC (using
//! the conventional local-time shape) because the standard library cannot
//! convert to the machine's local time zone. Log consumers that need local
//! time can convert the UTC timestamp themselves.

use std::fmt::{self, Write};
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
    /// Upstream that served the request, when the route proxied.
    pub upstream: Option<String>,
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
    /// 203.0.113.5 - [a1b2c3d4e5f60718] "GET /path HTTP/1.1" 200 1234 12ms "curl/8.0" host=example.com upstream=-
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
        out.push_str(" upstream=");
        match self.upstream.as_deref().filter(|name| !name.is_empty()) {
            Some(name) => escape_line(name, &mut out),
            None => out.push('-'),
        }
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
        match &self.upstream {
            Some(name) => push_str(&mut out, "upstream", name),
            None => {
                push_key(&mut out, "upstream");
                out.push_str("null,");
            }
        }

        out.pop();
        out.push('}');
        out
    }
}

/// A parsed, reusable access-log template.
///
/// Templates use nginx-like `$variable` placeholders. Text outside a
/// placeholder is copied verbatim, and a literal dollar sign is written as
/// `$$`. Example:
///
/// ```
/// use elira_accesslog::Format;
///
/// let format = Format::parse(r#"$remote_addr "$request" $status $request_time"#).unwrap();
/// # let _ = format;
/// ```
///
/// A field that an [`Entry`] cannot provide is written as `-`, following the
/// nginx convention. A `$name` that is not a known variable makes
/// [`Format::parse`] fail with [`Error::UnknownVariable`].
#[derive(Debug, Clone)]
pub struct Format {
    parts: Vec<Part>,
}

#[derive(Debug, Clone)]
enum Part {
    Literal(String),
    Variable(Variable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variable {
    RemoteAddr,
    RemotePort,
    Host,
    Upstream,
    Request,
    RequestMethod,
    RequestUri,
    ServerProtocol,
    Status,
    BodyBytesSent,
    HttpUserAgent,
    HttpReferer,
    RequestTime,
    RequestId,
    TimeIso8601,
    TimeLocal,
}

impl Variable {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "remote_addr" => Self::RemoteAddr,
            "remote_port" => Self::RemotePort,
            "host" => Self::Host,
            "upstream" => Self::Upstream,
            "request" => Self::Request,
            "request_method" => Self::RequestMethod,
            "request_uri" => Self::RequestUri,
            "server_protocol" => Self::ServerProtocol,
            "status" => Self::Status,
            "body_bytes_sent" => Self::BodyBytesSent,
            "http_user_agent" => Self::HttpUserAgent,
            "http_referer" => Self::HttpReferer,
            "request_time" => Self::RequestTime,
            "request_id" => Self::RequestId,
            "time_iso8601" => Self::TimeIso8601,
            "time_local" => Self::TimeLocal,
            _ => return None,
        })
    }

    fn render(self, entry: &Entry, now: SystemTime, out: &mut String) {
        match self {
            Self::RemoteAddr => {
                let _ = write!(out, "{}", entry.peer);
            }
            // Entry does not track the peer port; nginx writes "-" for an
            // unavailable variable.
            Self::RemotePort => out.push('-'),
            Self::Host => escape_line(&entry.host, out),
            Self::Upstream => match entry.upstream.as_deref().filter(|name| !name.is_empty()) {
                Some(name) => escape_line(name, out),
                None => out.push('-'),
            },
            Self::Request => {
                out.push_str(entry.method.as_str());
                out.push(' ');
                escape_line(&entry.path, out);
                out.push(' ');
                out.push_str(version_str(entry.version));
            }
            Self::RequestMethod => out.push_str(entry.method.as_str()),
            Self::RequestUri => escape_line(&entry.path, out),
            Self::ServerProtocol => out.push_str(version_str(entry.version)),
            Self::Status => {
                let _ = write!(out, "{}", entry.status.as_u16());
            }
            Self::BodyBytesSent => {
                let _ = write!(out, "{}", entry.bytes);
            }
            Self::HttpUserAgent => match entry.user_agent.as_deref().filter(|ua| !ua.is_empty()) {
                Some(ua) => escape_line(ua, out),
                None => out.push('-'),
            },
            // Entry does not track the Referer header.
            Self::HttpReferer => out.push('-'),
            Self::RequestTime => {
                let _ = write!(
                    out,
                    "{}.{:03}",
                    entry.duration.as_secs(),
                    entry.duration.subsec_millis()
                );
            }
            Self::RequestId => escape_line(&entry.request_id, out),
            Self::TimeIso8601 => out.push_str(&format_time_iso8601(now)),
            Self::TimeLocal => out.push_str(&format_time_local(now)),
        }
    }
}

impl Format {
    /// Parse an nginx-like `$variable` template.
    ///
    /// Supported variables are `$remote_addr`, `$remote_port`, `$host`,
    /// `$request`, `$request_method`, `$request_uri`, `$server_protocol`,
    /// `$status`, `$body_bytes_sent`, `$http_user_agent`, `$http_referer`,
    /// `$request_time`, `$request_id`, `$time_iso8601`, and `$time_local`.
    ///
    /// `$request_time` is rendered as seconds with exactly three decimal
    /// places. `$time_iso8601` and `$time_local` use UTC; see the crate
    /// documentation for why `$time_local` is not actually local.
    pub fn parse(template: &str) -> Result<Self, Error> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut rest = template;

        while let Some(dollar) = rest.find('$') {
            literal.push_str(&rest[..dollar]);
            let after = &rest[dollar + 1..];

            // "$$" is an escaped literal dollar sign.
            if let Some(after) = after.strip_prefix('$') {
                literal.push('$');
                rest = after;
                continue;
            }

            let end = after
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(after.len());
            let name = &after[..end];
            let variable =
                Variable::from_name(name).ok_or_else(|| Error::UnknownVariable(name.to_owned()))?;

            if !literal.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut literal)));
            }
            parts.push(Part::Variable(variable));
            rest = &after[end..];
        }

        literal.push_str(rest);
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }

        Ok(Self { parts })
    }

    /// Render one [`Entry`] with this template.
    ///
    /// Textual values are escaped with the same rules as [`Entry::line`], so
    /// the result never contains raw control characters.
    pub fn render(&self, entry: &Entry) -> String {
        let now = SystemTime::now();
        let mut out = String::with_capacity(160);
        for part in &self.parts {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Variable(variable) => variable.render(entry, now, &mut out),
            }
        }
        out
    }
}

/// Error returned when an access-log template cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A template used a `$name` that is not a supported variable.
    ///
    /// The contained string is the variable name without the leading `$`.
    /// A bare trailing `$` yields an empty name.
    UnknownVariable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVariable(name) => write!(f, "unknown access log variable `${name}`"),
        }
    }
}

impl std::error::Error for Error {}

/// A connected Unix datagram socket for local syslog output.
///
/// Messages are sent in `<14>tag: line` form: facility `user` (1) shifted by
/// three bits, severity `info` (6), yielding priority 14.
#[cfg(unix)]
#[derive(Debug)]
pub struct Syslog {
    socket: std::os::unix::net::UnixDatagram,
}

#[cfg(unix)]
impl Syslog {
    /// Connect a datagram socket to `path`, normally `/dev/log`.
    ///
    /// A missing socket is returned as an error so the caller can decide
    /// whether that is a startup failure or a warning.
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let socket = std::os::unix::net::UnixDatagram::unbound()?;
        socket.connect(path)?;
        Ok(Self { socket })
    }

    /// Send one line with the given tag, for example `"elira"`.
    ///
    /// The datagram payload is exactly `<14>tag: line` (no trailing newline).
    pub fn send(&self, tag: &str, line: &str) -> std::io::Result<()> {
        let mut message = String::with_capacity(7 + tag.len() + line.len());
        let _ = write!(message, "<14>{tag}: {line}");
        self.socket.send(message.as_bytes())?;
        Ok(())
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

/// Split a timestamp into UTC year, month, day, hour, minute, and second.
fn utc_parts(now: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since_epoch.as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (rem / 3_600) as u32;
    let minute = ((rem % 3_600) / 60) as u32;
    let second = (rem % 60) as u32;
    (year, month, day, hour, minute, second)
}

/// Convert days since 1970-01-01 to a civil date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, which works for the
/// whole proleptic Gregorian calendar without a time-zone database.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

/// Format `now` as ISO 8601 in UTC, e.g. `2026-11-08T12:34:56+00:00`.
fn format_time_iso8601(now: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = utc_parts(now);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

/// Format `now` in the conventional nginx local-time shape, in UTC.
///
/// The standard library has no local time-zone support, so the offset is
/// always `+0000`. See the crate-level documentation.
fn format_time_local(now: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day, hour, minute, second) = utc_parts(now);
    format!(
        "{day:02}/{}/{year:04}:{hour:02}:{minute:02}:{second:02} +0000",
        MONTHS[(month - 1) as usize]
    )
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
            upstream: None,
        }
    }

    #[test]
    fn line_has_the_documented_shape() {
        assert_eq!(
            entry().line(),
            "203.0.113.5 - [a1b2c3d4e5f60718] \"GET /path HTTP/1.1\" 200 1234 12ms \"curl/8.0\" host=example.com upstream=-"
        );
    }

    #[test]
    fn line_uses_dash_for_missing_user_agent() {
        let mut e = entry();
        e.user_agent = None;
        assert!(e.line().ends_with("\"-\" host=example.com upstream=-"));

        e.user_agent = Some(String::new());
        assert!(e.line().ends_with("\"-\" host=example.com upstream=-"));
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
        assert!(line.ends_with(r#"host=bad\"host upstream=-"#));
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
                r#""user_agent":"ua\"\\\r","request_id":"a1b2c3d4e5f60718","upstream":null}"#
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

    #[test]
    fn format_renders_every_supported_variable() {
        let format = Format::parse(concat!(
            "$remote_addr|$remote_port|$host|$request|$request_method|",
            "$request_uri|$server_protocol|$status|$body_bytes_sent|",
            "$http_user_agent|$http_referer|$request_time|$request_id|$upstream"
        ))
        .unwrap();

        let mut entry = entry();
        entry.upstream = Some("app".to_owned());
        assert_eq!(
            format.render(&entry),
            concat!(
                "203.0.113.5|-|example.com|GET /path HTTP/1.1|GET|/path|",
                "HTTP/1.1|200|1234|curl/8.0|-|0.012|a1b2c3d4e5f60718|app"
            )
        );
    }

    #[test]
    fn format_renders_the_time_variables() {
        let format = Format::parse("$time_iso8601|$time_local").unwrap();
        let rendered = format.render(&entry());
        let (iso, local) = rendered.split_once('|').unwrap();

        assert!(iso.ends_with("+00:00"));
        assert_eq!(iso.len(), "1970-01-01T00:00:00+00:00".len());
        assert!(local.ends_with(" +0000"));
        assert_eq!(local.len(), "01/Jan/1970:00:00:00 +0000".len());
        // Both timestamps come from the same render instant.
        assert_eq!(&iso[8..10], &local[..2]);
    }

    #[test]
    fn time_formatters_use_utc() {
        let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        assert_eq!(format_time_iso8601(time), "2023-11-14T22:13:20+00:00");
        assert_eq!(format_time_local(time), "14/Nov/2023:22:13:20 +0000");
    }

    #[test]
    fn unknown_variable_is_an_error_that_names_it() {
        let err = Format::parse("$remote_addr $nope").unwrap_err();
        assert_eq!(err, Error::UnknownVariable("nope".to_owned()));
        assert!(err.to_string().contains("$nope"));
        assert_eq!(
            Format::parse("$").unwrap_err(),
            Error::UnknownVariable(String::new())
        );
    }

    #[test]
    fn double_dollar_is_a_literal_dollar() {
        let format = Format::parse("$$remote_addr $$$host cost $$5").unwrap();
        assert_eq!(format.render(&entry()), "$remote_addr $example.com cost $5");
    }

    #[test]
    fn missing_fields_render_as_dash() {
        let format = Format::parse("$http_user_agent|$http_referer|$remote_port").unwrap();
        let mut e = entry();

        e.user_agent = None;
        assert_eq!(format.render(&e), "-|-|-");

        e.user_agent = Some(String::new());
        assert_eq!(format.render(&e), "-|-|-");
    }

    #[test]
    fn request_time_always_has_three_decimals() {
        let format = Format::parse("$request_time").unwrap();
        let mut e = entry();

        e.duration = Duration::from_millis(12);
        assert_eq!(format.render(&e), "0.012");

        e.duration = Duration::from_millis(1_500);
        assert_eq!(format.render(&e), "1.500");

        e.duration = Duration::from_micros(1);
        assert_eq!(format.render(&e), "0.000");

        e.duration = Duration::from_secs(59) + Duration::from_millis(999);
        assert_eq!(format.render(&e), "59.999");
    }

    #[test]
    fn format_escapes_control_characters() {
        let mut e = entry();
        e.path = "/a\nb".to_owned();

        assert_eq!(
            Format::parse("$request_uri").unwrap().render(&e),
            "/a\\x0ab"
        );
    }

    #[test]
    fn format_does_not_change_json_output() {
        assert!(entry().json().starts_with(r#"{"peer":"203.0.113.5","#));
    }

    #[cfg(unix)]
    fn socket_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "elira-accesslog-{}-{name}-{}.sock",
            std::process::id(),
            request_id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[cfg(unix)]
    #[test]
    fn syslog_open_fails_when_socket_is_missing() {
        let path = socket_path("missing");
        let err = Syslog::open(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn syslog_sends_priority_tag_and_line() {
        use std::os::unix::net::UnixDatagram;

        let path = socket_path("send");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let syslog = Syslog::open(&path).unwrap();
        syslog.send("elira", "GET /path 200").unwrap();

        let mut buffer = [0_u8; 128];
        let len = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"<14>elira: GET /path 200");

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn syslog_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Syslog>();
    }
}
