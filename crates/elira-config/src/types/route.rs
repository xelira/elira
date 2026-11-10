//! Routing, rewrites and named variables.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub pattern: String,
    pub replacement: String,
    #[serde(default)]
    pub flag: RewriteFlag,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteFlag {
    #[default]
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Map {
    pub name: String,
    /// Source variable including the leading `$`.
    pub source: String,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    pub name: String,
    #[serde(default)]
    pub default: Option<String>,
    /// Network or address to value.
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Split {
    pub name: String,
    /// Source variable including the leading `$`.
    pub source: String,
    pub buckets: Vec<SplitBucket>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SplitBucket {
    /// Percentage of the hash space, 1..100.
    pub percent: u8,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMatch {
    #[default]
    Prefix,
    Exact,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Satisfy {
    #[default]
    All,
    Any,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRewrite {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheValid {
    pub statuses: Vec<u16>,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureLink {
    /// Shared secret used by the MD5 calculation.
    pub secret: String,
    /// Template for the `md5` query argument. When omitted, the hash is the
    /// first path segment.
    #[serde(default)]
    pub md5: Option<String>,
    /// Template for the expiry Unix timestamp. Required together with `md5`.
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Host to match, case-insensitive. `*` catches everything else, and
    /// `*.example.com` matches any subdomain. Nested locations inherit the
    /// parent host when this is empty.
    #[serde(default)]
    pub host: String,

    /// Restrict the route to named listeners. Empty means every listener.
    #[serde(default)]
    pub listeners: Vec<String>,

    /// Path prefix. The longest matching prefix wins inside a host. A nested
    /// location appends this to its parent path.
    #[serde(default)]
    pub path: Option<String>,

    /// Nested locations, matched after the parent prefix. They inherit the
    /// parent host, listeners, target and unset options.
    #[serde(default)]
    pub locations: Vec<Route>,

    /// Literal prefix that a nested regex location must stay under. Set while
    /// flattening nested locations; it is not part of the TOML syntax.
    #[serde(skip)]
    pub regex_prefix: Option<String>,

    /// Named location such as `@fallback`. Named locations are never matched
    /// by URL; `try_files` reaches them through an internal redirect.
    #[serde(default)]
    pub name: Option<String>,

    /// Only serve this route after an internal redirect. Direct requests get
    /// a 404.
    #[serde(default)]
    pub internal: bool,

    /// `prefix` (default) or `exact`, like `location = /path`.
    #[serde(default, rename = "match")]
    pub match_type: RouteMatch,

    /// Skip regex routes when this prefix matches, like `location ^~`.
    #[serde(default)]
    pub no_regex: bool,

    /// Regular expression matched against the path after prefix routes.
    #[serde(default)]
    pub path_regex: Option<String>,

    /// Name of an upstream to proxy to. Exactly one target.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Directory to serve files from. Exactly one target.
    #[serde(default)]
    pub root: Option<PathBuf>,

    /// Serve files from this directory by stripping `path`, nginx-style.
    #[serde(default)]
    pub alias: Option<PathBuf>,

    /// Add `Cache-Control`/`Expires` for static responses.
    #[serde(default)]
    pub expires_secs: Option<u64>,

    /// Emit an `ETag` for static responses. Defaults to true.
    #[serde(default)]
    pub etag: Option<bool>,

    /// Honour `If-Modified-Since` for static responses. Defaults to true.
    #[serde(default)]
    pub if_modified_since: Option<bool>,

    /// Redirect instead of proxying or serving. Exactly one target.
    #[serde(default)]
    pub redirect: Option<Redirect>,

    /// Return a fixed status and body, with variable expansion. Exactly one
    /// target.
    #[serde(default, rename = "return")]
    pub return_response: Option<RouteReturn>,

    /// Conditional returns evaluated before the route target.
    #[serde(default, rename = "if")]
    pub if_conditions: Vec<RouteIf>,

    /// FastCGI target: `host:port` or `unix:/path`.
    #[serde(default)]
    pub fastcgi_pass: Option<String>,

    /// Document root used to build `SCRIPT_FILENAME`.
    #[serde(default)]
    pub fastcgi_root: Option<PathBuf>,

    /// Script appended when the request path ends with `/`.
    #[serde(default = "Route::default_fastcgi_index")]
    pub fastcgi_index: String,

    /// Extra FastCGI params as `NAME: value`.
    #[serde(default)]
    pub fastcgi_param: Vec<String>,

    /// Extra CGI environment variables as `NAME: value`.
    #[serde(default)]
    pub cgi_param: Vec<String>,

    /// SCGI target: `host:port` or `unix:/path`.
    #[serde(default)]
    pub scgi_pass: Option<String>,

    /// Document root exposed to the SCGI application.
    #[serde(default)]
    pub scgi_root: Option<PathBuf>,

    /// Extra SCGI params as `NAME: value`.
    #[serde(default)]
    pub scgi_param: Vec<String>,

    /// uWSGI target: `host:port` or `unix:/path`.
    #[serde(default)]
    pub uwsgi_pass: Option<String>,

    /// uWSGI request modifier 1.
    #[serde(default)]
    pub uwsgi_modifier1: Option<u8>,

    /// uWSGI request modifier 2.
    #[serde(default)]
    pub uwsgi_modifier2: Option<u8>,

    /// Extra uWSGI params as `NAME: value`.
    #[serde(default)]
    pub uwsgi_param: Vec<String>,

    /// AJP target: `host:port` or `unix:/path`.
    #[serde(default)]
    pub ajp_pass: Option<String>,

    /// AJP shared secret sent as the `secret` request attribute.
    #[serde(default)]
    pub ajp_secret: Option<String>,

    /// CGI script to execute for this route.
    #[serde(default)]
    pub cgi_pass: Option<PathBuf>,

    /// Native dynamic module (`.so`) handling this route.
    #[serde(default)]
    pub module: Option<PathBuf>,

    /// Run the module in a child process instead of in the server process.
    #[serde(default)]
    pub module_sandbox: bool,

    /// WebAssembly module handling this route.
    #[serde(default)]
    pub wasm: Option<PathBuf>,

    /// Concurrent FastCGI/CGI/module requests allowed for this route. Defaults
    /// to 16 for application targets and is ignored for static/proxy routes.
    #[serde(default)]
    pub max_concurrent: Option<usize>,

    /// Files tried for a directory request, in order.
    #[serde(default = "Route::default_index")]
    pub index: Vec<String>,

    /// Serve the first index file for missing paths. For client-side routers.
    #[serde(default)]
    pub spa: bool,

    /// Remove the matched path prefix before forwarding to the upstream.
    #[serde(default)]
    pub strip_prefix: bool,

    /// Candidates tried, in order, when the path does not exist. `$uri` is
    /// replaced with the request path.
    #[serde(default)]
    pub try_files: Vec<String>,

    /// Generate a directory listing when no index file exists.
    #[serde(default)]
    pub autoindex: bool,

    /// htpasswd file with bcrypt hashes. Empty means no authentication.
    #[serde(default)]
    pub auth_file: Option<PathBuf>,

    /// CIDR blocks allowed to reach this route.
    #[serde(default)]
    pub ip_allow: Vec<String>,

    /// CIDR blocks refused on this route; wins over `ip_allow`.
    #[serde(default)]
    pub ip_deny: Vec<String>,

    /// Overrides `limits.upstream_timeout_secs` for this route. This is the
    /// deadline for the upstream response headers.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// Overrides `limits.upstream_connect_timeout_secs` for this route.
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,

    /// Overrides `limits.upstream_send_timeout_secs` for this route. Zero
    /// disables the send idle check.
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,

    /// Overrides `limits.requests_per_second` for this route. Zero inherits.
    #[serde(default)]
    pub requests_per_second: Option<u32>,

    /// Bucket depth for the route limiter. Zero means the same as the rate.
    #[serde(default)]
    pub burst: Option<u32>,

    /// What identifies a client for this route's limiter: `ip` (default),
    /// `authorization`, `header:NAME` or `cookie:NAME`.
    #[serde(default)]
    pub rate_key: Option<String>,

    /// Concurrent requests allowed per client IP on this route. Zero disables
    /// the limit.
    #[serde(default)]
    pub limit_conn: Option<u32>,

    /// Delay requests over the rate instead of rejecting them until the burst
    /// queue is full. False keeps nginx's `nodelay` behaviour.
    #[serde(default)]
    pub rate_delay: Option<bool>,

    /// Overrides `limits.max_body_bytes` for this route.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,

    /// Overrides `limits.max_response_bytes` for streamed app responses.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,

    /// Overrides `limits.max_upstream_response_bytes` for proxied responses.
    #[serde(default)]
    pub max_upstream_response_bytes: Option<usize>,

    /// Overrides `limits.limit_rate` for this route.
    #[serde(default)]
    pub limit_rate: Option<u64>,

    /// Overrides `limits.limit_rate_after` for this route.
    #[serde(default)]
    pub limit_rate_after: Option<u64>,

    /// Idle FastCGI connections kept for this route's backend.
    #[serde(default)]
    pub fastcgi_pool_idle: Option<usize>,

    /// Keep several FastCGI requests in flight on one connection. The server
    /// must support `FCGI_MPXS_CONNS`; request and response bodies are
    /// buffered in this mode.
    #[serde(default)]
    pub fastcgi_multiplex: bool,

    /// Overrides whether this route uses the shared cache.
    #[serde(default)]
    pub cache_enabled: Option<bool>,

    /// Named cache zone from `[cache.zones.NAME]`. Empty uses the default
    /// `[cache]` zone.
    #[serde(default)]
    pub cache_zone: Option<String>,

    /// Overrides the cache TTL for this route.
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,

    /// Cache key template. Defaults to host plus path and query.
    #[serde(default)]
    pub cache_key: Option<String>,

    /// Variables whose non-empty, non-`0` value bypasses the cache.
    #[serde(default)]
    pub cache_bypass: Vec<String>,

    /// Per-status cache TTLs. The first matching status wins over
    /// `cache_ttl_secs`.
    #[serde(default)]
    pub cache_valid: Vec<CacheValid>,

    /// Write this route's requests to the access log.
    #[serde(default = "Route::default_access_log")]
    pub access_log: bool,

    /// Fraction of this route's requests to log. Overrides `log.sample`.
    #[serde(default)]
    pub access_log_sample: Option<f64>,

    /// Require a verified client certificate on this route.
    #[serde(default)]
    pub client_auth: bool,

    /// Require this subject common name.
    #[serde(default)]
    pub client_cn: Option<String>,

    /// Require this issuer common name.
    #[serde(default)]
    pub client_issuer_cn: Option<String>,

    /// Error pages as `STATUS /path.html`, served from `error_root` or `root`.
    #[serde(default)]
    pub error_pages: Vec<String>,

    /// Directory for `error_pages` when the route proxies instead of serving.
    #[serde(default)]
    pub error_root: Option<PathBuf>,

    /// Response headers to set, as `Name: value`.
    #[serde(default)]
    pub add_headers: Vec<String>,

    /// Response headers to drop.
    #[serde(default)]
    pub remove_headers: Vec<String>,

    /// Upstream response headers to drop.
    #[serde(default)]
    pub proxy_hide_header: Vec<String>,

    /// Upstream response headers to keep even when hidden.
    #[serde(default)]
    pub proxy_pass_header: Vec<String>,

    /// Rewrite `Location` and `Refresh` prefixes from upstream.
    #[serde(default)]
    pub proxy_redirect: Vec<HeaderRewrite>,

    /// Rewrite the `Domain` attribute of upstream `Set-Cookie` headers.
    #[serde(default)]
    pub proxy_cookie_domain: Vec<HeaderRewrite>,

    /// Rewrite the `Path` attribute of upstream `Set-Cookie` headers.
    #[serde(default)]
    pub proxy_cookie_path: Vec<HeaderRewrite>,

    /// Request headers to set or replace before forwarding, as `Name: value`.
    #[serde(default)]
    pub request_headers: Vec<String>,

    /// Request headers to drop before forwarding.
    #[serde(default)]
    pub request_remove_headers: Vec<String>,

    /// Internal URI whose 2xx response authorises this route.
    #[serde(default)]
    pub auth_request: Option<String>,

    /// `all` requires every access check, `any` accepts one.
    #[serde(default)]
    pub satisfy: Option<Satisfy>,

    /// MD5-signed link check.
    #[serde(default)]
    pub secure_link: Option<SecureLink>,

    /// Only files under this root may be returned through `X-Sendfile`.
    #[serde(default)]
    pub x_sendfile_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub to: String,
    #[serde(default = "Redirect::default_status")]
    pub status: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteReturn {
    pub status: u16,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIf {
    /// Variable including the leading `$`.
    pub variable: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub matches: Option<String>,
    #[serde(default, rename = "return")]
    pub return_response: Option<RouteReturn>,
}

impl Route {
    pub(crate) fn default_index() -> Vec<String> {
        vec!["index.html".to_owned()]
    }

    pub(crate) fn default_fastcgi_index() -> String {
        "index.php".to_owned()
    }

    pub(crate) fn default_access_log() -> bool {
        true
    }
}

impl Redirect {
    fn default_status() -> u16 {
        302
    }
}
