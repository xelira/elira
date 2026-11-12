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

    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Split {
    pub name: String,

    pub source: String,
    pub buckets: Vec<SplitBucket>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SplitBucket {
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
    pub secret: String,

    #[serde(default)]
    pub md5: Option<String>,

    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub host: String,

    #[serde(default)]
    pub listeners: Vec<String>,

    #[serde(default)]
    pub path: Option<String>,

    #[serde(default)]
    pub locations: Vec<Route>,

    #[serde(skip)]
    pub regex_prefix: Option<String>,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub internal: bool,

    #[serde(default, rename = "match")]
    pub match_type: RouteMatch,

    #[serde(default)]
    pub no_regex: bool,

    #[serde(default)]
    pub path_regex: Option<String>,

    #[serde(default)]
    pub upstream: Option<String>,

    #[serde(default)]
    pub root: Option<PathBuf>,

    #[serde(default)]
    pub alias: Option<PathBuf>,

    #[serde(default)]
    pub expires_secs: Option<u64>,

    #[serde(default)]
    pub etag: Option<bool>,

    #[serde(default)]
    pub if_modified_since: Option<bool>,

    #[serde(default)]
    pub redirect: Option<Redirect>,

    #[serde(default, rename = "return")]
    pub return_response: Option<RouteReturn>,

    #[serde(default, rename = "if")]
    pub if_conditions: Vec<RouteIf>,

    #[serde(default)]
    pub fastcgi_pass: Option<String>,

    #[serde(default)]
    pub fastcgi_root: Option<PathBuf>,

    #[serde(default = "Route::default_fastcgi_index")]
    pub fastcgi_index: String,

    #[serde(default)]
    pub fastcgi_param: Vec<String>,

    #[serde(default)]
    pub cgi_param: Vec<String>,

    #[serde(default)]
    pub scgi_pass: Option<String>,

    #[serde(default)]
    pub scgi_root: Option<PathBuf>,

    #[serde(default)]
    pub scgi_param: Vec<String>,

    #[serde(default)]
    pub uwsgi_pass: Option<String>,

    #[serde(default)]
    pub uwsgi_modifier1: Option<u8>,

    #[serde(default)]
    pub uwsgi_modifier2: Option<u8>,

    #[serde(default)]
    pub uwsgi_param: Vec<String>,

    #[serde(default)]
    pub ajp_pass: Option<String>,

    #[serde(default)]
    pub ajp_secret: Option<String>,

    #[serde(default)]
    pub cgi_pass: Option<PathBuf>,

    #[serde(default)]
    pub module: Option<PathBuf>,

    #[serde(default)]
    pub module_sandbox: bool,

    #[serde(default)]
    pub wasm: Option<PathBuf>,

    #[serde(default)]
    pub max_concurrent: Option<usize>,

    #[serde(default = "Route::default_index")]
    pub index: Vec<String>,

    #[serde(default)]
    pub spa: bool,

    #[serde(default)]
    pub strip_prefix: bool,

    #[serde(default)]
    pub try_files: Vec<String>,

    #[serde(default)]
    pub autoindex: bool,

    #[serde(default)]
    pub auth_file: Option<PathBuf>,

    #[serde(default)]
    pub ip_allow: Vec<String>,

    #[serde(default)]
    pub ip_deny: Vec<String>,

    #[serde(default)]
    pub timeout_secs: Option<u64>,

    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,

    #[serde(default)]
    pub send_timeout_secs: Option<u64>,

    #[serde(default)]
    pub requests_per_second: Option<u32>,

    #[serde(default)]
    pub burst: Option<u32>,

    #[serde(default)]
    pub rate_key: Option<String>,

    #[serde(default)]
    pub limit_conn: Option<u32>,

    #[serde(default)]
    pub limit_conn_key: Option<String>,

    #[serde(default)]
    pub rate_delay: Option<bool>,

    #[serde(default)]
    pub max_body_bytes: Option<usize>,

    #[serde(default)]
    pub max_response_bytes: Option<usize>,

    #[serde(default)]
    pub max_upstream_response_bytes: Option<usize>,

    #[serde(default)]
    pub limit_rate: Option<u64>,

    #[serde(default)]
    pub limit_rate_after: Option<u64>,

    #[serde(default)]
    pub fastcgi_pool_idle: Option<usize>,

    #[serde(default)]
    pub fastcgi_multiplex: bool,

    #[serde(default)]
    pub cache_enabled: Option<bool>,

    #[serde(default)]
    pub cache_zone: Option<String>,

    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,

    #[serde(default)]
    pub cache_key: Option<String>,

    #[serde(default)]
    pub cache_bypass: Vec<String>,

    #[serde(default)]
    pub cache_valid: Vec<CacheValid>,

    #[serde(default)]
    pub early_hints: Vec<String>,

    #[serde(default = "Route::default_access_log")]
    pub access_log: bool,

    #[serde(default)]
    pub access_log_sample: Option<f64>,

    #[serde(default)]
    pub client_auth: bool,

    #[serde(default)]
    pub client_cn: Option<String>,

    #[serde(default)]
    pub client_issuer_cn: Option<String>,

    #[serde(default)]
    pub error_pages: Vec<String>,

    #[serde(default)]
    pub error_root: Option<PathBuf>,

    #[serde(default)]
    pub add_headers: Vec<String>,

    #[serde(default)]
    pub remove_headers: Vec<String>,

    #[serde(default)]
    pub proxy_hide_header: Vec<String>,

    #[serde(default)]
    pub proxy_pass_header: Vec<String>,

    #[serde(default)]
    pub proxy_redirect: Vec<HeaderRewrite>,

    #[serde(default)]
    pub proxy_cookie_domain: Vec<HeaderRewrite>,

    #[serde(default)]
    pub proxy_cookie_path: Vec<HeaderRewrite>,

    #[serde(default)]
    pub request_headers: Vec<String>,

    #[serde(default)]
    pub request_remove_headers: Vec<String>,

    #[serde(default)]
    pub auth_request: Option<String>,

    #[serde(default)]
    pub satisfy: Option<Satisfy>,

    #[serde(default)]
    pub secure_link: Option<SecureLink>,

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
