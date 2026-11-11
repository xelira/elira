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
        Err(Error::DuplicateRoute { .. })
    ));
}

#[test]
fn allows_one_host_with_several_paths() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
path = "/api"
upstream = "app"

[[routes]]
host = "*"
upstream = "app"
"#;
    assert!(Config::parse(text).is_ok());
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
fn health_probe_settings_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[health]
enabled = true
method = "HEAD"
expect_status = [200, 204]
host = "health.example.com"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]
health_method = "GET"
health_expect_status = [200]
health_host = "app.internal"

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid");
    let health = &cfg.health;
    assert_eq!(health.method, "HEAD");
    assert_eq!(health.expect_status, vec![200, 204]);
    assert_eq!(
        cfg.upstreams[0].health_expect_status.as_deref(),
        Some([200].as_slice())
    );

    let bad_method = base.replace("method = \"HEAD\"", "method = \"POST\"");
    assert!(matches!(
        Config::parse(&bad_method),
        Err(Error::BadHealthMethod { .. })
    ));

    let bad_status = base.replace("expect_status = [200, 204]", "expect_status = [999]");
    assert!(matches!(
        Config::parse(&bad_status),
        Err(Error::BadHealthStatus)
    ));

    let bad_host = base.replace("host = \"health.example.com\"", "host = \"bad host\"");
    assert!(matches!(
        Config::parse(&bad_host),
        Err(Error::BadHealthHost)
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
    let text = format!("{MINIMAL}\n[http3]\nlisten = \"127.0.0.1:4433\"\ncert = \"cert.pem\"\n");
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
fn rejects_a_bad_trusted_proxy_cidr() {
    let text = format!("{MINIMAL}\n[limits]\ntrusted_proxies = [\"10.0.0.0/8\", \"nope\"]\n");
    assert!(matches!(
        Config::parse(&text),
        Err(Error::BadTrustedProxy { .. })
    ));
}

#[test]
fn compression_is_on_by_default() {
    let cfg = Config::parse(MINIMAL).expect("valid config");
    assert!(cfg.compression.enabled);
    assert_eq!(cfg.compression.min_bytes, 1024);
}

#[test]
fn parses_balance_and_retries() {
    let text = MINIMAL.replace(
        "servers = [\"127.0.0.1:3000\"]",
        "servers = [\"127.0.0.1:3000\"]\nbalance = \"least_conn\"\nretries = 2",
    );
    let cfg = Config::parse(&text).expect("valid config");
    assert_eq!(cfg.upstreams[0].balance, Balance::LeastConn);
    assert_eq!(cfg.upstreams[0].retries, 2);
}

#[test]
fn rejects_unknown_balance() {
    let text = MINIMAL.replace(
        "servers = [\"127.0.0.1:3000\"]",
        "servers = [\"127.0.0.1:3000\"]\nbalance = \"shuffle\"",
    );
    assert!(matches!(Config::parse(&text), Err(Error::Toml(_))));
}

#[test]
fn rejects_too_many_retries() {
    let text = MINIMAL.replace(
        "servers = [\"127.0.0.1:3000\"]",
        "servers = [\"127.0.0.1:3000\"]\nretries = 9",
    );
    assert!(matches!(
        Config::parse(&text),
        Err(Error::TooManyRetries { .. })
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

#[test]
fn parses_path_wildcard_redirect_and_headers() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*.example.com"
path = "/api"
upstream = "app"
strip_prefix = true
add_headers = ["X-Frame-Options: DENY"]
remove_headers = ["X-Powered-By"]

[[routes]]
host = "old.example.com"
redirect = { to = "https://new.example.com", status = 301 }
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert_eq!(cfg.routes[0].path.as_deref(), Some("/api"));
    assert!(cfg.routes[0].strip_prefix);
    assert_eq!(cfg.routes[0].add_headers.len(), 1);
    assert_eq!(cfg.routes[1].redirect.as_ref().map(|r| r.status), Some(301));
}

#[test]
fn rejects_a_bad_redirect_status() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 200 }
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::BadRedirectStatus { .. })
    ));
}

#[test]
fn rejects_strip_prefix_without_upstream() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
strip_prefix = true
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::StripWithoutUpstream { .. })
    ));
}

#[test]
fn rejects_a_path_without_a_leading_slash() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
path = "api"
upstream = "app"
"#;
    assert!(matches!(Config::parse(text), Err(Error::BadPath { .. })));
}

#[test]
fn rejects_a_header_without_a_colon() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
add_headers = ["X-Broken"]
"#;
    assert!(matches!(Config::parse(text), Err(Error::BadHeader { .. })));
}

#[test]
fn rejects_a_malformed_wildcard() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "api.*.example.com"
upstream = "app"
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::BadWildcardHost { .. })
    ));
}

#[test]
fn cache_is_off_by_default() {
    let cfg = Config::parse(MINIMAL).expect("valid config");
    assert!(!cfg.cache.enabled);
    assert_eq!(cfg.cache.ttl_secs, 60);
    assert!(cfg.server_header);
}

#[test]
fn rejects_acme_and_tls_together() {
    let text = r#"
listen = "127.0.0.1:8080"

[tls]
cert = "cert.pem"
key = "key.pem"

[acme]
domains = ["example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
    assert!(matches!(Config::parse(text), Err(Error::TlsAndAcme)));
}

#[test]
fn parses_try_files_autoindex_and_upstream_tls() {
    let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
insecure = true

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
tls = true

[[routes]]
host = "*"
root = "/srv"
try_files = ["$uri", "$uri.html"]
autoindex = true
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert_eq!(cfg.routes[0].try_files.len(), 2);
    assert!(cfg.routes[0].autoindex);
    assert!(cfg.upstreams[0].tls);
    assert!(cfg.upstream_tls.insecure);
}

#[test]
fn upstream_tls_client_auth_requires_paired_files() {
    let base = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
client_cert = "/tmp/client.pem"
client_key = "/tmp/client.key"
client_crl = "/tmp/revoked.pem"
cipher_suites = ["TLS13_AES_128_GCM_SHA256"]
curves = ["X25519"]

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(
        cfg.upstream_tls.client_cert.as_deref(),
        Some(std::path::Path::new("/tmp/client.pem"))
    );
    assert_eq!(cfg.upstream_tls.cipher_suites.as_ref().unwrap().len(), 1);
    assert_eq!(cfg.upstream_tls.curves.as_ref().unwrap().len(), 1);

    let missing_key = base.replace("client_key = \"/tmp/client.key\"\n", "");
    assert!(matches!(
        Config::parse(&missing_key),
        Err(Error::BadUpstreamTls)
    ));

    let empty_cert = base.replace("client_cert = \"/tmp/client.pem\"", "client_cert = \"\"");
    assert!(matches!(
        Config::parse(&empty_cert),
        Err(Error::BadUpstreamTls)
    ));

    let empty_crl = base.replace("client_crl = \"/tmp/revoked.pem\"", "client_crl = \"\"");
    assert!(matches!(
        Config::parse(&empty_crl),
        Err(Error::BadUpstreamTls)
    ));
}

#[test]
fn rejects_autoindex_without_root() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
autoindex = true
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::AutoindexWithoutRoot { .. })
    ));
}

#[test]
fn parses_a_log_file() {
    let text = format!(
        "{MINIMAL}\n[log]\nfile = \"/var/log/elira/access.log\"\nmax_bytes = 4096\nkeep = 5\n"
    );
    let cfg = Config::parse(&text).expect("valid config");
    assert!(cfg.log.file.is_some());
    assert_eq!(cfg.log.keep, 5);
}

#[test]
fn rejects_a_tiny_log_rotation() {
    let text = format!("{MINIMAL}\n[log]\nfile = \"/tmp/a.log\"\nmax_bytes = 10\n");
    assert!(matches!(
        Config::parse(&text),
        Err(Error::LogRotationTooSmall)
    ));
}

#[test]
fn parses_auth_and_acl() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
auth_file = "/etc/elira/htpasswd"
ip_allow = ["10.0.0.0/8"]
ip_deny = ["10.1.2.3/32"]
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert!(cfg.routes[0].auth_file.is_some());
    assert_eq!(cfg.routes[0].ip_allow.len(), 1);
}

#[test]
fn rejects_a_bad_acl() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
ip_allow = ["10.0.0.0/99"]
"#;
    assert!(matches!(Config::parse(text), Err(Error::BadAcl { .. })));
}

#[test]
fn rejects_a_zero_route_timeout() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
timeout_secs = 0
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::BadRouteTimeout { .. })
    ));
}

#[test]
fn client_auth_needs_a_ca() {
    let text = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_auth = "required"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::TlsClientCaRequired)
    ));
}

#[test]
fn http2_can_be_enabled_for_upstreams() {
    let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
http2 = true

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
tls = true

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert!(cfg.upstream_tls.http2);
}

#[test]
fn parses_sni_certificates() {
    let text = r#"
listen = "127.0.0.1:8443"

[tls]
min_version = "tls13"
client_auth = "off"

[[tls.certificates]]
cert = "/etc/elira/a.pem"
key = "/etc/elira/a.key"
names = ["a.example.com", "*.a.example.com"]

[[tls.certificates]]
cert = "/etc/elira/b.pem"
key = "/etc/elira/b.key"
names = ["b.example.com"]

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
    let cfg = Config::parse(text).expect("valid config");
    let tls = cfg.tls.expect("tls");
    assert_eq!(tls.certificates.len(), 2);
    assert_eq!(tls.min_version, TlsVersion::Tls13);
}

#[test]
fn allows_duplicate_certificate_names_for_dual_certificates() {
    let text = r#"
listen = "127.0.0.1:8443"

[tls]

[[tls.certificates]]
cert = "/etc/elira/rsa.pem"
key = "/etc/elira/rsa.key"
names = ["example.com"]

[[tls.certificates]]
cert = "/etc/elira/ecdsa.pem"
key = "/etc/elira/ecdsa.key"
names = ["example.com"]

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
    let cfg = Config::parse(text).expect("dual certificates");
    assert_eq!(cfg.tls.as_ref().unwrap().certificates.len(), 2);
}

#[test]
fn http3_client_auth_needs_a_ca() {
    let text = r#"
listen = "127.0.0.1:8443"

[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_auth = "required"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::Http3ClientCaRequired)
    ));
}

#[test]
fn parses_per_upstream_overrides_and_route_limits() {
    let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
insecure = true
min_version = "tls13"

[[upstreams]]
name = "app"
servers = ["10.0.0.1:8443"]
tls = true
http2 = true
sni = "app.internal"
health_path = "/ready"
tls_insecure = false

[[routes]]
host = "*"
upstream = "app"
requests_per_second = 10
burst = 20
max_body_bytes = 1024
error_pages = ["404 /404.html"]
error_root = "/srv/errors"
"#;
    let cfg = Config::parse(text).expect("valid config");
    let up = &cfg.upstreams[0];
    assert_eq!(up.sni.as_deref(), Some("app.internal"));
    assert_eq!(up.health_path.as_deref(), Some("/ready"));
    assert_eq!(up.http2, Some(true));
    let route = &cfg.routes[0];
    assert_eq!(route.requests_per_second, Some(10));
    assert_eq!(route.error_pages.len(), 1);
}

#[test]
fn rejects_a_bad_error_page() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
error_pages = ["404 nope"]
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::BadErrorPage { .. })
    ));
}

#[test]
fn tls_policy_lists_must_not_be_empty() {
    let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
cipher_suites = ["TLS13_AES_128_GCM_SHA256"]
curves = ["X25519"]

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    let tls = cfg.tls.expect("tls");
    assert_eq!(tls.cipher_suites.as_ref().map(Vec::len), Some(1));

    let empty_suites = base.replace(
        "cipher_suites = [\"TLS13_AES_128_GCM_SHA256\"]",
        "cipher_suites = []",
    );
    assert!(matches!(
        Config::parse(&empty_suites),
        Err(Error::EmptyTlsList { .. })
    ));

    let blank_curve = base.replace("curves = [\"X25519\"]", "curves = [\" \"]");
    assert!(matches!(
        Config::parse(&blank_curve),
        Err(Error::BlankTlsListEntry { .. })
    ));
}

#[test]
fn route_client_auth_needs_a_tls_listener() {
    let text = r#"
listen = "127.0.0.1:8080"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_ca = "/tmp/ca.pem"
client_auth = "optional"

[[routes]]
host = "*"
root = "/srv/www"
client_auth = true
client_cn = "service-a"
client_issuer_cn = "client-ca"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert!(cfg.routes[0].client_auth);
    assert_eq!(cfg.routes[0].client_cn.as_deref(), Some("service-a"));

    let no_tls = text.replace(
            "[tls]\ncert = \"/tmp/cert.pem\"\nkey = \"/tmp/key.pem\"\nclient_ca = \"/tmp/ca.pem\"\nclient_auth = \"optional\"\n",
            "",
        );
    assert!(matches!(
        Config::parse(&no_tls),
        Err(Error::RouteClientAuthWithoutTls { .. })
    ));

    let no_flag = text.replace("client_auth = true\n", "");
    assert!(matches!(
        Config::parse(&no_flag),
        Err(Error::RouteClientFilterWithoutAuth { .. })
    ));

    let empty_cn = text.replace("client_cn = \"service-a\"", "client_cn = \" \"");
    assert!(matches!(
        Config::parse(&empty_cn),
        Err(Error::EmptyClientCn { .. })
    ));
}

#[test]
fn access_log_sampling_is_validated() {
    let text = r#"
listen = "127.0.0.1:8080"

[log]
sample = 0.25

[[routes]]
host = "*"
root = "/srv/www"
access_log_sample = 0.1
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.log.sample, 0.25);
    assert_eq!(cfg.routes[0].access_log_sample, Some(0.1));

    let bad_global = text.replace("sample = 0.25", "sample = 1.5");
    assert!(matches!(
        Config::parse(&bad_global),
        Err(Error::BadLogSample)
    ));

    let bad_route = text.replace("access_log_sample = 0.1", "access_log_sample = -0.1");
    assert!(matches!(
        Config::parse(&bad_route),
        Err(Error::BadRouteLogSample { .. })
    ));
}

#[test]
fn global_error_pages_are_validated() {
    let valid = r#"
listen = "127.0.0.1:8080"
error_root = "/srv/errors"
error_pages = ["404 /404.html", "429 /429.html"]

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(valid).expect("valid");
    assert_eq!(cfg.error_pages.len(), 2);
    assert_eq!(cfg.error_root.as_deref(), Some(Path::new("/srv/errors")));

    let no_root = valid.replace("error_root = \"/srv/errors\"\n", "");
    assert!(matches!(
        Config::parse(&no_root),
        Err(Error::GlobalErrorPagesNeedRoot)
    ));

    let no_pages = valid.replace("error_pages = [\"404 /404.html\", \"429 /429.html\"]\n", "");
    assert!(matches!(
        Config::parse(&no_pages),
        Err(Error::GlobalErrorRootWithoutPages)
    ));

    let bad = valid.replace("\"404 /404.html\"", "\"404 nope\"");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadGlobalErrorPage { .. })
    ));
}

#[test]
fn request_headers_are_validated() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
request_headers = ["X-Service-Token: secret"]
request_remove_headers = ["X-Client-Secret"]
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.routes[0].request_headers.len(), 1);

    let bad = text.replace("X-Service-Token: secret", "nope");
    assert!(matches!(Config::parse(&bad), Err(Error::BadHeader { .. })));

    let reserved = text.replace("X-Service-Token: secret", "Transfer-Encoding: chunked");
    assert!(matches!(
        Config::parse(&reserved),
        Err(Error::ReservedRequestHeader { .. })
    ));

    let reserved_remove = text.replace("X-Client-Secret", "Connection");
    assert!(matches!(
        Config::parse(&reserved_remove),
        Err(Error::ReservedRequestHeader { .. })
    ));
}

#[test]
fn route_rate_key_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
requests_per_second = 10
rate_key = "header:X-Api-Key"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].rate_key.as_deref(), Some("header:X-Api-Key"));

    for key in ["ip", "authorization", "cookie:session"] {
        let text = base.replace("header:X-Api-Key", key);
        assert!(Config::parse(&text).is_ok(), "{key}");
    }

    for key in ["header:", "query:q", "cookie:"] {
        let text = base.replace("header:X-Api-Key", key);
        assert!(
            matches!(Config::parse(&text), Err(Error::BadRateKey { .. })),
            "{key}"
        );
    }

    let without_rate = base.replace("requests_per_second = 10\n", "");
    assert!(matches!(
        Config::parse(&without_rate),
        Err(Error::RateKeyWithoutRate { .. })
    ));
}

#[test]
fn rejects_a_zero_route_rate() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
requests_per_second = 0
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::BadRouteRate { .. })
    ));
}

#[test]
fn accepts_unix_upstreams_and_rejects_tls_over_them() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["unix:/run/app.sock", "127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#;
    assert!(Config::parse(text).is_ok());

    let tls = text.replace("name = \"app\"", "name = \"app\"\ntls = true");
    assert!(matches!(
        Config::parse(&tls),
        Err(Error::TlsOverUnix { .. })
    ));
}

#[test]
fn parses_disk_cache_and_stale_window() {
    let text = r#"
listen = "127.0.0.1:8080"

[cache]
enabled = true
ttl_secs = 30
stale_secs = 120
dir = "/var/cache/elira"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert_eq!(cfg.cache.stale_secs, 120);
    assert_eq!(
        cfg.cache.dir.as_deref().map(|p| p.to_str().unwrap()),
        Some("/var/cache/elira")
    );
}

#[test]
fn retry_conditions_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]
retries = 2
retry_on = ["error", "timeout", "502", "504"]

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.upstreams[0].retry_on.len(), 4);

    for condition in ["400", "200", "nope"] {
        let text = base.replace("\"504\"", &format!("\"{condition}\""));
        assert!(
            matches!(Config::parse(&text), Err(Error::BadRetryCondition { .. })),
            "{condition}"
        );
    }
}

#[test]
fn upstream_weights_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000", "127.0.0.1:9001"]
weights = [3, 1]

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.upstreams[0].weights, vec![3, 1]);

    let short = base.replace("weights = [3, 1]", "weights = [3]");
    assert!(matches!(
        Config::parse(&short),
        Err(Error::WeightsLength { .. })
    ));

    let zero = base.replace("weights = [3, 1]", "weights = [3, 0]");
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::ZeroWeight { .. })
    ));

    let hash = base.replace("weights = [3, 1]", "weights = [3, 1]\nbalance = \"hash\"");
    assert!(matches!(
        Config::parse(&hash),
        Err(Error::WeightsWithHash { .. })
    ));
}

#[test]
fn hash_balance_key_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000", "127.0.0.1:9001"]
balance = "hash"
hash_key = "header:X-User"

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.upstreams[0].balance, Balance::Hash);
    assert_eq!(cfg.upstreams[0].hash_key.as_deref(), Some("header:X-User"));

    for key in ["ip", "authorization", "cookie:session", "uri"] {
        let text = base.replace("header:X-User", key);
        assert!(Config::parse(&text).is_ok(), "{key}");
    }

    let without = base.replace("hash_key = \"header:X-User\"\n", "");
    assert!(Config::parse(&without).is_ok(), "ip is the default key");

    let bad = base.replace("header:X-User", "query:q");
    assert!(matches!(Config::parse(&bad), Err(Error::BadHashKey { .. })));

    let with_round_robin = base.replace("balance = \"hash\"", "balance = \"round_robin\"");
    assert!(matches!(
        Config::parse(&with_round_robin),
        Err(Error::HashKeyWithoutHashBalance { .. })
    ));
}

#[test]
fn ticket_key_is_validated() {
    let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ticket_key = "/etc/elira/ticket.key"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(
        cfg.tls.expect("tls").ticket_key.as_deref(),
        Some(Path::new("/etc/elira/ticket.key"))
    );

    let empty = base.replace(
        "ticket_key = \"/etc/elira/ticket.key\"",
        "ticket_key = \"\"",
    );
    assert!(matches!(Config::parse(&empty), Err(Error::EmptyTicketKey)));
}

#[test]
fn client_crl_needs_client_auth() {
    let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_ca = "/tmp/ca.pem"
client_crl = "/tmp/ca.crl.pem"
client_auth = "required"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(Config::parse(base).is_ok());

    let no_auth = base.replace("client_auth = \"required\"\n", "");
    assert!(matches!(
        Config::parse(&no_auth),
        Err(Error::ClientCrlWithoutAuth)
    ));

    let empty = base.replace("client_crl = \"/tmp/ca.crl.pem\"", "client_crl = \"\"");
    assert!(matches!(Config::parse(&empty), Err(Error::EmptyClientCrl)));
}

#[test]
fn stream_listeners_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[streams]]
listen = "127.0.0.1:9000"
upstreams = ["127.0.0.1:9001", "127.0.0.1:9002"]

[[streams]]
listen = "127.0.0.1:9003"
transport = "udp"
upstreams = ["127.0.0.1:9004"]

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.streams.len(), 2);

    let bad_upstream = base.replace("\"127.0.0.1:9001\"", "\"unix:/tmp/x\"");
    assert!(matches!(
        Config::parse(&bad_upstream),
        Err(Error::BadStreamUpstream { .. })
    ));

    let duplicate = format!(
        "{base}\n[[streams]]\nlisten = \"127.0.0.1:9000\"\nupstreams = [\"127.0.0.1:9005\"]\n"
    );
    assert!(matches!(
        Config::parse(&duplicate),
        Err(Error::DuplicateStreamListen { .. })
    ));

    let udp_tls = base.replace("transport = \"udp\"", "transport = \"udp\"\ntls = true");
    assert!(matches!(
        Config::parse(&udp_tls),
        Err(Error::StreamTlsOnUdp)
    ));

    let no_upstreams = base.replace(
        "upstreams = [\"127.0.0.1:9001\", \"127.0.0.1:9002\"]",
        "upstreams = []",
    );
    assert!(matches!(
        Config::parse(&no_upstreams),
        Err(Error::EmptyStream)
    ));
}

#[test]
fn process_settings_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"
user = "nobody"
worker_rlimit_nofile = 65536
pid_file = "/run/elira.pid"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.user.as_deref(), Some("nobody"));
    assert_eq!(cfg.worker_rlimit_nofile, Some(65536));

    let empty_user = base.replace("user = \"nobody\"", "user = \" \"");
    assert!(matches!(Config::parse(&empty_user), Err(Error::BadUser)));

    let zero_rlimit = base.replace("worker_rlimit_nofile = 65536", "worker_rlimit_nofile = 0");
    assert!(matches!(Config::parse(&zero_rlimit), Err(Error::BadRlimit)));

    let empty_pid = base.replace("pid_file = \"/run/elira.pid\"", "pid_file = \"\"");
    assert!(matches!(
        Config::parse(&empty_pid),
        Err(Error::EmptyPidFile)
    ));

    let empty_chroot = base.replace(
        "pid_file = \"/run/elira.pid\"",
        "pid_file = \"/run/elira.pid\"\nchroot = \"\"",
    );
    assert!(matches!(
        Config::parse(&empty_chroot),
        Err(Error::EmptyChroot)
    ));

    let empty_cpus = base.replace(
        "pid_file = \"/run/elira.pid\"",
        "pid_file = \"/run/elira.pid\"\nworker_cpu_affinity = []",
    );
    assert!(matches!(
        Config::parse(&empty_cpus),
        Err(Error::BadCpuAffinity)
    ));
}

#[test]
fn additional_listeners_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[listeners]]
listen = "127.0.0.1:8081"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.listeners.len(), 1);

    let tls_listener = base.replace(
        "listen = \"127.0.0.1:8081\"",
        "listen = \"127.0.0.1:8081\"\ntls = true",
    );
    assert!(Config::parse(&tls_listener).is_ok());

    let named = base.replace(
        "listen = \"127.0.0.1:8081\"",
        "listen = \"127.0.0.1:8081\"\nname = \"public\"",
    );
    let named = named.replace(
        "[[routes]]\nhost = \"*\"",
        "[[routes]]\nhost = \"*\"\nlisteners = [\"public\"]",
    );
    assert!(Config::parse(&named).is_ok());

    let unknown = named.replace("listeners = [\"public\"]", "listeners = [\"missing\"]");
    assert!(matches!(
        Config::parse(&unknown),
        Err(Error::UnknownListener { .. })
    ));

    let duplicate_name = base.replace(
        "listen = \"127.0.0.1:8081\"",
        "listen = \"127.0.0.1:8081\"\nname = \"default\"",
    );
    assert!(matches!(
        Config::parse(&duplicate_name),
        Err(Error::DuplicateListenerName { .. })
    ));

    let duplicate = base.replace("listen = \"127.0.0.1:8081\"", "listen = \"127.0.0.1:8080\"");
    assert!(matches!(
        Config::parse(&duplicate),
        Err(Error::DuplicateListener { .. })
    ));

    let no_tls = base.replace(
        "[tls]\ncert = \"/tmp/cert.pem\"\nkey = \"/tmp/key.pem\"\n",
        "",
    );
    let no_tls = no_tls.replace(
        "listen = \"127.0.0.1:8081\"",
        "listen = \"127.0.0.1:8081\"\ntls = true",
    );
    assert!(matches!(
        Config::parse(&no_tls),
        Err(Error::ListenerTlsWithoutConfig)
    ));
}

#[test]
fn unix_socket_permissions_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"
listen_unix = "/run/elira.sock"
listen_unix_mode = 0o660
listen_unix_owner = "1000:1000"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.listen_unix_mode, Some(0o660));
    assert_eq!(cfg.listen_unix_owner.as_deref(), Some("1000:1000"));

    let no_listener = base.replace("listen_unix = \"/run/elira.sock\"\n", "");
    assert!(matches!(
        Config::parse(&no_listener),
        Err(Error::UnixOptionsWithoutListener)
    ));

    let bad_mode = base.replace("0o660", "0o10000");
    assert!(matches!(Config::parse(&bad_mode), Err(Error::BadUnixMode)));

    let bad_owner = base.replace("\"1000:1000\"", "\"nobody\"");
    assert!(matches!(
        Config::parse(&bad_owner),
        Err(Error::BadUnixOwner)
    ));
}

#[test]
fn unix_tls_needs_a_listener_and_certificate() {
    let base = r#"
listen = "127.0.0.1:8080"
listen_unix = "/run/elira.sock"
unix_tls = true

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(Config::parse(base).is_ok());

    let no_listener = base.replace("listen_unix = \"/run/elira.sock\"\n", "");
    assert!(matches!(
        Config::parse(&no_listener),
        Err(Error::UnixTlsWithoutListener)
    ));

    let no_tls = base.replace(
        "[tls]\ncert = \"/tmp/cert.pem\"\nkey = \"/tmp/key.pem\"\n",
        "",
    );
    assert!(matches!(
        Config::parse(&no_tls),
        Err(Error::UnixTlsWithoutTls)
    ));
}

#[test]
fn geo_and_split_variables_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[geos]]
name = "zone"
default = "other"
values = { "127.0.0.0/8" = "loopback" }

[[splits]]
name = "variant"
source = "$http_x_user"
buckets = [{ percent = 40, value = "a" }, { percent = 60, value = "b" }]

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.geos.len(), 1);
    assert_eq!(cfg.splits.len(), 1);

    let bad_geo = base.replace("\"127.0.0.0/8\"", "\"not-a-network\"");
    assert!(matches!(Config::parse(&bad_geo), Err(Error::BadGeo)));

    let bad_split = base.replace("percent = 60", "percent = 70");
    assert!(matches!(Config::parse(&bad_split), Err(Error::BadSplit)));
}

#[test]
fn map_variables_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[maps]]
name = "tenant"
source = "$http_x_tenant"
default = "guest"
values = { acme = "gold" }

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.maps.len(), 1);
    assert_eq!(cfg.maps[0].name, "tenant");

    let bad_name = base.replace("name = \"tenant\"", "name = \"bad name\"");
    assert!(matches!(Config::parse(&bad_name), Err(Error::BadMapName)));

    let bad_source = base.replace("source = \"$http_x_tenant\"", "source = \"http\"");
    assert!(matches!(
        Config::parse(&bad_source),
        Err(Error::BadMapSource)
    ));
}

#[test]
fn rewrite_rules_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[rewrites]]
pattern = "^/old/(.*)$"
replacement = "/new/$1"
flag = "last"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.rewrites.len(), 1);
    assert_eq!(cfg.rewrites[0].flag, RewriteFlag::Last);

    let empty = base.replace("^/old/(.*)$", "");
    assert!(matches!(Config::parse(&empty), Err(Error::BadRewrite)));
}

#[test]
fn nested_locations_are_flattened_and_inherit() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "example.com"
path = "/app"
timeout_secs = 7
return = { status = 200, body = "app" }

[[routes.locations]]
path = "/admin"

[[routes.locations]]
path_regex = "\\.php$"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.routes.len(), 3);

    let admin = &cfg.routes[1];
    assert_eq!(admin.path.as_deref(), Some("/app/admin"));
    assert_eq!(admin.host, "example.com");
    assert_eq!(admin.timeout_secs, Some(7));
    assert_eq!(
        admin
            .return_response
            .as_ref()
            .map(|ret| ret.body.as_deref()),
        Some(Some("app"))
    );

    let php = &cfg.routes[2];
    assert_eq!(php.path, None);
    assert_eq!(php.regex_prefix.as_deref(), Some("/app"));
    assert_eq!(php.path_regex.as_deref(), Some(r"\.php$"));
}

#[test]
fn nested_location_without_a_path_is_rejected() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "example.com"
path = "/app"
return = { status = 200, body = "app" }

[[routes.locations]]
return = { status = 200, body = "child" }
"#;
    assert!(matches!(Config::parse(text), Err(Error::BadNestedLocation)));
}

#[test]
fn scgi_routes_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
scgi_pass = "127.0.0.1:9000"
scgi_param = ["APP_ENV: test"]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].scgi_pass.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(cfg.routes[0].scgi_param.len(), 1);

    let empty = base.replace("127.0.0.1:9000", "");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::EmptyScgiTarget { .. })
    ));

    let bad_root = base.replace(
        "scgi_param = [\"APP_ENV: test\"]",
        "scgi_root = \"\"\nscgi_param = [\"APP_ENV: test\"]",
    );
    assert!(matches!(
        Config::parse(&bad_root),
        Err(Error::BadScgiRoot { .. })
    ));

    let two = base.replace(
        "scgi_pass = \"127.0.0.1:9000\"",
        "scgi_pass = \"127.0.0.1:9000\"\nroot = \"/srv\"",
    );
    assert!(matches!(
        Config::parse(&two),
        Err(Error::RouteHasTwoTargets { .. })
    ));
}

#[test]
fn uwsgi_routes_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
uwsgi_pass = "127.0.0.1:9000"
uwsgi_modifier1 = 9
uwsgi_param = ["APP_ENV: test"]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].uwsgi_pass.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(cfg.routes[0].uwsgi_modifier1, Some(9));

    let empty = base.replace("127.0.0.1:9000", "");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::EmptyUwsgiTarget { .. })
    ));

    let two = base.replace(
        "uwsgi_pass = \"127.0.0.1:9000\"",
        "uwsgi_pass = \"127.0.0.1:9000\"\nroot = \"/srv\"",
    );
    assert!(matches!(
        Config::parse(&two),
        Err(Error::RouteHasTwoTargets { .. })
    ));
}

#[test]
fn ajp_routes_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
ajp_pass = "127.0.0.1:8009"
ajp_secret = "s3cret"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].ajp_pass.as_deref(), Some("127.0.0.1:8009"));
    assert_eq!(cfg.routes[0].ajp_secret.as_deref(), Some("s3cret"));

    let empty = base.replace("127.0.0.1:8009", "");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::EmptyAjpTarget { .. })
    ));

    let two = base.replace(
        "ajp_pass = \"127.0.0.1:8009\"",
        "ajp_pass = \"127.0.0.1:8009\"\nroot = \"/srv\"",
    );
    assert!(matches!(
        Config::parse(&two),
        Err(Error::RouteHasTwoTargets { .. })
    ));
}

#[test]
fn fastcgi_multiplex_needs_fastcgi() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
fastcgi_root = "/srv/app"
fastcgi_multiplex = true
"#;
    let cfg = Config::parse(base).expect("valid");
    assert!(cfg.routes[0].fastcgi_multiplex);

    let no_fastcgi = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
fastcgi_multiplex = true
return = { status = 200, body = "x" }
"#;
    assert!(matches!(
        Config::parse(no_fastcgi),
        Err(Error::MultiplexWithoutFastCgi { .. })
    ));
}

#[test]
fn openssl_tls_backend_is_validated() {
    let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
backend = "openssl"
min_version = "tls10"

[[routes]]
host = "*"
return = { status = 200, body = "ok" }
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(
        cfg.tls.as_ref().map(|tls| tls.backend),
        Some(TlsBackend::Openssl)
    );

    let rustls_legacy = base.replace("backend = \"openssl\"\n", "");
    assert!(matches!(
        Config::parse(&rustls_legacy),
        Err(Error::LegacyTlsNeedsOpenssl)
    ));

    let ticket = base.replace(
        "min_version = \"tls10\"",
        "min_version = \"tls10\"\nticket_key = \"/tmp/ticket\"",
    );
    assert!(Config::parse(&ticket).is_ok());
}

#[test]
fn auth_request_paths_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
path = "/private"
root = "/srv/private"
auth_request = "/auth"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].auth_request.as_deref(), Some("/auth"));

    let relative = base.replace("auth_request = \"/auth\"", "auth_request = \"auth\"");
    assert!(matches!(
        Config::parse(&relative),
        Err(Error::BadAuthRequest { .. })
    ));

    let spaced = base.replace("auth_request = \"/auth\"", "auth_request = \"/a b\"");
    assert!(matches!(
        Config::parse(&spaced),
        Err(Error::BadAuthRequest { .. })
    ));
}

#[test]
fn satisfy_is_parsed() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
satisfy = "any"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].satisfy, Some(Satisfy::Any));

    let default = base.replace("satisfy = \"any\"\n", "");
    let cfg = Config::parse(&default).expect("valid");
    assert_eq!(cfg.routes[0].satisfy, None);

    let invalid = base.replace("satisfy = \"any\"", "satisfy = \"some\"");
    assert!(Config::parse(&invalid).is_err());
}

#[test]
fn secure_link_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
secure_link = { secret = "s3cret", md5 = "$arg_md5", expires = "$arg_expires" }
"#;
    let cfg = Config::parse(base).expect("valid");
    assert!(cfg.routes[0].secure_link.is_some());

    let no_secret = base.replace("secret = \"s3cret\"", "secret = \"\"");
    assert!(matches!(
        Config::parse(&no_secret),
        Err(Error::BadSecureLink { .. })
    ));

    let no_expires = base.replace(", expires = \"$arg_expires\"", "");
    assert!(matches!(
        Config::parse(&no_expires),
        Err(Error::BadSecureLink { .. })
    ));

    let path_form = base.replace(
        "secure_link = { secret = \"s3cret\", md5 = \"$arg_md5\", expires = \"$arg_expires\" }",
        "secure_link = { secret = \"s3cret\" }",
    );
    assert!(Config::parse(&path_form).is_ok());
}

#[test]
fn x_sendfile_root_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
x_sendfile_root = "/srv/files"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(
        cfg.routes[0].x_sendfile_root.as_deref(),
        Some(std::path::Path::new("/srv/files"))
    );

    let empty = base.replace("x_sendfile_root = \"/srv/files\"", "x_sendfile_root = \"\"");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::BadSendfileRoot { .. })
    ));
}

#[test]
fn error_page_status_overrides_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
error_pages = ["404 =200 /404.html"]
"#;
    assert!(Config::parse(base).is_ok());

    let bad = base.replace("=200", "=abc");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadErrorPage { .. })
    ));
}

#[test]
fn if_modified_since_is_optional() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
if_modified_since = false
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].if_modified_since, Some(false));

    let default = base.replace("if_modified_since = false\n", "");
    let cfg = Config::parse(&default).expect("valid");
    assert_eq!(cfg.routes[0].if_modified_since, None);
}

#[test]
fn cache_valid_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
cache_valid = [{ statuses = [200, 404], ttl_secs = 60 }]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].cache_valid.len(), 1);

    let bad_status = base.replace("[200, 404]", "[99, 404]");
    assert!(matches!(
        Config::parse(&bad_status),
        Err(Error::BadCacheValid { .. })
    ));

    let bad_ttl = base.replace("ttl_secs = 60", "ttl_secs = 0");
    assert!(matches!(
        Config::parse(&bad_ttl),
        Err(Error::BadCacheValid { .. })
    ));
}

#[test]
fn proxy_header_rewrites_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
proxy_hide_header = ["x-secret"]
proxy_pass_header = ["x-secret"]
proxy_redirect = [{ from = "http://backend/", to = "https://public/" }]
proxy_cookie_domain = [{ from = "backend", to = "public" }]
proxy_cookie_path = [{ from = "/old", to = "/new" }]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].proxy_hide_header.len(), 1);
    assert_eq!(cfg.routes[0].proxy_redirect.len(), 1);

    let bad_header = base.replace("\"x-secret\"", "\"bad header\"");
    assert!(matches!(
        Config::parse(&bad_header),
        Err(Error::BadHeader { .. })
    ));

    let bad_rewrite = base.replace("from = \"backend\"", "from = \"\"");
    assert!(matches!(
        Config::parse(&bad_rewrite),
        Err(Error::BadProxyRewrite { .. })
    ));
}

#[test]
fn cache_key_and_bypass_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
cache_key = "$host$uri"
cache_bypass = ["$http_x_nocache"]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].cache_key.as_deref(), Some("$host$uri"));
    assert_eq!(cfg.routes[0].cache_bypass.len(), 1);

    let bad_key = base.replace("cache_key = \"$host$uri\"", "cache_key = \"\"");
    assert!(matches!(
        Config::parse(&bad_key),
        Err(Error::BadCacheKey { .. })
    ));

    let bad_bypass = base.replace(
        "cache_bypass = [\"$http_x_nocache\"]",
        "cache_bypass = [\"\"]",
    );
    assert!(matches!(
        Config::parse(&bad_bypass),
        Err(Error::BadCacheKey { .. })
    ));
}

#[test]
fn separate_upstream_timeouts_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[limits]
upstream_timeout_secs = 30
upstream_connect_timeout_secs = 2
upstream_send_timeout_secs = 3

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
connect_timeout_secs = 4
send_timeout_secs = 0
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(cfg.limits.upstream_connect_timeout_secs, 2);
    assert_eq!(cfg.limits.upstream_send_timeout_secs, 3);
    assert_eq!(cfg.routes[0].connect_timeout_secs, Some(4));
    assert_eq!(cfg.routes[0].send_timeout_secs, Some(0));

    let zero_limits = base.replace(
        "upstream_connect_timeout_secs = 2",
        "upstream_connect_timeout_secs = 0",
    );
    assert!(matches!(
        Config::parse(&zero_limits),
        Err(Error::UpstreamConnectTimeoutZero)
    ));

    let zero_route = base.replace("connect_timeout_secs = 4", "connect_timeout_secs = 0");
    assert!(matches!(
        Config::parse(&zero_route),
        Err(Error::BadRouteConnectTimeout { .. })
    ));
}

#[test]
fn proxy_protocol_and_bind_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]
bind = "127.0.0.2"
proxy_protocol = true

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(
        cfg.upstreams[0].bind,
        Some("127.0.0.2".parse().expect("ip"))
    );
    assert!(cfg.upstreams[0].proxy_protocol);

    let h3 = base.replace(
        "proxy_protocol = true",
        "proxy_protocol = true\ntls = true\nh3_pool = true",
    );
    assert!(matches!(
        Config::parse(&h3),
        Err(Error::BadProxyProtocol { .. })
    ));

    let unix = base.replace(
        "servers = [\"127.0.0.1:9000\"]",
        "servers = [\"unix:/tmp/app.sock\"]",
    );
    assert!(matches!(
        Config::parse(&unix),
        Err(Error::BadProxyProtocol { .. })
    ));
}

#[test]
fn keepalive_and_random_balance_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000", "127.0.0.1:9001"]
balance = "random"
keepalive = 0
keepalive_secs = 12
keepalive_requests = 10

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(cfg.upstreams[0].balance, Balance::Random);
    assert_eq!(cfg.upstreams[0].keepalive, Some(0));
    assert_eq!(cfg.upstreams[0].keepalive_secs, Some(12));
    assert_eq!(cfg.upstreams[0].keepalive_requests, Some(10));

    let bad = base.replace("keepalive_secs = 12", "keepalive_secs = 0");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadKeepaliveTtl { .. })
    ));
}

#[test]
fn server_options_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = [
    "127.0.0.1:9000",
    { address = "127.0.0.1:9001", backup = true, max_conns = 20, slow_start_secs = 5 },
]

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid config");
    let servers = &cfg.upstreams[0].servers;
    assert_eq!(servers[0].address(), "127.0.0.1:9000");
    assert!(!servers[0].backup());
    assert_eq!(servers[1].address(), "127.0.0.1:9001");
    assert!(servers[1].backup());
    assert_eq!(servers[1].max_conns(), 20);
    assert_eq!(servers[1].slow_start_secs(), 5);

    let all_down = base.replace(
        "{ address = \"127.0.0.1:9001\", backup = true, max_conns = 20, slow_start_secs = 5 }",
        "{ address = \"127.0.0.1:9001\", down = true }",
    );
    let all_down = all_down.replace(
        "\"127.0.0.1:9000\",",
        "{ address = \"127.0.0.1:9000\", down = true },",
    );
    assert!(matches!(
        Config::parse(&all_down),
        Err(Error::AllServersDown { .. })
    ));
}

#[test]
fn resolver_hosts_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[resolver.hosts]]
name = "backend.test"
addresses = ["127.0.0.1", "::1"]

[[upstreams]]
name = "app"
servers = ["backend.test:9000"]

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(cfg.resolver.hosts.len(), 1);
    assert_eq!(cfg.resolver.hosts[0].addresses.len(), 2);

    let empty = base.replace("addresses = [\"127.0.0.1\", \"::1\"]", "addresses = []");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::EmptyResolverHost { .. })
    ));

    let duplicate = format!(
        "{base}\n[[resolver.hosts]]\nname = \"BACKEND.test\"\naddresses = [\"127.0.0.1\"]\n"
    );
    assert!(matches!(
        Config::parse(&duplicate),
        Err(Error::DuplicateResolverHost { .. })
    ));
}

#[test]
fn cache_zones_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[cache]
enabled = true

[cache.zones.api]
max_bytes = 4096
max_item_bytes = 1024
ttl_secs = 10

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
cache_zone = "api"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(cfg.cache.zones["api"].max_bytes, 4096);
    assert_eq!(cfg.routes[0].cache_zone.as_deref(), Some("api"));

    let unknown = base.replace("cache_zone = \"api\"", "cache_zone = \"missing\"");
    assert!(matches!(
        Config::parse(&unknown),
        Err(Error::UnknownCacheZone { .. })
    ));

    let bad_name = base.replace("[cache.zones.api]", "[cache.zones.\"bad name\"]");
    assert!(matches!(
        Config::parse(&bad_name),
        Err(Error::BadCacheZone { .. })
    ));
}

#[test]
fn rate_limits_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[limits]
limit_rate = 1000
limit_rate_after = 100

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]

[[routes]]
host = "*"
upstream = "app"
limit_rate = 2000
limit_rate_after = 0
rate_delay = true
limit_conn = 4
limit_conn_key = "header:X-Tenant"
"#;
    let cfg = Config::parse(base).expect("valid config");
    assert_eq!(cfg.limits.limit_rate, 1000);
    assert_eq!(cfg.limits.limit_rate_after, 100);
    assert_eq!(cfg.routes[0].limit_rate, Some(2000));
    assert_eq!(cfg.routes[0].limit_rate_after, Some(0));
    assert_eq!(cfg.routes[0].rate_delay, Some(true));
    assert_eq!(cfg.routes[0].limit_conn, Some(4));
    assert_eq!(
        cfg.routes[0].limit_conn_key.as_deref(),
        Some("header:X-Tenant")
    );

    let bad_key = base.replace(
        "limit_conn_key = \"header:X-Tenant\"",
        "limit_conn_key = \"header:bad name\"",
    );
    assert!(matches!(
        Config::parse(&bad_key),
        Err(Error::BadLimitConnKey { .. })
    ));
}

#[test]
fn open_file_cache_is_parsed() {
    let text = r#"
listen = "127.0.0.1:8080"

[limits]
open_file_cache = 128
open_file_cache_ttl_secs = 12

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert_eq!(cfg.limits.open_file_cache, 128);
    assert_eq!(cfg.limits.open_file_cache_ttl_secs, 12);
}

#[test]
fn workers_accept_auto() {
    let base = r#"
listen = "127.0.0.1:8080"
workers = "auto"
reuse_port = true

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(base).expect("auto workers");
    assert!((1..=64).contains(&cfg.workers));

    let bad = base.replace("workers = \"auto\"", "workers = \"many\"");
    assert!(matches!(Config::parse(&bad), Err(Error::Toml(_))));
}

#[test]
fn http2_tuning_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[http2]
max_concurrent_streams = 128
initial_stream_window_size = 65536
initial_connection_window_size = 1048576
max_frame_size = 32768
keep_alive_interval_secs = 10
keep_alive_timeout_secs = 5

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(base).expect("valid http2 config");
    assert_eq!(cfg.http2.max_concurrent_streams, Some(128));
    assert_eq!(cfg.http2.max_frame_size, Some(32768));

    let bad = base.replace("max_frame_size = 32768", "max_frame_size = 1024");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadHttp2Setting { .. })
    ));
}

#[test]
fn http3_transport_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[http3]
listen = "127.0.0.1:4433"
cert = "cert.pem"
key = "key.pem"
max_concurrent_bidi_streams = 128
stream_receive_window = 1048576
receive_window = 8388608
send_window = 8388608

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(base).expect("valid http3 config");
    let http3 = cfg.http3.as_ref().expect("http3");
    assert_eq!(http3.max_concurrent_bidi_streams, Some(128));

    let bad = base.replace(
        "stream_receive_window = 1048576",
        "stream_receive_window = 0",
    );
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadHttp3Transport { .. })
    ));
}

#[test]
fn reject_unknown_sni_requires_certificates() {
    let base = r#"
listen = "127.0.0.1:8080"

[tls]
cert = "cert.pem"
key = "key.pem"
reject_unknown_sni = true

[[routes]]
host = "*"
root = "/srv"
"#;
    assert!(matches!(
        Config::parse(base),
        Err(Error::RejectSniWithoutCertificates)
    ));

    let with_cert = format!(
        "{base}\n[[tls.certificates]]\nnames = [\"a.example\"]\ncert = \"a.pem\"\nkey = \"a.key\"\n"
    );
    let cfg = Config::parse(&with_cert).expect("named certificate");
    assert!(cfg.tls.as_ref().unwrap().reject_unknown_sni);
}

#[test]
fn verify_ocsp_is_parsed() {
    let text = r#"
listen = "127.0.0.1:8080"

[tls]
cert = "cert.pem"
key = "key.pem"
verify_ocsp = true

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(text).expect("valid tls");
    assert!(cfg.tls.as_ref().unwrap().verify_ocsp);
}

#[test]
fn lingering_close_settings_are_parsed() {
    let text = r#"
listen = "127.0.0.1:8080"

[limits]
lingering_close = false
lingering_timeout_secs = 2
reset_timedout_connection = true

[[routes]]
host = "*"
root = "/srv"
"#;
    let cfg = Config::parse(text).expect("valid limits");
    assert!(!cfg.limits.lingering_close);
    assert_eq!(cfg.limits.lingering_timeout_secs, 2);
    assert!(cfg.limits.reset_timedout_connection);
}

#[test]
fn named_error_pages_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
error_pages = ["404 @fallback"]

[[routes]]
host = "*"
name = "@fallback"
return = { status = 200, body = "fallback" }
"#;
    Config::parse(base).expect("named error page");

    let empty = base.replace("@fallback\"]", "@\"]");
    assert!(matches!(
        Config::parse(&empty),
        Err(Error::BadErrorPage { .. })
    ));
}

#[test]
fn early_hints_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
early_hints = ["</app.css>; rel=preload; as=style"]
"#;
    let cfg = Config::parse(base).expect("valid early hints");
    assert_eq!(cfg.routes[0].early_hints.len(), 1);

    let bad = base.replace("</app.css>", "</app\\r.css>");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadEarlyHint { .. })
    ));
}

#[test]
fn named_locations_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "example.com"
path = "/app"
root = "/srv/app"
try_files = ["$uri", "@fallback"]

[[routes]]
host = "example.com"
name = "@fallback"
return = { status = 200, body = "fallback" }
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[1].name.as_deref(), Some("@fallback"));

    let with_path = base.replace(
        "name = \"@fallback\"",
        "name = \"@fallback\"\npath = \"/other\"",
    );
    assert!(matches!(
        Config::parse(&with_path),
        Err(Error::NamedLocationPath { .. })
    ));

    let bad_name = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "example.com"
name = "fallback"
return = { status = 200, body = "bad" }
"#;
    assert!(matches!(
        Config::parse(bad_name),
        Err(Error::BadLocationName { .. })
    ));

    let unknown = base.replace("@fallback\"]", "@missing\"]");
    assert!(matches!(
        Config::parse(&unknown),
        Err(Error::UnknownNamedLocation { .. })
    ));
}

#[test]
fn route_match_modes_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
path = "/app"
match = "exact"
return = { status = 200, body = "exact" }

[[routes]]
host = "*"
path = "/api"
no_regex = true
return = { status = 200, body = "prefix" }
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].match_type, RouteMatch::Exact);
    assert!(cfg.routes[1].no_regex);

    let no_path = base.replace("path = \"/app\"\n", "");
    assert!(matches!(
        Config::parse(&no_path),
        Err(Error::BadRouteMatch { .. })
    ));

    let regex = base.replace(
        "match = \"exact\"",
        "match = \"exact\"\npath_regex = \"^/app$\"",
    );
    assert!(matches!(
        Config::parse(&regex),
        Err(Error::PathAndRegex { .. }) | Err(Error::BadRouteMatch { .. })
    ));
}

#[test]
fn route_if_conditions_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
if = [{ variable = "$http_x_debug", equals = "1", return = { status = 503, body = "blocked" } }]
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].if_conditions.len(), 1);

    let both = base.replace("equals = \"1\"", "equals = \"1\", matches = \"^1$\"");
    assert!(matches!(Config::parse(&both), Err(Error::BadIf { .. })));

    let no_return = base.replace(", return = { status = 503, body = \"blocked\" }", "");
    assert!(matches!(
        Config::parse(&no_return),
        Err(Error::BadIf { .. })
    ));
}

#[test]
fn return_route_is_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
return = { status = 503, body = "down", content_type = "text/plain" }
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].return_response.as_ref().unwrap().status, 503);

    let bad_status = base.replace("status = 503", "status = 700");
    assert!(matches!(
        Config::parse(&bad_status),
        Err(Error::BadReturnStatus { .. })
    ));

    let bad_type = base.replace("text/plain", "bad\\u007fvalue");
    assert!(matches!(
        Config::parse(&bad_type),
        Err(Error::BadReturnContentType { .. })
    ));
}

#[test]
fn alias_and_static_headers_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
path = "/static"
alias = "/srv/static"
expires_secs = 60
etag = false
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(
        cfg.routes[0].alias.as_deref(),
        Some(Path::new("/srv/static"))
    );
    assert_eq!(cfg.routes[0].expires_secs, Some(60));
    assert_eq!(cfg.routes[0].etag, Some(false));

    let no_path = base.replace("path = \"/static\"\n", "");
    assert!(matches!(
        Config::parse(&no_path),
        Err(Error::AliasNeedsPrefix { .. })
    ));

    let with_root = base.replace(
        "alias = \"/srv/static\"",
        "alias = \"/srv/static\"\nroot = \"/srv/www\"",
    );
    assert!(matches!(
        Config::parse(&with_root),
        Err(Error::RouteHasTwoTargets { .. })
    ));
}

#[test]
fn response_spool_is_configured() {
    let text = r#"
listen = "127.0.0.1:8080"

[limits]
response_buffer_bytes = 1024
response_spool_bytes = 4096
spool_budget_bytes = 1048576
request_buffer_bytes = 512
request_spool_bytes = 2048

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.limits.response_buffer_bytes, 1024);
    assert_eq!(cfg.limits.response_spool_bytes, 4096);
    assert_eq!(cfg.limits.spool_budget_bytes, 1_048_576);
    assert_eq!(cfg.limits.request_buffer_bytes, 512);
    assert_eq!(cfg.limits.request_spool_bytes, 2048);
}

#[test]
fn passive_ejection_needs_a_cooldown() {
    let base = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]
failures_before_eject = 3
eject_secs = 15

[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.upstreams[0].failures_before_eject, 3);
    assert_eq!(cfg.upstreams[0].eject_secs, 15);

    let zero = base.replace("eject_secs = 15", "eject_secs = 0");
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::BadEjectTimeout { .. })
    ));

    let default = base.replace("eject_secs = 15\n", "");
    let cfg = Config::parse(&default).expect("default cooldown");
    assert_eq!(cfg.upstreams[0].eject_secs, 30);
}

#[test]
fn rejects_a_zero_dns_ttl() {
    let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
dns_ttl_secs = 0

[[routes]]
host = "*"
upstream = "app"
"#;
    assert!(matches!(Config::parse(text), Err(Error::BadDnsTtl { .. })));
}

#[test]
fn http01_needs_a_port_80_listener() {
    let text = r#"
listen = "127.0.0.1:8443"

[acme]
domains = ["example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"
challenge = "http_01"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::Http01NeedsListener)
    ));

    let with_listener = text.replace(
        "challenge = \"http_01\"",
        "challenge = \"http_01\"\nhttp01_listen = \"0.0.0.0:80\"",
    );
    assert!(Config::parse(&with_listener).is_ok());
}

#[test]
fn regex_routes_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
path_regex = "^(/[a-z]+)/"
"#;
    assert!(Config::parse(base).is_ok());

    let invalid = base.replace("^(/[a-z]+)/", "([");
    assert!(matches!(
        Config::parse(&invalid),
        Err(Error::BadPathRegex { .. })
    ));

    let both = base.replace("root = \"/srv/www\"", "root = \"/srv/www\"\npath = \"/x\"");
    assert!(matches!(
        Config::parse(&both),
        Err(Error::PathAndRegex { .. })
    ));
}

#[test]
fn parses_fastcgi_cgi_and_module_targets() {
    let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "php.example"
fastcgi_pass = "unix:/run/php.sock"
fastcgi_root = "/srv/www"
fastcgi_index = "index.php"

[[routes]]
host = "cgi.example"
path = "/cgi"
cgi_pass = "/srv/cgi/hello"

[[routes]]
host = "module.example"
module = "/etc/elira/hello.so"
"#;
    let cfg = Config::parse(text).expect("valid targets");
    assert_eq!(cfg.routes.len(), 3);
    assert_eq!(cfg.routes[0].fastcgi_index, "index.php");
}

#[test]
fn rejects_bad_fastcgi_and_module_targets() {
    let missing_root = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
"#;
    assert!(matches!(
        Config::parse(missing_root),
        Err(Error::FastCgiNeedRoot { .. })
    ));

    let relative = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
module = "hello.so"
"#;
    assert!(matches!(
        Config::parse(relative),
        Err(Error::BadModulePath { .. })
    ));
}

#[test]
fn workers_need_reuse_port() {
    let text = r#"
listen = "127.0.0.1:8080"
workers = 2

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::WorkersNeedReusePort)
    ));
}

#[test]
fn h2c_is_opt_in() {
    let text = r#"
listen = "127.0.0.1:8080"
h2c = true

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert!(cfg.h2c);
}

#[test]
fn loads_includes_and_substitutes_the_environment() {
    let dir = std::env::temp_dir().join(format!("elira-config-inc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("routes")).expect("dir");

    std::env::set_var("ELIRA_TEST_PORT", "18081");
    std::fs::write(
        dir.join("elira.toml"),
        r#"
listen = "127.0.0.1:${ELIRA_TEST_PORT}"
include = ["routes/*.toml"]

[limits]
max_body_bytes = ${ELIRA_TEST_BODY:-4096}
"#,
    )
    .expect("main");
    std::fs::write(
        dir.join("routes/app.toml"),
        r#"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#,
    )
    .expect("fragment");

    let cfg = Config::load(&dir.join("elira.toml")).expect("load");
    assert_eq!(cfg.listen.port(), 18081);
    assert_eq!(cfg.limits.max_body_bytes, 4096);
    assert_eq!(cfg.routes.len(), 1);
    assert_eq!(cfg.upstreams.len(), 1);

    std::env::remove_var("ELIRA_TEST_PORT");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_environment_variable_is_an_error() {
    let dir = std::env::temp_dir().join(format!("elira-config-env-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("elira.toml"),
        "listen = \"127.0.0.1:${ELIRA_TEST_MISSING}\"\n",
    )
    .expect("config");

    assert!(matches!(
        Config::load(&dir.join("elira.toml")),
        Err(Error::EnvMissing { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_include_without_matches_is_an_error() {
    let dir = std::env::temp_dir().join(format!("elira-config-incmiss-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("elira.toml"),
        "listen = \"127.0.0.1:8080\"\ninclude = [\"nope/*.toml\"]\n",
    )
    .expect("config");

    assert!(matches!(
        Config::load(&dir.join("elira.toml")),
        Err(Error::BadInclude { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parses_ocsp_and_app_concurrency() {
    let text = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ocsp = "/tmp/ocsp.der"

[[routes]]
host = "*"
cgi_pass = "/srv/cgi/app"
max_concurrent = 4
"#;
    let cfg = Config::parse(text).expect("valid config");
    assert_eq!(cfg.routes[0].max_concurrent, Some(4));
    assert!(cfg.tls.expect("tls").ocsp.is_some());
}

#[test]
fn dns01_requires_a_hook() {
    let text = r#"
listen = "127.0.0.1:8443"

[acme]
domains = ["*.example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"
challenge = "dns_01"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(matches!(Config::parse(text), Err(Error::DnsHookRequired)));
    let with_hook = text.replace(
        "challenge = \"dns_01\"",
        "challenge = \"dns_01\"\ndns_hook = \"/usr/local/bin/publish-txt\"",
    );
    assert!(Config::parse(&with_hook).is_ok());
}

#[test]
fn ocsp_hook_needs_a_file_and_positive_interval() {
    let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ocsp_hook = "/usr/local/bin/fetch-ocsp"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(matches!(Config::parse(base), Err(Error::OcspHookNeedsFile)));
    let with_file = base.replace(
        "ocsp_hook = \"/usr/local/bin/fetch-ocsp\"",
        "ocsp = \"/tmp/ocsp.der\"\nocsp_hook = \"/usr/local/bin/fetch-ocsp\"",
    );
    let cfg = Config::parse(&with_file).expect("valid");
    assert_eq!(cfg.tls.expect("tls").ocsp_refresh_secs, 86400);
}

#[test]
fn sni_certificates_can_staple_their_own_ocsp() {
    let text = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ocsp_hook = "/usr/local/bin/fetch-ocsp"

[[tls.certificates]]
cert = "/tmp/a.pem"
key = "/tmp/a.key"
names = ["a.example.com"]
ocsp = "/tmp/a.ocsp"

[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(
        cfg.tls.expect("tls").certificates[0].ocsp.as_deref(),
        Some(Path::new("/tmp/a.ocsp"))
    );

    let no_ocsp = text.replace("ocsp = \"/tmp/a.ocsp\"\n", "");
    assert!(matches!(
        Config::parse(&no_ocsp),
        Err(Error::OcspHookNeedsFile)
    ));

    let empty = text.replace("ocsp = \"/tmp/a.ocsp\"", "ocsp = \"\"");
    assert!(matches!(Config::parse(&empty), Err(Error::EmptyOcspPath)));
}

#[test]
fn per_route_response_cap_is_validated() {
    let text = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
cgi_pass = "/srv/cgi/app"
max_response_bytes = 1024
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.routes[0].max_response_bytes, Some(1024));

    let zero = text.replace("max_response_bytes = 1024", "max_response_bytes = 0");
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::BadResponseCap { .. })
    ));
}

#[test]
fn per_route_upstream_response_cap_is_validated() {
    let text = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
upstream = "app"
max_upstream_response_bytes = 2048

[[upstreams]]
name = "app"
servers = ["127.0.0.1:9000"]
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.routes[0].max_upstream_response_bytes, Some(2048));

    let zero = text.replace(
        "max_upstream_response_bytes = 2048",
        "max_upstream_response_bytes = 0",
    );
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::BadUpstreamResponseCap { .. })
    ));

    let global = r#"
listen = "127.0.0.1:8080"
[limits]
max_upstream_response_bytes = 4096
[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(global).expect("valid");
    assert_eq!(cfg.limits.max_upstream_response_bytes, 4096);
}

#[test]
fn per_route_fastcgi_pool_only_applies_to_fastcgi() {
    let base = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
fastcgi_root = "/srv"
fastcgi_pool_idle = 4
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].fastcgi_pool_idle, Some(4));

    let wrong = base.replace("fastcgi_pass = \"127.0.0.1:9000\"", "root = \"/srv\"");
    assert!(matches!(
        Config::parse(&wrong),
        Err(Error::PoolWithoutFastCgi { .. }) | Err(Error::RouteHasTwoTargets { .. })
    ));
}

#[test]
fn route_cache_overrides_are_validated() {
    let base = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
root = "/srv/www"
cache_enabled = false
cache_ttl_secs = 30
"#;
    let cfg = Config::parse(base).expect("valid");
    assert_eq!(cfg.routes[0].cache_enabled, Some(false));
    assert_eq!(cfg.routes[0].cache_ttl_secs, Some(30));

    let zero = base.replace("cache_ttl_secs = 30", "cache_ttl_secs = 0");
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::BadRouteCacheTtl { .. })
    ));
}

#[test]
fn http3_idle_timeout_is_positive() {
    let text = r#"
listen = "127.0.0.1:8080"
[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
idle_timeout_secs = 45
[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.http3.expect("http3").idle_timeout_secs, 45);
    let zero = text.replace("idle_timeout_secs = 45", "idle_timeout_secs = 0");
    assert!(matches!(
        Config::parse(&zero),
        Err(Error::Http3IdleTimeoutZero)
    ));
}

#[test]
fn tls_resumption_and_early_data_parse() {
    let text = r#"
listen = "127.0.0.1:8443"
[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
session_tickets = 4
session_cache = 0
[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
early_data = true
idle_timeout_secs = 15
[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid");
    let tls = cfg.tls.expect("tls");
    assert_eq!(tls.session_tickets, 4);
    assert_eq!(tls.session_cache, 0);
    let h3 = cfg.http3.expect("http3");
    assert!(h3.early_data);
    assert_eq!(h3.idle_timeout_secs, 15);
}

#[test]
fn shared_cache_needs_a_directory() {
    let text = r#"
listen = "127.0.0.1:8080"
[cache]
enabled = true
shared = true
[[routes]]
host = "*"
root = "/srv/www"
"#;
    assert!(matches!(
        Config::parse(text),
        Err(Error::SharedCacheWithoutDir)
    ));
}

#[test]
fn drain_timeouts_are_configurable_and_positive() {
    let text = r#"
listen = "127.0.0.1:8080"
[limits]
connection_drain_secs = 3
shutdown_timeout_secs = 20
[[routes]]
host = "*"
root = "/srv/www"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert_eq!(cfg.limits.connection_drain_secs, 3);
    assert_eq!(cfg.limits.shutdown_timeout_secs, 20);

    let zero = text.replace("connection_drain_secs = 3", "connection_drain_secs = 0");
    assert!(matches!(Config::parse(&zero), Err(Error::DrainTimeoutZero)));
}

#[test]
fn wasm_routes_need_an_absolute_path() {
    let ok = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
wasm = "/etc/elira/echo.wasm"
"#;
    assert!(Config::parse(ok).is_ok());

    let relative = ok.replace("/etc/elira/echo.wasm", "echo.wasm");
    assert!(matches!(
        Config::parse(&relative),
        Err(Error::BadWasmPath { .. })
    ));
}

#[test]
fn upstream_can_use_the_custom_h2_pool() {
    let text = r#"
listen = "127.0.0.1:8080"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
h2_pool = true
[[routes]]
host = "*"
upstream = "app"
"#;
    let cfg = Config::parse(text).expect("valid");
    assert!(cfg.upstreams[0].h2_pool);
}

#[test]
fn h3_pool_needs_tls_and_excludes_h2_pool() {
    let base = r#"
listen = "127.0.0.1:8080"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
h3_pool = true
[[routes]]
host = "*"
upstream = "app"
"#;
    assert!(matches!(
        Config::parse(base),
        Err(Error::H3PoolNeedsTls { .. })
    ));
    let tls = base.replace(
        "servers = [\"127.0.0.1:3000\"]",
        "servers = [\"127.0.0.1:3000\"]\ntls = true",
    );
    assert!(Config::parse(&tls).is_ok());
    let both = tls.replace("h3_pool = true", "h3_pool = true\nh2_pool = true");
    assert!(matches!(
        Config::parse(&both),
        Err(Error::H3AndH2Pool { .. })
    ));
}

#[test]
fn app_params_are_validated() {
    let ok = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
fastcgi_root = "/srv"
fastcgi_param = ["APP_ENV: production", "FLAG:1"]
"#;
    assert!(Config::parse(ok).is_ok());
    let bad = ok.replace("APP_ENV: production", "bad name: x");
    assert!(matches!(
        Config::parse(&bad),
        Err(Error::BadAppParam { .. })
    ));
}
