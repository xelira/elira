//! Configuration loading and validation errors.

use thiserror::Error;

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

    #[error("environment variable {name} is not set")]
    EnvMissing { name: String },

    #[error("include depth exceeded at {path}")]
    IncludeDepth { path: String },

    #[error("include {path}: {reason}")]
    BadInclude { path: String, reason: String },

    #[error("no routes configured")]
    NoRoutes,

    #[error("listen_unix must not be empty")]
    EmptyUnixListen,

    #[error("listener {listen} is configured twice")]
    DuplicateListener { listen: String },

    #[error("a TCP listener with tls = true needs [tls] or [acme]")]
    ListenerTlsWithoutConfig,

    #[error("listener name must not be empty or contain whitespace")]
    BadListenerName,

    #[error("listener name {name:?} is used twice")]
    DuplicateListenerName { name: String },

    #[error("route {index} refers to unknown listener {name:?}")]
    UnknownListener { index: usize, name: String },

    #[error("stream listener {listen} is configured twice")]
    DuplicateStreamListen { listen: String },

    #[error("stream listen must not use port 0")]
    BadStreamListen,

    #[error("rewrite pattern and replacement must not be empty")]
    BadRewrite,

    #[error("map name must be a non-empty identifier")]
    BadMapName,

    #[error("map source must be a $variable")]
    BadMapSource,

    #[error("map name {name:?} is used twice")]
    DuplicateMapName { name: String },

    #[error("geo needs at least one valid IP or CIDR value")]
    BadGeo,

    #[error("split needs buckets with 1..100 percent and a total of at most 100")]
    BadSplit,

    #[error("stream needs at least one upstream")]
    EmptyStream,

    #[error("stream connect_timeout_secs must be greater than zero")]
    BadStreamConnect,

    #[error("TLS termination is only supported on TCP streams")]
    StreamTlsOnUdp,

    #[error("a stream with tls = true needs [tls] or [acme]")]
    StreamTlsWithoutConfig,

    #[error("stream upstream {addr:?} must be a TCP host:port address")]
    BadStreamUpstream { addr: String },

    #[error("unix_tls needs listen_unix")]
    UnixTlsWithoutListener,

    #[error("listen_unix_mode/listen_unix_owner need listen_unix")]
    UnixOptionsWithoutListener,

    #[error("listen_unix_mode must not exceed 0o7777")]
    BadUnixMode,

    #[error("listen_unix_owner must look like \"uid:gid\"")]
    BadUnixOwner,

    #[error("unix_tls needs a [tls] section with a certificate")]
    UnixTlsWithoutTls,

    #[error("limits.max_header_bytes must be at least 8192, hyper refuses smaller buffers")]
    MaxHeaderBytesTooSmall,

    #[error("limits.max_headers must be greater than zero")]
    MaxHeadersZero,

    #[error("limits.max_connections must be greater than zero")]
    MaxConnectionsZero,

    #[error("limits.connection_drain_secs must be greater than zero")]
    DrainTimeoutZero,

    #[error("limits.shutdown_timeout_secs must be greater than zero")]
    ShutdownTimeoutZero,

    #[error("workers must be between 1 and 64")]
    BadWorkers,

    #[error("workers > 1 requires reuse_port = true")]
    WorkersNeedReusePort,

    #[error("user must not be empty or contain whitespace")]
    BadUser,

    #[error("worker_rlimit_nofile must be greater than zero")]
    BadRlimit,

    #[error("worker_cpu_affinity must be a non-empty list of CPU indices below 4096")]
    BadCpuAffinity,

    #[error("pid_file must not be empty")]
    EmptyPidFile,

    #[error("chroot must not be empty")]
    EmptyChroot,

    #[error("health.path must start with '/' and contain no spaces or control characters")]
    BadHealthPath,

    #[error("health method {method:?} must be GET or HEAD")]
    BadHealthMethod { method: String },

    #[error("health expect_status values must be between 100 and 599")]
    BadHealthStatus,

    #[error("health host must not be empty or contain whitespace")]
    BadHealthHost,

    #[error("health.interval_secs must be greater than zero")]
    BadHealthInterval,

    #[error("health.timeout_secs must be greater than zero")]
    BadHealthTimeout,

    #[error("http3.idle_timeout_secs must be greater than zero")]
    Http3IdleTimeoutZero,

    #[error("http3.cert must not be empty")]
    Http3MissingCert,

    #[error("http3.key must not be empty")]
    Http3MissingKey,

    #[error("http3.client_ca is required unless http3.client_auth = \"off\"")]
    Http3ClientCaRequired,

    #[error("connect.enabled requires a non-empty connect.allow list")]
    ConnectEmptyAllow,

    #[error("limits.trusted_proxies: \"{cidr}\" is not a CIDR block")]
    BadTrustedProxy { cidr: String },

    #[error("connect target \"{target}\" is not host:port")]
    BadConnectTarget { target: String },

    #[error("tls.cert is required when [tls] is set and must not be empty")]
    TlsMissingCert,

    #[error("tls.key is required when [tls] is set and must not be empty")]
    TlsMissingKey,

    #[error("tls.client_ca is required unless tls.client_auth = \"off\"")]
    TlsClientCaRequired,

    #[error("tls.ocsp must not be empty")]
    EmptyOcspPath,

    #[error("tls.ocsp_hook needs a non-empty tls.ocsp path")]
    OcspHookNeedsFile,

    #[error("tls.ocsp_refresh_secs must be greater than zero")]
    OcspRefreshZero,

    #[error("tls.client_ca must not be empty")]
    TlsClientCaEmpty,

    #[error("client_crl must not be empty")]
    EmptyClientCrl,

    #[error("ticket_key must not be empty")]
    EmptyTicketKey,
    #[error("client_crl needs client_auth = \"optional\" or \"required\"")]
    ClientCrlWithoutAuth,

    #[error("tls.certificates[{index}] needs both cert and key")]
    TlsCertificatePair { index: usize },

    #[error("tls.certificates[{index}]: \"{name}\" is not a host name")]
    TlsCertificateName { index: usize, name: String },

    #[error("tls certificate name \"{name}\" is used twice")]
    TlsCertificateNameDuplicate { name: String },

    #[error("upstream name is empty")]
    EmptyUpstreamName,

    #[error("upstream \"{name}\" is defined twice")]
    DuplicateUpstream { name: String },

    #[error("upstream \"{name}\" has no servers")]
    EmptyUpstream { name: String },

    #[error("upstream \"{name}\": h3_pool requires tls = true")]
    H3PoolNeedsTls { name: String },

    #[error("upstream \"{name}\": h3_pool and h2_pool are mutually exclusive")]
    H3AndH2Pool { name: String },

    #[error("upstream \"{name}\": dns_ttl_secs must be greater than zero")]
    BadDnsTtl { name: String },

    #[error("upstream \"{name}\": weights and balance = \"hash\" cannot be combined")]
    WeightsWithHash { name: String },

    #[error("upstream \"{name}\": weights must contain one positive value per server")]
    WeightsLength { name: String },

    #[error("upstream \"{name}\": weights must be greater than zero")]
    ZeroWeight { name: String },

    #[error("upstream \"{name}\": total weight must not exceed 10000")]
    WeightsTooLarge { name: String },

    #[error("upstream \"{name}\": eject_secs must be greater than zero when failures_before_eject is set")]
    BadEjectTimeout { name: String },

    #[error("upstream \"{name}\": hash_key needs balance = \"hash\"")]
    HashKeyWithoutHashBalance { name: String },

    #[error("upstream \"{name}\": \"{key}\" is not a hash key (ip, authorization, header:NAME, cookie:NAME, uri)")]
    BadHashKey { name: String, key: String },

    #[error("upstream \"{name}\": TLS over a unix socket is not supported")]
    TlsOverUnix { name: String },

    #[error("upstream \"{name}\": health_path must start with /")]
    BadUpstreamHealthPath { name: String },

    #[error("upstream \"{name}\" has {retries} retries, the maximum is 5")]
    TooManyRetries { name: String, retries: u32 },

    #[error("upstream \"{name}\": {condition:?} is not a retry condition")]
    BadRetryCondition { name: String, condition: String },

    #[error("upstream \"{upstream}\": \"{addr}\" is not host:port")]
    BadServer { upstream: String, addr: String },

    #[error("route {index} has an empty host")]
    EmptyRouteHost { index: usize },

    #[error("route for host \"{host}\" is defined twice")]
    DuplicateRoute { host: String },

    #[error("route {index} points to unknown upstream \"{upstream}\"")]
    UnknownUpstream { index: usize, upstream: String },

    #[error("route {index} needs exactly one of `upstream` or `root`")]
    RouteNeedsTarget { index: usize },

    #[error("route {index} has both `upstream` and `root`")]
    RouteHasTwoTargets { index: usize },

    #[error("route {index} has an empty `root`")]
    EmptyRoot { index: usize },

    #[error("route {index}: alias must be a non-empty absolute path")]
    BadAlias { index: usize },

    #[error("route {index}: alias needs a literal path prefix")]
    AliasNeedsPrefix { index: usize },

    #[error("route {index}: return.status must be between 200 and 599")]
    BadReturnStatus { index: usize },

    #[error("route {index}: return.content_type is not a valid header value")]
    BadReturnContentType { index: usize },

    #[error("route {index}: if needs a $variable, exactly one of equals/matches, and a return")]
    BadIf { index: usize },

    #[error("route {index}: index file \"{entry}\" must be a plain file name")]
    BadIndexEntry { index: usize, entry: String },

    #[error("route {index}: `spa` needs at least one index file")]
    SpaNeedsIndex { index: usize },

    #[error("route {index}: path \"{path}\" must start with '/'")]
    BadPath { index: usize, path: String },

    #[error("route {index}: path and path_regex are mutually exclusive")]
    PathAndRegex { index: usize },

    #[error("route {index}: match = \"exact\" and no_regex need a literal path and no path_regex")]
    BadRouteMatch { index: usize },

    #[error("route {index}: \"{pattern}\" is not a valid regular expression")]
    BadPathRegex { index: usize, pattern: String },

    #[error("route {index}: strip_prefix cannot be used with path_regex")]
    StripPrefixWithRegex { index: usize },

    #[error("route {index}: `strip_prefix` needs an upstream")]
    StripWithoutUpstream { index: usize },

    #[error("route {index}: fastcgi_pass must not be empty")]
    EmptyFastCgiTarget { index: usize },

    #[error("route {index}: fastcgi_pass needs fastcgi_root")]
    FastCgiNeedRoot { index: usize },

    #[error("route {index}: fastcgi_index must be a file name")]
    BadFastCgiIndex { index: usize },

    #[error("route {index}: \"{param}\" is not \"NAME: value\"")]
    BadAppParam { index: usize, param: String },

    #[error("route {index}: cgi_pass must be an absolute script path")]
    BadCgiScript { index: usize },

    #[error("route {index}: module must be an absolute path")]
    BadModulePath { index: usize },

    #[error("route {index}: wasm must be an absolute path")]
    BadWasmPath { index: usize },

    #[error("route {index}: module_sandbox needs module")]
    SandboxWithoutModule { index: usize },

    #[error("route {index}: max_concurrent must be greater than zero")]
    BadConcurrency { index: usize },

    #[error("route {index}: max_response_bytes must be greater than zero")]
    BadResponseCap { index: usize },

    #[error("route {index}: max_upstream_response_bytes must be greater than zero")]
    BadUpstreamResponseCap { index: usize },

    #[error("route {index}: access_log_sample must be between 0 and 1")]
    BadRouteLogSample { index: usize },

    #[error("route {index}: client_cn/client_issuer_cn need client_auth = true")]
    RouteClientFilterWithoutAuth { index: usize },

    #[error("route {index}: client_auth needs tls.client_auth = \"optional\" or \"required\"")]
    RouteClientAuthWithoutTls { index: usize },

    #[error("route {index}: client_auth needs http3.client_auth = \"optional\" or \"required\"")]
    RouteClientAuthWithoutHttp3 { index: usize },

    #[error("route {index}: client_cn must not be empty")]
    EmptyClientCn { index: usize },

    #[error("route {index}: client_issuer_cn must not be empty")]
    EmptyClientIssuerCn { index: usize },

    #[error("log.sample must be a fraction between 0 and 1")]
    BadLogSample,

    #[error("route {index}: cache_ttl_secs must be greater than zero")]
    BadRouteCacheTtl { index: usize },

    #[error("route {index}: fastcgi_pool_idle is only valid on fastcgi routes")]
    PoolWithoutFastCgi { index: usize },

    #[error("route {index}: `autoindex` needs a root")]
    AutoindexWithoutRoot { index: usize },

    #[error("route {index}: auth_file must not be empty")]
    EmptyAuthFile { index: usize },

    #[error("route {index}: timeout_secs must be greater than zero")]
    BadRouteTimeout { index: usize },

    #[error("route {index}: requests_per_second must be greater than zero")]
    BadRouteRate { index: usize },

    #[error("error_root needs at least one error_pages entry")]
    GlobalErrorRootWithoutPages,

    #[error("global error_pages need error_root")]
    GlobalErrorPagesNeedRoot,

    #[error("{page:?} is not \"STATUS /path\"")]
    BadGlobalErrorPage { page: String },

    #[error("route {index}: error_root needs at least one error_pages entry")]
    ErrorRootWithoutPages { index: usize },

    #[error("route {index}: rate_key needs requests_per_second")]
    RateKeyWithoutRate { index: usize },

    #[error("{field} must not be empty")]
    EmptyTlsList { field: &'static str },

    #[error("{field} entries must not be blank")]
    BlankTlsListEntry { field: &'static str },

    #[error(
        "route {index}: {key:?} is not a rate key (ip, authorization, header:NAME, cookie:NAME)"
    )]
    BadRateKey { index: usize, key: String },

    #[error("route {index}: \"{page}\" is not \"STATUS /path\"")]
    BadErrorPage { index: usize, page: String },

    #[error("route {index}: \"{value}\" is not a CIDR block")]
    BadAcl { index: usize, value: String },

    #[error("[acme] and [tls] cannot both be set")]
    TlsAndAcme,

    #[error("acme.domains must not be empty")]
    AcmeNoDomains,

    #[error("acme.contacts must not be empty")]
    AcmeNoContacts,

    #[error("acme HTTP-01 needs a listener on port 80 or acme.http01_listen")]
    Http01NeedsListener,

    #[error("acme DNS-01 needs a non-empty acme.dns_hook")]
    DnsHookRequired,

    #[error("acme.dns_cleanup_hook must not be empty")]
    EmptyDnsCleanupHook,

    #[error("acme.cache_dir must not be empty")]
    AcmeNoCacheDir,

    #[error("cache.dir must not be empty")]
    EmptyCacheDir,

    #[error("cache.shared needs cache.dir")]
    SharedCacheWithoutDir,

    #[error("log.file must not be empty")]
    EmptyLogFile,

    #[error("log.max_bytes must be at least 1024")]
    LogRotationTooSmall,

    #[error("route {index}: try_files entry \"{candidate}\" is empty or unsafe")]
    BadTryFile { index: usize, candidate: String },

    #[error("route {index}: redirect target is empty or contains control characters")]
    BadRedirect { index: usize },

    #[error("route {index}: redirect status {status} is not 301, 302, 303, 307 or 308")]
    BadRedirectStatus { index: usize, status: u16 },

    #[error("route {index}: \"{header}\" is not a `Name: value` header")]
    BadHeader { index: usize, header: String },

    #[error("route {index}: request headers cannot override hop-by-hop or framing headers")]
    ReservedRequestHeader { index: usize },

    #[error("route {index}: host wildcard must look like `*.example.com`")]
    BadWildcardHost { index: usize },

    #[error("nested location needs a path or path_regex under a literal parent prefix")]
    BadNestedLocation,

    #[error("route {index}: named location must look like `@name`")]
    BadLocationName { index: usize },

    #[error("route {index}: a named location cannot have path or path_regex")]
    NamedLocationPath { index: usize },

    #[error("route {index}: try_files refers to unknown named location {name:?}")]
    UnknownNamedLocation { index: usize, name: String },

    #[error("route {index}: scgi_pass is empty")]
    EmptyScgiTarget { index: usize },

    #[error("route {index}: scgi_root is empty")]
    BadScgiRoot { index: usize },

    #[error("route {index}: uwsgi_pass is empty")]
    EmptyUwsgiTarget { index: usize },

    #[error("route {index}: ajp_pass is empty")]
    EmptyAjpTarget { index: usize },

    #[error("route {index}: fastcgi_multiplex needs fastcgi_pass")]
    MultiplexWithoutFastCgi { index: usize },

    #[error("route {index}: auth_request must be an internal path starting with /")]
    BadAuthRequest { index: usize },

    #[error("route {index}: secure_link needs a non-empty secret and md5/expires together")]
    BadSecureLink { index: usize },

    #[error("route {index}: x_sendfile_root is empty")]
    BadSendfileRoot { index: usize },

    #[error("route {index}: cache_valid needs statuses in 100..599 and a positive TTL")]
    BadCacheValid { index: usize },

    #[error("route {index}: proxy header rewrite is invalid")]
    BadProxyRewrite { index: usize },

    #[error("route {index}: cache_key/cache_bypass template is invalid")]
    BadCacheKey { index: usize },

    #[error("tls.min_version tls10/tls11 needs tls.backend = \"openssl\"")]
    LegacyTlsNeedsOpenssl,
}
