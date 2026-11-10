//! Compile the configuration into pools, routes and derived variables.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::uri::Authority;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::Semaphore;

use elira_auth::{BasicAuth, IpAcl};
use elira_config::{Config, ServerConfig};
use elira_limit::RateLimiter;
use elira_upstream::{https_connector, TlsOptions};

use crate::*;

type Pools = HashMap<String, Arc<Pool>>;

#[derive(Clone)]
pub(crate) struct Caches {
    pub(crate) default: Option<Arc<Cache>>,
    pub(crate) zones: HashMap<String, Arc<Cache>>,
    pub(crate) all: Vec<Arc<Cache>>,
}

pub(crate) fn build_caches(cfg: &Config) -> Caches {
    let default = cfg.cache.enabled.then(|| {
        Arc::new(Cache::with_shared_disk(
            cfg.cache.max_bytes,
            Duration::from_secs(cfg.cache.ttl_secs),
            cfg.cache.dir.clone(),
            Duration::from_secs(cfg.cache.stale_secs),
            cfg.cache.shared,
        ))
    });
    let zones: HashMap<String, Arc<Cache>> = cfg
        .cache
        .zones
        .iter()
        .map(|(name, zone)| {
            (
                name.clone(),
                Arc::new(Cache::with_shared_disk(
                    zone.max_bytes,
                    Duration::from_secs(zone.ttl_secs),
                    zone.dir.clone(),
                    Duration::from_secs(zone.stale_secs),
                    zone.shared,
                )),
            )
        })
        .collect();
    let mut all = Vec::with_capacity(zones.len() + 1);
    if let Some(cache) = &default {
        all.push(cache.clone());
    }
    all.extend(zones.values().cloned());
    Caches {
        default,
        zones,
        all,
    }
}

pub(crate) fn build_resolver(cfg: &Config) -> elira_upstream::Resolver {
    elira_upstream::Resolver::new(elira_upstream::ResolverOptions {
        ttl: Duration::from_secs(cfg.resolver.ttl_secs),
        negative_ttl: Duration::from_secs(cfg.resolver.negative_ttl_secs),
        hosts: cfg
            .resolver
            .hosts
            .iter()
            .map(|host| {
                (
                    host.name.trim_end_matches('.').to_ascii_lowercase(),
                    host.addresses.clone(),
                )
            })
            .collect(),
    })
}

pub(crate) fn build_pools(
    cfg: &Config,
    resolver: elira_upstream::Resolver,
) -> Result<(Pools, Vec<Arc<Pool>>), Error> {
    let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
    for up in &cfg.upstreams {
        let mut servers = Vec::with_capacity(up.servers.len());
        for entry in &up.servers {
            let server = ServerAddr::parse(entry.address()).ok_or_else(|| Error::BadServer {
                upstream: up.name.clone(),
                addr: entry.address().to_owned(),
            })?;
            servers.push(server);
        }
        let health = (0..servers.len()).map(|_| AtomicBool::new(true)).collect();
        let active = (0..servers.len()).map(|_| AtomicUsize::new(0)).collect();
        let backup = up.servers.iter().map(ServerConfig::backup).collect();
        let down = up.servers.iter().map(ServerConfig::down).collect();
        let max_conns = up.servers.iter().map(ServerConfig::max_conns).collect();
        let slow_start = up
            .servers
            .iter()
            .map(|server| Duration::from_secs(server.slow_start_secs()))
            .collect();
        let passive = (0..servers.len())
            .map(|_| Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            })
            .collect();
        let server_labels = servers.iter().map(ToString::to_string).collect();
        let recover_at = (0..servers.len()).map(|_| AtomicU64::new(0)).collect();
        let weights = if up.weights.is_empty() {
            vec![1; servers.len()]
        } else {
            up.weights.clone()
        };

        // Each pool gets its own connector: trust and ALPN may differ
        // between upstreams.
        let tls = TlsOptions {
            insecure: up.tls_insecure.unwrap_or(cfg.upstream_tls.insecure),
            ca: up.tls_ca.clone().or_else(|| cfg.upstream_tls.ca.clone()),
            sni: up.sni.clone(),
            http2: up.http2.unwrap_or(cfg.upstream_tls.http2),
            tls13_only: cfg.upstream_tls.min_version == elira_config::TlsVersion::Tls13,
            client_cert: cfg.upstream_tls.client_cert.clone(),
            client_key: cfg.upstream_tls.client_key.clone(),
            client_crl: cfg.upstream_tls.client_crl.clone(),
            cipher_suites: cfg.upstream_tls.cipher_suites.clone(),
            curves: cfg.upstream_tls.curves.clone(),
            connect_timeout: Some(Duration::from_secs(
                cfg.limits.upstream_connect_timeout_secs,
            )),
            local_address: up.bind,
        };
        let connector =
            https_connector(&tls, resolver.clone()).map_err(|err| Error::UpstreamTls {
                reason: err.to_string(),
            })?;
        let tls_config =
            Arc::new(
                elira_upstream::client_config(&tls).map_err(|err| Error::UpstreamTls {
                    reason: err.to_string(),
                })?,
            );
        let idle = Duration::from_secs(up.keepalive_secs.or(up.dns_ttl_secs).unwrap_or(30));
        let mut builder = Client::builder(TokioExecutor::new());
        // Hyper resolves the name for each new connection, so the pool
        // lifetime is the upper bound on DNS staleness.
        builder.pool_idle_timeout(Some(idle));
        if let Some(keepalive) = up.keepalive {
            builder.pool_max_idle_per_host(keepalive);
        }
        let client = builder.build(connector);

        pools.insert(
            up.name.clone(),
            Arc::new(Pool {
                name: up.name.clone(),
                servers,
                health,
                active,
                backup,
                down,
                max_conns,
                slow_start,
                recover_at,
                passive,
                failures_before_eject: up.failures_before_eject,
                eject_for: Duration::from_secs(up.eject_secs),
                started: Instant::now(),
                hash_key: parse_request_key(up.hash_key.as_deref()),
                server_labels,
                weights,
                retry_on: RetryOn::parse(&up.retry_on),
                next: AtomicUsize::new(0),
                balance: up.balance,
                retries: up.retries,
                scheme: if up.tls { "https" } else { "http" },
                client,
                tls: tls.clone(),
                tls_config,
                resolver: resolver.clone(),
                proxy_protocol: up.proxy_protocol,
                health_path: up.health_path.clone(),
                health_method: up.health_method.clone(),
                health_status: up.health_expect_status.clone(),
                health_host: up.health_host.clone(),
                h3: up.h3_pool.then(|| {
                    elira_h3upstream::Pool::new(elira_h3upstream::PoolConfig {
                        max_connections: 4,
                        connect_timeout: Duration::from_secs(
                            cfg.limits.upstream_connect_timeout_secs,
                        ),
                        tls: tls.clone(),
                        bind: up.bind,
                        resolver: resolver.clone(),
                    })
                }),
                h2: up.h2_pool.then(|| {
                    let mut config = elira_h2::PoolConfig::new(
                        4,
                        Duration::from_secs(cfg.limits.upstream_connect_timeout_secs),
                        tls.clone(),
                    );
                    config.bind = up.bind;
                    config.resolver = resolver.clone();
                    elira_h2::Pool::new(config)
                }),
            }),
        );
    }
    let all_pools: Vec<Arc<Pool>> = pools.values().cloned().collect();
    Ok((pools, all_pools))
}

pub(crate) fn build_route(
    route: &elira_config::Route,
    cfg: &Config,
    pools: &Pools,
    caches: &Caches,
    file_cache: Option<&Arc<FileCache>>,
) -> Result<RouteEntry, Error> {
    let target = build_target(route, cfg, pools, file_cache)?;
    let (cache, cache_max_item) = if route.cache_enabled == Some(false) {
        (None, 0)
    } else if let Some(name) = &route.cache_zone {
        match (caches.zones.get(name), cfg.cache.zones.get(name)) {
            (Some(cache), Some(zone)) => (Some(cache.clone()), zone.max_item_bytes),
            _ => (None, 0),
        }
    } else {
        (caches.default.clone(), cfg.cache.max_item_bytes)
    };

    let auth = build_auth(route)?;

    let acl = build_acl(route)?;

    let limiter = build_limiter(route);

    let error_root = route.error_root.clone().or_else(|| route.root.clone());
    let error_pages = match error_root {
        Some(root) => error_page_set(root, route.index.clone(), &route.error_pages),
        None => Vec::new(),
    };

    let app_permits = match &target {
        Target::FastCgi { .. } | Target::Cgi { .. } | Target::Scgi { .. } | Target::Module(_) => {
            Some(Arc::new(Semaphore::new(route.max_concurrent.unwrap_or(16))))
        }
        _ => None,
    };
    let proxy_permits = match &target {
        Target::Proxy(_) => route
            .max_concurrent
            .map(|limit| Arc::new(Semaphore::new(limit))),
        _ => None,
    };

    let if_conditions = build_if_conditions(route)?;

    let entry = RouteEntry {
        label: match &route.name {
            Some(name) => format!("{}{name}", route.host),
            None => format!(
                "{}{}",
                route.host,
                route
                    .path
                    .as_deref()
                    .or(route.path_regex.as_deref())
                    .unwrap_or_default()
            ),
        },
        host: route.host.trim().to_ascii_lowercase(),
        name: route.name.clone(),
        internal: route.internal,
        prefix: route
            .path
            .clone()
            .or_else(|| route.regex_prefix.clone())
            .unwrap_or_default(),
        exact: route.match_type == elira_config::RouteMatch::Exact,
        no_regex: route.no_regex,
        regex: route
            .path_regex
            .as_deref()
            .and_then(|pattern| regex::Regex::new(pattern).ok()),
        target,
        strip_prefix: route.strip_prefix,
        add_headers: route
            .add_headers
            .iter()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((
                    HeaderName::from_bytes(name.trim().as_bytes()).ok()?,
                    value.trim().to_owned(),
                ))
            })
            .collect(),
        remove_headers: route
            .remove_headers
            .iter()
            .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
            .collect(),
        hide_headers: route
            .proxy_hide_header
            .iter()
            .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
            .collect(),
        pass_headers: route
            .proxy_pass_header
            .iter()
            .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
            .collect(),
        proxy_redirect: route
            .proxy_redirect
            .iter()
            .map(|rewrite| (rewrite.from.clone(), rewrite.to.clone()))
            .collect(),
        cookie_domain: route
            .proxy_cookie_domain
            .iter()
            .map(|rewrite| (rewrite.from.clone(), rewrite.to.clone()))
            .collect(),
        cookie_path: route
            .proxy_cookie_path
            .iter()
            .map(|rewrite| (rewrite.from.clone(), rewrite.to.clone()))
            .collect(),
        request_headers: route
            .request_headers
            .iter()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((
                    HeaderName::from_bytes(name.trim().as_bytes()).ok()?,
                    value.trim().to_owned(),
                ))
            })
            .collect(),
        request_remove_headers: route
            .request_remove_headers
            .iter()
            .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
            .collect(),
        auth_request: route.auth_request.clone(),
        satisfy: route.satisfy.unwrap_or_default(),
        secure_link: route.secure_link.clone(),
        x_sendfile_root: route.x_sendfile_root.clone(),
        if_conditions,
        auth,
        acl,
        timeout: route.timeout_secs.map(Duration::from_secs),
        connect_timeout: route.connect_timeout_secs.map(Duration::from_secs),
        send_timeout: route.send_timeout_secs.map(Duration::from_secs),
        rate: route
            .limit_rate
            .or(Some(cfg.limits.limit_rate))
            .filter(|rate| *rate > 0),
        rate_after: route
            .limit_rate_after
            .unwrap_or(cfg.limits.limit_rate_after),
        limiter,
        rate_key: parse_request_key(route.rate_key.as_deref()),
        body_limit: route.max_body_bytes,
        error_pages,
        app_permits,
        proxy_permits,
        max_response: route.max_response_bytes,
        cache,
        cache_max_item,
        cache_ttl: route.cache_ttl_secs.map(Duration::from_secs),
        cache_key: route.cache_key.clone(),
        cache_bypass: route.cache_bypass.clone(),
        cache_valid: route.cache_valid.clone(),
        access_log: route.access_log,
        access_log_sample: route.access_log_sample.unwrap_or(cfg.log.sample),
        client_auth: route.client_auth.then(|| ClientCertRule {
            subject_cn: route.client_cn.clone(),
            issuer_cn: route.client_issuer_cn.clone(),
        }),
        max_upstream_response: route.max_upstream_response_bytes,
        expires_secs: route.expires_secs,
        etag: route.etag.unwrap_or(true),
        if_modified_since: route.if_modified_since.unwrap_or(true),
        fastcgi_param: route
            .fastcgi_param
            .iter()
            .filter_map(|line| parse_param(line))
            .collect(),
        cgi_param: route
            .cgi_param
            .iter()
            .filter_map(|line| parse_param(line))
            .collect(),
        scgi_param: route
            .scgi_param
            .iter()
            .filter_map(|line| parse_param(line))
            .collect(),
        uwsgi_param: route
            .uwsgi_param
            .iter()
            .filter_map(|line| parse_param(line))
            .collect(),
        fastcgi_pool: route.fastcgi_pool_idle.map(|idle| {
            Arc::new(elira_fastcgi::Pool::new(
                idle,
                Duration::from_secs(cfg.limits.fastcgi_pool_idle_secs),
            ))
        }),
        fastcgi_mux: route.fastcgi_multiplex.then(|| {
            Arc::new(elira_fastcgi::MultiplexPool::new(
                route.fastcgi_pool_idle.unwrap_or(4).max(1),
                16,
            ))
        }),
    };
    Ok(entry)
}

fn build_target(
    route: &elira_config::Route,
    cfg: &Config,
    pools: &Pools,
    file_cache: Option<&Arc<FileCache>>,
) -> Result<Target, Error> {
    Ok(if let Some(upstream) = &route.upstream {
        Target::Proxy(
            pools
                .get(upstream)
                .cloned()
                .ok_or_else(|| Error::UnknownUpstream {
                    upstream: upstream.clone(),
                })?,
        )
    } else if let Some(root) = &route.root {
        Target::Files(Arc::new(Files::new(
            root.clone(),
            None,
            route.index.clone(),
            route.spa,
            route.try_files.clone(),
            route.autoindex,
            cfg.compression.enabled,
            cfg.compression.min_bytes,
            route.expires_secs,
            route.etag.unwrap_or(true),
            route.if_modified_since.unwrap_or(true),
            file_cache.cloned(),
        )))
    } else if let Some(alias) = &route.alias {
        Target::Files(Arc::new(Files::new(
            alias.clone(),
            Some(route.path.clone().unwrap_or_default()),
            route.index.clone(),
            route.spa,
            route.try_files.clone(),
            route.autoindex,
            cfg.compression.enabled,
            cfg.compression.min_bytes,
            route.expires_secs,
            route.etag.unwrap_or(true),
            route.if_modified_since.unwrap_or(true),
            file_cache.cloned(),
        )))
    } else if let Some(pass) = &route.fastcgi_pass {
        let target = elira_fastcgi::Target::parse(pass).map_err(|err| Error::RouteConfig {
            host: route.host.clone(),
            reason: err.to_string(),
        })?;
        let root = route
            .fastcgi_root
            .clone()
            .ok_or_else(|| Error::RouteConfig {
                host: route.host.clone(),
                reason: "fastcgi_pass needs fastcgi_root".to_owned(),
            })?;
        Target::FastCgi {
            target,
            root,
            index: route.fastcgi_index.clone(),
        }
    } else if let Some(script) = &route.cgi_pass {
        Target::Cgi {
            script: script.clone(),
        }
    } else if let Some(pass) = &route.scgi_pass {
        let target = crate::app_target::Target::parse(pass).ok_or_else(|| Error::RouteConfig {
            host: route.host.clone(),
            reason: format!("scgi_pass {pass:?} is not host:port or unix:/path"),
        })?;
        Target::Scgi {
            target,
            root: route.scgi_root.clone(),
        }
    } else if let Some(pass) = &route.uwsgi_pass {
        let target = crate::app_target::Target::parse(pass).ok_or_else(|| Error::RouteConfig {
            host: route.host.clone(),
            reason: format!("uwsgi_pass {pass:?} is not host:port or unix:/path"),
        })?;
        Target::Uwsgi {
            target,
            modifier1: route.uwsgi_modifier1.unwrap_or(0),
            modifier2: route.uwsgi_modifier2.unwrap_or(0),
        }
    } else if let Some(pass) = &route.ajp_pass {
        let target = crate::app_target::Target::parse(pass).ok_or_else(|| Error::RouteConfig {
            host: route.host.clone(),
            reason: format!("ajp_pass {pass:?} is not host:port or unix:/path"),
        })?;
        Target::Ajp {
            target,
            secret: route.ajp_secret.clone(),
        }
    } else if let Some(path) = &route.wasm {
        let module = elira_wasm::WasmModule::load(path).map_err(|err| Error::RouteConfig {
            host: route.host.clone(),
            reason: err.to_string(),
        })?;
        Target::Wasm(Arc::new(module))
    } else if let Some(path) = &route.module {
        // A world-writable module is a privilege escalation waiting
        // to happen: any local user could replace the code.
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o002 != 0 {
                return Err(Error::RouteConfig {
                    host: route.host.clone(),
                    reason: format!("module {} is world-writable", path.display()),
                });
            }
            let owner = std::os::unix::fs::MetadataExt::uid(&meta);
            let server = unsafe { libc::geteuid() };
            if !route.module_sandbox && !module_owner_allowed(owner, server) {
                return Err(Error::RouteConfig {
                    host: route.host.clone(),
                    reason: format!(
                        "module {} is owned by uid {owner}, not root or the server user",
                        path.display()
                    ),
                });
            }
        }
        if route.module_sandbox {
            let runner = std::env::var_os("ELIRA_MODULE_RUNNER")
                .map(PathBuf::from)
                .map(Ok)
                .unwrap_or_else(std::env::current_exe)
                .map_err(|err| Error::RouteConfig {
                    host: route.host.clone(),
                    reason: format!("cannot locate the module runner: {err}"),
                })?;
            Target::Module(ModuleTarget::Sandbox(Arc::new(
                elira_module::ProcessModule::new(runner, path.clone()),
            )))
        } else {
            let module = elira_module::Module::load(path).map_err(|err| Error::RouteConfig {
                host: route.host.clone(),
                reason: err.to_string(),
            })?;
            Target::Module(ModuleTarget::InProcess(Arc::new(module)))
        }
    } else if let Some(redirect) = &route.redirect {
        let status = StatusCode::from_u16(redirect.status).map_err(|_| Error::BadRedirect {
            host: route.host.clone(),
        })?;
        let location = redirect.to.clone();
        Target::Redirect { status, location }
    } else if let Some(ret) = &route.return_response {
        let status = StatusCode::from_u16(ret.status).map_err(|_| Error::BadRedirect {
            host: route.host.clone(),
        })?;
        Target::Return {
            status,
            body: ret.body.clone().unwrap_or_default(),
            content_type: ret.content_type.clone(),
        }
    } else {
        return Err(Error::MissingTarget {
            host: route.host.clone(),
        });
    })
}

fn build_auth(route: &elira_config::Route) -> Result<Option<Arc<BasicAuth>>, Error> {
    Ok(match &route.auth_file {
        Some(path) => Some(Arc::new(BasicAuth::from_file(path).map_err(|err| {
            Error::RouteConfig {
                host: route.host.clone(),
                reason: err.to_string(),
            }
        })?)),
        None => None,
    })
}

fn build_acl(route: &elira_config::Route) -> Result<Option<Arc<IpAcl>>, Error> {
    Ok(if route.ip_allow.is_empty() && route.ip_deny.is_empty() {
        None
    } else {
        Some(Arc::new(
            IpAcl::new(&route.ip_allow, &route.ip_deny).map_err(|err| Error::RouteConfig {
                host: route.host.clone(),
                reason: err.to_string(),
            })?,
        ))
    })
}

fn build_limiter(route: &elira_config::Route) -> Option<Arc<RateLimiter>> {
    match route.requests_per_second {
        Some(rate) if rate > 0 => Some(Arc::new(RateLimiter::new(
            rate,
            route.burst.unwrap_or(rate).max(rate),
        ))),
        _ => None,
    }
}

fn build_if_conditions(route: &elira_config::Route) -> Result<Vec<CompiledIf>, Error> {
    route
        .if_conditions
        .iter()
        .map(|condition| {
            let regex = match &condition.matches {
                Some(pattern) => {
                    Some(
                        regex::Regex::new(pattern).map_err(|err| Error::RouteConfig {
                            host: route.host.clone(),
                            reason: err.to_string(),
                        })?,
                    )
                }
                None => None,
            };
            let ret = condition
                .return_response
                .as_ref()
                .expect("if return is validated");
            Ok(CompiledIf {
                variable: condition
                    .variable
                    .strip_prefix('$')
                    .unwrap_or(&condition.variable)
                    .to_owned(),
                equals: condition.equals.clone(),
                regex,
                status: StatusCode::from_u16(ret.status).expect("if status is validated"),
                body: ret.body.clone().unwrap_or_default(),
                content_type: ret.content_type.clone(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()
}

pub(crate) fn build_routers(
    cfg: &Config,
    entries: Vec<(RouteEntry, Vec<String>)>,
) -> HashMap<String, Router> {
    let mut listener_names: Vec<String> = vec!["default".to_owned()];
    if cfg.listen_unix.is_some() {
        listener_names.push("unix".to_owned());
    }
    if cfg.http3.is_some() {
        listener_names.push("http3".to_owned());
    }
    for (index, listener) in cfg.listeners.iter().enumerate() {
        listener_names.push(
            listener
                .name
                .clone()
                .unwrap_or_else(|| format!("listener-{index}")),
        );
    }
    let mut grouped: HashMap<String, Vec<RouteEntry>> = listener_names
        .into_iter()
        .map(|name| (name, Vec::new()))
        .collect();
    for (entry, scoped) in entries {
        if scoped.is_empty() {
            for list in grouped.values_mut() {
                list.push(entry.clone());
            }
        } else {
            for name in scoped {
                if let Some(list) = grouped.get_mut(&name) {
                    list.push(entry.clone());
                }
            }
        }
    }
    let routers: HashMap<String, Router> = grouped
        .into_iter()
        .map(|(name, entries)| (name, Router::from_entries(entries)))
        .collect();
    routers
}

pub(crate) fn build_rewrites(cfg: &Config) -> Result<Vec<CompiledRewrite>, Error> {
    let rewrites = cfg
        .rewrites
        .iter()
        .map(|rewrite| {
            let regex = regex::Regex::new(&rewrite.pattern).map_err(|err| Error::RouteConfig {
                host: "rewrite".to_owned(),
                reason: err.to_string(),
            })?;
            Ok(CompiledRewrite {
                regex,
                replacement: rewrite.replacement.clone(),
                flag: rewrite.flag,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(rewrites)
}

pub(crate) fn build_geos(cfg: &Config) -> Vec<CompiledGeo> {
    let mut geos = Vec::with_capacity(cfg.geos.len());
    for geo in &cfg.geos {
        let mut networks = Vec::with_capacity(geo.values.len());
        for (network, value) in &geo.values {
            let network = if let Ok(network) = network.parse::<ipnet::IpNet>() {
                network
            } else if let Ok(ip) = network.parse::<std::net::IpAddr>() {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                match ipnet::IpNet::new(ip, prefix) {
                    Ok(network) => network,
                    Err(_) => continue,
                }
            } else {
                continue;
            };
            networks.push((network, value.clone()));
        }
        networks.sort_by_key(|(network, _)| std::cmp::Reverse(network.prefix_len()));
        geos.push(CompiledGeo {
            name: geo.name.clone(),
            default: geo.default.clone().unwrap_or_default(),
            networks,
        });
    }
    geos
}

pub(crate) fn build_splits(cfg: &Config) -> Vec<CompiledSplit> {
    let splits = cfg
        .splits
        .iter()
        .map(|split| CompiledSplit {
            name: split.name.clone(),
            source: split.source.clone(),
            buckets: split
                .buckets
                .iter()
                .map(|bucket| (bucket.percent, bucket.value.clone()))
                .collect(),
        })
        .collect();
    splits
}

pub(crate) fn build_connect(cfg: &Config) -> Result<Option<Vec<Authority>>, Error> {
    let connect = if cfg.connect.enabled {
        let mut allowed = Vec::with_capacity(cfg.connect.allow.len());
        for target in &cfg.connect.allow {
            allowed.push(
                target
                    .parse::<Authority>()
                    .map_err(|_| Error::BadConnectTarget {
                        target: target.clone(),
                    })?,
            );
        }
        Some(allowed)
    } else {
        None
    };
    Ok(connect)
}
