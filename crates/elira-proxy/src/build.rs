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
use elira_config::Config;
use elira_limit::RateLimiter;
use elira_upstream::{https_connector, TlsOptions};

use crate::*;

type Pools = HashMap<String, Arc<Pool>>;

pub(crate) fn build_pools(cfg: &Config) -> Result<(Pools, Vec<Arc<Pool>>), Error> {
    let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
    for up in &cfg.upstreams {
        let mut servers = Vec::with_capacity(up.servers.len());
        for addr in &up.servers {
            let server = ServerAddr::parse(addr).ok_or_else(|| Error::BadServer {
                upstream: up.name.clone(),
                addr: addr.clone(),
            })?;
            servers.push(server);
        }
        let health = (0..servers.len()).map(|_| AtomicBool::new(true)).collect();
        let active = (0..servers.len()).map(|_| AtomicUsize::new(0)).collect();
        let passive = (0..servers.len())
            .map(|_| Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            })
            .collect();
        let server_labels = servers.iter().map(ToString::to_string).collect();
        let weights = if up.weights.is_empty() {
            vec![1; servers.len()]
        } else {
            up.weights.clone()
        };
        let total_weight: u64 = weights.iter().map(|weight| u64::from(*weight)).sum();
        let weighted = weights.iter().any(|weight| *weight != 1);

        // Each pool gets its own connector: trust and ALPN may differ
        // between upstreams.
        let tls = TlsOptions {
            insecure: up.tls_insecure.unwrap_or(cfg.upstream_tls.insecure),
            ca: up.tls_ca.clone().or_else(|| cfg.upstream_tls.ca.clone()),
            sni: up.sni.clone(),
            http2: up.http2.unwrap_or(cfg.upstream_tls.http2),
            tls13_only: cfg.upstream_tls.min_version == elira_config::TlsVersion::Tls13,
        };
        let connector = https_connector(&tls).map_err(|err| Error::UpstreamTls {
            reason: err.to_string(),
        })?;
        let client = Client::builder(TokioExecutor::new())
            // Hyper resolves the name for each new connection, so the
            // pool lifetime is the upper bound on DNS staleness.
            .pool_idle_timeout(Some(Duration::from_secs(up.dns_ttl_secs.unwrap_or(30))))
            .build(connector);

        pools.insert(
            up.name.clone(),
            Arc::new(Pool {
                name: up.name.clone(),
                servers,
                health,
                active,
                passive,
                failures_before_eject: up.failures_before_eject,
                eject_for: Duration::from_secs(up.eject_secs),
                started: Instant::now(),
                hash_key: parse_request_key(up.hash_key.as_deref()),
                server_labels,
                weights,
                total_weight,
                weighted,
                retry_on: RetryOn::parse(&up.retry_on),
                next: AtomicUsize::new(0),
                balance: up.balance,
                retries: up.retries,
                scheme: if up.tls { "https" } else { "http" },
                client,
                tls: tls.clone(),
                health_path: up.health_path.clone(),
                health_method: up.health_method.clone(),
                health_status: up.health_expect_status.clone(),
                health_host: up.health_host.clone(),
                h3: up.h3_pool.then(|| {
                    elira_h3upstream::Pool::new(elira_h3upstream::PoolConfig {
                        max_connections: 4,
                        connect_timeout: Duration::from_secs(5),
                        tls: tls.clone(),
                    })
                }),
                h2: up.h2_pool.then(|| {
                    elira_h2::Pool::new(elira_h2::PoolConfig::new(
                        4,
                        Duration::from_secs(5),
                        tls.clone(),
                    ))
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
) -> Result<RouteEntry, Error> {
    let target = build_target(route, cfg, pools)?;

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
        limiter,
        rate_key: parse_request_key(route.rate_key.as_deref()),
        body_limit: route.max_body_bytes,
        error_pages,
        app_permits,
        proxy_permits,
        max_response: route.max_response_bytes,
        cache: route.cache_enabled,
        cache_ttl: route.cache_ttl_secs.map(Duration::from_secs),
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

fn build_target(route: &elira_config::Route, cfg: &Config, pools: &Pools) -> Result<Target, Error> {
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
