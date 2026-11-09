//! Configuration validation.

use std::collections::HashSet;

use http::header::{HeaderName, HeaderValue};
use http::uri::Authority;

use crate::*;

impl Config {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if let Some(path) = &self.listen_unix {
            if path.as_os_str().is_empty() {
                return Err(Error::EmptyUnixListen);
            }
        }
        let mut addresses = HashSet::new();
        addresses.insert(self.listen);
        for listener in &self.listeners {
            if !addresses.insert(listener.listen) {
                return Err(Error::DuplicateListener {
                    listen: listener.listen.to_string(),
                });
            }
            if listener.tls && self.tls.is_none() && self.acme.is_none() {
                return Err(Error::ListenerTlsWithoutConfig);
            }
        }

        let mut udp_addresses = HashSet::new();
        if let Some(http3) = &self.http3 {
            udp_addresses.insert(http3.listen);
        }
        for stream in &self.streams {
            let duplicate = match stream.transport {
                StreamTransport::Tcp => !addresses.insert(stream.listen),
                StreamTransport::Udp => !udp_addresses.insert(stream.listen),
            };
            if duplicate {
                return Err(Error::DuplicateStreamListen {
                    listen: stream.listen.to_string(),
                });
            }
            if stream.upstreams.is_empty() {
                return Err(Error::EmptyStream);
            }
            if stream.listen.port() == 0 {
                return Err(Error::BadStreamListen);
            }
            if stream.connect_timeout_secs == 0 {
                return Err(Error::BadStreamConnect);
            }
            if stream.tls {
                if stream.transport != StreamTransport::Tcp {
                    return Err(Error::StreamTlsOnUdp);
                }
                if self.tls.is_none() && self.acme.is_none() {
                    return Err(Error::StreamTlsWithoutConfig);
                }
            }
            for addr in &stream.upstreams {
                if addr.starts_with("unix:") || check_server(addr).is_err() {
                    return Err(Error::BadStreamUpstream { addr: addr.clone() });
                }
            }
        }

        for rewrite in &self.rewrites {
            if rewrite.pattern.is_empty() || rewrite.replacement.is_empty() {
                return Err(Error::BadRewrite);
            }
        }

        let mut variable_names = HashSet::new();
        for map in &self.maps {
            if map.name.is_empty()
                || !map
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::BadMapName);
            }
            if !map.source.starts_with('$') || map.source.len() < 2 {
                return Err(Error::BadMapSource);
            }
            if !variable_names.insert(map.name.as_str()) {
                return Err(Error::DuplicateMapName {
                    name: map.name.clone(),
                });
            }
        }
        for geo in &self.geos {
            if geo.name.is_empty()
                || !geo
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::BadMapName);
            }
            if !variable_names.insert(geo.name.as_str()) {
                return Err(Error::DuplicateMapName {
                    name: geo.name.clone(),
                });
            }
            if geo.values.is_empty() {
                return Err(Error::BadGeo);
            }
            for network in geo.values.keys() {
                if network.parse::<ipnet::IpNet>().is_err()
                    && network.parse::<std::net::IpAddr>().is_err()
                {
                    return Err(Error::BadGeo);
                }
            }
        }
        for split in &self.splits {
            if split.name.is_empty()
                || !split
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::BadMapName);
            }
            if !split.source.starts_with('$') || split.source.len() < 2 {
                return Err(Error::BadMapSource);
            }
            if !variable_names.insert(split.name.as_str()) {
                return Err(Error::DuplicateMapName {
                    name: split.name.clone(),
                });
            }
            if split.buckets.is_empty()
                || split
                    .buckets
                    .iter()
                    .any(|bucket| bucket.percent == 0 || bucket.percent > 100)
            {
                return Err(Error::BadSplit);
            }
            let total: u16 = split
                .buckets
                .iter()
                .map(|bucket| u16::from(bucket.percent))
                .sum();
            if total > 100 {
                return Err(Error::BadSplit);
            }
        }

        let mut listener_names = HashSet::new();
        listener_names.insert("default".to_owned());
        if self.listen_unix.is_some() {
            listener_names.insert("unix".to_owned());
        }
        if self.http3.is_some() {
            listener_names.insert("http3".to_owned());
        }
        for (index, listener) in self.listeners.iter().enumerate() {
            let name = listener
                .name
                .clone()
                .unwrap_or_else(|| format!("listener-{index}"));
            if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(Error::BadListenerName);
            }
            if !listener_names.insert(name.clone()) {
                return Err(Error::DuplicateListenerName { name });
            }
        }
        if self.unix_tls && self.listen_unix.is_none() {
            return Err(Error::UnixTlsWithoutListener);
        }
        if (self.listen_unix_mode.is_some() || self.listen_unix_owner.is_some())
            && self.listen_unix.is_none()
        {
            return Err(Error::UnixOptionsWithoutListener);
        }
        if self.listen_unix_mode.is_some_and(|mode| mode > 0o7777) {
            return Err(Error::BadUnixMode);
        }
        if let Some(owner) = &self.listen_unix_owner {
            let valid = owner
                .split_once(':')
                .is_some_and(|(uid, gid)| uid.parse::<u32>().is_ok() && gid.parse::<u32>().is_ok());
            if !valid {
                return Err(Error::BadUnixOwner);
            }
        }
        if self.unix_tls && self.tls.is_none() {
            return Err(Error::UnixTlsWithoutTls);
        }
        if self.limits.max_header_bytes < 8192 {
            return Err(Error::MaxHeaderBytesTooSmall);
        }
        if self.limits.max_headers == 0 {
            return Err(Error::MaxHeadersZero);
        }
        if self.limits.max_connections == 0 {
            return Err(Error::MaxConnectionsZero);
        }
        if self.limits.connection_drain_secs == 0 {
            return Err(Error::DrainTimeoutZero);
        }
        if self.limits.shutdown_timeout_secs == 0 {
            return Err(Error::ShutdownTimeoutZero);
        }
        if self.workers == 0 || self.workers > 64 {
            return Err(Error::BadWorkers);
        }
        if self.workers > 1 && !self.reuse_port {
            return Err(Error::WorkersNeedReusePort);
        }
        if let Some(user) = &self.user {
            if user.trim().is_empty() || user.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(Error::BadUser);
            }
        }
        if self.worker_rlimit_nofile == Some(0) {
            return Err(Error::BadRlimit);
        }
        if let Some(cpus) = &self.worker_cpu_affinity {
            if cpus.is_empty() || cpus.iter().any(|cpu| *cpu >= 4096) {
                return Err(Error::BadCpuAffinity);
            }
        }
        if self
            .pid_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::EmptyPidFile);
        }
        if self
            .chroot
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::EmptyChroot);
        }

        if !self.log.sample.is_finite() || !(0.0..=1.0).contains(&self.log.sample) {
            return Err(Error::BadLogSample);
        }

        if self.error_pages.is_empty() {
            if self.error_root.is_some() {
                return Err(Error::GlobalErrorRootWithoutPages);
            }
        } else {
            if self.error_root.is_none() {
                return Err(Error::GlobalErrorPagesNeedRoot);
            }
            for page in &self.error_pages {
                let mut parts = page.splitn(2, char::is_whitespace);
                let status = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default().trim();
                if status.parse::<u16>().is_err()
                    || !(100..=599).contains(&status.parse::<u16>().unwrap_or(0))
                    || !path.starts_with('/')
                    || path.contains("..")
                {
                    return Err(Error::BadGlobalErrorPage { page: page.clone() });
                }
            }
        }

        if self.health.enabled {
            if !self.health.path.starts_with('/')
                || self.health.path.chars().any(|c| c.is_control() || c == ' ')
            {
                return Err(Error::BadHealthPath);
            }
            if !valid_health_method(&self.health.method) {
                return Err(Error::BadHealthMethod {
                    method: self.health.method.clone(),
                });
            }
            if !valid_health_status(&self.health.expect_status) {
                return Err(Error::BadHealthStatus);
            }
            if self
                .health
                .host
                .as_deref()
                .is_some_and(|host| !valid_health_host(host))
            {
                return Err(Error::BadHealthHost);
            }
            if self.health.interval_secs == 0 {
                return Err(Error::BadHealthInterval);
            }
            if self.health.timeout_secs == 0 {
                return Err(Error::BadHealthTimeout);
            }
        }

        if let Some(acme) = &self.acme {
            if self.tls.is_some() {
                return Err(Error::TlsAndAcme);
            }
            if acme.domains.is_empty() {
                return Err(Error::AcmeNoDomains);
            }
            if acme.contacts.is_empty() {
                return Err(Error::AcmeNoContacts);
            }
            if acme.cache_dir.as_os_str().is_empty() {
                return Err(Error::AcmeNoCacheDir);
            }
            if acme.challenge == AcmeChallenge::Http01
                && acme.http01_listen.is_none()
                && self.listen.port() != 80
            {
                return Err(Error::Http01NeedsListener);
            }
            if acme.challenge == AcmeChallenge::Dns01
                && acme
                    .dns_hook
                    .as_ref()
                    .is_none_or(|path| path.as_os_str().is_empty())
            {
                return Err(Error::DnsHookRequired);
            }
        }

        if let Some(dir) = &self.cache.dir {
            if dir.as_os_str().is_empty() {
                return Err(Error::EmptyCacheDir);
            }
        }
        if self.cache.shared && self.cache.dir.is_none() {
            return Err(Error::SharedCacheWithoutDir);
        }

        if let Some(file) = &self.log.file {
            if file.as_os_str().is_empty() {
                return Err(Error::EmptyLogFile);
            }
            if self.log.max_bytes < 1024 {
                return Err(Error::LogRotationTooSmall);
            }
        }

        if let Some(http3) = &self.http3 {
            if http3.cert.as_os_str().is_empty() {
                return Err(Error::Http3MissingCert);
            }
            if http3.key.as_os_str().is_empty() {
                return Err(Error::Http3MissingKey);
            }
            if http3.idle_timeout_secs == 0 {
                return Err(Error::Http3IdleTimeoutZero);
            }
            validate_tls_list("http3.cipher_suites", &http3.cipher_suites)?;
            validate_tls_list("http3.curves", &http3.curves)?;
            if http3
                .ticket_key
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(Error::EmptyTicketKey);
            }
            if http3.client_auth != ClientAuthMode::Off {
                match &http3.client_ca {
                    Some(path) if !path.as_os_str().is_empty() => {}
                    _ => return Err(Error::Http3ClientCaRequired),
                }
            }
            if let Some(crl) = &http3.client_crl {
                if crl.as_os_str().is_empty() {
                    return Err(Error::EmptyClientCrl);
                }
                if http3.client_auth == ClientAuthMode::Off {
                    return Err(Error::ClientCrlWithoutAuth);
                }
            }
            let mut seen: Vec<String> = Vec::new();
            for (index, entry) in http3.certificates.iter().enumerate() {
                if entry.cert.as_os_str().is_empty() || entry.key.as_os_str().is_empty() {
                    return Err(Error::TlsCertificatePair { index });
                }
                if entry
                    .ocsp
                    .as_ref()
                    .is_some_and(|path| path.as_os_str().is_empty())
                {
                    return Err(Error::EmptyOcspPath);
                }
                for name in &entry.names {
                    let name = name.trim().to_ascii_lowercase();
                    if name.is_empty() || (!name.starts_with("*.") && !is_plain_name(&name)) {
                        return Err(Error::TlsCertificateName {
                            index,
                            name: name.clone(),
                        });
                    }
                    if seen.contains(&name) {
                        return Err(Error::TlsCertificateNameDuplicate { name: name.clone() });
                    }
                    seen.push(name);
                }
            }
        }

        if self.connect.enabled {
            if self.connect.allow.is_empty() {
                return Err(Error::ConnectEmptyAllow);
            }
            for target in &self.connect.allow {
                let parsed: Authority = target.parse().map_err(|_| Error::BadConnectTarget {
                    target: target.clone(),
                })?;
                if parsed.port_u16().is_none() || target.contains('@') || target.contains('/') {
                    return Err(Error::BadConnectTarget {
                        target: target.clone(),
                    });
                }
            }
        }

        for cidr in &self.limits.trusted_proxies {
            cidr.parse::<ipnet::IpNet>()
                .map_err(|_| Error::BadTrustedProxy { cidr: cidr.clone() })?;
        }

        if self.routes.is_empty() {
            return Err(Error::NoRoutes);
        }

        if let Some(tls) = &self.tls {
            let has_cert = !tls.cert.as_os_str().is_empty();
            let has_key = !tls.key.as_os_str().is_empty();
            if has_cert != has_key {
                return Err(if has_cert {
                    Error::TlsMissingKey
                } else {
                    Error::TlsMissingCert
                });
            }

            let wants_clients = tls.client_auth != ClientAuthMode::Off;
            match &tls.client_ca {
                // Off ignores the CA entirely, so a stale path is harmless.
                Some(path) if wants_clients => {
                    if path.as_os_str().is_empty() {
                        return Err(Error::TlsClientCaEmpty);
                    }
                }
                None if wants_clients => return Err(Error::TlsClientCaRequired),
                _ => {}
            }
            if let Some(crl) = &tls.client_crl {
                if crl.as_os_str().is_empty() {
                    return Err(Error::EmptyClientCrl);
                }
                if !wants_clients {
                    return Err(Error::ClientCrlWithoutAuth);
                }
            }

            if tls
                .ocsp
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(Error::EmptyOcspPath);
            }
            validate_tls_list("tls.cipher_suites", &tls.cipher_suites)?;
            validate_tls_list("tls.curves", &tls.curves)?;
            if tls
                .ticket_key
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(Error::EmptyTicketKey);
            }
            if tls.ocsp_hook.as_ref().is_some_and(|path| {
                path.as_os_str().is_empty()
                    || (tls.ocsp.is_none()
                        && tls.certificates.iter().all(|entry| entry.ocsp.is_none()))
            }) {
                return Err(Error::OcspHookNeedsFile);
            }
            if tls.ocsp_refresh_secs == 0 && tls.ocsp_hook.is_some() {
                return Err(Error::OcspRefreshZero);
            }

            let has_default = has_cert && has_key;
            if tls.certificates.is_empty() && !has_default {
                return Err(Error::TlsMissingCert);
            }

            let mut seen: Vec<String> = Vec::new();
            for (index, entry) in tls.certificates.iter().enumerate() {
                if entry.cert.as_os_str().is_empty() || entry.key.as_os_str().is_empty() {
                    return Err(Error::TlsCertificatePair { index });
                }
                if entry
                    .ocsp
                    .as_ref()
                    .is_some_and(|path| path.as_os_str().is_empty())
                {
                    return Err(Error::EmptyOcspPath);
                }
                for name in &entry.names {
                    let name = name.trim().to_ascii_lowercase();
                    if name.is_empty() || (!name.starts_with("*.") && !is_plain_name(&name)) {
                        return Err(Error::TlsCertificateName {
                            index,
                            name: name.clone(),
                        });
                    }
                    if seen.contains(&name) {
                        return Err(Error::TlsCertificateNameDuplicate { name: name.clone() });
                    }
                    seen.push(name);
                }
            }
        }

        let mut names = HashSet::new();
        for up in &self.upstreams {
            if up.name.trim().is_empty() {
                return Err(Error::EmptyUpstreamName);
            }
            if !names.insert(up.name.as_str()) {
                return Err(Error::DuplicateUpstream {
                    name: up.name.clone(),
                });
            }
            if up.servers.is_empty() {
                return Err(Error::EmptyUpstream {
                    name: up.name.clone(),
                });
            }
            if !up.weights.is_empty() {
                if up.weights.len() != up.servers.len() {
                    return Err(Error::WeightsLength {
                        name: up.name.clone(),
                    });
                }
                if up.weights.contains(&0) {
                    return Err(Error::ZeroWeight {
                        name: up.name.clone(),
                    });
                }
                if up.balance == Balance::Hash {
                    return Err(Error::WeightsWithHash {
                        name: up.name.clone(),
                    });
                }
                let total: u64 = up.weights.iter().map(|weight| u64::from(*weight)).sum();
                if total > 10_000 {
                    return Err(Error::WeightsTooLarge {
                        name: up.name.clone(),
                    });
                }
            }
            if up.retries > 5 {
                return Err(Error::TooManyRetries {
                    name: up.name.clone(),
                    retries: up.retries,
                });
            }
            for condition in &up.retry_on {
                let valid = matches!(condition.as_str(), "error" | "timeout")
                    || condition
                        .parse::<u16>()
                        .is_ok_and(|code| (500..=599).contains(&code));
                if !valid {
                    return Err(Error::BadRetryCondition {
                        name: up.name.clone(),
                        condition: condition.clone(),
                    });
                }
            }
            if up.h3_pool && !up.tls {
                return Err(Error::H3PoolNeedsTls {
                    name: up.name.clone(),
                });
            }
            if up.h3_pool && up.h2_pool {
                return Err(Error::H3AndH2Pool {
                    name: up.name.clone(),
                });
            }
            if up.dns_ttl_secs == Some(0) {
                return Err(Error::BadDnsTtl {
                    name: up.name.clone(),
                });
            }
            if up.failures_before_eject > 0 && up.eject_secs == 0 {
                return Err(Error::BadEjectTimeout {
                    name: up.name.clone(),
                });
            }
            if let Some(key) = &up.hash_key {
                if up.balance != Balance::Hash {
                    return Err(Error::HashKeyWithoutHashBalance {
                        name: up.name.clone(),
                    });
                }
                if !valid_rate_key(key) {
                    return Err(Error::BadHashKey {
                        name: up.name.clone(),
                        key: key.clone(),
                    });
                }
            }
            if up.tls && up.servers.iter().any(|addr| addr.starts_with("unix:")) {
                return Err(Error::TlsOverUnix {
                    name: up.name.clone(),
                });
            }
            if let Some(path) = &up.health_path {
                if !path.starts_with('/') {
                    return Err(Error::BadUpstreamHealthPath {
                        name: up.name.clone(),
                    });
                }
            }
            if let Some(method) = &up.health_method {
                if !valid_health_method(method) {
                    return Err(Error::BadHealthMethod {
                        method: method.clone(),
                    });
                }
            }
            if let Some(status) = &up.health_expect_status {
                if !valid_health_status(status) {
                    return Err(Error::BadHealthStatus);
                }
            }
            if let Some(host) = &up.health_host {
                if !valid_health_host(host) {
                    return Err(Error::BadHealthHost);
                }
            }
            for addr in &up.servers {
                check_server(addr).map_err(|_| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
            }
        }

        let mut seen = HashSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            let host = route.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(Error::EmptyRouteHost { index });
            }
            for name in &route.listeners {
                if !listener_names.contains(name) {
                    return Err(Error::UnknownListener {
                        index,
                        name: name.clone(),
                    });
                }
            }

            // The same host may appear several times with different paths;
            // only an identical pair is ambiguous.
            let mut discriminator = route
                .path
                .clone()
                .or_else(|| route.path_regex.clone())
                .unwrap_or_default();
            if route.match_type == RouteMatch::Exact {
                discriminator.push_str("|exact");
            }
            if route.no_regex {
                discriminator.push_str("|noregex");
            }
            let mut route_listeners = route.listeners.clone();
            route_listeners.sort();
            route_listeners.dedup();
            if !seen.insert((host.clone(), discriminator, route_listeners.join(","))) {
                return Err(Error::DuplicateRoute {
                    host: route.host.clone(),
                });
            }

            let targets = usize::from(route.upstream.is_some())
                + usize::from(route.root.is_some())
                + usize::from(route.alias.is_some())
                + usize::from(route.redirect.is_some())
                + usize::from(route.return_response.is_some())
                + usize::from(route.fastcgi_pass.is_some())
                + usize::from(route.cgi_pass.is_some())
                + usize::from(route.module.is_some())
                + usize::from(route.wasm.is_some());
            if targets == 0 {
                return Err(Error::RouteNeedsTarget { index });
            }
            if targets > 1 {
                return Err(Error::RouteHasTwoTargets { index });
            }
            if let Some(alias) = &route.alias {
                if alias.as_os_str().is_empty() || !alias.is_absolute() {
                    return Err(Error::BadAlias { index });
                }
                if route.path.is_none() || route.path_regex.is_some() {
                    return Err(Error::AliasNeedsPrefix { index });
                }
            }
            if let Some(ret) = &route.return_response {
                if !(200..=599).contains(&ret.status) {
                    return Err(Error::BadReturnStatus { index });
                }
                if let Some(content_type) = &ret.content_type {
                    if HeaderValue::from_str(content_type).is_err() {
                        return Err(Error::BadReturnContentType { index });
                    }
                }
            }
            for condition in &route.if_conditions {
                if !condition.variable.starts_with('$')
                    || condition.variable.len() < 2
                    || condition.equals.is_some() == condition.matches.is_some()
                {
                    return Err(Error::BadIf { index });
                }
                let Some(ret) = &condition.return_response else {
                    return Err(Error::BadIf { index });
                };
                if !(200..=599).contains(&ret.status) {
                    return Err(Error::BadReturnStatus { index });
                }
                if let Some(content_type) = &ret.content_type {
                    if HeaderValue::from_str(content_type).is_err() {
                        return Err(Error::BadReturnContentType { index });
                    }
                }
            }

            if route.fastcgi_pool_idle.is_some() && route.fastcgi_pass.is_none() {
                return Err(Error::PoolWithoutFastCgi { index });
            }

            if let Some(target) = &route.fastcgi_pass {
                if target.trim().is_empty() {
                    return Err(Error::EmptyFastCgiTarget { index });
                }
                if route
                    .fastcgi_root
                    .as_ref()
                    .is_none_or(|root| root.as_os_str().is_empty())
                {
                    return Err(Error::FastCgiNeedRoot { index });
                }
            }
            if route.fastcgi_index.contains('/') || route.fastcgi_index.contains("..") {
                return Err(Error::BadFastCgiIndex { index });
            }
            for param in route.fastcgi_param.iter().chain(route.cgi_param.iter()) {
                if parse_param(param).is_none() {
                    return Err(Error::BadAppParam {
                        index,
                        param: param.clone(),
                    });
                }
            }
            if let Some(script) = &route.cgi_pass {
                if script.as_os_str().is_empty() || !script.is_absolute() {
                    return Err(Error::BadCgiScript { index });
                }
            }
            if let Some(module) = &route.module {
                if module.as_os_str().is_empty() || !module.is_absolute() {
                    return Err(Error::BadModulePath { index });
                }
            }
            if let Some(wasm) = &route.wasm {
                if wasm.as_os_str().is_empty() || !wasm.is_absolute() {
                    return Err(Error::BadWasmPath { index });
                }
            }
            if route.module_sandbox && route.module.is_none() {
                return Err(Error::SandboxWithoutModule { index });
            }
            if route.max_concurrent == Some(0) {
                return Err(Error::BadConcurrency { index });
            }
            if route.max_response_bytes == Some(0) {
                return Err(Error::BadResponseCap { index });
            }
            if route.max_upstream_response_bytes == Some(0) {
                return Err(Error::BadUpstreamResponseCap { index });
            }
            if let Some(sample) = route.access_log_sample {
                if !sample.is_finite() || !(0.0..=1.0).contains(&sample) {
                    return Err(Error::BadRouteLogSample { index });
                }
            }
            if route.cache_ttl_secs == Some(0) {
                return Err(Error::BadRouteCacheTtl { index });
            }

            if let Some(path) = &route.path {
                if !path.starts_with('/') || path.chars().any(char::is_control) {
                    return Err(Error::BadPath {
                        index,
                        path: path.clone(),
                    });
                }
            }
            if route.path.is_some() && route.path_regex.is_some() {
                return Err(Error::PathAndRegex { index });
            }
            if (route.match_type == RouteMatch::Exact || route.no_regex)
                && (route.path.is_none() || route.path_regex.is_some())
            {
                return Err(Error::BadRouteMatch { index });
            }
            if route.match_type == RouteMatch::Exact && route.no_regex {
                return Err(Error::BadRouteMatch { index });
            }
            if let Some(pattern) = &route.path_regex {
                if regex::Regex::new(pattern).is_err() {
                    return Err(Error::BadPathRegex {
                        index,
                        pattern: pattern.clone(),
                    });
                }
                if route.strip_prefix {
                    return Err(Error::StripPrefixWithRegex { index });
                }
            }

            if route.strip_prefix && route.upstream.is_none() {
                return Err(Error::StripWithoutUpstream { index });
            }

            if route.autoindex && route.root.is_none() {
                return Err(Error::AutoindexWithoutRoot { index });
            }

            if route.timeout_secs == Some(0) {
                return Err(Error::BadRouteTimeout { index });
            }

            if route.requests_per_second == Some(0) {
                return Err(Error::BadRouteRate { index });
            }
            if let Some(key) = &route.rate_key {
                if route.requests_per_second.is_none() {
                    return Err(Error::RateKeyWithoutRate { index });
                }
                if !valid_rate_key(key) {
                    return Err(Error::BadRateKey {
                        index,
                        key: key.clone(),
                    });
                }
            }

            if route.error_root.is_some() && route.error_pages.is_empty() {
                return Err(Error::ErrorRootWithoutPages { index });
            }

            for page in &route.error_pages {
                let mut parts = page.splitn(2, char::is_whitespace);
                let status = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default().trim();
                if status.parse::<u16>().is_err()
                    || !(100..=599).contains(&status.parse::<u16>().unwrap_or(0))
                    || !path.starts_with('/')
                    || path.contains("..")
                {
                    return Err(Error::BadErrorPage {
                        index,
                        page: page.clone(),
                    });
                }
            }

            if (route.client_cn.is_some() || route.client_issuer_cn.is_some()) && !route.client_auth
            {
                return Err(Error::RouteClientFilterWithoutAuth { index });
            }
            if route.client_auth {
                let listener_ok = self
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.client_auth != ClientAuthMode::Off);
                if !listener_ok {
                    return Err(Error::RouteClientAuthWithoutTls { index });
                }
                if self
                    .http3
                    .as_ref()
                    .is_some_and(|http3| http3.client_auth == ClientAuthMode::Off)
                {
                    return Err(Error::RouteClientAuthWithoutHttp3 { index });
                }
            }
            if route
                .client_cn
                .as_ref()
                .is_some_and(|cn| cn.trim().is_empty())
            {
                return Err(Error::EmptyClientCn { index });
            }
            if route
                .client_issuer_cn
                .as_ref()
                .is_some_and(|cn| cn.trim().is_empty())
            {
                return Err(Error::EmptyClientIssuerCn { index });
            }

            if let Some(path) = &route.auth_file {
                if path.as_os_str().is_empty() {
                    return Err(Error::EmptyAuthFile { index });
                }
            }

            for value in route.ip_allow.iter().chain(route.ip_deny.iter()) {
                value.parse::<ipnet::IpNet>().map_err(|_| Error::BadAcl {
                    index,
                    value: value.clone(),
                })?;
            }

            for candidate in &route.try_files {
                if candidate.is_empty()
                    || candidate.chars().any(char::is_control)
                    || candidate.contains("..")
                {
                    return Err(Error::BadTryFile {
                        index,
                        candidate: candidate.clone(),
                    });
                }
            }

            if let Some(upstream) = &route.upstream {
                if !names.contains(upstream.as_str()) {
                    return Err(Error::UnknownUpstream {
                        index,
                        upstream: upstream.clone(),
                    });
                }
            }

            if let Some(root) = &route.root {
                if root.as_os_str().is_empty() {
                    return Err(Error::EmptyRoot { index });
                }
                if route.spa && route.index.is_empty() {
                    return Err(Error::SpaNeedsIndex { index });
                }
                for entry in &route.index {
                    if entry.is_empty() || entry.contains('/') || entry.contains("..") {
                        return Err(Error::BadIndexEntry {
                            index,
                            entry: entry.clone(),
                        });
                    }
                }
            }

            if let Some(redirect) = &route.redirect {
                if redirect.to.is_empty() || redirect.to.chars().any(char::is_control) {
                    return Err(Error::BadRedirect { index });
                }
                if !matches!(redirect.status, 301 | 302 | 303 | 307 | 308) {
                    return Err(Error::BadRedirectStatus {
                        index,
                        status: redirect.status,
                    });
                }
            }

            for header in &route.add_headers {
                parse_header_line(header).ok_or_else(|| Error::BadHeader {
                    index,
                    header: header.clone(),
                })?;
            }
            for name in &route.remove_headers {
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::BadHeader {
                    index,
                    header: name.clone(),
                })?;
            }
            for header in &route.request_headers {
                let (name, _) = parse_header_line(header).ok_or_else(|| Error::BadHeader {
                    index,
                    header: header.clone(),
                })?;
                if reserved_request_header(&name) {
                    return Err(Error::ReservedRequestHeader { index });
                }
            }
            for name in &route.request_remove_headers {
                let name =
                    HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::BadHeader {
                        index,
                        header: name.clone(),
                    })?;
                if reserved_request_header(&name) {
                    return Err(Error::ReservedRequestHeader { index });
                }
            }

            if host != "*" {
                if let Some(suffix) = host.strip_prefix('*') {
                    if !suffix.starts_with('.') || suffix.len() < 2 || suffix.contains('*') {
                        return Err(Error::BadWildcardHost { index });
                    }
                } else if host.contains('*') {
                    return Err(Error::BadWildcardHost { index });
                }
            }
        }

        Ok(())
    }
}

fn validate_tls_list(field: &'static str, list: &Option<Vec<String>>) -> Result<(), Error> {
    let Some(list) = list else {
        return Ok(());
    };
    if list.is_empty() {
        return Err(Error::EmptyTlsList { field });
    }
    if list.iter().any(|value| value.trim().is_empty()) {
        return Err(Error::BlankTlsListEntry { field });
    }
    Ok(())
}

fn valid_health_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn valid_health_status(codes: &[u16]) -> bool {
    codes.iter().all(|status| (100..=599).contains(status))
}

fn valid_health_host(host: &str) -> bool {
    !host.trim().is_empty() && !host.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn valid_rate_key(value: &str) -> bool {
    if value == "ip" || value == "authorization" || value == "uri" {
        return true;
    }
    if let Some(name) = value.strip_prefix("header:") {
        return HeaderName::from_bytes(name.as_bytes()).is_ok();
    }
    if let Some(name) = value.strip_prefix("cookie:") {
        return !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
    }
    false
}

fn parse_param(value: &str) -> Option<(String, String)> {
    let (name, value) = value.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

/// Host name without wildcards: letters, digits, dots, hyphens, underscores.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !name.starts_with('.')
        && !name.ends_with('.')
}

fn parse_header_line(line: &str) -> Option<(HeaderName, HeaderValue)> {
    let (name, value) = line.split_once(':')?;
    let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    let value = HeaderValue::from_str(value.trim()).ok()?;
    Some((name, value))
}

fn reserved_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn check_server(addr: &str) -> Result<(), ()> {
    if let Some(path) = addr.strip_prefix("unix:") {
        if path.is_empty() || path.contains('\0') {
            return Err(());
        }
        return Ok(());
    }
    if addr.contains('@') || addr.contains('/') {
        return Err(());
    }
    let authority: Authority = addr.parse().map_err(|_| ())?;
    if authority.port_u16().is_none() {
        return Err(());
    }
    Ok(())
}
