//! Flatten nested locations into the flat route table.
//!
//! Nested blocks are a configuration convenience: after this pass the proxy
//! sees ordinary routes with full paths. Targets and unset options are
//! inherited from the parent; booleans that default to false are enabled by
//! either level.

use crate::*;

const MAX_DEPTH: usize = 16;

pub(crate) fn expand_locations(cfg: &mut Config) -> Result<(), Error> {
    let routes = std::mem::take(&mut cfg.routes);
    let mut out = Vec::new();
    for route in routes {
        expand(route, None, 0, &mut out)?;
    }
    cfg.routes = out;
    Ok(())
}

fn expand(
    mut route: Route,
    parent: Option<&Route>,
    depth: usize,
    out: &mut Vec<Route>,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::BadNestedLocation);
    }
    if parent.is_some() && route.path.is_none() && route.path_regex.is_none() {
        return Err(Error::BadNestedLocation);
    }
    if let Some(parent) = parent {
        inherit(parent, &mut route)?;
    }

    let children = std::mem::take(&mut route.locations);
    if has_target(&route) || children.is_empty() {
        out.push(route.clone());
    } else if route.path.is_none() && route.path_regex.is_none() {
        // A host-level grouping block covers the whole host.
        route.path = Some("/".to_owned());
    }

    for child in children {
        expand(child, Some(&route), depth + 1, out)?;
    }
    Ok(())
}

fn inherit(parent: &Route, child: &mut Route) -> Result<(), Error> {
    if child.host.trim().is_empty() {
        child.host = parent.host.clone();
    }
    if child.listeners.is_empty() {
        child.listeners = parent.listeners.clone();
    }

    let child_path = child.path.clone().unwrap_or_default();
    if child.path_regex.is_some() {
        let prefix = parent
            .path
            .clone()
            .or_else(|| parent.regex_prefix.clone())
            .ok_or(Error::BadNestedLocation)?;
        child.path = None;
        child.regex_prefix = Some(prefix.trim_end_matches('/').to_owned());
    } else {
        let parent_path = parent.path.as_deref().unwrap_or("");
        child.path = Some(join_path(parent_path, &child_path));
    }

    if !has_target(child) {
        child.upstream = parent.upstream.clone();
        child.root = parent.root.clone();
        // An alias points at the parent's directory, so append the part the
        // child path adds below the parent.
        child.alias = parent
            .alias
            .as_ref()
            .map(|alias| alias.join(relative_path(parent.path.as_deref(), &child_path)));
        child.redirect = parent.redirect.clone();
        child.return_response = parent.return_response.clone();
        child.fastcgi_pass = parent.fastcgi_pass.clone();
        child.fastcgi_root = parent.fastcgi_root.clone();
        child.cgi_pass = parent.cgi_pass.clone();
        child.scgi_pass = parent.scgi_pass.clone();
        child.scgi_root = parent.scgi_root.clone();
        child.uwsgi_pass = parent.uwsgi_pass.clone();
        child.uwsgi_modifier1 = parent.uwsgi_modifier1;
        child.uwsgi_modifier2 = parent.uwsgi_modifier2;
        child.module = parent.module.clone();
        child.wasm = parent.wasm.clone();
    }

    child.max_concurrent = child.max_concurrent.or(parent.max_concurrent);
    if child.path_regex.is_none() {
        child.strip_prefix |= parent.strip_prefix;
    }
    child.spa |= parent.spa;
    child.autoindex |= parent.autoindex;
    child.module_sandbox |= parent.module_sandbox;
    child.client_auth |= parent.client_auth;
    child.timeout_secs = child.timeout_secs.or(parent.timeout_secs);
    child.requests_per_second = child.requests_per_second.or(parent.requests_per_second);
    child.burst = child.burst.or(parent.burst);
    child.rate_key = child.rate_key.clone().or_else(|| parent.rate_key.clone());
    child.max_body_bytes = child.max_body_bytes.or(parent.max_body_bytes);
    child.max_response_bytes = child.max_response_bytes.or(parent.max_response_bytes);
    child.max_upstream_response_bytes = child
        .max_upstream_response_bytes
        .or(parent.max_upstream_response_bytes);
    child.fastcgi_pool_idle = child.fastcgi_pool_idle.or(parent.fastcgi_pool_idle);
    child.cache_enabled = child.cache_enabled.or(parent.cache_enabled);
    child.cache_ttl_secs = child.cache_ttl_secs.or(parent.cache_ttl_secs);
    child.access_log_sample = child.access_log_sample.or(parent.access_log_sample);
    child.client_cn = child.client_cn.clone().or_else(|| parent.client_cn.clone());
    child.client_issuer_cn = child
        .client_issuer_cn
        .clone()
        .or_else(|| parent.client_issuer_cn.clone());
    child.error_root = child
        .error_root
        .clone()
        .or_else(|| parent.error_root.clone());
    child.expires_secs = child.expires_secs.or(parent.expires_secs);
    child.etag = child.etag.or(parent.etag);
    child.auth_file = child.auth_file.clone().or_else(|| parent.auth_file.clone());

    if child.access_log == Route::default_access_log() {
        child.access_log = parent.access_log;
    }
    if child.index == Route::default_index() {
        child.index = parent.index.clone();
    }
    if child.fastcgi_index == Route::default_fastcgi_index() {
        child.fastcgi_index = parent.fastcgi_index.clone();
    }

    inherit_vec(&mut child.try_files, &parent.try_files);
    inherit_vec(&mut child.ip_allow, &parent.ip_allow);
    inherit_vec(&mut child.ip_deny, &parent.ip_deny);
    inherit_vec(&mut child.error_pages, &parent.error_pages);
    inherit_vec(&mut child.add_headers, &parent.add_headers);
    inherit_vec(&mut child.remove_headers, &parent.remove_headers);
    inherit_vec(&mut child.request_headers, &parent.request_headers);
    inherit_vec(
        &mut child.request_remove_headers,
        &parent.request_remove_headers,
    );
    inherit_vec(&mut child.fastcgi_param, &parent.fastcgi_param);
    inherit_vec(&mut child.cgi_param, &parent.cgi_param);
    inherit_vec(&mut child.scgi_param, &parent.scgi_param);
    inherit_vec(&mut child.uwsgi_param, &parent.uwsgi_param);
    inherit_vec(&mut child.if_conditions, &parent.if_conditions);

    Ok(())
}

fn inherit_vec<T: Clone>(child: &mut Vec<T>, parent: &[T]) {
    if child.is_empty() {
        *child = parent.to_vec();
    }
}

fn has_target(route: &Route) -> bool {
    route.upstream.is_some()
        || route.root.is_some()
        || route.alias.is_some()
        || route.redirect.is_some()
        || route.return_response.is_some()
        || route.fastcgi_pass.is_some()
        || route.cgi_pass.is_some()
        || route.scgi_pass.is_some()
        || route.uwsgi_pass.is_some()
        || route.module.is_some()
        || route.wasm.is_some()
}

fn relative_path(parent: Option<&str>, child: &str) -> String {
    let Some(parent) = parent else {
        return child.trim_start_matches('/').to_owned();
    };
    let parent = parent.trim_end_matches('/');
    child
        .strip_prefix(parent)
        .unwrap_or(child)
        .trim_start_matches('/')
        .to_owned()
}

fn join_path(parent: &str, child: &str) -> String {
    let parent = parent.trim().trim_end_matches('/');
    let child = child.trim();
    if child.is_empty() {
        return if parent.is_empty() {
            "/".to_owned()
        } else {
            parent.to_owned()
        };
    }
    if !parent.is_empty() && (child == parent || child.starts_with(&format!("{parent}/"))) {
        return child.to_owned();
    }
    let child = child.trim_start_matches('/');
    if parent.is_empty() {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str) -> Route {
        Route {
            host: String::new(),
            listeners: Vec::new(),
            path: Some(path.to_owned()),
            locations: Vec::new(),
            regex_prefix: None,
            name: None,
            internal: false,
            match_type: RouteMatch::Prefix,
            no_regex: false,
            path_regex: None,
            upstream: None,
            root: None,
            alias: None,
            expires_secs: None,
            etag: None,
            redirect: None,
            return_response: None,
            if_conditions: Vec::new(),
            fastcgi_pass: None,
            fastcgi_root: None,
            fastcgi_index: Route::default_fastcgi_index(),
            fastcgi_param: Vec::new(),
            cgi_param: Vec::new(),
            scgi_pass: None,
            scgi_root: None,
            scgi_param: Vec::new(),
            uwsgi_pass: None,
            uwsgi_modifier1: None,
            uwsgi_modifier2: None,
            uwsgi_param: Vec::new(),
            cgi_pass: None,
            module: None,
            module_sandbox: false,
            wasm: None,
            max_concurrent: None,
            index: Route::default_index(),
            spa: false,
            strip_prefix: false,
            try_files: Vec::new(),
            autoindex: false,
            auth_file: None,
            ip_allow: Vec::new(),
            ip_deny: Vec::new(),
            timeout_secs: None,
            requests_per_second: None,
            burst: None,
            rate_key: None,
            max_body_bytes: None,
            max_response_bytes: None,
            max_upstream_response_bytes: None,
            fastcgi_pool_idle: None,
            cache_enabled: None,
            cache_ttl_secs: None,
            access_log: Route::default_access_log(),
            access_log_sample: None,
            client_auth: false,
            client_cn: None,
            client_issuer_cn: None,
            error_pages: Vec::new(),
            error_root: None,
            add_headers: Vec::new(),
            remove_headers: Vec::new(),
            request_headers: Vec::new(),
            request_remove_headers: Vec::new(),
        }
    }

    #[test]
    fn nested_paths_are_joined() {
        assert_eq!(join_path("/app", "/admin"), "/app/admin");
        assert_eq!(join_path("/app/", "admin"), "/app/admin");
        assert_eq!(join_path("/app", "/app/admin"), "/app/admin");
        assert_eq!(join_path("/", "/admin"), "/admin");
        assert_eq!(join_path("/app", "/application"), "/app/application");
    }

    #[test]
    fn child_inherits_target_and_options() {
        let mut parent = route("/app");
        parent.host = "example.com".to_owned();
        parent.upstream = Some("app".to_owned());
        parent.timeout_secs = Some(9);
        let mut child = route("/admin");
        child.timeout_secs = Some(3);

        inherit(&parent, &mut child).expect("inherit");
        assert_eq!(child.host, "example.com");
        assert_eq!(child.path.as_deref(), Some("/app/admin"));
        assert_eq!(child.upstream.as_deref(), Some("app"));
        assert_eq!(child.timeout_secs, Some(3));
    }

    #[test]
    fn nested_regex_keeps_the_parent_prefix() {
        let mut parent = route("/app");
        parent.upstream = Some("app".to_owned());
        let mut child = route("/ignored");
        child.path = None;
        child.path_regex = Some(r"\.php$".to_owned());

        inherit(&parent, &mut child).expect("inherit");
        assert_eq!(child.path, None);
        assert_eq!(child.regex_prefix.as_deref(), Some("/app"));
        assert_eq!(child.upstream.as_deref(), Some("app"));
    }

    #[test]
    fn host_level_grouping_parent_covers_the_whole_host() {
        let mut parent = route("/");
        parent.path = None;
        parent.host = "example.com".to_owned();
        parent.locations = vec![{
            let mut child = route("/admin");
            child.upstream = Some("app".to_owned());
            child
        }];
        let mut out = Vec::new();

        expand(parent, None, 0, &mut out).expect("expand");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_deref(), Some("/admin"));
        assert_eq!(out[0].host, "example.com");
    }

    #[test]
    fn grouping_parent_without_target_is_dropped() {
        let mut parent = route("/app");
        parent.host = "example.com".to_owned();
        parent.locations = vec![{
            let mut child = route("/admin");
            child.upstream = Some("app".to_owned());
            child
        }];
        let mut out = Vec::new();

        expand(parent, None, 0, &mut out).expect("expand");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_deref(), Some("/app/admin"));
        assert_eq!(out[0].host, "example.com");
    }
}
