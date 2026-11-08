//! nginx config migration.
//!
//! The converter understands the small subset of the nginx configuration
//! language that maps onto Elira's one-listener, route-table model. Anything
//! it cannot translate is reported as a warning instead of failing the whole
//! migration, so the output can still be used as a starting point.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use thiserror::Error;

/// A successfully converted configuration.
#[derive(Debug, Clone)]
pub struct Migration {
    /// TOML accepted by `elira_config::Config::parse`.
    pub toml: String,
    /// Directives and constructs that had no Elira equivalent.
    pub warnings: Vec<String>,
}

/// Convert an nginx configuration into Elira TOML.
pub fn migrate(input: &str) -> Result<Migration, Error> {
    let tokens = lex(input)?;
    let nodes = parse(tokens)?;

    let mut converter = Converter::default();
    let mut upstream_nodes = Vec::new();
    let mut server_nodes = Vec::new();
    converter.gather(&nodes, &mut upstream_nodes, &mut server_nodes);

    if server_nodes.is_empty() {
        return Err(Error::NoServer);
    }

    for node in upstream_nodes {
        converter.upstream(node)?;
    }
    for node in server_nodes {
        converter.server(node)?;
    }

    if converter.routes.is_empty() {
        return Err(Error::NoRoutes);
    }

    Ok(Migration {
        toml: converter.render(),
        warnings: converter.warnings,
    })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("line {line}: {message}")]
    Syntax { line: usize, message: String },

    #[error("no `server` block found in the nginx config")]
    NoServer,

    #[error("the nginx config produced no routes")]
    NoRoutes,

    #[error("upstream `{name}` is defined twice")]
    DuplicateUpstream { name: String },
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    Word(String),
    Open,
    Close,
    Semi,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    line: usize,
}

fn lex(input: &str) -> Result<Vec<Token>, Error> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut line = 1;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' => {
                tokens.push(Token {
                    kind: TokenKind::Open,
                    line,
                });
                i += 1;
            }
            '}' => {
                tokens.push(Token {
                    kind: TokenKind::Close,
                    line,
                });
                i += 1;
            }
            ';' => {
                tokens.push(Token {
                    kind: TokenKind::Semi,
                    line,
                });
                i += 1;
            }
            _ => {
                let start_line = line;
                let mut word = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || matches!(c, '{' | '}' | ';' | '#') {
                        break;
                    }
                    match c {
                        '"' | '\'' => {
                            let (text, next, next_line) = read_quoted(&chars, i, line)?;
                            word.push_str(&text);
                            i = next;
                            line = next_line;
                        }
                        '\\' => {
                            i += 1;
                            if i >= chars.len() {
                                return Err(syntax(line, "trailing backslash"));
                            }
                            // nginx treats a backslash as a literal escape for
                            // `"`, `'`, `\`, `$` and whitespace; keep the
                            // target character so words survive the round trip.
                            let escaped = chars[i];
                            match escaped {
                                'n' => word.push('\n'),
                                'r' => word.push('\r'),
                                't' => word.push('\t'),
                                other => word.push(other),
                            }
                            i += 1;
                        }
                        _ => {
                            word.push(c);
                            i += 1;
                        }
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line: start_line,
                });
            }
        }
    }

    Ok(tokens)
}

fn read_quoted(
    chars: &[char],
    start: usize,
    mut line: usize,
) -> Result<(String, usize, usize), Error> {
    let quote = chars[start];
    let mut text = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        let c = chars[i];
        if c == quote {
            return Ok((text, i + 1, line));
        }
        if c == '\\' && i + 1 < chars.len() {
            let escaped = chars[i + 1];
            match escaped {
                'n' => text.push('\n'),
                'r' => text.push('\r'),
                't' => text.push('\t'),
                '\\' => text.push('\\'),
                '"' => text.push('"'),
                '\'' => text.push('\''),
                '\n' => line += 1,
                other => {
                    text.push('\\');
                    text.push(other);
                }
            }
            i += 2;
            continue;
        }
        if c == '\n' {
            line += 1;
        }
        text.push(c);
        i += 1;
    }
    Err(syntax(line, format!("unterminated {quote} quote")))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Node {
    name: String,
    args: Vec<String>,
    line: usize,
    children: Option<Vec<Node>>,
}

fn parse(tokens: Vec<Token>) -> Result<Vec<Node>, Error> {
    let mut pos = 0;
    let nodes = parse_block(&tokens, &mut pos, false)?;
    Ok(nodes)
}

fn parse_block(tokens: &[Token], pos: &mut usize, nested: bool) -> Result<Vec<Node>, Error> {
    let mut nodes = Vec::new();
    loop {
        let Some(token) = tokens.get(*pos) else {
            if nested {
                return Err(syntax(
                    tokens.last().map(|t| t.line).unwrap_or(1),
                    "unexpected end of file, expected `}`",
                ));
            }
            return Ok(nodes);
        };
        match &token.kind {
            TokenKind::Close => {
                if !nested {
                    return Err(syntax(token.line, "unexpected `}`"));
                }
                *pos += 1;
                return Ok(nodes);
            }
            TokenKind::Semi => return Err(syntax(token.line, "unexpected `;`")),
            TokenKind::Open => return Err(syntax(token.line, "unexpected `{`")),
            TokenKind::Word(name) => {
                let (name, line) = (name.clone(), token.line);
                *pos += 1;
                let mut args = Vec::new();
                loop {
                    let Some(next) = tokens.get(*pos) else {
                        return Err(syntax(
                            line,
                            format!("directive `{name}` is not terminated"),
                        ));
                    };
                    match &next.kind {
                        TokenKind::Word(arg) => {
                            args.push(arg.clone());
                            *pos += 1;
                        }
                        TokenKind::Semi => {
                            *pos += 1;
                            nodes.push(Node {
                                name,
                                args,
                                line,
                                children: None,
                            });
                            break;
                        }
                        TokenKind::Open => {
                            *pos += 1;
                            let children = parse_block(tokens, pos, true)?;
                            nodes.push(Node {
                                name,
                                args,
                                line,
                                children: Some(children),
                            });
                            break;
                        }
                        TokenKind::Close => {
                            return Err(syntax(
                                next.line,
                                format!("directive `{name}` is missing `;`"),
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn syntax(line: usize, message: impl Into<String>) -> Error {
    Error::Syntax {
        line,
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Converter
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Converter {
    warnings: Vec<String>,
    upstreams: Vec<Upstream>,
    /// Names that appeared in an `upstream` block, even if unusable.
    declared_upstreams: HashSet<String>,
    /// Names of upstreams that made it into the output.
    usable_upstreams: HashSet<String>,
    literal_upstreams: HashMap<(String, bool), String>,
    routes: Vec<Route>,
    route_keys: HashSet<(String, String)>,
    listen: Option<String>,
}

#[derive(Debug)]
struct Upstream {
    name: String,
    servers: Vec<String>,
    balance: Option<String>,
    tls: bool,
}

#[derive(Debug)]
struct Route {
    host: String,
    path: Option<String>,
    upstream: Option<String>,
    root: Option<String>,
    index: Option<Vec<String>>,
    redirect: Option<(String, u16)>,
    strip_prefix: bool,
}

impl Converter {
    fn warn(&mut self, line: usize, message: impl Into<String>) {
        self.warnings
            .push(format!("line {line}: {}", message.into()));
    }

    fn gather<'a>(
        &mut self,
        nodes: &'a [Node],
        upstreams: &mut Vec<&'a Node>,
        servers: &mut Vec<&'a Node>,
    ) {
        for node in nodes {
            match node.name.as_str() {
                "upstream" => {
                    if node.children.is_some() {
                        upstreams.push(node);
                    } else {
                        self.warn(node.line, "`upstream` without a block, skipped");
                    }
                }
                "server" => {
                    if node.children.is_some() {
                        servers.push(node);
                    } else {
                        self.warn(node.line, "`server` without a block, skipped");
                    }
                }
                // Common in full nginx configs and purely a container for
                // what we already understand.
                "http" => {
                    if let Some(children) = &node.children {
                        self.gather(children, upstreams, servers);
                    } else {
                        self.warn(node.line, "`http` without a block, skipped");
                    }
                }
                other => self.warn(
                    node.line,
                    format!("unsupported top-level directive `{other}`, skipped"),
                ),
            }
        }
    }

    fn upstream(&mut self, node: &Node) -> Result<(), Error> {
        let Some(name) = node.args.first() else {
            self.warn(node.line, "`upstream` without a name, skipped");
            return Ok(());
        };
        if name.contains('$') {
            self.warn(
                node.line,
                format!("upstream name `{name}` uses variables, skipped"),
            );
            return Ok(());
        }
        if !self.declared_upstreams.insert(name.clone()) {
            return Err(Error::DuplicateUpstream { name: name.clone() });
        }

        let mut servers = Vec::new();
        let mut balance = None;
        for child in node.children.as_deref().unwrap_or(&[]) {
            match child.name.as_str() {
                "server" => {
                    if child.args.len() > 1 {
                        self.warn(
                            child.line,
                            "upstream `server` parameters (weight, backup, ...) are not migrated",
                        );
                    }
                    match child.args.first() {
                        Some(raw) => match server_address(raw) {
                            Ok(addr) => servers.push(addr),
                            Err(reason) => self.warn(
                                child.line,
                                format!("upstream server `{raw}` skipped: {reason}"),
                            ),
                        },
                        None => self.warn(child.line, "upstream `server` has no address, skipped"),
                    }
                }
                "least_conn" => balance = Some("least_conn".to_owned()),
                "ip_hash" | "hash" | "random" => self.warn(
                    child.line,
                    format!(
                        "load-balancing method `{}` is not supported, round_robin is used",
                        child.name
                    ),
                ),
                "keepalive" | "keepalive_requests" | "keepalive_timeout" | "zone" | "resolver" => {
                    self.warn(
                        child.line,
                        format!("upstream directive `{}` is not migrated", child.name),
                    )
                }
                other => self.warn(
                    child.line,
                    format!("unsupported upstream directive `{other}`, skipped"),
                ),
            }
        }

        if servers.is_empty() {
            self.warn(
                node.line,
                format!("upstream `{name}` has no usable servers, skipped"),
            );
            return Ok(());
        }

        self.usable_upstreams.insert(name.clone());
        self.upstreams.push(Upstream {
            name: name.clone(),
            servers,
            balance,
            tls: false,
        });
        Ok(())
    }

    fn server(&mut self, node: &Node) -> Result<(), Error> {
        let children = node.children.as_deref().unwrap_or(&[]);
        let mut listen: Option<String> = None;
        let mut names: Vec<String> = Vec::new();
        let mut default_root: Option<String> = None;
        let mut default_index: Option<Vec<String>> = None;
        let mut default_return: Option<(u16, String)> = None;
        let mut locations: Vec<&Node> = Vec::new();

        for child in children {
            match child.name.as_str() {
                "listen" => {
                    if listen.is_some() {
                        self.warn(
                            child.line,
                            "additional `listen` directive ignored, Elira has one listener",
                        );
                        continue;
                    }
                    match child.args.first() {
                        Some(raw) => match listen_address(raw) {
                            Ok(addr) => listen = Some(addr),
                            Err(reason) => {
                                self.warn(child.line, format!("listen `{raw}` skipped: {reason}"))
                            }
                        },
                        None => self.warn(child.line, "`listen` without an address, ignored"),
                    }
                    for param in child.args.iter().skip(1) {
                        self.warn(
                            child.line,
                            format!("`listen` parameter `{param}` is not migrated"),
                        );
                    }
                }
                "server_name" => {
                    if child.args.is_empty() {
                        self.warn(child.line, "`server_name` without names, ignored");
                    }
                    for raw in &child.args {
                        match server_name(raw) {
                            Ok(name) => names.push(name),
                            Err(reason) => self
                                .warn(child.line, format!("server name `{raw}` skipped: {reason}")),
                        }
                    }
                }
                "root" => match child.args.first() {
                    Some(root) => default_root = Some(root.clone()),
                    None => self.warn(child.line, "`root` without a directory, ignored"),
                },
                "index" => {
                    if child.args.is_empty() {
                        self.warn(child.line, "`index` without file names, ignored");
                    } else {
                        default_index = Some(child.args.clone());
                    }
                }
                "return" => default_return = self.parse_return(child),
                "location" => {
                    if child.children.is_some() {
                        locations.push(child);
                    } else {
                        self.warn(child.line, "`location` without a block, skipped");
                    }
                }
                other => self.unsupported(child, "server", other),
            }
        }

        let effective_listen = listen.unwrap_or_else(|| "0.0.0.0:80".to_owned());
        match &self.listen {
            None => self.listen = Some(effective_listen),
            Some(existing) if existing == &effective_listen => {}
            Some(existing) => self.warn(
                node.line,
                format!(
                    "another server listens on `{effective_listen}`; Elira has one listener, keeping `{existing}`"
                ),
            ),
        }

        let mut hosts = dedup(names);
        if hosts.is_empty() {
            hosts.push("*".to_owned());
        }

        if let Some((status, to)) = default_return {
            if !locations.is_empty() {
                self.warn(
                    node.line,
                    "server-level `return` ignores all locations in this server",
                );
            }
            for host in hosts {
                self.push_route(
                    Route {
                        host,
                        path: None,
                        upstream: None,
                        root: None,
                        index: None,
                        redirect: Some((to.clone(), status)),
                        strip_prefix: false,
                    },
                    node.line,
                );
            }
            return Ok(());
        }

        if locations.is_empty() {
            match default_root {
                Some(root) => {
                    for host in hosts {
                        self.push_route(
                            Route {
                                host,
                                path: None,
                                upstream: None,
                                root: Some(root.clone()),
                                index: default_index.clone(),
                                redirect: None,
                                strip_prefix: false,
                            },
                            node.line,
                        );
                    }
                }
                None => self.warn(
                    node.line,
                    "server block has no locations and no root, no routes generated",
                ),
            }
            return Ok(());
        }

        for location in locations {
            self.location(
                location,
                &hosts,
                default_root.as_deref(),
                default_index.as_deref(),
            )?;
        }
        Ok(())
    }

    fn location(
        &mut self,
        node: &Node,
        hosts: &[String],
        default_root: Option<&str>,
        default_index: Option<&[String]>,
    ) -> Result<(), Error> {
        let Some(path) = location_path(&node.args, node.line, &mut self.warnings) else {
            return Ok(());
        };

        let mut proxy: Option<String> = None;
        let mut root: Option<String> = None;
        let mut index: Option<Vec<String>> = None;
        let mut redirect: Option<(u16, String)> = None;

        for child in node.children.as_deref().unwrap_or(&[]) {
            match child.name.as_str() {
                "proxy_pass" => match child.args.first() {
                    Some(url) if proxy.is_none() => proxy = Some(url.clone()),
                    Some(_) => self.warn(
                        child.line,
                        "duplicate `proxy_pass` in a location, keeping the first",
                    ),
                    None => self.warn(child.line, "`proxy_pass` without a URL, ignored"),
                },
                "root" => match child.args.first() {
                    Some(dir) => root = Some(dir.clone()),
                    None => self.warn(child.line, "`root` without a directory, ignored"),
                },
                "index" => {
                    if child.args.is_empty() {
                        self.warn(child.line, "`index` without file names, ignored");
                    } else {
                        index = Some(child.args.clone());
                    }
                }
                "return" => {
                    if let Some(parsed) = self.parse_return(child) {
                        redirect = Some(parsed);
                    }
                }
                "location" => self.warn(
                    child.line,
                    "nested `location` blocks are not supported, skipped",
                ),
                other => self.unsupported(child, "location", other),
            }
        }

        if let Some((status, to)) = redirect {
            if proxy.is_some() || root.is_some() {
                self.warn(
                    node.line,
                    "`return` wins over `proxy_pass`/`root` in the same location",
                );
            }
            for host in hosts {
                self.push_route(
                    Route {
                        host: host.clone(),
                        path: path.clone(),
                        upstream: None,
                        root: None,
                        index: None,
                        redirect: Some((to.clone(), status)),
                        strip_prefix: false,
                    },
                    node.line,
                );
            }
            return Ok(());
        }

        if let Some(url) = proxy {
            if root.is_some() {
                self.warn(
                    node.line,
                    "location has both `proxy_pass` and `root`, using `proxy_pass`",
                );
            }
            if let Some((upstream, strip_prefix)) = self.proxy_target(&url, node.line) {
                for host in hosts {
                    self.push_route(
                        Route {
                            host: host.clone(),
                            path: path.clone(),
                            upstream: Some(upstream.clone()),
                            root: None,
                            index: None,
                            redirect: None,
                            strip_prefix,
                        },
                        node.line,
                    );
                }
            }
            return Ok(());
        }

        let effective_root = root.as_deref().or(default_root);
        let effective_index = index
            .clone()
            .or_else(|| default_index.map(<[String]>::to_vec));
        match effective_root {
            Some(root) => {
                for host in hosts {
                    self.push_route(
                        Route {
                            host: host.clone(),
                            path: path.clone(),
                            upstream: None,
                            root: Some(root.to_owned()),
                            index: effective_index.clone(),
                            redirect: None,
                            strip_prefix: false,
                        },
                        node.line,
                    );
                }
            }
            None => self.warn(
                node.line,
                format!(
                    "location `{}` has no `proxy_pass`, `root` or `return`, skipped",
                    path.as_deref().unwrap_or("/")
                ),
            ),
        }
        Ok(())
    }

    fn proxy_target(&mut self, url: &str, line: usize) -> Option<(String, bool)> {
        if url.contains('$') {
            self.warn(line, format!("`proxy_pass {url}` uses variables, skipped"));
            return None;
        }
        let Some((scheme, rest)) = url.split_once("://") else {
            self.warn(
                line,
                format!("`proxy_pass {url}` is not an http:// or https:// URL, skipped"),
            );
            return None;
        };
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            other => {
                self.warn(
                    line,
                    format!("`proxy_pass` scheme `{other}` is not supported, skipped"),
                );
                return None;
            }
        };
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], Some(&rest[index..])),
            None => (rest, None),
        };
        if authority.is_empty() || authority.contains('@') || authority.contains(['?', '#']) {
            self.warn(
                line,
                format!("`proxy_pass {url}` has an unusable authority, skipped"),
            );
            return None;
        }

        // nginx drops the matched location prefix when proxy_pass carries a
        // URI part; a bare `/` is the common case for that.
        let strip_prefix = match path {
            None => false,
            Some("/") => true,
            Some(other) => {
                self.warn(
                    line,
                    format!(
                        "`proxy_pass` URI `{other}` cannot be rewritten; stripping the location prefix instead"
                    ),
                );
                true
            }
        };

        if self.declared_upstreams.contains(authority) {
            if !self.usable_upstreams.contains(authority) {
                self.warn(
                    line,
                    format!("upstream `{authority}` has no usable servers, route skipped"),
                );
                return None;
            }
            if tls {
                self.mark_upstream_tls(authority);
            }
            return Some((authority.to_owned(), strip_prefix));
        }

        let address = match literal_address(authority, tls) {
            Ok(address) => address,
            Err(reason) => {
                self.warn(
                    line,
                    format!("`proxy_pass` authority `{authority}` skipped: {reason}"),
                );
                return None;
            }
        };
        Some((self.literal_upstream(&address, tls), strip_prefix))
    }

    fn mark_upstream_tls(&mut self, name: &str) {
        if let Some(upstream) = self.upstreams.iter_mut().find(|u| u.name == name) {
            upstream.tls = true;
        }
    }

    fn literal_upstream(&mut self, address: &str, tls: bool) -> String {
        if let Some(name) = self.literal_upstreams.get(&(address.to_owned(), tls)) {
            return name.clone();
        }

        let mut name = address.to_owned();
        let mut suffix = 2;
        while self.declared_upstreams.contains(&name) {
            name = format!("{address}-{suffix}");
            suffix += 1;
        }

        self.declared_upstreams.insert(name.clone());
        self.usable_upstreams.insert(name.clone());
        self.literal_upstreams
            .insert((address.to_owned(), tls), name.clone());
        self.upstreams.push(Upstream {
            name: name.clone(),
            servers: vec![address.to_owned()],
            balance: None,
            tls,
        });
        name
    }

    fn parse_return(&mut self, node: &Node) -> Option<(u16, String)> {
        let Some(code) = node.args.first() else {
            self.warn(node.line, "`return` without a status, ignored");
            return None;
        };
        let Ok(status) = code.parse::<u16>() else {
            self.warn(
                node.line,
                format!("`return {code}` does not start with a status code, ignored"),
            );
            return None;
        };
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            self.warn(
                node.line,
                format!("`return {status}` is not a redirect status, skipped"),
            );
            return None;
        }
        let Some(to) = node.args.get(1) else {
            self.warn(
                node.line,
                format!("`return {status}` without a target URL, skipped"),
            );
            return None;
        };
        if to.contains('$') {
            self.warn(
                node.line,
                format!("`return {status} {to}` uses variables, skipped"),
            );
            return None;
        }
        if node.args.len() > 2 {
            self.warn(
                node.line,
                "extra arguments to `return` are not migrated, ignored",
            );
        }
        Some((status, to.clone()))
    }

    fn unsupported(&mut self, node: &Node, context: &str, name: &str) {
        let detail = match name {
            "ssl_certificate" | "ssl_certificate_key" => {
                "; configure [tls] by hand after migrating"
            }
            "add_header" => "; set add_headers on the route by hand",
            "try_files" => "; Elira routes have a single target",
            "if" => "; nginx conditional logic has no equivalent",
            "rewrite" => "; use a redirect route instead",
            "gzip" => "; Elira compresses according to [compression]",
            "autoindex" => "; set autoindex on the route by hand",
            _ => "",
        };
        self.warn(
            node.line,
            format!("unsupported directive `{name}` in {context}, skipped{detail}"),
        );
        // `if` and similar blocks can hide more unsupported directives;
        // surface them too instead of silently dropping the whole subtree.
        if let Some(children) = &node.children {
            self.warn_inside(children, name);
        }
    }

    fn warn_inside(&mut self, children: &[Node], parent: &str) {
        for child in children {
            self.warn(
                child.line,
                format!(
                    "unsupported directive `{}` inside `{parent}` is not migrated",
                    child.name
                ),
            );
            if let Some(nested) = &child.children {
                self.warn_inside(nested, &child.name);
            }
        }
    }

    fn push_route(&mut self, route: Route, line: usize) {
        let key = (
            route.host.to_ascii_lowercase(),
            route.path.clone().unwrap_or_default(),
        );
        if !self.route_keys.insert(key) {
            self.warn(
                line,
                format!(
                    "duplicate route for host `{}` path `{}`, skipped",
                    route.host,
                    route.path.as_deref().unwrap_or("/")
                ),
            );
            return;
        }
        self.routes.push(route);
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# Generated by elira-migrate from an nginx configuration.\n");
        let listen = self.listen.as_deref().unwrap_or("0.0.0.0:80");
        out.push_str(&format!("listen = {}\n", toml_string(listen)));

        for upstream in &self.upstreams {
            out.push_str("\n[[upstreams]]\n");
            out.push_str(&format!("name = {}\n", toml_string(&upstream.name)));
            let servers = upstream
                .servers
                .iter()
                .map(|server| toml_string(server))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("servers = [{servers}]\n"));
            if let Some(balance) = &upstream.balance {
                out.push_str(&format!("balance = {}\n", toml_string(balance)));
            }
            if upstream.tls {
                out.push_str("tls = true\n");
            }
        }

        for route in &self.routes {
            out.push_str("\n[[routes]]\n");
            out.push_str(&format!("host = {}\n", toml_string(&route.host)));
            if let Some(path) = &route.path {
                out.push_str(&format!("path = {}\n", toml_string(path)));
            }
            if let Some(upstream) = &route.upstream {
                out.push_str(&format!("upstream = {}\n", toml_string(upstream)));
            }
            if let Some(root) = &route.root {
                out.push_str(&format!("root = {}\n", toml_string(root)));
            }
            if let Some(index) = &route.index {
                let list = index
                    .iter()
                    .map(|entry| toml_string(entry))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("index = [{list}]\n"));
            }
            if let Some((to, status)) = &route.redirect {
                out.push_str(&format!(
                    "redirect = {{ to = {}, status = {status} }}\n",
                    toml_string(to)
                ));
            }
            if route.strip_prefix {
                out.push_str("strip_prefix = true\n");
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Directive helpers
// ---------------------------------------------------------------------------

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn server_name(raw: &str) -> Result<String, String> {
    if raw.contains('$') {
        return Err("variables are not supported".to_owned());
    }
    if raw.starts_with('~') {
        return Err("regular expressions are not supported".to_owned());
    }
    if raw == "_" {
        return Ok("*".to_owned());
    }
    // nginx allows a leading dot as a compact form of a wildcard.
    if let Some(suffix) = raw.strip_prefix('.') {
        return Ok(format!("*.{suffix}"));
    }
    Ok(raw.to_owned())
}

fn server_address(raw: &str) -> Result<String, String> {
    if raw.contains('$') {
        return Err("variables are not supported".to_owned());
    }
    if raw.starts_with("unix:") {
        return Err("unix sockets are not supported".to_owned());
    }
    if raw.starts_with('[') {
        if raw.contains("]:") {
            return Ok(raw.to_owned());
        }
        return Ok(format!("{raw}:80"));
    }
    match raw.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            Ok(raw.to_owned())
        }
        Some(_) => Err("expected host:port".to_owned()),
        None => Ok(format!("{raw}:80")),
    }
}

fn listen_address(raw: &str) -> Result<String, String> {
    if raw.starts_with("unix:") || raw.starts_with('/') {
        return Err("unix sockets are not supported".to_owned());
    }

    let (host, port) = if let Some((host, port)) = raw.rsplit_once(':') {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return Err("expected [host:]port".to_owned());
        }
        (host.to_owned(), port.to_owned())
    } else if raw.chars().all(|c| c.is_ascii_digit()) {
        ("0.0.0.0".to_owned(), raw.to_owned())
    } else {
        return Err("expected [host:]port".to_owned());
    };

    let port: u16 = port.parse().map_err(|_| "port out of range".to_owned())?;
    if port == 0 {
        return Err("port must not be zero".to_owned());
    }

    if host.is_empty() || host == "*" {
        return Ok(format!("0.0.0.0:{port}"));
    }

    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Ok(format!("{v4}:{port}")),
        Ok(IpAddr::V6(v6)) => Ok(format!("[{v6}]:{port}")),
        Err(_) => Ok(format!("0.0.0.0:{port}")),
    }
}

fn location_path(
    args: &[String],
    line: usize,
    warnings: &mut Vec<String>,
) -> Option<Option<String>> {
    let mut args = args;
    let mut exact = false;

    if let Some(modifier) = args.first() {
        match modifier.as_str() {
            "=" => {
                exact = true;
                args = &args[1..];
            }
            "^~" => args = &args[1..],
            "~" | "~*" => {
                warnings.push(format!(
                    "line {line}: regex location `{}` is not supported, skipped",
                    args.get(1).map(String::as_str).unwrap_or("")
                ));
                return None;
            }
            _ => {}
        }
    }

    let path = args.first()?;
    if path.starts_with('@') {
        warnings.push(format!(
            "line {line}: named location `{path}` is not supported, skipped"
        ));
        return None;
    }
    if !path.starts_with('/') {
        warnings.push(format!(
            "line {line}: location `{path}` does not start with `/`, skipped"
        ));
        return None;
    }
    if exact {
        warnings.push(format!(
            "line {line}: exact location `= {path}` becomes a prefix route"
        ));
    }
    if args.len() > 1 {
        warnings.push(format!(
            "line {line}: extra location arguments after `{path}` are ignored"
        ));
    }

    if path == "/" {
        Some(None)
    } else {
        Some(Some(path.clone()))
    }
}

fn literal_address(authority: &str, tls: bool) -> Result<String, String> {
    let default_port = if tls { 443 } else { 80 };
    if authority.starts_with('[') {
        if authority.contains("]:") {
            return Ok(authority.to_owned());
        }
        return Ok(format!("{authority}:{default_port}"));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Ok(authority.to_owned());
        }
        return Err("expected host:port".to_owned());
    }
    Ok(format!("{authority}:{default_port}"))
}

fn toml_string(value: &str) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use elira_config::Config;

    fn convert(input: &str) -> Migration {
        migrate(input).unwrap_or_else(|e| panic!("migration failed: {e}"))
    }

    fn parse(migration: &Migration) -> Config {
        Config::parse(&migration.toml).unwrap_or_else(|e| {
            panic!(
                "generated TOML does not parse: {e}\n---\n{}",
                migration.toml
            )
        })
    }

    #[test]
    fn migrates_a_simple_proxy() {
        let input = r#"
# front door
upstream app {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
    least_conn;
}

server {
    listen 8080;
    server_name example.com;

    location / {
        proxy_pass http://app;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].name, "app");
        assert_eq!(config.upstreams[0].servers.len(), 2);
        assert_eq!(
            config.upstreams[0].balance,
            elira_config::Balance::LeastConn
        );
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].host, "example.com");
        assert_eq!(config.routes[0].path, None);
        assert_eq!(config.routes[0].upstream.as_deref(), Some("app"));
        assert!(!config.routes[0].strip_prefix);
    }

    #[test]
    fn migrates_static_files() {
        let input = r#"
server {
    listen 127.0.0.1:8081;
    server_name static.example;

    location /assets {
        root /var/www;
        index index.html index.htm;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.listen.to_string(), "127.0.0.1:8081");
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.path.as_deref(), Some("/assets"));
        assert_eq!(
            route.root.as_deref(),
            Some(std::path::Path::new("/var/www"))
        );
        assert_eq!(route.index, vec!["index.html", "index.htm"]);
    }

    #[test]
    fn expands_several_server_names() {
        let input = r#"
server {
    listen 80;
    server_name a.example b.example a.example;

    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.routes.len(), 2);
        let hosts: Vec<_> = config.routes.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, vec!["a.example", "b.example"]);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].name, "127.0.0.1:9000");
        assert_eq!(config.routes[0].upstream.as_deref(), Some("127.0.0.1:9000"));
    }

    #[test]
    fn migrates_a_return_redirect() {
        let input = r#"
server {
    listen 80;
    server_name old.example;

    location / {
        return 301 https://new.example;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        let redirect = config.routes[0].redirect.as_ref().expect("redirect");
        assert_eq!(redirect.to, "https://new.example");
        assert_eq!(redirect.status, 301);
    }

    #[test]
    fn trailing_slash_sets_strip_prefix() {
        let input = r#"
upstream app {
    server 127.0.0.1:3000;
}

server {
    listen 80;
    server_name api.example;

    location /api/ {
        proxy_pass http://app/;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.routes[0].path.as_deref(), Some("/api/"));
        assert!(config.routes[0].strip_prefix);
        assert!(migration.warnings.is_empty(), "{:?}", migration.warnings);
    }

    #[test]
    fn literal_https_proxy_creates_a_tls_upstream() {
        let input = r#"
server {
    listen 80;
    server_name proxy.example;

    location /api/ {
        proxy_pass https://backend.example/;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.upstreams[0].name, "backend.example:443");
        assert_eq!(config.upstreams[0].servers, vec!["backend.example:443"]);
        assert!(config.upstreams[0].tls);
        assert!(config.routes[0].strip_prefix);
    }

    #[test]
    fn warns_about_unsupported_directives() {
        let input = r#"
server {
    listen 80;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.pem;
    gzip on;

    location / {
        proxy_pass http://127.0.0.1:3000;
        add_header X-Frame-Options DENY;
        try_files $uri $uri/ /index.html;
    }

    location /old {
        if ($host) {
            rewrite ^ /new;
        }
        return 404;
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.routes.len(), 1);
        let warnings = migration.warnings.join("\n");
        for needle in [
            "ssl_certificate",
            "gzip",
            "add_header",
            "try_files",
            "if",
            "rewrite",
            "404",
        ] {
            assert!(
                warnings.contains(needle),
                "missing `{needle}` in:\n{warnings}"
            );
        }
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(migrate(""), Err(Error::NoServer)));
        assert!(matches!(
            migrate("# only a comment\n   \n"),
            Err(Error::NoServer)
        ));
    }

    #[test]
    fn flattens_an_http_block() {
        let input = r#"
http {
    upstream app {
        server 127.0.0.1:3000;
    }

    server {
        listen 80;
        server_name wrapped.example;
        location / {
            proxy_pass http://app;
        }
    }
}
"#;
        let migration = convert(input);
        let config = parse(&migration);

        assert_eq!(config.upstreams[0].name, "app");
        assert_eq!(config.routes[0].host, "wrapped.example");
    }

    #[test]
    fn unterminated_block_is_a_syntax_error() {
        let input = "server { listen 80; ";
        assert!(matches!(migrate(input), Err(Error::Syntax { .. })));
    }
}
