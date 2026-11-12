use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ipnet::{AddrParseError, IpNet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("open {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("read htpasswd: {source}")]
    Read {
        #[source]
        source: io::Error,
    },

    #[error("htpasswd line {line}: missing ':' separator")]
    MissingColon { line: usize },

    #[error("htpasswd line {line}: empty {field}")]
    EmptyField { line: usize, field: &'static str },

    #[error("htpasswd line {line}: bcrypt cost {cost} is outside 4..=16")]
    BadBcryptCost { line: usize, cost: u32 },

    #[error("invalid CIDR {value:?}: {source}")]
    InvalidCidr {
        value: String,
        #[source]
        source: AddrParseError,
    },
}

pub struct BasicAuth {
    users: HashMap<String, String>,
}

impl BasicAuth {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|source| Error::Open {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_reader(BufReader::new(file))
    }

    pub fn from_reader(mut reader: impl BufRead) -> Result<Self, Error> {
        let mut users = HashMap::new();
        let mut line = String::new();
        let mut number = 0;

        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .map_err(|source| Error::Read { source })?;
            if read == 0 {
                break;
            }
            number += 1;

            let line = line.strip_suffix('\n').unwrap_or(&line);
            let line = line.strip_suffix('\r').unwrap_or(line);

            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }

            let (user, hash) = line
                .split_once(':')
                .ok_or(Error::MissingColon { line: number })?;
            if user.is_empty() {
                return Err(Error::EmptyField {
                    line: number,
                    field: "user",
                });
            }
            if hash.is_empty() {
                return Err(Error::EmptyField {
                    line: number,
                    field: "password hash",
                });
            }
            if let Some(cost) = bcrypt_cost(hash) {
                if !(4..=16).contains(&cost) {
                    return Err(Error::BadBcryptCost { line: number, cost });
                }
            }

            users.insert(user.to_string(), hash.to_string());
        }

        Ok(Self { users })
    }

    pub fn check(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };

        let mut parts = header.split_ascii_whitespace();
        let Some(scheme) = parts.next() else {
            return false;
        };
        let Some(token) = parts.next() else {
            return false;
        };
        if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Basic") {
            return false;
        }

        let Ok(decoded) = BASE64.decode(token) else {
            return false;
        };
        let Ok(credentials) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((user, password)) = credentials.split_once(':') else {
            return false;
        };

        let known = self.users.get(user);
        let hash = match known {
            Some(hash) => hash.as_str(),
            None => dummy_hash(),
        };
        bcrypt::verify(password, hash).unwrap_or(false) && known.is_some()
    }
}

fn bcrypt_cost(hash: &str) -> Option<u32> {
    let mut parts = hash.split('$');
    parts.next()?;
    let version = parts.next()?;
    if !matches!(version, "2a" | "2b" | "2y") {
        return None;
    }
    parts.next()?.parse().ok()
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY
        .get_or_init(|| bcrypt::hash("elira-dummy-password", 10).expect("dummy bcrypt hash"))
        .as_str()
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("users", &self.users.len())
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct IpAcl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl IpAcl {
    pub fn new(allow: &[String], deny: &[String]) -> Result<Self, Error> {
        Ok(Self {
            allow: parse_nets(allow)?,
            deny: parse_nets(deny)?,
        })
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|net| net.contains(&ip))
    }
}

fn parse_nets(values: &[String]) -> Result<Vec<IpNet>, Error> {
    values
        .iter()
        .map(|value| {
            value
                .trim()
                .parse::<IpNet>()
                .map_err(|source| Error::InvalidCidr {
                    value: value.clone(),
                    source,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(password: &str) -> String {
        bcrypt::hash(password, 4).expect("bcrypt hash")
    }

    fn auth(entries: &str) -> BasicAuth {
        BasicAuth::from_reader(entries.as_bytes()).expect("htpasswd parses")
    }

    fn header(credentials: &str) -> String {
        format!("Basic {}", BASE64.encode(credentials))
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address")
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn acl(allow: &[&str], deny: &[&str]) -> IpAcl {
        IpAcl::new(&strings(allow), &strings(deny)).expect("acl parses")
    }

    #[test]
    fn accepts_a_correct_password() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(auth.check(Some(&header("alice:s3cret"))));
    }

    #[test]
    fn rejects_a_wrong_password() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(Some(&header("alice:wrong"))));
    }

    #[test]
    fn rejects_an_unknown_user() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(Some(&header("bob:s3cret"))));
    }

    #[test]
    fn rejects_a_missing_header() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(None));
    }

    #[test]
    fn rejects_broken_base64() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(Some("Basic not-base64!!")));
    }

    #[test]
    fn rejects_a_non_basic_scheme() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(Some(&format!("Bearer {}", BASE64.encode("alice:s3cret")))));
    }

    #[test]
    fn rejects_credentials_without_a_colon() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(!auth.check(Some(&header("alice"))));
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let auth = auth(&format!("alice:{}\n", hash("s3cret")));
        assert!(auth.check(Some(&header("alice:s3cret").replacen("Basic", "bAsIc", 1))));
    }

    #[test]
    fn password_may_contain_colons() {
        let auth = auth(&format!("alice:{}\n", hash("a:b:c")));
        assert!(auth.check(Some(&header("alice:a:b:c"))));
    }

    #[test]
    fn htpasswd_skips_comments_blank_lines_and_crlf() {
        let auth = auth(&format!(
            "# generated by htpasswd\n\nalice:{}\r\n  # also a comment\n",
            hash("s3cret")
        ));
        assert_eq!(auth.users.len(), 1);
        assert!(auth.check(Some(&header("alice:s3cret"))));
    }

    #[test]
    fn htpasswd_reports_the_line_without_a_colon() {
        let err = BasicAuth::from_reader("# comment\nbroken\n".as_bytes()).unwrap_err();
        assert!(matches!(err, Error::MissingColon { line: 2 }));
    }

    #[test]
    fn htpasswd_rejects_an_empty_user() {
        let err = BasicAuth::from_reader(":hash\n".as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            Error::EmptyField {
                line: 1,
                field: "user"
            }
        ));
    }

    #[test]
    fn htpasswd_rejects_an_empty_hash() {
        let err = BasicAuth::from_reader("alice:\n".as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            Error::EmptyField {
                line: 1,
                field: "password hash"
            }
        ));
    }

    #[test]
    fn reads_users_from_a_file() {
        let path = std::env::temp_dir().join(format!(
            "elira-auth-{}-from-file.htpasswd",
            std::process::id()
        ));
        std::fs::write(&path, format!("alice:{}\n", hash("s3cret"))).unwrap();

        let auth = BasicAuth::from_file(&path).expect("file loads");
        let _ = std::fs::remove_file(&path);

        assert!(auth.check(Some(&header("alice:s3cret"))));
    }

    #[test]
    fn missing_file_names_the_path() {
        let path = std::env::temp_dir().join("elira-auth-does-not-exist.htpasswd");
        let err = BasicAuth::from_file(&path).unwrap_err();
        assert!(matches!(err, Error::Open { .. }));
    }

    #[test]
    fn empty_allow_list_allows_everything() {
        let acl = acl(&[], &[]);
        assert!(acl.allows(ip("192.0.2.1")));
        assert!(acl.allows(ip("2001:db8::1")));
    }

    #[test]
    fn non_empty_allow_list_limits_access() {
        let acl = acl(&["10.0.0.0/8"], &[]);
        assert!(acl.allows(ip("10.1.2.3")));
        assert!(!acl.allows(ip("11.0.0.1")));
        assert!(!acl.allows(ip("2001:db8::1")));
    }

    #[test]
    fn deny_wins_over_allow() {
        let acl = acl(&["0.0.0.0/0"], &["10.0.0.1/32"]);
        assert!(!acl.allows(ip("10.0.0.1")));
        assert!(acl.allows(ip("10.0.0.2")));
    }

    #[test]
    fn deny_applies_even_when_allow_is_empty() {
        let acl = acl(&[], &["192.0.2.0/24"]);
        assert!(!acl.allows(ip("192.0.2.10")));
        assert!(acl.allows(ip("192.0.3.10")));
    }

    #[test]
    fn ipv6_networks_match() {
        let acl = acl(&["2001:db8::/32"], &["2001:db8:bad::/48"]);
        assert!(acl.allows(ip("2001:db8:1::1")));
        assert!(!acl.allows(ip("2001:db8:bad::1")));
        assert!(!acl.allows(ip("2001:db9::1")));
        assert!(!acl.allows(ip("127.0.0.1")));
        assert!(!acl.allows(ip("::1")));
    }

    #[test]
    fn invalid_cidr_reports_the_original_string() {
        let err = IpAcl::new(&strings(&["10.0.0.0/33"]), &[]).unwrap_err();
        match err {
            Error::InvalidCidr { value, .. } => assert_eq!(value, "10.0.0.0/33"),
            other => panic!("unexpected error: {other}"),
        }
    }
}

#[cfg(test)]
mod cost_tests {
    use super::*;

    #[test]
    fn rejects_excessive_bcrypt_cost() {
        let hash = bcrypt::hash("x", 4).expect("hash");
        let hash = hash.replacen("$04$", "$31$", 1);
        let err = BasicAuth::from_reader(format!("user:{hash}\n").as_bytes()).expect_err("cost");
        assert!(matches!(err, Error::BadBcryptCost { cost: 31, .. }));
    }

    #[test]
    fn unknown_users_still_pay_for_a_bcrypt_check() {
        let hash = bcrypt::hash("x", 4).expect("hash");
        let auth = BasicAuth::from_reader(format!("user:{hash}\n").as_bytes()).expect("auth file");
        let header = format!("Basic {}", BASE64.encode("missing:password"));
        assert!(!auth.check(Some(&header)));
    }
}
