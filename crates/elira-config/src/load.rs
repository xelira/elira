use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::Error;

pub(crate) fn load_value(path: &Path, depth: usize) -> Result<toml::Value, Error> {
    let mut visited = HashSet::new();
    load_value_inner(path, depth, &mut visited)
}

fn load_value_inner(
    path: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
) -> Result<toml::Value, Error> {
    if depth > 16 {
        return Err(Error::IncludeDepth {
            path: path.display().to_string(),
        });
    }
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(key.clone()) {
        return Err(Error::BadInclude {
            path: path.display().to_string(),
            reason: "include cycle detected".to_owned(),
        });
    }

    let meta = std::fs::symlink_metadata(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(Error::BadInclude {
            path: path.display().to_string(),
            reason: "include must be a regular file".to_owned(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    let text = substitute_env(&text)?;
    let mut value: toml::Value = toml::from_str(&text).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })?;

    let includes = take_includes(&mut value, path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for pattern in includes {
        let pattern_path = if Path::new(&pattern).is_absolute() {
            PathBuf::from(&pattern)
        } else {
            base.join(&pattern)
        };
        for included in expand_include(&pattern_path)? {
            let extra = load_value_inner(&included, depth + 1, visited)?;
            merge_values(&mut value, extra);
        }
    }

    visited.remove(&key);
    Ok(value)
}

fn take_includes(value: &mut toml::Value, path: &Path) -> Result<Vec<String>, Error> {
    let Some(table) = value.as_table_mut() else {
        return Ok(Vec::new());
    };
    let Some(entry) = table.remove("include") else {
        return Ok(Vec::new());
    };

    let bad = || Error::BadInclude {
        path: path.display().to_string(),
        reason: "include must be a string or an array of strings".to_owned(),
    };

    match entry {
        toml::Value::String(value) => Ok(vec![value]),
        toml::Value::Array(values) => values
            .into_iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or_else(bad))
            .collect(),
        _ => Err(bad()),
    }
}

fn expand_include(pattern: &Path) -> Result<Vec<PathBuf>, Error> {
    let name = pattern
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "include path has no file name".to_owned(),
        })?;
    if !name.contains('*') {
        return Ok(vec![pattern.to_path_buf()]);
    }
    if name.matches('*').count() != 1 {
        return Err(Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "only one * is allowed in a file name".to_owned(),
        });
    }

    let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
    let dir = pattern.parent().unwrap_or_else(|| Path::new("."));
    let entries = std::fs::read_dir(dir).map_err(|source| Error::BadInclude {
        path: pattern.display().to_string(),
        reason: format!("cannot read {}: {source}", dir.display()),
    })?;
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let candidate = entry.file_name();
        let Some(candidate) = candidate.to_str() else {
            continue;
        };
        if candidate.starts_with(prefix) && candidate.ends_with(suffix) {
            matches.push(entry.path());
        }
    }
    matches.sort();
    if matches.is_empty() {
        return Err(Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "no files matched".to_owned(),
        });
    }
    Ok(matches)
}

fn merge_values(base: &mut toml::Value, extra: toml::Value) {
    match (base, extra) {
        (toml::Value::Table(base), toml::Value::Table(extra)) => {
            for (key, value) in extra {
                match base.get_mut(&key) {
                    Some(existing) => merge_values(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (toml::Value::Array(base), toml::Value::Array(mut extra)) => base.append(&mut extra),
        (base, extra) => *base = extra,
    }
}

fn substitute_env(text: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;

    while let Some(relative) = text[pos..].find('$') {
        let index = pos + relative;
        out.push_str(&text[pos..index]);
        let rest = &text[index..];

        if rest.starts_with("$$") {
            out.push('$');
            pos = index + 2;
            continue;
        }
        let Some(body) = rest.strip_prefix("${") else {
            out.push('$');
            pos = index + 1;
            continue;
        };
        let Some(end) = body.find('}') else {
            out.push('$');
            pos = index + 1;
            continue;
        };
        let expression = &body[..end];
        let (name, default) = match expression.split_once(":-") {
            Some((name, default)) => (name, Some(default)),
            None => (expression, None),
        };
        if name.is_empty() {
            return Err(Error::EnvMissing {
                name: expression.to_owned(),
            });
        }
        let value = match std::env::var(name) {
            Ok(value) => value,
            Err(_) => match default {
                Some(value) => value.to_owned(),
                None => {
                    return Err(Error::EnvMissing {
                        name: name.to_owned(),
                    })
                }
            },
        };
        let value = match quote_state(text, index) {
            QuoteState::Basic => escape_basic(&value),
            QuoteState::Literal => escape_literal(&value, name)?,
            QuoteState::Normal => escape_bare(&value, name)?,
        };
        out.push_str(&value);
        pos = index + 2 + end + 1;
    }
    out.push_str(&text[pos..]);
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    Normal,
    Basic,
    Literal,
}

fn quote_state(text: &str, end: usize) -> QuoteState {
    let mut state = QuoteState::Normal;
    let mut escaped = false;
    for ch in text[..end].chars() {
        match state {
            QuoteState::Normal => {
                if ch == '"' {
                    state = QuoteState::Basic;
                } else if ch == '\'' {
                    state = QuoteState::Literal;
                }
            }
            QuoteState::Basic => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    state = QuoteState::Normal;
                }
            }
            QuoteState::Literal => {
                if ch == '\'' {
                    state = QuoteState::Normal;
                }
            }
        }
    }
    state
}

fn escape_basic(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out
}

fn escape_literal(value: &str, name: &str) -> Result<String, Error> {
    if value.contains('\'') || value.chars().any(char::is_control) {
        return Err(Error::BadEnvValue {
            name: name.to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn escape_bare(value: &str, name: &str) -> Result<String, Error> {
    let safe = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "_-./:@*+".contains(ch));
    if !safe {
        return Err(Error::BadEnvValue {
            name: name.to_owned(),
        });
    }
    Ok(value.to_owned())
}
