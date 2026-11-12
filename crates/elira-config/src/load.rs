use std::path::{Path, PathBuf};

use crate::Error;

pub(crate) fn load_value(path: &Path, depth: usize) -> Result<toml::Value, Error> {
    if depth > 16 {
        return Err(Error::IncludeDepth {
            path: path.display().to_string(),
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
            let extra = load_value(&included, depth + 1)?;
            merge_values(&mut value, extra);
        }
    }

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
    let mut rest = text;

    while let Some(index) = rest.find('$') {
        out.push_str(&rest[..index]);
        rest = &rest[index..];

        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
            rest = after;
            continue;
        }
        let Some(body) = rest.strip_prefix("${") else {
            out.push('$');
            rest = &rest[1..];
            continue;
        };
        let Some(end) = body.find('}') else {
            out.push('$');
            rest = &rest[1..];
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
        match std::env::var(name) {
            Ok(value) => out.push_str(&value),
            Err(_) => match default {
                Some(value) => out.push_str(value),
                None => {
                    return Err(Error::EnvMissing {
                        name: name.to_owned(),
                    })
                }
            },
        }
        rest = &body[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
