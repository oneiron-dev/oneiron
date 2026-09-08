//! Leaf config helpers: env lookups, value parsing, and secret redaction.

use std::path::PathBuf;

pub(super) const DEFAULT_CONFIG_FILE: &str = "oneiron.toml";

pub(super) const DEFAULT_CONFIG_DIR: &str = "oneiron";

pub(super) const LEGACY_DEFAULT_VAULT_PATH: &str = "./vault";

pub(super) fn lookup_parse<T>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    lookup(key)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("parse {key}={value:?}: {e}"))
        })
        .transpose()
}

pub(super) fn lookup_bool(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<bool>> {
    lookup(key).map(|value| parse_bool(key, &value)).transpose()
}

pub(super) fn lookup_path(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<PathBuf> {
    lookup(key).map(PathBuf::from)
}

pub(super) fn lookup_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<String>> {
    lookup(key).map(|value| split_list(&value))
}

pub(super) fn lookup_path_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<PathBuf>> {
    lookup(key).map(|value| split_list(&value).into_iter().map(PathBuf::from).collect())
}

fn parse_bool(key: &'static str, value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("parse {key}={value:?}: expected true/false, yes/no, on/off, or 1/0"),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

pub(super) fn expand_home(path: PathBuf) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path;
    };
    if raw == "~" {
        return std::env::var_os("HOME").map(PathBuf::from).unwrap_or(path);
    }
    if let Some(suffix) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(suffix);
    }
    path
}

pub(super) fn redacted_secret(secret: &Option<String>) -> Option<&'static str> {
    secret.as_ref().map(|_| "<redacted>")
}
