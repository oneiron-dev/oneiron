//! Explicit same-host retention of one `[[shared_env]]` entry.
//!
//! [`retain_shared_env`] upserts `entry` into the existing config file at
//! `config_path`, holding that file's sibling `<config>.lock` across the
//! read, modify, validate and atomic replace. The lock serializes
//! cooperating retain calls; writers that do not acquire it (init's config
//! assembly, external editors) are unchanged and can still interleave, so
//! this is advisory, not a global same-file proof. The running serve is
//! unchanged; the entry stands from the next start.

use std::path::Path;

use anyhow::Context as _;

use super::SharedEnvConfig;

/// Upserts `entry` into the existing config file at `config_path`.
///
/// Only `entry` is validated; old rows that are semantically invalid are
/// preserved as the registry's log-and-skip would, and only a row that is
/// not even the entry's type shape refuses the write. Keyed by
/// `(vault_id, member.trim().to_ascii_lowercase())`: the first matching row
/// is replaced with `entry`'s values, same-key duplicates are removed, and
/// an absent key is appended. Any other table value stays as it was. A
/// single existing entry that is already `entry` returns without rewriting.
/// A missing file, a file that does not parse, a non-array `shared_env`,
/// or a row that is not the entry's shape is a truthful error and the file
/// stays as it was. The new row writes `vault_id` as a decimal string so
/// the full `u64` round-trips; readers still accept a numeric `vault_id`.
/// A file whose unrelated values hold a high numeric `u64` fails the
/// table parse even though the typed serve read accepts it: the file stays
/// unchanged with that safe parse error.
pub(crate) fn retain_shared_env(config_path: &Path, entry: &SharedEnvConfig) -> anyhow::Result<()> {
    entry.validate()?;
    let _held = sibling_lock(config_path)?;
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config file {}", config_path.display()))?;
    let table: toml::Table = crate::config::parse_toml(config_path, &raw)?;
    let existing: Vec<toml::Value> = match table.get("shared_env") {
        None => Vec::new(),
        Some(toml::Value::Array(rows)) => rows.clone(),
        Some(_) => anyhow::bail!(
            "config file {}: shared_env is not an array",
            config_path.display()
        ),
    };
    let mut typed: Vec<SharedEnvConfig> = Vec::with_capacity(existing.len());
    for row in &existing {
        typed.push(row_shape(row, config_path)?);
    }
    let new_key = entry_key(entry);
    let mut matching = typed.iter().filter(|old| entry_key(old) == new_key);
    if matching.next().is_some_and(|old| old == entry) && matching.next().is_none() {
        return Ok(());
    }
    let staged_row = entry_value(entry)?;
    let mut next: Vec<toml::Value> = Vec::with_capacity(existing.len() + 1);
    let mut replaced = false;
    for (row, old) in existing.iter().zip(typed.iter()) {
        if entry_key(old) == new_key {
            if !replaced {
                next.push(staged_row.clone());
                replaced = true;
            }
        } else {
            next.push(row.clone());
        }
    }
    if !replaced {
        next.push(staged_row);
    }
    let mut staged_table = table.clone();
    staged_table.insert("shared_env".to_owned(), toml::Value::Array(next));
    let staged_text =
        toml::to_string_pretty(&staged_table).context("serialize retained shared-env config")?;
    let reparsed: toml::Table = crate::config::parse_toml(config_path, &staged_text)?;
    let staged_rows = match reparsed.get("shared_env") {
        Some(toml::Value::Array(rows)) => rows,
        _ => anyhow::bail!(
            "config file {}: retained shared_env did not stage as an array",
            config_path.display()
        ),
    };
    let mut seen = 0;
    for row in staged_rows {
        let back = row_shape(row, config_path)?;
        if entry_key(&back) == new_key {
            seen += 1;
            anyhow::ensure!(
                back == *entry,
                "config file {}: retained shared-env entry did not round-trip",
                config_path.display()
            );
        }
    }
    anyhow::ensure!(
        seen == 1,
        "config file {}: retained shared-env entry is missing after staging",
        config_path.display()
    );
    crate::commands::credential_file::replace(config_path, staged_text.as_bytes())?;
    Ok(())
}

/// One row as the entry's type shape: a value that is not even this shape
/// is a truthful parse error naming only the file, never the value refused.
fn row_shape(row: &toml::Value, config_path: &Path) -> anyhow::Result<SharedEnvConfig> {
    row.clone().try_into().map_err(|_| {
        anyhow::anyhow!(
            "config file {} holds an invalid [shared_env] entry",
            config_path.display()
        )
    })
}

/// The membership an upsert names: the shared vault id and the member
/// trimmed and lowercased, as the registry's leave check names it.
fn entry_key(entry: &SharedEnvConfig) -> (u64, String) {
    (entry.vault_id, entry.member.trim().to_ascii_lowercase())
}

/// `entry` as a staged `[[shared_env]]` row: the five fields, `vault_id` as
/// a decimal string for the full `u64`, paths as UTF-8, never lossy.
fn entry_value(entry: &SharedEnvConfig) -> anyhow::Result<toml::Value> {
    let path = entry
        .path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("[shared_env] path must be UTF-8"))?;
    let credential = entry
        .credential_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("[shared_env] credential_file must be UTF-8"))?;
    let mut row = toml::Table::new();
    row.insert("path".to_owned(), toml::Value::String(path.to_owned()));
    row.insert(
        "vault_id".to_owned(),
        toml::Value::String(entry.vault_id.to_string()),
    );
    row.insert(
        "member".to_owned(),
        toml::Value::String(entry.member.clone()),
    );
    row.insert(
        "home_url".to_owned(),
        toml::Value::String(entry.home_url.clone()),
    );
    row.insert(
        "credential_file".to_owned(),
        toml::Value::String(credential.to_owned()),
    );
    Ok(toml::Value::Table(row))
}

/// The sibling `<config>.lock`, held across the read, modify, validate and
/// replace. Blocking, with no deadline; the empty lock holds no secrets, so
/// a new one is made 0600 and an old one is never gated on its mode. Never
/// removed: waiters hold its inode.
fn sibling_lock(config_path: &Path) -> anyhow::Result<std::fs::File> {
    let name = config_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no file", config_path.display()))?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    let lock_path = config_path.with_file_name(lock_name);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    file.lock()
        .with_context(|| format!("lock {}", lock_path.display()))?;
    Ok(file)
}
