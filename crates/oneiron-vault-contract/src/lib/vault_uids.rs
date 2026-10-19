//! The host's vault UID allocation table: one row per managed vault, binding
//! its dedicated non-root UID to its name and its canonical data directory,
//! one to one.
//!
//! The supervisor writes the table at [`PATH`], under its create lock: it
//! writes the whole table with [`serialize`] to a temporary file beside it,
//! root:root [`MODE`], and renames that into place, so a reader sees the old
//! table or the new one and never a part. Creating a vault adds its row and
//! retiring the vault removes it. The managed open's isolation probe reads
//! the table: it refuses the file unless it is a regular file, opened without
//! following a symlink, owned by [`OWNER_UID`], with no
//! [`REFUSED_MODE_BITS`] in its mode and at most [`MAX_BYTES`] long; then it
//! [`parse`]s it and admits the vault only when [`binding_matches`]. Both
//! sides use this one codec, so the rows the supervisor writes and the rows
//! the probe reads cannot drift.
//!
//! A row is `uid<TAB>vault-name<TAB>canonical-data-directory` on a line of
//! its own; empty lines and lines starting `#` are skipped.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// Where the table lives on the host.
pub const PATH: &str = "/etc/oneiron/vault-uids";

/// The table file's owner: root. The probe refuses a file another user owns.
pub const OWNER_UID: u32 = 0;

/// The mode the supervisor gives the table file: anyone reads it, root alone
/// writes it. The probe refuses a mode with any [`REFUSED_MODE_BITS`].
pub const MODE: u32 = 0o644;

/// The group and other write bits: the probe refuses the table file when
/// its mode has either.
pub const REFUSED_MODE_BITS: u32 = 0o022;

/// The longest table file, in bytes (1 MiB). The probe refuses a longer
/// file, and [`serialize`] a longer table.
pub const MAX_BYTES: u64 = 1_048_576;

/// What a field may not hold: a TAB ends the field, a CR or LF the line.
const SEPARATORS: [char; 3] = ['\t', '\r', '\n'];

/// One vault's allocation: its dedicated non-root UID, its name and its
/// canonical data directory. No other row of a table holds the same uid,
/// name or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultUidRow {
    pub uid: u32,
    pub vault: String,
    pub data_dir: PathBuf,
}

/// Why a table does not parse, or a row or table cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultUidsError {
    /// A line (counted from 1) that is not three TAB-separated fields with a
    /// `u32` uid first. It refuses the whole table.
    Malformed { line: usize },
    /// A row [`parse`] could not read back or the probe could never admit;
    /// `fault` says which part.
    InvalidRow { uid: u32, fault: &'static str },
    /// Two rows hold the same `field`: the uid, the vault name or the data
    /// directory.
    Shared { field: &'static str },
    /// A table of `len` bytes, over [`MAX_BYTES`].
    TooLarge { len: usize },
}

impl fmt::Display for VaultUidsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { line } => write!(
                f,
                "vault-uids line {line} is not uid<TAB>vault<TAB>data-dir with a u32 uid"
            ),
            Self::InvalidRow { uid, fault } => write!(f, "vault-uids row for uid {uid}: {fault}"),
            Self::Shared { field } => write!(f, "two vault-uids rows hold the same {field}"),
            Self::TooLarge { len } => write!(
                f,
                "vault-uids table of {len} bytes is over the {MAX_BYTES}-byte cap"
            ),
        }
    }
}

impl std::error::Error for VaultUidsError {}

/// The table's rows, in order. Empty lines and lines starting `#` are
/// skipped; every other line must be `uid<TAB>vault<TAB>data_dir` with a
/// `u32` uid, or the whole table is refused. Nothing else is checked here:
/// the probe's rule is [`binding_matches`].
pub fn parse(table: &str) -> Result<Vec<VaultUidRow>, VaultUidsError> {
    table
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(index, line)| {
            let malformed = VaultUidsError::Malformed { line: index + 1 };
            let mut fields = line.split('\t');
            let (Some(uid), Some(vault), Some(data_dir), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(malformed);
            };
            let Ok(uid) = uid.parse::<u32>() else {
                return Err(malformed);
            };
            Ok(VaultUidRow {
                uid,
                vault: vault.to_owned(),
                data_dir: PathBuf::from(data_dir),
            })
        })
        .collect()
}

/// The row as one line, `uid<TAB>vault<TAB>data_dir`, without a line end.
/// Refuses a row [`parse`] could not read back or the probe could never
/// admit: uid 0, an empty vault name, a TAB, CR or LF in the name or the
/// directory, and a non-UTF-8 or relative directory.
pub fn format_row(row: &VaultUidRow) -> Result<String, VaultUidsError> {
    let invalid = |fault: &'static str| VaultUidsError::InvalidRow {
        uid: row.uid,
        fault,
    };
    if row.uid == 0 {
        return Err(invalid("uid 0 is root"));
    }
    if row.vault.is_empty() {
        return Err(invalid("the vault name is empty"));
    }
    if row.vault.contains(SEPARATORS) {
        return Err(invalid("the vault name holds a TAB, CR or LF"));
    }
    let Some(data_dir) = row.data_dir.to_str() else {
        return Err(invalid("the data directory is not UTF-8"));
    };
    if data_dir.contains(SEPARATORS) {
        return Err(invalid("the data directory holds a TAB, CR or LF"));
    }
    if !row.data_dir.is_absolute() {
        return Err(invalid("the data directory is relative"));
    }
    Ok(format!("{}\t{}\t{data_dir}", row.uid, row.vault))
}

/// The whole table: each row as [`format_row`] writes it, one per line, each
/// ending `\n`. Refuses what [`format_row`] refuses, two rows holding the
/// same uid, vault name or data directory, and a table over [`MAX_BYTES`].
/// [`parse`] reads what it writes back as `rows`.
pub fn serialize(rows: &[VaultUidRow]) -> Result<String, VaultUidsError> {
    let mut uids = HashSet::new();
    let mut vaults = HashSet::new();
    let mut data_dirs = HashSet::new();
    let mut table = String::new();
    for row in rows {
        table.push_str(&format_row(row)?);
        table.push('\n');
        for (fresh, field) in [
            (uids.insert(row.uid), "uid"),
            (vaults.insert(row.vault.as_str()), "vault name"),
            (data_dirs.insert(row.data_dir.as_path()), "data directory"),
        ] {
            if !fresh {
                return Err(VaultUidsError::Shared { field });
            }
        }
    }
    if table.len() as u64 > MAX_BYTES {
        return Err(VaultUidsError::TooLarge { len: table.len() });
    }
    Ok(table)
}

/// Whether `rows` allocate `uid` to `vault` at `data_dir` one to one: every
/// row holding any one of the three holds all three, and exactly one row
/// does. The managed open's isolation probe admits a vault's UID by this
/// rule.
#[must_use]
pub fn binding_matches(rows: &[VaultUidRow], uid: u32, vault: &str, data_dir: &Path) -> bool {
    let mut matched = 0;
    for row in rows {
        if row.uid == uid || row.vault == vault || row.data_dir.as_path() == data_dir {
            if row.uid != uid || row.vault != vault || row.data_dir.as_path() != data_dir {
                return false;
            }
            matched += 1;
        }
    }
    matched == 1
}
