//! This machine's measured engine rows: where they live, how they are read
//! and written, and what keys them.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// This machine's measured rows, under its data directory.
const ROWS_FILE: &str = "engines.json";

/// One engine measured on this machine against one bundle's reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub(crate) stack_sha16: String,
    pub(crate) reference_sha16: String,
    pub(crate) engine: String,
    /// The server build that measured it: another build may run other kernels.
    pub(crate) build: String,
    /// Whether every reference answer cleared the bar.
    pub(crate) clears: bool,
    /// Mean wall-clock milliseconds per reference case after one warm-up
    /// call; `None` when the engine could not load the bundle or answer.
    pub(crate) mean_ms: Option<f64>,
    pub(crate) cases: usize,
    /// Unix seconds.
    pub(crate) measured_at: u64,
}

impl Row {
    pub(super) fn is_for(&self, stack: &str, reference: &str, engine: &str, build: &str) -> bool {
        self.stack_sha16 == stack
            && self.reference_sha16 == reference
            && self.engine == engine
            && self.build == build
    }

    /// Its speed, when it clears the bar and was timed.
    pub(super) fn clearing_ms(&self) -> Option<f64> {
        self.clears.then_some(self.mean_ms).flatten()
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RowsFile {
    rows: Vec<Row>,
}

/// The server build a row is measured under.
pub(super) fn build_id() -> String {
    format!(
        "{}+{}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

/// The rows file: `rows_location` when the caller names one, and then no
/// environment is read; else `<data>/oneiron/oneironer/engines.json`, the
/// data directory found the way the embedder's model root is:
/// `XDG_DATA_HOME`, then the home share tree. `None` when nothing is named
/// and neither names an absolute directory; rows are then measured and kept
/// for this process only.
///
/// A managed vault names its own, under its data directory: it reads no HOME
/// or XDG, and its rows never go under a shared model root or a bundle.
pub(super) fn rows_path(rows_location: Option<&Path>) -> Option<PathBuf> {
    if let Some(rows_location) = rows_location {
        return Some(rows_location.to_path_buf());
    }
    let absolute = |key: &str| {
        let path = PathBuf::from(std::env::var_os(key)?);
        path.is_absolute().then_some(path)
    };
    let data = absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))?;
    Some(data.join("oneiron").join("oneironer").join(ROWS_FILE))
}

/// The rows file, empty when absent; an unreadable one is measured over.
pub(super) fn read_rows(path: &Path) -> Vec<Row> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<RowsFile>(&bytes) {
            Ok(file) => file.rows,
            Err(_) => {
                tracing::warn!(path = %path.display(), "oneironer engine rows unreadable; measuring again");
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Writes the rows whole, through a sibling file and a rename.
pub(super) fn write_rows(path: &Path, rows: &[Row]) {
    let written = (|| -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staged = path.with_extension("json.tmp");
        std::fs::write(
            &staged,
            serde_json::to_vec_pretty(&RowsFile {
                rows: rows.to_vec(),
            })?,
        )?;
        std::fs::rename(&staged, path)?;
        Ok(())
    })();
    if let Err(error) = written {
        tracing::warn!(path = %path.display(), %error, "oneironer engine rows not saved; the next start measures again");
    }
}

pub(super) fn sha16(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_owned()
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
