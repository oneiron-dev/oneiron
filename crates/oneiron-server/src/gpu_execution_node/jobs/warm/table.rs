//! The node's warm-key table (pass 34, `34-compute-general/DESIGN.md` section 4.1; row P2):
//! `{ key, bytes, last_used_ms, uses }` for each warm key the machine holds or has used, in
//! [`WARM_KEYS_FILE_NAME`] in the state directory. It is a node-local hint, not a record: a file
//! that does not read is started again empty, and a key found again is counted from then, so a
//! lost table keeps caches longer and removes nothing early. Each write replaces the file whole
//! (a new file, synced, renamed over the old one, the directory synced).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The table's file in the node's state directory.
pub const WARM_KEYS_FILE_NAME: &str = "warm-keys.json";

/// The table file's form.
const WARM_KEYS_FILE_VERSION: u32 = 1;

/// One warm key the node holds or has used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmKeyRecord {
    pub key: String,
    /// What its path held at the last cache pass; 0 for a key with no path or not measured yet.
    #[serde(default)]
    pub bytes: u64,
    /// When an attempt that listed it last ended with exit 0, or when the node first found its
    /// path.
    pub last_used_ms: u64,
    /// How many attempts that listed it ended with exit 0.
    #[serde(default)]
    pub uses: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct TableFile {
    version: u32,
    keys: Vec<WarmKeyRecord>,
    /// The job keys of the journal whose exit-0 end is counted in `keys`.
    #[serde(default)]
    counted: BTreeSet<String>,
}

/// The table, as read from and written to the state directory.
#[derive(Debug, Clone)]
pub struct WarmKeyTable {
    path: PathBuf,
    records: BTreeMap<String, WarmKeyRecord>,
    counted: BTreeSet<String>,
}

impl WarmKeyTable {
    /// The table in `state_dir`: empty when there is no file, and empty, with a warning, when the
    /// file does not read.
    #[must_use]
    pub fn open(state_dir: &Path) -> Self {
        let path = state_dir.join(WARM_KEYS_FILE_NAME);
        let empty = || (BTreeMap::new(), BTreeSet::new());
        let (records, counted) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<TableFile>(&bytes) {
                Ok(file) if file.version == WARM_KEYS_FILE_VERSION => (
                    file.keys
                        .into_iter()
                        .map(|record| (record.key.clone(), record))
                        .collect(),
                    file.counted,
                ),
                Ok(file) => {
                    tracing::warn!(path = %path.display(), version = file.version, "warm keys: the table's form is not this engine's; it starts empty");
                    empty()
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "warm keys: the table does not read; it starts empty");
                    empty()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => empty(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "warm keys: the table does not read; it starts empty");
                empty()
            }
        };
        Self {
            path,
            records,
            counted,
        }
    }

    /// Every record, by key.
    pub fn records(&self) -> impl Iterator<Item = &WarmKeyRecord> {
        self.records.values()
    }

    /// The record of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&WarmKeyRecord> {
        self.records.get(key)
    }

    /// An attempt that listed `keys` ended with exit 0 at `now_ms`: each key's last use is then,
    /// and its uses one more. A key not in the table yet is added.
    pub fn used(&mut self, keys: &[String], now_ms: u64) {
        for key in keys {
            let record = self
                .records
                .entry(key.clone())
                .or_insert_with(|| WarmKeyRecord {
                    key: key.clone(),
                    bytes: 0,
                    last_used_ms: now_ms,
                    uses: 0,
                });
            record.last_used_ms = record.last_used_ms.max(now_ms);
            record.uses = record.uses.saturating_add(1);
        }
    }

    /// The node found `key`'s path at `now_ms`: a key not in the table yet is added with its last
    /// use then. Returns whether it was added.
    pub fn found(&mut self, key: &str, now_ms: u64) -> bool {
        if self.records.contains_key(key) {
            return false;
        }
        self.records.insert(
            key.to_owned(),
            WarmKeyRecord {
                key: key.to_owned(),
                bytes: 0,
                last_used_ms: now_ms,
                uses: 0,
            },
        );
        true
    }

    /// The cache pass measured `bytes` beneath `key`'s path.
    pub fn measured(&mut self, key: &str, bytes: u64) {
        if let Some(record) = self.records.get_mut(key) {
            record.bytes = bytes;
        }
    }

    /// Whether the exit-0 end of the journal's job key `job_key` is counted.
    #[must_use]
    pub fn counted(&self, job_key: &str) -> bool {
        self.counted.contains(job_key)
    }

    /// The exit-0 end of the journal's job key `job_key` is counted.
    pub fn count(&mut self, job_key: &str) {
        self.counted.insert(job_key.to_owned());
    }

    /// Keeps the counted job keys `in_journal` holds: the journal no longer holds the rest, so
    /// none of them can be counted twice. Returns whether any was dropped.
    pub fn retain_counted(&mut self, in_journal: impl Fn(&str) -> bool) -> bool {
        let before = self.counted.len();
        self.counted.retain(|key| in_journal(key));
        self.counted.len() != before
    }

    /// Keeps at most `keys_max` records: the least recently used of the keys `has_path` says no
    /// template maps are forgotten first, then the least recently used of the rest. Returns the
    /// keys forgotten.
    pub fn bound(&mut self, keys_max: usize, has_path: impl Fn(&str) -> bool) -> Vec<String> {
        let excess = self.records.len().saturating_sub(keys_max);
        if excess == 0 {
            return Vec::new();
        }
        let mut order: Vec<(bool, u64, String)> = self
            .records
            .values()
            .map(|record| {
                (
                    has_path(&record.key),
                    record.last_used_ms,
                    record.key.clone(),
                )
            })
            .collect();
        order.sort();
        let forgotten: Vec<String> = order
            .into_iter()
            .take(excess)
            .map(|(_, _, key)| key)
            .collect();
        for key in &forgotten {
            self.records.remove(key);
        }
        forgotten
    }

    /// Writes the table whole.
    ///
    /// # Errors
    ///
    /// The write, sync or rename failed; the file on disk is then the one before.
    pub fn save(&self) -> std::io::Result<()> {
        let file = TableFile {
            version: WARM_KEYS_FILE_VERSION,
            keys: self.records.values().cloned().collect(),
            counted: self.counted.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        let staging = self.path.with_extension("json.new");
        {
            let mut out = std::fs::File::create(&staging)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
        }
        std::fs::rename(&staging, &self.path)?;
        if let Some(dir) = self.path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}
