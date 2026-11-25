//! The node's warm-key table (pass 34, `34-compute-general/DESIGN.md` section 4.1; row P2):
//! `{ key, bytes, last_used_ms, uses }` for each warm key the machine holds or has used, in
//! [`WARM_KEYS_FILE_NAME`] in the state directory. It is a node-local hint, not a record: a file
//! that does not read is started again empty, and a key found again is counted from then, so a
//! lost table keeps caches longer and removes nothing early. Each write replaces the file whole
//! (a new file, synced, renamed over the old one, the directory synced). The table is encoded
//! under the warm lock and written after it is dropped ([`TableWrite`]): writes land in the order
//! of the changes, and a write older than the file on disk is skipped.
//!
//! The table also records each cache path a pass moved into the removed caches' directory and
//! has not deleted yet ([`EvictedRecord`]): only a recorded entry is ever deleted from there. A
//! lost record leaves its entry on disk, never deletes another.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

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

/// A cache path a pass moved into the removed caches' directory and has not deleted yet: its
/// name there and its inode, as the move left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictedRecord {
    pub name: String,
    pub ino: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct TableFile {
    version: u32,
    keys: Vec<WarmKeyRecord>,
    /// The job keys of the journal whose exit-0 end is counted in `keys`.
    #[serde(default)]
    counted: BTreeSet<String>,
    /// The moved cache paths not deleted yet.
    #[serde(default)]
    evicted: Vec<EvictedRecord>,
}

/// The table, as read from and written to the state directory.
#[derive(Debug, Clone)]
pub struct WarmKeyTable {
    path: PathBuf,
    records: BTreeMap<String, WarmKeyRecord>,
    counted: BTreeSet<String>,
    evicted: BTreeMap<String, EvictedRecord>,
    /// The number of the table's newest change.
    generation: u64,
    /// The number of the change the file on disk holds.
    written: Arc<Mutex<u64>>,
}

/// One write of the table, encoded under the warm lock and written after it is dropped.
#[derive(Debug)]
#[must_use = "a table write does nothing until it is written"]
pub struct TableWrite {
    path: PathBuf,
    bytes: Vec<u8>,
    generation: u64,
    written: Arc<Mutex<u64>>,
}

impl TableWrite {
    /// Writes the table whole, unless the file already holds this change or a newer one.
    ///
    /// # Errors
    ///
    /// The write, sync or rename failed, and the file on disk is the one before; or the
    /// directory's sync after the rename failed, and the file holds this change, which may not
    /// survive a crash. No older change replaces it either way.
    pub fn write(self) -> std::io::Result<()> {
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        if *written >= self.generation {
            return Ok(());
        }
        let staging = self.path.with_extension("json.new");
        {
            let mut out = std::fs::File::create(&staging)?;
            out.write_all(&self.bytes)?;
            out.sync_all()?;
        }
        std::fs::rename(&staging, &self.path)?;
        // The file holds this change from the rename on: an older one must not replace it, even
        // when the directory's sync fails.
        *written = self.generation;
        if let Some(dir) = self.path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

impl WarmKeyTable {
    /// The table in `state_dir`: empty when there is no file, and empty, with a warning, when the
    /// file does not read.
    #[must_use]
    pub fn open(state_dir: &Path) -> Self {
        let path = state_dir.join(WARM_KEYS_FILE_NAME);
        let empty = || (BTreeMap::new(), BTreeSet::new(), BTreeMap::new());
        let (records, counted, evicted) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<TableFile>(&bytes) {
                Ok(file) if file.version == WARM_KEYS_FILE_VERSION => (
                    file.keys
                        .into_iter()
                        .map(|record| (record.key.clone(), record))
                        .collect(),
                    file.counted,
                    file.evicted
                        .into_iter()
                        .map(|record| (record.name.clone(), record))
                        .collect(),
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
            evicted,
            generation: 0,
            written: Arc::new(Mutex::new(0)),
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

    /// Keeps at most `keys_max` of the records whose keys `has_path` says no template maps (the
    /// hints remembered from use alone), forgetting the least recently used first. A key a
    /// template maps is never forgotten: its last use is what the cache budget ages it by, and
    /// the templates bound those keys themselves. Returns the keys forgotten.
    pub fn bound(&mut self, keys_max: usize, has_path: impl Fn(&str) -> bool) -> Vec<String> {
        let mut hints: Vec<(u64, String)> = self
            .records
            .values()
            .filter(|record| !has_path(&record.key))
            .map(|record| (record.last_used_ms, record.key.clone()))
            .collect();
        let excess = hints.len().saturating_sub(keys_max);
        if excess == 0 {
            return Vec::new();
        }
        hints.sort();
        let forgotten: Vec<String> = hints.into_iter().take(excess).map(|(_, key)| key).collect();
        for key in &forgotten {
            self.records.remove(key);
        }
        forgotten
    }

    /// A pass moved a cache path into the removed caches' directory as `record`.
    pub fn evicted(&mut self, record: EvictedRecord) {
        self.evicted.insert(record.name.clone(), record);
    }

    /// The moved cache paths not deleted yet, by name.
    #[must_use]
    pub fn evicted_records(&self) -> &BTreeMap<String, EvictedRecord> {
        &self.evicted
    }

    /// The moved cache path `name` is deleted. Returns whether it was recorded.
    pub fn deleted(&mut self, name: &str) -> bool {
        self.evicted.remove(name).is_some()
    }

    /// The table as it is now, to write after the warm lock is dropped.
    ///
    /// # Errors
    ///
    /// The table does not encode.
    pub fn encode(&mut self) -> std::io::Result<TableWrite> {
        let file = TableFile {
            version: WARM_KEYS_FILE_VERSION,
            keys: self.records.values().cloned().collect(),
            counted: self.counted.clone(),
            evicted: self.evicted.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        self.generation = self.generation.saturating_add(1);
        Ok(TableWrite {
            path: self.path.clone(),
            bytes,
            generation: self.generation,
            written: Arc::clone(&self.written),
        })
    }

    /// Writes the table whole, now.
    ///
    /// # Errors
    ///
    /// As [`TableWrite::write`].
    pub fn save(&mut self) -> std::io::Result<()> {
        self.encode()?.write()
    }
}
