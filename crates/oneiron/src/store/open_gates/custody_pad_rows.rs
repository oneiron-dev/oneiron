//! The paired custody read (PAD-1, the L01 seam approved 10-22 10:3x): an
//! existing vault's live custody rows and its home's current pad object
//! rows, read off its directory in one read-only environment and one
//! transaction, so what a side restore carries of the objects is the same
//! revision as the custody it reads. It is the read-only door's open: the
//! same root-open registration, existing-only and alias checks, and the same
//! page seal; no database is created and nothing reopens writable.

use std::path::{Path, PathBuf};

use heed::types::Bytes;

use crate::error::{Error, Result};

use super::read_only_door::{canonical_existing_root, open_read_only_with};

/// The named databases a paired read opens: `vault_meta` and `sync_state`.
const PAIRED_DATABASES: u32 = 2;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// One paired read of an existing vault, and the canonical root it was read
/// from.
pub(in crate::store) struct CustodyPadRows {
    pub(in crate::store) root: PathBuf,
    /// The `vault_meta` rows under the custody prefixes asked.
    pub(in crate::store) vault_meta: Rows,
    /// Every `sync_state` row under the pad object prefixes asked that
    /// `keep` keeps, full keys, no count or size cap. A fault reading them
    /// is theirs alone: the custody rows still read.
    pub(in crate::store) sync_state: Result<Rows>,
}

/// Reads the `vault_meta` rows under `vault_meta` and the `sync_state` rows
/// under `sync_state` that `keep` keeps, of the vault at `path`, in one
/// transaction of one read-only environment, as the read-only door reads
/// one database ([`super::read_only_door::read_existing_vault_meta`]). A
/// missing, empty or incomplete root refuses with nothing created; so does
/// a vault with no `vault_meta`.
pub(in crate::store) fn read_existing_custody_pad_rows(
    path: &Path,
    vault_meta: &[&[u8]],
    sync_state: &[&[u8]],
    keep: impl Fn(&[u8]) -> bool,
) -> Result<CustodyPadRows> {
    let root = canonical_existing_root(path)?;
    let (env, registered) = open_read_only_with(&root, PAIRED_DATABASES)?;
    let read = (|| -> Result<(Rows, Result<Rows>)> {
        let txn = env.read_txn()?;
        let meta = env
            .open_database::<Bytes, Bytes>(&txn, Some("vault_meta"))?
            .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
        let mut custody = Vec::new();
        for prefix in vault_meta {
            for row in meta.prefix_iter(&txn, prefix)? {
                let (key, value) = row?;
                custody.push((key.to_vec(), value.to_vec()));
            }
        }
        let pads = (|| -> Result<Rows> {
            let mut rows = Vec::new();
            if sync_state.is_empty() {
                return Ok(rows);
            }
            let state = env
                .open_database::<Bytes, Bytes>(&txn, Some("sync_state"))?
                .ok_or(Error::CorruptedIndex("vault holds no sync state database"))?;
            for prefix in sync_state {
                for row in state.prefix_iter(&txn, prefix)? {
                    let (key, value) = row?;
                    if keep(key) {
                        rows.push((key.to_vec(), value.to_vec()));
                    }
                }
            }
            Ok(rows)
        })();
        Ok((custody, pads))
    })();
    // The environment closes before its path registration is released.
    drop(env);
    drop(registered);
    let (vault_meta, sync_state) = read?;
    Ok(CustodyPadRows {
        root,
        vault_meta,
        sync_state,
    })
}
