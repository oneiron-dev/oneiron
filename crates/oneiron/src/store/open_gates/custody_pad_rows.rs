//! Core half of `store::open_gates::custody_pad_rows`: its store-layer items live in `oneiron_store::open_gates::custody_pad_rows` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::open_gates::custody_pad_rows::*;

use super::read_only_door::{canonical_existing_root, open_read_only_with};
use crate::error::{Error, Result};
use heed::types::Bytes;
use heed::{Env, RoTxn};
use std::path::{Path, PathBuf};

/// Reads the `vault_meta` rows under `vault_meta` of the vault at `path`,
/// and beside them what `ask` takes of its `sync_state` and its entities,
/// in one transaction of one read-only environment, as the read-only door
/// reads one database ([`super::read_only_door::read_existing_vault_meta`]).
/// A missing, empty or incomplete root refuses with nothing created; so does
/// a vault with no `vault_meta`.
pub(in crate::store) fn read_existing_custody_pad_rows(
    path: &Path,
    vault_meta: &[&[u8]],
    ask: &PairedSourceAsk<'_>,
) -> Result<CustodyPadRows> {
    let root = canonical_existing_root(path)?;
    let (env, registered) = open_read_only_with(&root, PAIRED_DATABASES)?;
    let read = (|| -> Result<(Rows, Result<PairedSyncRows>, Result<PairedIdentityRows>)> {
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
        let sync_state = sync_rows_in(&env, &txn, ask);
        let identity = identity_rows_in(&env, &txn, ask);
        Ok((custody, sync_state, identity))
    })();
    // The environment closes before its path registration is released.
    drop(env);
    drop(registered);
    let (vault_meta, sync_state, identity) = read?;
    Ok(CustodyPadRows {
        root,
        vault_meta,
        sync_state,
        identity,
    })
}
