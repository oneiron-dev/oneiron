//! The paired custody read (PAD-1, the L01 seam approved 10-22 10:3x, its
//! identity and bundle rows agreed with L14 10-30 06:07): an existing vault's
//! live custody rows, its home's current pad object rows, its bundle parts,
//! its install's machine id and its stored authority records, read off its
//! directory in one read-only environment and one transaction, so what a side
//! restore carries of the objects, and the vault and home it names them for,
//! are the same revision as the custody it reads. It is the read-only door's
//! open: the same root-open registration, existing-only and alias checks, and
//! the same page seal; no database is created and nothing reopens writable.

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Env, RoTxn};

use crate::error::{Error, Result};

use super::read_only_door::{canonical_existing_root, open_read_only_with};

/// The named databases a paired read opens: `vault_meta`, `sync_state`,
/// `entities` and the `type_index` that names its records by type.
const PAIRED_DATABASES: u32 = 4;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// What a paired read takes of a vault beside its custody rows.
pub(in crate::store) struct PairedSourceAsk<'a> {
    /// The `sync_state` prefixes its pad object and bundle part rows are
    /// under.
    pub(in crate::store) sync_state: &'a [&'a [u8]],
    /// Which `sync_state` rows under those prefixes are pad object rows.
    pub(in crate::store) pad_object: fn(&[u8]) -> bool,
    /// Which of them are bundle parts, read apart from the pad object rows.
    pub(in crate::store) bundle_part: fn(&[u8]) -> bool,
    /// The `sync_state` key its install's machine id is stored under.
    pub(in crate::store) machine_id: &'a [u8],
    /// The entity type whose stored records it reads, by the type index.
    pub(in crate::store) entity_type: u8,
}

/// The `sync_state` rows a paired read took under the prefixes asked, full
/// keys, no count or size cap.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(in crate::store) struct PairedSyncRows {
    pub(in crate::store) pad_objects: Rows,
    pub(in crate::store) bundle_parts: Rows,
}

/// What a paired read took to name the vault and the home its objects are
/// for.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(in crate::store) struct PairedIdentityRows {
    /// The machine id row's stored bytes; `None` when the vault holds none.
    pub(in crate::store) machine_id: Option<Vec<u8>>,
    /// Every stored record of the entity type asked, its id key and its
    /// stored bytes (header and body), in id order.
    pub(in crate::store) records: Rows,
}

/// One paired read of an existing vault, and the canonical root it was read
/// from.
pub(in crate::store) struct CustodyPadRows {
    pub(in crate::store) root: PathBuf,
    /// The `vault_meta` rows under the custody prefixes asked.
    pub(in crate::store) vault_meta: Rows,
    /// Its pad object rows and bundle parts. A fault reading them is theirs
    /// alone: the custody rows still read.
    pub(in crate::store) sync_state: Result<PairedSyncRows>,
    /// Its machine id and its stored records of the type asked. A fault
    /// reading them is theirs alone too.
    pub(in crate::store) identity: Result<PairedIdentityRows>,
}

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

/// The `sync_state` database of the vault `env` opened.
fn sync_state_in(env: &Env, txn: &RoTxn<'_>) -> Result<heed::Database<Bytes, Bytes>> {
    env.open_database::<Bytes, Bytes>(txn, Some("sync_state"))?
        .ok_or(Error::CorruptedIndex("vault holds no sync state database"))
}

/// The pad object rows and the bundle parts `ask` keeps under its
/// `sync_state` prefixes, in `txn`.
fn sync_rows_in(env: &Env, txn: &RoTxn<'_>, ask: &PairedSourceAsk<'_>) -> Result<PairedSyncRows> {
    let mut rows = PairedSyncRows {
        pad_objects: Vec::new(),
        bundle_parts: Vec::new(),
    };
    if ask.sync_state.is_empty() {
        return Ok(rows);
    }
    let state = sync_state_in(env, txn)?;
    for prefix in ask.sync_state {
        for row in state.prefix_iter(txn, prefix)? {
            let (key, value) = row?;
            if (ask.pad_object)(key) {
                rows.pad_objects.push((key.to_vec(), value.to_vec()));
            } else if (ask.bundle_part)(key) {
                rows.bundle_parts.push((key.to_vec(), value.to_vec()));
            }
        }
    }
    Ok(rows)
}

/// The machine id row and every stored record of `ask`'s entity type, in
/// `txn`: the type index names each record's id, and `entities` holds it.
fn identity_rows_in(
    env: &Env,
    txn: &RoTxn<'_>,
    ask: &PairedSourceAsk<'_>,
) -> Result<PairedIdentityRows> {
    let machine_id = sync_state_in(env, txn)?
        .get(txn, ask.machine_id)?
        .map(<[u8]>::to_vec);
    let types = env
        .open_database::<Bytes, Bytes>(txn, Some("type_index"))?
        .ok_or(Error::CorruptedIndex("vault holds no type index database"))?;
    let entities = env
        .open_database::<Bytes, Bytes>(txn, Some("entities"))?
        .ok_or(Error::CorruptedIndex("vault holds no entity database"))?;
    let mut records = Vec::new();
    for row in types.prefix_iter(txn, &[ask.entity_type][..])? {
        let (key, _) = row?;
        let id = key
            .get(1..)
            .filter(|id| id.len() == 16)
            .ok_or(Error::CorruptedIndex("type index key"))?;
        let raw = entities
            .get(txn, id)?
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        records.push((id.to_vec(), raw.to_vec()));
    }
    Ok(PairedIdentityRows {
        machine_id,
        records,
    })
}
