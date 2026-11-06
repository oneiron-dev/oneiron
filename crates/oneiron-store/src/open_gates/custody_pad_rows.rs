//! The paired custody read (PAD-1, the L01 seam approved 10-22 10:3x, its
//! identity and bundle rows agreed with L14 10-30 06:07): an existing vault's
//! live custody rows, its home's current pad object rows, its bundle parts,
//! its install's machine id, its stored authority records and the checkpoint
//! image it adopted, pin row and image bytes (FIX 11823), read off its
//! directory in one read-only environment and one transaction, so what a side
//! restore carries of the objects, and the vault and home it names them for,
//! are the same revision as the custody it reads. It is the read-only door's
//! open: the same root-open registration, existing-only and alias checks, and
//! the same page seal; no database is created and nothing reopens writable.

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Env, RoTxn};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The named databases a paired read opens: `vault_meta`, `sync_state`,
/// `entities` and the `type_index` that names its records by type.
pub const PAIRED_DATABASES: u32 = 4;

pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// What a paired read takes of a vault beside its custody rows.
pub struct PairedSourceAsk<'a> {
    /// The `sync_state` prefixes its pad object and bundle part rows are
    /// under.
    pub sync_state: &'a [&'a [u8]],
    /// Which `sync_state` rows under those prefixes are pad object rows.
    pub pad_object: fn(&[u8]) -> bool,
    /// Which of them are bundle parts it takes, read apart from the pad
    /// object rows: the parts of the generations a copy does not keep, none
    /// of the rest (FIX 11824).
    pub bundle_part: Box<dyn Fn(&[u8]) -> bool + 'a>,
    /// The `sync_state` key its install's machine id is stored under.
    pub machine_id: &'a [u8],
    /// The entity type whose stored records it reads, by the type index.
    pub entity_type: u8,
    /// The `vault_meta` key its adopted checkpoint pin row is stored under.
    pub adopted_pin: &'a [u8],
    /// The `vault_meta` key of the image a stored pin row names.
    pub adopted_image: fn(&[u8]) -> Result<Vec<u8>>,
}

/// The `sync_state` rows a paired read took under the prefixes asked, full
/// keys, no count or size cap.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub struct PairedSyncRows {
    pub pad_objects: Rows,
    pub bundle_parts: Rows,
}

/// What a paired read took to name the vault and the home its objects are
/// for.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub struct PairedIdentityRows {
    /// The machine id row's stored bytes; `None` when the vault holds none.
    pub machine_id: Option<Vec<u8>>,
    /// Every stored record of the entity type asked, its id key and its
    /// stored bytes (header and body), in id order.
    pub records: Rows,
    /// The adopted checkpoint pin row's stored bytes; `None` when the vault
    /// adopted no image.
    pub adopted_pin: Option<Vec<u8>>,
    /// The stored bytes of the image that pin row names; `None` with no pin
    /// row, or none stored under the key it names.
    pub adopted_image: Option<Vec<u8>>,
}

/// One paired read of an existing vault, and the canonical root it was read
/// from.
pub struct CustodyPadRows {
    pub root: PathBuf,
    /// The `vault_meta` rows under the custody prefixes asked.
    pub vault_meta: Rows,
    /// Its pad object rows and bundle parts. A fault reading them is theirs
    /// alone: the custody rows still read.
    pub sync_state: Result<PairedSyncRows>,
    /// Its machine id and its stored records of the type asked. A fault
    /// reading them is theirs alone too.
    pub identity: Result<PairedIdentityRows>,
}

/// The `sync_state` database of the vault `env` opened.
fn sync_state_in(env: &Env, txn: &RoTxn<'_>) -> Result<heed::Database<Bytes, Bytes>> {
    env.open_database::<Bytes, Bytes>(txn, Some("sync_state"))?
        .ok_or(Error::CorruptedIndex("vault holds no sync state database"))
}

/// The pad object rows and the bundle parts `ask` keeps under its
/// `sync_state` prefixes, in `txn`.
pub fn sync_rows_in(
    env: &Env,
    txn: &RoTxn<'_>,
    ask: &PairedSourceAsk<'_>,
) -> Result<PairedSyncRows> {
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

/// The machine id row, every stored record of `ask`'s entity type, and the
/// adopted checkpoint's pin row with the image bytes it names, in `txn`: the
/// type index names each record's id, `entities` holds it, and `vault_meta`
/// holds the pin and the image.
pub fn identity_rows_in(
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
    let meta = env
        .open_database::<Bytes, Bytes>(txn, Some("vault_meta"))?
        .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
    let adopted_pin = meta.get(txn, ask.adopted_pin)?.map(<[u8]>::to_vec);
    let adopted_image = match &adopted_pin {
        Some(pin) => meta
            .get(txn, &(ask.adopted_image)(pin)?)?
            .map(<[u8]>::to_vec),
        None => None,
    };
    Ok(PairedIdentityRows {
        machine_id,
        records,
        adopted_pin,
        adopted_image,
    })
}
