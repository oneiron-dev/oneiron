//! The id links a structure row keeps (FIX 6376). A short id, its reverse,
//! an edge, an asset refcount marker, an entity's update counter and the
//! deletion markers hold no payload, so they stay under the image's seal,
//! but each names an owner. When the checkpoint holds that owner's
//! compartment and it does not come back (retired at a restore, or erased
//! between a capture's read and its mint), the row goes with it; an owner
//! the checkpoint holds no compartment for drops nothing, as an opened
//! part's dependency does (`Dependency`). Every other structure family
//! keeps no link: nothing is kept or dropped by id alone.
//!
//! One rule, [`dependencies`], fills a capture's links and recounts them
//! from the image a restore lands.

use std::collections::{BTreeMap, BTreeSet};

use super::super::CanonicalRows;
use crate::entity_id::EntityId;
use crate::side_table::{self, SideTableDecl};
use crate::store::checkpoint_payload::rows::OwnerRef;

/// The sync families whose key is the prefix, then the entity's id in hex.
static ENTITY_KEYED: [&SideTableDecl; 6] = [
    &side_table::DELETION_ARCHIVE_MARKER,
    &side_table::DELETION_ROW_FENCE,
    &side_table::DELETION_HARD_DELETE_MARKER,
    &side_table::DELETION_IDENTITY_SOFT_DELETE_MARKER,
    &side_table::DELETION_WITHDRAWN_GENERATION_FENCE,
    &side_table::SYNC_M_U_SEQ_E,
];

/// The databases whose rows [`dependencies`] reads links from.
const LINKED: [&str; 6] = [
    "short_ids",
    "short_ids_reverse",
    "edges_out",
    "edges_in",
    "vault_meta",
    "sync_state",
];

/// One image row that holds an id link: its database, its key and the
/// owners it links to.
pub(super) struct Link {
    pub(super) database: &'static str,
    pub(super) key: Vec<u8>,
    pub(super) on: Vec<OwnerRef>,
}

fn entity(bytes: &[u8]) -> Option<OwnerRef> {
    let id = EntityId::from_bytes(bytes.try_into().ok()?).ok()?;
    Some(OwnerRef::entity(&id))
}

fn entity_hex(text: &str) -> Option<OwnerRef> {
    EntityId::from_hex(text).ok().map(|id| OwnerRef::entity(&id))
}

/// The owners a sync row links to: an entity-keyed marker's or counter's
/// entity, or a pending mirror's row, or both ends of its edge.
fn sync_links(key: &[u8]) -> Vec<OwnerRef> {
    if let Some(id) = ENTITY_KEYED.iter().find_map(|decl| key.strip_prefix(decl.prefix)) {
        return std::str::from_utf8(id).ok().and_then(entity_hex).into_iter().collect();
    }
    // A pending mirror: its window, which holds no `:`, then a row's id, or
    // an edge's key, its kind between its two ids.
    let owed = key
        .strip_prefix(side_table::SYNC_PENDING_MIRROR.prefix)
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, owed)| owed);
    let parts: Option<Vec<&str>> = owed.map(|owed| owed.split(':').collect());
    match parts.as_deref() {
        Some([id]) => entity_hex(id).into_iter().collect(),
        Some([source, _, target]) => {
            [source, target].into_iter().filter_map(|id| entity_hex(id)).collect()
        }
        _ => Vec::new(),
    }
}

/// The owners the image row `key` of `database` holds an id link to, as
/// it rests.
pub(super) fn dependencies(database: &str, key: &[u8], value: &[u8]) -> Vec<OwnerRef> {
    match database {
        "short_ids" => entity(value).into_iter().collect(),
        "short_ids_reverse" => entity(key).into_iter().collect(),
        "edges_out" | "edges_in" if key.len() == 33 => {
            [&key[..16], &key[17..]].into_iter().filter_map(entity).collect()
        }
        // An asset refcount marker: the bytes' digest (32), then the id of
        // the record holding them.
        "vault_meta" => key
            .strip_prefix(side_table::BLOB_ARTIFACT_ASSET_REF.prefix)
            .and_then(|rest| rest.get(32..))
            .and_then(entity)
            .into_iter()
            .collect(),
        "sync_state" => sync_links(key),
        _ => Vec::new(),
    }
}

/// `database`'s row `key` as a link, when it holds one.
pub(super) fn link(database: &'static str, key: &[u8], value: &[u8]) -> Option<Link> {
    let on = dependencies(database, key, value);
    (!on.is_empty()).then(|| Link {
        database,
        key: key.to_vec(),
        on,
    })
}

/// The rows of `links` that link to one of `gone`, by database.
pub(super) fn dependents(
    links: &[&Link],
    gone: &BTreeSet<OwnerRef>,
) -> BTreeMap<&'static str, BTreeSet<Vec<u8>>> {
    let mut rows: BTreeMap<&'static str, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for link in links {
        if link.on.iter().any(|owner| gone.contains(owner)) {
            rows.entry(link.database).or_default().insert(link.key.clone());
        }
    }
    rows
}

/// Takes `rows`, by database, out of `databases`: how many went.
pub(super) fn strip(
    databases: &mut BTreeMap<String, CanonicalRows>,
    rows: &BTreeMap<&str, BTreeSet<Vec<u8>>>,
) -> usize {
    let mut gone = 0;
    for (database, keys) in rows {
        if let Some(held) = databases.get_mut(*database) {
            let before = held.len();
            held.retain(|(key, _)| !keys.contains(key));
            gone += before - held.len();
        }
    }
    gone
}

/// Takes every row of `databases` that links to one of `gone` out, its
/// links recounted by [`dependencies`]: how many went.
pub(super) fn prune(
    databases: &mut BTreeMap<String, CanonicalRows>,
    gone: &BTreeSet<OwnerRef>,
) -> usize {
    if gone.is_empty() {
        return 0;
    }
    let mut pruned = 0;
    for database in LINKED {
        if let Some(rows) = databases.get_mut(database) {
            let before = rows.len();
            rows.retain(|(key, value)| {
                !dependencies(database, key, value)
                    .iter()
                    .any(|owner| gone.contains(owner))
            });
            pruned += before - rows.len();
        }
    }
    pruned
}
