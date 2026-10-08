//! A historical restore gives content as it stood, never authority as it stood.
//!
//! ARCH-0038 (RD-20, amended 2026-09-26): a checkpoint never resets the current
//! authority root or freshness pins and never restores a destroyed identity
//! key. Restoring over a live vault classes every canonical row by
//! [`super::restore_class`], deny by default:
//!
//! - **content** comes from the image;
//! - **live** rows replace the image's, and a row the live vault no longer
//!   holds stays absent: the root, device and slip plane, freshness pins,
//!   key custody, spent approvals, consent and policy switches and their
//!   receipts, erasure state, and the ledgers of sends and exports, so
//!   nothing spent, revoked, withdrawn or switched off comes back and no
//!   send is made twice;
//! - **refused** families hold authority entangled with content (grants,
//!   policy manifests, room roles and membership, e-sign ceremonies). A
//!   restore that would change one is refused before anything is created,
//!   rather than half-applied.
//!
//! Membership is checked on the result: a restore may not make anyone an
//! owner or member who is not one now, whether by reviving a deleted or
//! merged PERSON or a removed shared member (`refuse_new_members`).
use super::CanonicalRows;
use super::restore_class::{Class, Classes, Scope};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::ConversationBody;
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CONVERSATION};
use crate::{EntityId, Error, Result, Vault};
use heed::types::Bytes;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

/// The `vault_meta` row holding a store's random id (`vault::identity`).
const VAULT_STORE_ID: &[u8] = b"vault_identity:local:v1";

/// Rewrites `databases` so every live row is `current`'s, or refuses when a
/// refused family moved since the checkpoint.
pub(super) fn carry_current_authority(
    databases: &mut BTreeMap<String, CanonicalRows>,
    current: &Vault,
) -> Result<()> {
    let classes = Classes::new();
    let live = current_rows(current, &classes)?;
    // A store's random id, minted at its first open, names the vault even
    // before it has an authority log. Every image carries one; a missing or
    // different id is another vault.
    let store_id = |rows: &CanonicalRows| {
        rows.iter()
            .find(|(key, _)| key.as_slice() == VAULT_STORE_ID)
            .map(|(_, value)| value.clone())
    };
    let image_id = store_id(&databases["vault_meta"]);
    if image_id.is_none() || image_id != store_id(&live.rows["vault_meta"]) {
        return Err(Error::InvalidConfig(
            "this checkpoint belongs to another vault".into(),
        ));
    }
    // The log only grows. An image entry the live vault never saw means the
    // image is another vault's, or this one's history was rewritten.
    let log = |rows: &CanonicalRows| -> BTreeSet<Vec<u8>> {
        rows.iter()
            .filter(|(_, value)| {
                EntityMetadataHeader::parse(value)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    if !log(&databases["entities"]).is_subset(&log(&live.rows["entities"])) {
        return Err(Error::InvalidConfig(
            "this checkpoint's authority log is not a prefix of this vault's; it belongs to another vault"
                .into(),
        ));
    }
    let image_entities: BTreeSet<&[u8]> = databases["entities"]
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect();
    let mut moved = BTreeSet::new();
    for (database, live_rows) in &live.rows {
        let scoped = |rows| refused(&classes, database, rows, &image_entities, &live.rooms);
        let image = scoped(&databases[*database]);
        let current = scoped(live_rows);
        for what in image.keys().chain(current.keys()) {
            if image.get(what) != current.get(what) {
                moved.insert(*what);
            }
        }
    }
    if !moved.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "restoring this checkpoint would roll back {} changed since it was taken; restore it beside the vault instead",
            moved.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    for (database, live_rows) in &live.rows {
        let is_live =
            |(key, value): &(Vec<u8>, Vec<u8>)| classes.row(database, key, value).0 == Class::Live;
        let rows = databases
            .get_mut(*database)
            .ok_or_else(super::codec_error)?;
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = std::mem::take(rows)
            .into_iter()
            .filter(|row| !is_live(row))
            .collect();
        merged.extend(live_rows.iter().filter(|row| is_live(row)).cloned());
        *rows = merged.into_iter().collect();
    }
    Ok(())
}

/// The live vault's rows that are not content, by database.
struct LiveRows {
    rows: BTreeMap<&'static str, CanonicalRows>,
    /// Rooms the live vault holds and has not deleted.
    rooms: BTreeSet<Vec<u8>>,
}

fn current_rows(current: &Vault, classes: &Classes) -> Result<LiveRows> {
    let txn = current.store.env.read_txn()?;
    let mut live = LiveRows {
        rows: BTreeMap::new(),
        rooms: BTreeSet::new(),
    };
    for entry in crate::store::DB_MANIFEST {
        if !Classes::has_authority(entry.name) {
            continue;
        }
        let db = current
            .store
            .env
            .open_database::<Bytes, Bytes>(&txn, Some(entry.name))?
            .ok_or_else(super::codec_error)?;
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            if super::storage_tier(entry.name, key) != super::StorageTier::Canonical
                || classes.row(entry.name, key, value).0 == Class::Content
            {
                continue;
            }
            if entry.name == "entities"
                && EntityMetadataHeader::parse(value)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_CONVERSATION)
            {
                let id = EntityId::from_bytes(key.try_into().map_err(|_| super::codec_error())?)?;
                if !crate::ports::TombstoneStoreRead::port_deletion_state(
                    &current.store,
                    &txn,
                    &id,
                )?
                .deleted
                {
                    live.rooms.insert(key.to_vec());
                }
            }
            rows.push((key.to_vec(), value.to_vec()));
        }
        live.rows.insert(entry.name, rows);
    }
    Ok(live)
}

/// One refused family's compared rows: each key with what is compared of it.
type Compared<'a> = Vec<(&'a [u8], Cow<'a, [u8]>)>;

/// The rows of each refused family that its scope compares, by name.
fn refused<'a>(
    classes: &Classes,
    database: &str,
    rows: &'a CanonicalRows,
    image_entities: &BTreeSet<&[u8]>,
    rooms: &BTreeSet<Vec<u8>>,
) -> BTreeMap<&'static str, Compared<'a>> {
    let mut families: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (key, value) in rows {
        let (Class::Refuse { what, scope }, prefix) = classes.row(database, key, value) else {
            continue;
        };
        let compared = match scope {
            Scope::Family => Cow::Borrowed(value.as_slice()),
            Scope::ImageEntities => {
                let id = key.get(prefix..prefix + 16);
                if !id.is_some_and(|id| image_entities.contains(id)) {
                    continue;
                }
                Cow::Borrowed(value.as_slice())
            }
            Scope::RoomAuthority => {
                if !image_entities.contains(key.as_slice()) || !rooms.contains(key) {
                    continue;
                }
                Cow::Owned(room_authority(value))
            }
        };
        families
            .entry(what)
            .or_default()
            .push((key.as_slice(), compared));
    }
    families
}

/// Who a room's body admits, in what role, and from when: its members, role
/// overrides and history default. A body that does not decode compares whole.
fn room_authority(raw: &[u8]) -> Vec<u8> {
    raw.get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|body| ConversationBody::from_bytes(body).ok())
        .and_then(|body| {
            let members: BTreeSet<EntityId> = body.member_ids.into_iter().collect();
            rmp_serde::to_vec(&(members, body.roles, body.history_visible)).ok()
        })
        .unwrap_or_else(|| raw.to_vec())
}

/// Refuses a restored vault in which someone is a member who is not a member
/// of `current` now (the owner of a personal vault; any role of a shared one).
/// Membership rides content (PERSON rows, lifecycle, shared grants), so it is
/// checked on the result rather than by row: a person deleted or merged away
/// since the checkpoint does not regain the authority their unchanged grants
/// would confer.
pub(super) fn refuse_new_members(current: &Vault, restored: &Vault) -> Result<()> {
    if restored
        .live_member_ids()?
        .is_subset(&current.live_member_ids()?)
    {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "restoring this checkpoint would make someone a vault owner or member who is not one now; restore it beside the vault instead"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests;
