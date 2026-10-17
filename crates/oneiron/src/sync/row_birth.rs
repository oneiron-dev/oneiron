//! Rule A row births on sync. A window's `row_births` map carries each
//! replicated row's immutable `made_by` envelope beside its entity carrier,
//! so a peer learns how a row was made in the same import that brings the
//! row (ARCH-0035 Rule A).
//!
//! Key: the owner's canonical (lowercase) hex id. Value: the Named
//! MessagePack [`RowBirth`], the same bytes the vault's birth row holds. The
//! born-from index never travels; the receiver rebuilds it from the envelope.
//!
//! A birth travels only with its owner: every filter that keeps or drops an
//! entity carrier keeps or drops its birth with it. Among the owner's own
//! machines the envelope goes whole; a copy to or from another vault rewrites
//! it (owner Q26 = B): each ref the copy does not carry becomes a masked
//! handle, and who made the row, by which process, stays.

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::birth::{RowBirth, WithheldKey, stamp_replicated_row_birth_in_txn};

/// The window map that carries row births.
pub(crate) const ROW_BIRTHS_MAP: &str = "row_births";

fn births(doc: &LoroDoc) -> LoroMap {
    doc.get_map(ROW_BIRTHS_MAP)
}

fn encode(birth: &RowBirth) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(birth)
        .map_err(|_| Error::InvalidConfig("a row birth does not encode".into()))
}

/// The carried envelope, when `bytes` is its canonical encoding.
fn decode(bytes: &[u8]) -> Option<RowBirth> {
    let birth: RowBirth = rmp_serde::from_slice(bytes).ok()?;
    (encode(&birth).ok()? == bytes).then_some(birth)
}

/// The owner a birth key names, when the key is its canonical hex.
fn owner(key: &str) -> Option<EntityId> {
    EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key)
}

/// Mirrors `id`'s stored birth into `doc`. An equal carrier stays; a
/// different one is replaced, because the local row is the authority for its
/// own birth. Returns whether the map changed.
pub(in crate::sync) fn mirror_local_birth(
    vault: &Vault,
    doc: &LoroDoc,
    id: &EntityId,
) -> Result<bool> {
    let Some(birth) = vault.row_birth(id)? else {
        return Ok(false);
    };
    let bytes = encode(&birth)?;
    let map = births(doc);
    let key = id.to_hex();
    if map_get_bytes(&map, &key).as_deref() == Some(bytes.as_slice()) {
        return Ok(false);
    }
    map_insert_bytes(&map, &key, &bytes)?;
    Ok(true)
}

/// Copies the births `src` carries for `owners` into `dst`. Selector, guest
/// and federation rebuilds call it with the owners they finally kept, never
/// with candidates, so a birth can never bring a denied row into scope.
pub(crate) fn copy_births(src: &LoroDoc, dst: &LoroDoc, owners: &[EntityId]) -> Result<()> {
    let from = births(src);
    let to = births(dst);
    for id in owners {
        let key = id.to_hex();
        if let Some(bytes) = map_get_bytes(&from, &key) {
            map_insert_bytes(&to, &key, &bytes)?;
        }
    }
    Ok(())
}

/// Where a window copy's rows go, as their births see it.
#[derive(Clone, Copy)]
pub(crate) enum BirthReach<'a> {
    /// Among the owner's own machines: births go whole.
    OwnMachines,
    /// To or from another vault: births go rewritten, masked under the key
    /// that destination reads ([`WithheldKey::for_destination`]).
    OtherVault(&'a WithheldKey),
}

/// Copies the births `src` carries for every entity `dst` holds, as far as
/// `reach` lets them go. Every crossing to or from another vault comes
/// through here (OF-491, owner Q26 = B): its births travel rewritten
/// ([`RowBirth::masked`]). Each input, prompt or trigger ref whose row `dst`
/// does not carry becomes a masked handle ("1 source withheld") under the
/// destination's key, so a ref reads as the same handle on every copy to it
/// and never reverses; the process that made the row, its time and its input
/// hash stay.
pub(crate) fn copy_births_within(
    src: &LoroDoc,
    dst: &LoroDoc,
    reach: BirthReach<'_>,
) -> Result<()> {
    match reach {
        BirthReach::OwnMachines => copy_births_for_entities(src, dst),
        BirthReach::OtherVault(key) => copy_masked_births(src, dst, key),
    }
}

/// Copies, rewritten, the births `src` carries for every entity `dst` holds:
/// a ref ships only when `dst` carries its row. A carrier that does not
/// decode stays behind.
fn copy_masked_births(src: &LoroDoc, dst: &LoroDoc, key: &WithheldKey) -> Result<()> {
    let carried: std::collections::BTreeSet<EntityId> = dst
        .get_map("entities")
        .keys()
        .filter_map(|key| owner(&key))
        .collect();
    let from = births(src);
    let to = births(dst);
    for id in &carried {
        let hex = id.to_hex();
        let Some(birth) = map_get_bytes(&from, &hex).and_then(|bytes| decode(&bytes)) else {
            continue;
        };
        let masked = birth.masked(|row| carried.contains(row), key);
        map_insert_bytes(&to, &hex, &encode(&masked)?)?;
    }
    Ok(())
}

/// Copies the births `src` carries for every entity `dst` holds.
fn copy_births_for_entities(src: &LoroDoc, dst: &LoroDoc) -> Result<()> {
    let owners: Vec<EntityId> = dst
        .get_map("entities")
        .keys()
        .filter_map(|key| owner(&key))
        .collect();
    copy_births(src, dst, &owners)
}

/// Removes `id`'s birth carrier from `doc`. Returns whether one was there.
pub(in crate::sync) fn remove_birth_carrier(doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let map = births(doc);
    let key = id.to_hex();
    if map.get(&key).is_none() {
        return Ok(false);
    }
    map_delete(&map, &key)?;
    Ok(true)
}

/// Removes every birth carrier whose owner `doc` no longer carries as an
/// entity. Egress scrubs call it after they drop owners.
pub(in crate::sync) fn drop_orphan_births(doc: &LoroDoc) -> Result<bool> {
    let entities = doc.get_map("entities");
    let map = births(doc);
    let orphans: Vec<String> = map
        .keys()
        .map(|key| key.to_string())
        .filter(|key| {
            !matches!(
                entities.get(key),
                Some(ValueOrContainer::Value(LoroValue::Binary(_)))
            )
        })
        .collect();
    for key in &orphans {
        map_delete(&map, key)?;
    }
    Ok(!orphans.is_empty())
}

/// Window admission for one inserted birth: the key is a canonical id, the
/// value is a canonical envelope, and the admitted document carries its
/// owner entity. A birth for a row the sender did not ship is refused before
/// import.
pub(crate) fn validate_carried_birth(
    candidate: &LoroDoc,
    key: &str,
    value: &LoroValue,
) -> Result<()> {
    let well_formed = owner(key).is_some()
        && matches!(value, LoroValue::Binary(bytes) if decode(bytes).is_some())
        && matches!(
            candidate.get_map("entities").get(key),
            Some(ValueOrContainer::Value(LoroValue::Binary(_)))
        );
    if !well_formed {
        return Err(Error::InvalidConfig(
            "a carried row birth is malformed or names a row the window does not carry".into(),
        ));
    }
    Ok(())
}

/// Stamps the birth `doc` carries for `id` in `wtxn`, beside the row the same
/// transaction admitted. A row with no carried birth stays unknown. A
/// malformed or conflicting remote birth is left out with a warning: the row
/// itself stands, and its stored birth is never replaced.
pub(in crate::sync) fn stamp_carried_birth_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
    id: &EntityId,
) -> Result<()> {
    let Some(bytes) = map_get_bytes(&births(doc), &id.to_hex()) else {
        return Ok(());
    };
    let Some(birth) = decode(&bytes) else {
        tracing::warn!(entity = %id.to_hex(), "row birth carrier does not decode; left out");
        return Ok(());
    };
    stamp_birth_or_warn(vault, wtxn, id, &birth)
}

pub(in crate::sync) fn stamp_birth_or_warn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    match stamp_replicated_row_birth_in_txn(&vault.store, wtxn, id, birth) {
        Ok(()) => Ok(()),
        Err(err @ (Error::InvalidConfig(_) | Error::InvariantViolation(_))) => {
            tracing::warn!(entity = %id.to_hex(), error = %err, "carried row birth refused");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Observer B for the birth map: a birth that lands after its row (a later
/// import, or a promotion snapshot) is stamped once the row is live. A birth
/// whose row has not landed waits: the entity pass stamps it on arrival.
pub(crate) fn materialize_births_from_delta(
    _doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut carried = Vec::new();
    for (key, value) in &delta.updated {
        let Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) = value else {
            continue;
        };
        match (owner(key), decode(bytes)) {
            (Some(id), Some(birth)) => carried.push((id, birth)),
            _ => {
                tracing::warn!(window = window_key, key = %key, "row birth carrier malformed; left out")
            }
        }
    }
    if carried.is_empty() {
        return Some(Vec::new());
    }
    let result = vault.with_write_txn_grouped(|wtxn| {
        for (id, birth) in &carried {
            if crate::vault::live_entity_row_in_txn(&vault.store, wtxn, id)?.is_live() {
                stamp_birth_or_warn(vault, wtxn, id, birth)?;
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => Some(Vec::new()),
        Err(err) => {
            tracing::warn!(window = window_key, error = %err, "row birth materialization failed");
            None
        }
    }
}
