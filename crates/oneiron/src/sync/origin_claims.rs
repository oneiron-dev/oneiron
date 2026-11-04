//! Origin claim carriers under an erase (FIX 3877).
//!
//! A window carries origin's claims like any CLAIM. A copy that names an
//! actor this vault erased, or that differs from the held copy only in who it
//! names, settles by one rule (`origin::actor_erase::settle_in_txn`): the
//! erased form wins, and two live actors still conflict. Ingest takes the
//! carried copy in that form and rewrites the held one in place when the copy
//! erases more of it, so a late copy never brings an erased actor back. The
//! reverse mirror pins the window history-free before it replaces a carrier
//! with its erased form, and every export and the erase sweep rewrite a
//! carrier that still names an erased actor, pinned first. No producer proof
//! is minted for a copy that lacks one.

use std::borrow::Cow;

use loro::{CommitOptions, LoroDoc, LoroMap};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_for_each_bytes, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, encode_claim_body};
use crate::context_board::PREDICATE_SKILL_SECTION_FIT;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::actor_erase::{
    erases_more, held_claim_in_txn, origin_claim_row, redact_origin_claim_in_txn, settle_in_txn,
};

/// What ingest does with one carried entity row.
pub(in crate::sync) enum CarriedClaim<'a> {
    /// Admit these body bytes, as any row.
    Put(Cow<'a, [u8]>),
    /// The held copy already stands for it.
    Held,
    /// The held copy took its erased form, which stands for it.
    Redacted,
}

/// The carried row `blob` at `id`, whose body is `data`, as this vault
/// admits it.
///
/// # Errors
///
/// Storage errors, or a held claim that cannot be rewritten.
pub(in crate::sync) fn carried_claim_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    data: &'a [u8],
) -> Result<CarriedClaim<'a>> {
    let Some((kind, carried)) = origin_claim_row(blob) else {
        return Ok(CarriedClaim::Put(Cow::Borrowed(data)));
    };
    let held = held_claim_in_txn(vault, wtxn, kind, id)?;
    let settled = settle_in_txn(vault, wtxn, kind, id, held.as_ref(), &carried)?;
    if settled.held.is_none() && settled.carried.is_none() {
        return Ok(CarriedClaim::Put(Cow::Borrowed(data)));
    }
    if let Some(redacted) = &settled.held {
        redact_origin_claim_in_txn(vault, wtxn, kind, id, redacted)?;
    }
    let now = settled.carried.as_ref().unwrap_or(&carried);
    Ok(match settled.held.as_ref().or(held.as_ref()) {
        Some(stands) if stands == now && settled.held.is_some() => CarriedClaim::Redacted,
        Some(stands) if stands == now => CarriedClaim::Held,
        _ => CarriedClaim::Put(Cow::Owned(encode_claim_body(now)?)),
    })
}

/// What ingest does with a carried `skill.section_fit` receipt (FIX 12713):
/// its actor leaf reads `""` where this vault erased whom it names, so a
/// replay never brings an erased actor back. The held copy takes that form
/// in place when the carried one erases more of it, as an origin claim does
/// ([`carried_claim_in_txn`]); a receipt that names a live actor here, names
/// no one, or no receipt at all admits unchanged. An existing empty leaf wins
/// in either direction for actor-only variants, even where this vault holds
/// no marker. Never an authority or replay check.
pub(in crate::sync) fn carried_section_fit_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    data: Cow<'a, [u8]>,
) -> Result<CarriedClaim<'a>> {
    let Some(body) = section_fit_body(blob, &data) else {
        return Ok(CarriedClaim::Put(data));
    };
    // The held copy is read before either passthrough below, so an existing
    // empty leaf wins in either direction for actor-only variants: a carried
    // `""` scrubs a held live actor in place, and a held `""` stands against
    // a carried live actor even where this vault holds no marker.
    let held_row = vault.get_raw_in(wtxn, id)?;
    if let Some(raw) = held_row.as_ref()
        && let Some(held) = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|held| section_fit_body(raw, held))
    {
        let mut held_scrubbed = held.clone();
        let mut carried_scrubbed = body.clone();
        if set_receipt_actor(&mut held_scrubbed)
            && set_receipt_actor(&mut carried_scrubbed)
            && held_scrubbed == carried_scrubbed
        {
            let held_empty = receipt_actor(&held).is_some_and(|leaf| leaf.is_empty());
            let carried_empty = receipt_actor(&body).is_some_and(|leaf| leaf.is_empty());
            match (held_empty, carried_empty) {
                (false, true) => {
                    let encoded = encode_claim_body(&carried_scrubbed)?;
                    scrub_held_section_fit_in_txn(vault, wtxn, id, raw, &encoded)?;
                    return Ok(CarriedClaim::Redacted);
                }
                (true, _) => return Ok(CarriedClaim::Held),
                (false, false) => {}
            }
        }
    }
    let Some(actor) = receipt_actor(&body).and_then(|leaf| EntityId::from_hex(leaf).ok()) else {
        return Ok(CarriedClaim::Put(data));
    };
    if !vault.carrier_actor_erased_in_txn(wtxn, &actor)? {
        return Ok(CarriedClaim::Put(data));
    }
    let mut normalized = body.clone();
    if !set_receipt_actor(&mut normalized) {
        return Ok(CarriedClaim::Put(data));
    }
    let encoded = encode_claim_body(&normalized)?;
    let Some(raw) = vault.get_raw_in(wtxn, id)? else {
        return Ok(CarriedClaim::Put(Cow::Owned(encoded)));
    };
    let Some(held) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|held| section_fit_body(&raw, held))
    else {
        return Ok(CarriedClaim::Put(Cow::Owned(encoded)));
    };
    if held == normalized {
        return Ok(CarriedClaim::Held);
    }
    let mut scrubbed = held.clone();
    if !set_receipt_actor(&mut scrubbed) || scrubbed != normalized {
        // Beyond the actor leaf the carried copy is simply newer: it lands
        // scrubbed, but the held one is not its erased form.
        return Ok(CarriedClaim::Put(Cow::Owned(encoded)));
    }
    scrub_held_section_fit_in_txn(vault, wtxn, id, &raw, &encoded)?;
    Ok(CarriedClaim::Redacted)
}

/// The `skill.section_fit` receipt the `row` carries with the `data` body,
/// if any.
pub(in crate::sync) fn section_fit_body(row: &[u8], data: &[u8]) -> Option<ClaimBody> {
    let header = EntityMetadataHeader::parse(row)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let body = crate::claim::decode_claim_body(data, true).ok()?;
    (body.predicate == PREDICATE_SKILL_SECTION_FIT).then_some(body)
}

/// The receipt's actor leaf, if it names one.
pub(in crate::sync) fn receipt_actor(body: &ClaimBody) -> Option<&str> {
    let rmpv::Value::Map(entries) = &body.value else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("actor"))
        .and_then(|(_, value)| value.as_str())
}

/// Scrubs the receipt's actor leaf to `""`, as the erase's own scrub does
/// (FIX 11060). Whether anything changed.
fn set_receipt_actor(body: &mut ClaimBody) -> bool {
    let rmpv::Value::Map(entries) = &mut body.value else {
        return false;
    };
    let mut scrubbed = false;
    for (key, value) in entries.iter_mut() {
        if key.as_str() == Some("actor") {
            *value = rmpv::Value::from("");
            scrubbed = true;
        }
    }
    scrubbed
}

/// Rewrites the stored section-fit receipt `id` with the scrubbed `encoded`
/// body in place, its header times unchanged: the erase's own scrub (FIX
/// 11060) for a copy a replay carries, so no retained revision keeps the old
/// actor leaf.
///
/// # Errors
///
/// Storage errors, or a body the claim door refuses.
fn scrub_held_section_fit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    encoded: &[u8],
) -> Result<()> {
    let header = EntityMetadataHeader::parse(raw).ok_or(crate::error::Error::CorruptedIndex(
        "section-fit receipt header",
    ))?;
    crate::claim::validate_claim_body_and_decode_in_txn(&vault.store, wtxn, encoded, true)?;
    let next = crate::ports::EntityRecord {
        entity_type: header.entity_type,
        occurred: crate::temporal::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        learned_at: header.learned_at,
        body: encoded.to_vec(),
    };
    let staged = next.encode();
    crate::ports::EntityStoreStaging::port_stage_entity_row(&vault.store, wtxn, id, &staged)?;
    crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, id)?;
    let raw = vault
        .get_raw_in(wtxn, id)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    crate::vault::entity_revision::capture_entity_revision(&vault.store, wtxn, id, &raw)?;
    Ok(())
}

/// Pins `key` history-free before the reverse mirror replaces the carrier
/// under `map_key` with `raw`, when `raw` is that carrier's claim with more
/// of whom it names erased: the replaced operation still names them.
///
/// # Errors
///
/// The pin's write.
pub(in crate::sync) fn pin_erased_replacement(
    vault: &Vault,
    key: &WindowKey,
    entities: &LoroMap,
    map_key: &str,
    raw: &[u8],
) -> Result<()> {
    let Some((kind, local)) = origin_claim_row(raw) else {
        return Ok(());
    };
    let carried = map_get_bytes(entities, map_key).and_then(|blob| origin_claim_row(&blob));
    if let (Some((carried_kind, carried)), Ok(id)) = (carried, EntityId::from_hex(map_key))
        && carried_kind == kind
        && erases_more(kind, &id, &carried, &local)
    {
        super::window::require_history_free_window(vault, key)?;
    }
    Ok(())
}

/// Rewrites, under the same key, each carrier in `doc` that names an actor
/// this vault erased or whose held copy is its erased form: every export,
/// and the erase sweep. The window `history_free` names is pinned
/// history-free first. Whether anything changed.
///
/// # Errors
///
/// Storage errors, or a rewrite that cannot be written.
pub(crate) fn scrub_origin_claims(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut carried = Vec::new();
    map_for_each_bytes(&entities, |map_key, blob| {
        if let Ok(id) = EntityId::from_hex(map_key)
            && let Some((kind, body)) = origin_claim_row(blob)
        {
            let header = blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
            carried.push((map_key.to_owned(), id, header, kind, body));
        }
    });
    let mut rewrites = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, id, mut blob, kind, body) in carried {
            let held = held_claim_in_txn(vault, &rtxn, kind, &id)?;
            if let Some(erased) =
                settle_in_txn(vault, &rtxn, kind, &id, held.as_ref(), &body)?.carried
            {
                blob.extend_from_slice(&encode_claim_body(&erased)?);
                rewrites.push((map_key, blob));
            }
        }
    }
    if rewrites.is_empty() {
        return Ok(false);
    }
    // Pin BEFORE the rewrite: the operation it replaces still names them.
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for (map_key, blob) in &rewrites {
        map_insert_bytes(&entities, map_key, blob)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// Pins `key` history-free before the reverse mirror replaces the carrier
/// under `map_key` with `raw`, when `raw` is that carrier's
/// `skill.section_fit` receipt with more of whom it names erased (FIX
/// 12769): the replaced operation still names them. The pin lands only
/// when the carried receipt's actor leaf, scrubbed to `""`, is otherwise
/// identical to the local replacement. Never an authority or replay check.
///
/// # Errors
///
/// The pin's write.
pub(in crate::sync) fn pin_section_fit_replacement(
    vault: &Vault,
    key: &WindowKey,
    entities: &LoroMap,
    map_key: &str,
    raw: &[u8],
) -> Result<()> {
    let Some(local_data) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(());
    };
    let Some(local) = section_fit_body(raw, local_data) else {
        return Ok(());
    };
    let carried = map_get_bytes(entities, map_key).and_then(|blob| {
        let data = blob.get(ENTITY_METADATA_HEADER_LEN..)?;
        section_fit_body(&blob, data)
    });
    if let Some(carried) = carried {
        let mut normalized = carried.clone();
        if set_receipt_actor(&mut normalized) && normalized == local && normalized != carried {
            super::window::require_history_free_window(vault, key)?;
        }
    }
    Ok(())
}

/// Rewrites, under the same key, each `skill.section_fit` receipt carrier
/// in `doc` whose actor leaf names an actor this vault erased (FIX 12769):
/// every export, and the erase sweep. The window `history_free` names is
/// pinned history-free first. Whether anything changed. Never an authority
/// or replay check.
///
/// # Errors
///
/// Storage errors, or a rewrite that cannot be written.
pub(crate) fn scrub_section_fit_receipts(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut carried = Vec::new();
    map_for_each_bytes(&entities, |map_key, blob| {
        if let Some(data) = blob.get(ENTITY_METADATA_HEADER_LEN..)
            && let Some(body) = section_fit_body(blob, data)
        {
            let header = blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
            carried.push((map_key.to_owned(), header, body));
        }
    });
    let mut rewrites = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, mut blob, body) in carried {
            let Some(actor) = receipt_actor(&body).and_then(|leaf| EntityId::from_hex(leaf).ok())
            else {
                continue;
            };
            if !vault.carrier_actor_erased_in_txn(&rtxn, &actor)? {
                continue;
            }
            let mut normalized = body.clone();
            if !set_receipt_actor(&mut normalized) {
                continue;
            }
            blob.extend_from_slice(&encode_claim_body(&normalized)?);
            rewrites.push((map_key, blob));
        }
    }
    if rewrites.is_empty() {
        return Ok(false);
    }
    // Pin BEFORE the rewrite: the operation it replaces still names them.
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for (map_key, blob) in &rewrites {
        map_insert_bytes(&entities, map_key, blob)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
