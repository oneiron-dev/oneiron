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
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::encode_claim_body;
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
