//! The voice reference bank in checkpoint images (FIX 8972, KEY STORE = A):
//! every row of its seven tables (a pack, an identity, its incarnation, a
//! target pointer, the current render decision, a recorded render event and
//! an owner index entry) is a row-held response of its own (KS-2B1), sealed
//! whole under a body instance that its owner's erase retires in every older
//! image, as that erase deletes the row live ([`super::delete_owner_refs`]).
//!
//! An image holds nothing in the row's place: a live instance lands the
//! exact row, and a retired one's row goes. No marker, no voice row made up
//! and no bank policy changes. A row that does not decode is carried whole
//! the same way, opaque.
//!
//! Its owner is the bank's subject: a real voice's person or a designed
//! voice's creator (FIX 4393), as the bank's own rows prove it: the typed
//! owner of a pack or an identity, the subject of a render decision, the
//! owner an index entry is keyed by, the identity's owner for its
//! incarnation and target pointers, and the reverse owner index for a row
//! that does not decode. Never the decision's recorder, never a payer. An
//! owner no row proves is reported, never guessed.

use super::{
    IDENTITIES, INCARNATIONS, OWNER_INDEX, PACKS, RENDER_CONSENT, RENDER_EVENTS, TARGETS, TargetKey,
};
use crate::side_table::{SideKey, SideTableDecl};
use crate::store::{ResponseCarriage, ResponseOwners, ResponseScan, Store};
use crate::{EntityId, Result};

/// The bank's seven tables, by declaration.
fn tables() -> [&'static SideTableDecl; 7] {
    [
        PACKS.decl(),
        IDENTITIES.decl(),
        INCARNATIONS.decl(),
        TARGETS.decl(),
        RENDER_CONSENT.decl(),
        RENDER_EVENTS.decl(),
        OWNER_INDEX.decl(),
    ]
}

/// Whether the full `vault_meta` key `key` is a row of the bank.
pub(crate) fn voice_bank_row(key: &[u8]) -> bool {
    tables().iter().any(|decl| key.starts_with(decl.prefix))
}

/// The owner the bank row `key` holding `value` names in its own bytes or
/// key, once it decodes: `Some(None)` for a row that decodes and names its
/// owner only through its voice's identity, `None` for one that does not
/// decode.
fn decoded_owner(key: &[u8], value: &[u8]) -> Option<Option<EntityId>> {
    if let Some(rest) = key.strip_prefix(OWNER_INDEX.decl().prefix) {
        OWNER_INDEX.decode_value(value).ok()?;
        return <(EntityId, Vec<u8>) as SideKey>::decode_key(rest).map(|(owner, _)| Some(owner));
    }
    if key.starts_with(PACKS.decl().prefix) {
        return PACKS.decode_value(value).ok().map(|pack| Some(pack.owner));
    }
    if key.starts_with(IDENTITIES.decl().prefix) {
        return IDENTITIES
            .decode_value(value)
            .ok()
            .map(|identity| Some(identity.owner));
    }
    if key.starts_with(RENDER_CONSENT.decl().prefix) {
        return RENDER_CONSENT
            .decode_value(value)
            .ok()
            .map(|consent| Some(consent.decision.subject));
    }
    if key.starts_with(RENDER_EVENTS.decl().prefix) {
        return RENDER_EVENTS
            .decode_value(value)
            .ok()
            .map(|receipt| Some(receipt.consent.decision.subject));
    }
    if key.starts_with(INCARNATIONS.decl().prefix) {
        return INCARNATIONS.decode_value(value).ok().map(|_| None);
    }
    TARGETS.decode_value(value).ok().map(|_| None)
}

/// The voice id the bank row `key` belongs to, by its key alone: an
/// incarnation's and a target pointer's, the rows whose owner is their
/// identity's.
fn voice_of(key: &[u8]) -> Option<String> {
    if let Some(rest) = key.strip_prefix(INCARNATIONS.decl().prefix) {
        return String::decode_key(rest);
    }
    key.strip_prefix(TARGETS.decl().prefix)
        .and_then(TargetKey::decode_key)
        .map(|target| target.voice_id)
}

/// What a checkpoint carries of the bank row `key` holding `value`: the
/// whole row, nothing in its place, nothing kept once retired; opaque for a
/// row that does not decode.
pub(crate) fn voice_bank_scan(key: &[u8], value: &[u8]) -> ResponseScan {
    let whole = ResponseCarriage::whole(Vec::new());
    if decoded_owner(key, value).is_some() {
        ResponseScan::Decoded(whole)
    } else {
        ResponseScan::Opaque(whole)
    }
}

/// Who owns the bank row `key` holding `value`, as far as the bank proves
/// it: its typed owner or subject, its index key's owner, its identity's
/// owner, or, for a row that names none it reads, every owner the reverse
/// owner index files it under.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn voice_bank_owners(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<ResponseOwners> {
    if let Some(Some(owner)) = decoded_owner(key, value) {
        return Ok(ResponseOwners::Known(vec![owner]));
    }
    if let Some(voice) = voice_of(key)
        && let Some(identity) = IDENTITIES.get_lenient(store, txn, &voice)?
    {
        return Ok(ResponseOwners::Known(vec![identity.owner]));
    }
    let mut owners = Vec::new();
    for row in OWNER_INDEX.iter_raw_from(store, txn, &[])? {
        let (index, _) = row?;
        if let Some((owner, indexed)) = <(EntityId, Vec<u8>) as SideKey>::decode_key(&index)
            && indexed == key
        {
            owners.push(owner);
        }
    }
    owners.sort_unstable();
    owners.dedup();
    Ok(if owners.is_empty() {
        ResponseOwners::Unknown
    } else {
        ResponseOwners::Known(owners)
    })
}
