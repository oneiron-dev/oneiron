//! The urgent digest's stated-intent read: the Approved, Active, non-stale
//! UserStated `profile.intent` about one owner, untimed or with the owner's
//! own declared time, at the exact bytes it is stored at.
//!
//! An intent's value is one of two intentional shapes, both read from the
//! same stored CLAIM: its plain-text words, or exactly `text` plus a
//! `needed_before` Unix-seconds time. Any other map is not an intent, and is
//! never read as prose. The time is factual evidence the harm question
//! reads, never a gate or an expiry.

use rmpv::Value;

use super::{DigestNeededBefore, DigestVersionRef};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};

/// The stored claim an urgent digest answers to.
const INTENT_PREDICATE: &str = "profile.intent";

/// The words and the declared time an intent value states: its plain text
/// with no time, or exactly `text` plus a `needed_before` Unix-seconds time.
/// `None` for any other shape, which is not an intent.
pub(super) fn stated_intent_text_and_due(value: &Value) -> Option<(&str, Option<u64>)> {
    if let Some(text) = value.as_str() {
        return Some((text, None));
    }
    let entries = value.as_map()?;
    if entries.len() != 2 {
        return None;
    }
    let mut text = None;
    let mut due = None;
    for (key, val) in entries {
        match key.as_str() {
            Some("text") => {
                if text.is_some() {
                    return None;
                }
                text = Some(val.as_str()?);
            }
            Some("needed_before") => {
                if due.is_some() {
                    return None;
                }
                due = Some(val.as_u64()?);
            }
            _ => return None,
        }
    }
    Some((text?, Some(due?)))
}

/// The person a claim is the live stated intent of: an Approved, Active,
/// non-stale UserStated `profile.intent` with words, about one entity.
pub(super) fn stated_intent_of(body: &crate::ClaimBody) -> Option<EntityId> {
    let crate::ClaimSubject::Entity(person) = &body.subject else {
        return None;
    };
    (body.predicate == INTENT_PREDICATE
        && body.source == Some(ClaimSource::UserStated)
        && stated_intent_text_and_due(&body.value).is_some_and(|(text, _)| !text.trim().is_empty())
        && body.approval == ClaimApprovalStatus::Approved
        && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale)
        .then_some(*person)
}

/// [`stated_intent_of`] the stored claim `id`, as the vault reads it.
pub(super) fn stated_intent_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    Ok(vault
        .get_claim_in_txn(txn, &id)?
        .as_ref()
        .and_then(stated_intent_of))
}

/// Each live stated intent about `owner`, at the bytes it is stored at, with
/// the time it states when it states one: the same claim's words and hash
/// carry the evidence, so a timed intent's source is itself.
pub(super) fn stated_intents_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<Vec<(DigestVersionRef, Option<DigestNeededBefore>)>> {
    let mut intents = Vec::new();
    for id in crate::ports::ClaimStore::port_claim_list(vault, txn, &owner)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if stated_intent_of(&body) != Some(owner) {
            continue;
        }
        if let Some(body_hash) = body_hash_in(vault, txn, id)? {
            let needed_before = stated_intent_text_and_due(&body.value)
                .and_then(|(_, due)| due)
                .map(|at_unix_secs| DigestNeededBefore {
                    at_unix_secs,
                    source_ref: id,
                    source_body_hash: body_hash,
                });
            intents.push((
                DigestVersionRef {
                    claim_ref: id,
                    body_hash,
                },
                needed_before,
            ));
        }
    }
    Ok(intents)
}

/// BLAKE3 of the stored claim `id`'s body bytes, as a digest revision is
/// taken; `None` for no stored claim.
pub(super) fn body_hash_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<[u8; 32]>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let claim = EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM);
    Ok((claim && raw.len() > ENTITY_METADATA_HEADER_LEN)
        .then(|| *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes()))
}
