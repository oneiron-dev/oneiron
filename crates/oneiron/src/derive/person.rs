//! The person item (untangle 6.9h, S69-C-KINDS = A): an agent names a PERSON
//! it found in TURNs it reads, and the engine mints it as the Dreamer's
//! extraction does (`dreamer_consolidation::extracted_people`), with the
//! agent's live derive verdict in place of an author check.
//!
//! The caller supplies a name and the TURNs; the engine decides the rest. A
//! wire caller could otherwise copy a name it read only in a private MESSAGE
//! into a row every reader reads, pick a PERSON it cannot see by guessing
//! its id, or test a guess against a key it is served as a handle (the
//! lesson of the `about` item taken off the wire). So:
//! - the id is derived from the attempt's retry lineage, the normalized name
//!   and the first TURN that names it; an id that stands, that a provisional
//!   entity holds, that was deleted or that was minted before is refused;
//! - the name must be a bounded span, by the extraction writer's own rules,
//!   in the words of a live TURN the actor reads at the version the batch
//!   pins, spoken by a speaker extraction mints people from, each lifted key
//!   in those words read as its handle;
//! - the PERSON is born under the audience of the rows whose words name it
//!   and under the facet of the first naming TURN, as a provisional entity's
//!   confirmation is (OPUS-LEAKS, FIX 10168); an actor whose standing grant
//!   has a scope is judged over the PERSON as born, so its grant reaches
//!   where the row stands.
//!
//! The row is the extraction mint's: `Generated`, and while it stays empty
//! the cleanup's to archive. A batch revert archives it by that same rule.

use std::collections::BTreeSet;

use super::batch::DerivedPerson;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::claim::{ClaimSource, ScopedRead};
use crate::dreamer_consolidation::{
    TurnText, has_name_span, normalize_name_span, origin_in_txn, speaker_admissible_in_txn,
};
use crate::entity_id::derived_domains::DERIVE_PERSON;
use crate::error::{Error, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::snapshot_read::source_version_in_txn;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The refusal of a person whose commit names no attempt to derive its id
/// from.
pub const PERSON_NEEDS_ATTEMPT: &str = "gate.deny.derive.person_needs_attempt";

/// The refusal of a person whose evidence holds a row that is no live TURN
/// the actor reads, or a TURN whose speaker extraction mints no one from.
pub const PERSON_SOURCE_INADMISSIBLE: &str = "gate.deny.derive.person_source_inadmissible";

/// The refusal of a person whose name holds no letter, or is no bounded span
/// in the words any of its TURNs serves.
pub const PERSON_NAME_UNREAD: &str = "gate.deny.derive.person_name_unread";

/// The refusal of a person whose derived id stands, is held by a provisional
/// entity, was deleted, or was minted before.
pub const PERSON_ID_TAKEN: &str = "gate.deny.derive.person_id_taken";

/// The allowance token of a landed person.
const PERSON_ALLOWED: &str = "gate.allow.derive.person";

/// Stages one person item of the batch in `context`: the name and the TURNs,
/// then the derive verdict, then the mint, its source audience and its birth
/// facet through a savepoint of `txn`.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedPerson,
) -> Result<ItemOutcome> {
    let actor = context.stamp.actor;
    let Some(attempt) = context.stamp.attempt else {
        return refuse(vault, txn, context, None, PERSON_NEEDS_ATTEMPT);
    };
    let name = item.name.trim();
    let normalized = normalize_name_span(name);
    if !normalized.chars().any(char::is_alphabetic) {
        return refuse(vault, txn, context, None, PERSON_NAME_UNREAD);
    }
    let mut turns = BTreeSet::new();
    for named in &item.evidence {
        turns.insert(context.resolve(named)?);
    }
    if turns.is_empty() {
        return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE);
    }
    let read = super::actor_read(vault, actor)?;
    let mut naming_turns = Vec::new();
    let mut naming_rows = BTreeSet::new();
    for turn in &turns {
        let live_turn = matches!(
            live_entity_row_in_txn(&vault.store, txn, turn)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                ..
            }
        );
        let text = match source_version_in_txn(&read, txn, turn)? {
            Some((_, Some(text))) if live_turn => text,
            _ => return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE),
        };
        if !speaker_admissible_in_txn(vault, txn, turn)? {
            return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE);
        }
        let served = masked_words_in_txn(vault, &read, txn, turn, text)?;
        let mut names = false;
        for (row, words) in served.pieces()? {
            if has_name_span(words, &normalized) {
                naming_rows.insert(row.unwrap_or(*turn));
                names = true;
            }
        }
        if names {
            naming_turns.push(*turn);
        }
    }
    let Some(&anchor) = naming_turns.first() else {
        return refuse(vault, txn, context, None, PERSON_NAME_UNREAD);
    };
    let mut allowance =
        match derive_verdict_in_txn(&vault.store, txn, actor, DeriveCapability::Derive, None)? {
            Ok(allowance) => allowance,
            Err(refusal) => return refuse(vault, txn, context, None, refusal.token()),
        };
    let origin = origin_in_txn(vault, txn, attempt)?;
    let id = EntityId::derive(
        DERIVE_PERSON,
        &[origin.as_bytes(), normalized.as_bytes(), anchor.as_bytes()],
    )?;
    let body = person_body(
        name,
        crate::tagging::naming_rows_audience_in_txn(vault, txn, &naming_rows)?,
    )?;
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    // A provisional entity's id is held for its confirmation: the mint's own
    // put would refuse it as an error, so it is refused here as an item.
    if crate::tagging::provisional_in_txn(&vault.store, &savepoint, &id)?.is_some() {
        drop(savepoint);
        return refuse(vault, txn, context, Some(id), PERSON_ID_TAKEN);
    }
    let at = TimeRange {
        start: context.now,
        end: context.now,
    };
    if !vault.put_extraction_minted_person_in_txn(
        &mut savepoint,
        &id,
        ClaimSource::Generated,
        at,
        context.now,
        &body,
    )? {
        drop(savepoint);
        return refuse(vault, txn, context, Some(id), PERSON_ID_TAKEN);
    }
    // Born under the facet of the TURN its name was read in, never the
    // generic put's own substrate facet.
    if let Some(facet) =
        crate::federation::record_scope::birth_facet(&vault.store, &savepoint, anchor)?
    {
        crate::federation::record_scope::settle_source_birth(
            &vault.store,
            &mut savepoint,
            id,
            ENTITY_TYPE_PERSON,
            facet,
        )?;
    }
    // An actor whose standing grant has a scope is judged again over the
    // PERSON as born, so its grant reaches where the row now stands.
    if crate::federation::steward_reach_in(&vault.store, &savepoint, actor.entity_ref())?.is_some()
    {
        match derive_verdict_in_txn(
            &vault.store,
            &savepoint,
            actor,
            DeriveCapability::Derive,
            Some(id),
        )? {
            Ok(judged) => allowance = judged,
            Err(refusal) => {
                drop(savepoint);
                return refuse(vault, txn, context, None, refusal.token());
            }
        }
    }
    savepoint.commit()?;
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(id),
        &[PERSON_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![id],
        approval: None,
        receipt: Some(receipt),
    })
}

/// `text`, the words of TURN `turn` as `read` serves them, with each lifted
/// key its own body or a MESSAGE row its words come from holds read as its
/// handle, whoever reads it: a name is never read inside a key.
///
/// # Errors
///
/// Storage errors, and a layout that does not cut the text.
fn masked_words_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    text: TurnText,
) -> Result<TurnText> {
    let mut rows = vec![*turn];
    rows.extend(text.message_ids());
    let bodies: Vec<Vec<u8>> = read
        .get_entities_parts_in_txn(txn, &rows)?
        .into_iter()
        .flatten()
        .map(|(_, _, body)| body)
        .collect();
    let keys = crate::memory::lifted_keys_of_bodies_in_txn(&vault.store, txn, &bodies)?;
    let masked = text.masked_by(|words| keys.masked(words))?;
    Ok(masked.unwrap_or(text))
}

/// The minted PERSON's body: its name and, unless an open row names it, the
/// source audience its naming rows give it.
fn person_body(name: &str, audience: Option<rmpv::Value>) -> Result<Vec<u8>> {
    let mut fields = vec![(rmpv::Value::from("name"), rmpv::Value::from(name))];
    if let Some(audience) = audience {
        fields.push((
            rmpv::Value::from(crate::claim::IDENTITY_SOURCE_AUDIENCE_KEY),
            audience,
        ));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields))
        .map_err(|_| Error::InvariantViolation("derived person body"))?;
    Ok(body)
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, about, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
