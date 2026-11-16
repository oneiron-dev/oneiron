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
//!   entity holds, that was deleted or archived, or that was minted before is
//!   refused. Under an extraction binding's commit alone, an id that holds
//!   the live PERSON is answered: a retry, or a second listing page, learns
//!   the id its lineage's earlier commit returned, and the row is not written;
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
//! the cleanup's to archive. Its minting batch's revert archives it by that rule.
//!
//! Under a queued extraction attempt the stamp's actor must be the attempt's
//! Dreamer, each evidence TURN must be one the attempt's inputs page serves,
//! and the words read through the verdict's TURN read; any other stamp reads
//! each TURN through the actor's bare key, as before.

use std::collections::BTreeSet;

use super::batch::DerivedPerson;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use super::extraction_opening::{open_attempt, open_verdict_read};
use super::verified_landing::{attempt_dreamer_matches, refuse_or_abort};
use crate::claim::{ClaimSource, ScopedRead};
use crate::dreamer_consolidation::{
    TurnText, has_name_span, normalize_name_span, origin_in_txn, speaker_admissible_in_txn,
};
use crate::entity_id::derived_domains::DERIVE_PERSON;
use crate::error::{Error, Result};
use crate::gate::{DeriveAllowance, DeriveCapability, DeriveRefusal, derive_verdict_in_txn};
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
/// Under an extraction attempt, also the refusal of a TURN the attempt's
/// inputs page does not serve.
pub const PERSON_SOURCE_INADMISSIBLE: &str = "gate.deny.derive.person_source_inadmissible";

/// The refusal of a person item under an extraction attempt whose stamp's
/// actor is not the attempt's Dreamer.
pub const PERSON_NOT_ATTEMPT_DREAMER: &str = "gate.deny.derive.person_not_attempt_dreamer";

/// The refusal of a person whose name holds no letter, or is no bounded span
/// in the words any of its TURNs serves.
pub const PERSON_NAME_UNREAD: &str = "gate.deny.derive.person_name_unread";

/// The refusal of a person whose derived id stands, is held by a provisional
/// entity, was deleted or archived, or was minted before. Under an extraction
/// binding's commit an id that holds the live PERSON is answered instead
/// ([`PERSON_MINTED_BEFORE`]): a retry, or a second listing page, names the
/// same person, and the answer tells the attempt's Dreamer the id its
/// lineage's earlier commit returned.
pub const PERSON_ID_TAKEN: &str = "gate.deny.derive.person_id_taken";

/// The allowance of a person item under an extraction binding's commit whose
/// derived id already holds the live PERSON. The item wrote no row.
pub const PERSON_MINTED_BEFORE: &str = "gate.allow.derive.person_minted_before";

/// The allowance token of a landed person.
const PERSON_ALLOWED: &str = "gate.allow.derive.person";

/// One person item's outcome, and whether its row stood before the item: an
/// answered item wrote no row, so its batch's revert leaves the row.
pub(super) struct StagedPerson {
    pub(super) outcome: ItemOutcome,
    pub(super) row_stood_before: bool,
}

impl StagedPerson {
    fn written_or_refused(outcome: ItemOutcome) -> Self {
        Self {
            outcome,
            row_stood_before: false,
        }
    }
}

/// What the checks of [`stage_in_txn`] hand to the mint: the derived id, the
/// first naming TURN, the PERSON's body and the allowance in force.
struct PersonMint<'a> {
    id: EntityId,
    anchor: EntityId,
    body: &'a [u8],
    allowance: DeriveAllowance,
}

/// Stages one person item of the batch in `context`: the name and the TURNs,
/// then the derive verdict, then a mint with its source audience and birth
/// facet in a savepoint, or a binding's answer of an existing live PERSON.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedPerson,
) -> Result<StagedPerson> {
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
    // Under a queued extraction attempt the naming TURNs read as the
    // extraction reads them: the attempt's Dreamer, the TURNs its inputs
    // page serves, the words through the verdict's TURN read. Any other
    // stamp keeps the actor's bare read below.
    let extraction = match open_attempt(vault, txn, context.stamp)? {
        None => None,
        Some(attempt_id) => {
            if !attempt_dreamer_matches(vault, txn, attempt_id, actor)? {
                return refuse(vault, txn, context, None, PERSON_NOT_ATTEMPT_DREAMER);
            }
            match open_verdict_read(vault, txn, context.stamp) {
                Ok(Some(opening)) => Some((
                    EntityId::from_bytes_unchecked(*attempt_id.as_bytes()),
                    opening,
                )),
                Ok(None) => {
                    return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE);
                }
                Err(error) => {
                    return refuse_or_abort(vault, txn, context, error, PERSON_SOURCE_INADMISSIBLE)
                        .map(StagedPerson::written_or_refused);
                }
            }
        }
    };
    let bare;
    let read = if let Some((_, opening)) = extraction.as_ref() {
        opening.turn_read()
    } else {
        bare = super::actor_read(vault, actor)?;
        &bare
    };
    let mut naming_turns = Vec::new();
    let mut naming_rows = BTreeSet::new();
    for turn in &turns {
        if let Some((attempt_entity, opening)) = extraction.as_ref() {
            let serves = match crate::snapshot_read::attempt_serves_turn_in_txn(
                &opening.memory,
                txn,
                (&opening.read, opening.turn_read()),
                *attempt_entity,
                *turn,
            ) {
                Ok(serves) => serves,
                Err(error) => {
                    return refuse_or_abort(vault, txn, context, error, PERSON_SOURCE_INADMISSIBLE)
                        .map(StagedPerson::written_or_refused);
                }
            };
            if !serves {
                return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE);
            }
        }
        let live_turn = matches!(
            live_entity_row_in_txn(&vault.store, txn, turn)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                ..
            }
        );
        let text = match source_version_in_txn(read, txn, turn)? {
            Some((_, Some(text))) if live_turn => text,
            _ => return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE),
        };
        if !speaker_admissible_in_txn(vault, txn, turn)? {
            return refuse(vault, txn, context, None, PERSON_SOURCE_INADMISSIBLE);
        }
        let served = masked_words_in_txn(vault, read, txn, turn, text)?;
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
    let allowance =
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
    mint_or_answer_in_txn(
        vault,
        txn,
        context,
        PersonMint {
            id,
            anchor,
            body: &body,
            allowance,
        },
    )
}

/// Mints the PERSON through a savepoint of `txn`, or refuses a taken id.
/// Under an extraction binding's commit, an id that holds a live PERSON is
/// answered instead: the item lands naming that row and writes none.
fn mint_or_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    mint: PersonMint<'_>,
) -> Result<StagedPerson> {
    let PersonMint {
        id,
        anchor,
        body,
        allowance,
    } = mint;
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
        body,
    )? {
        drop(savepoint);
        // A live row is neither a deleted shell nor archived nor stale: each
        // of those ids stays taken, as every id does outside a binding.
        if !context.record_outputs
            || !matches!(
                live_entity_row_in_txn(&vault.store, txn, &id)?,
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_PERSON,
                    ..
                }
            )
        {
            return refuse(vault, txn, context, Some(id), PERSON_ID_TAKEN);
        }
        let allowance = match person_allowance_in_txn(vault, txn, context, id, allowance)? {
            Ok(allowance) => allowance,
            Err(refusal) => return refuse(vault, txn, context, None, refusal.token()),
        };
        return land_in_txn(vault, txn, context, id, allowance, true);
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
    let allowance = match person_allowance_in_txn(vault, &savepoint, context, id, allowance)? {
        Ok(allowance) => allowance,
        Err(refusal) => {
            drop(savepoint);
            return refuse(vault, txn, context, None, refusal.token());
        }
    };
    savepoint.commit()?;
    land_in_txn(vault, txn, context, id, allowance, false)
}

/// The allowance over the PERSON `id` as it stands in `txn`: an actor whose
/// standing grant has a scope is judged again there, so its grant reaches
/// where the row stands; any other actor keeps `allowance`.
fn person_allowance_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    context: &ItemContext<'_>,
    id: EntityId,
    allowance: DeriveAllowance,
) -> Result<std::result::Result<DeriveAllowance, DeriveRefusal>> {
    let actor = context.stamp.actor;
    if crate::federation::steward_reach_in(&vault.store, txn, actor.entity_ref())?.is_some() {
        derive_verdict_in_txn(&vault.store, txn, actor, DeriveCapability::Derive, Some(id))
    } else {
        Ok(Ok(allowance))
    }
}

/// The landed outcome naming `id`, with its allowance receipt: the mint's
/// token, or [`PERSON_MINTED_BEFORE`] for a row that stood before the item.
fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    id: EntityId,
    allowance: DeriveAllowance,
    row_stood_before: bool,
) -> Result<StagedPerson> {
    let token = if row_stood_before {
        PERSON_MINTED_BEFORE
    } else {
        PERSON_ALLOWED
    };
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(id),
        &[token.to_owned()],
        &allowance,
    )?;
    Ok(StagedPerson {
        outcome: ItemOutcome::Landed {
            rows: vec![id],
            approval: None,
            receipt: Some(receipt),
        },
        row_stood_before,
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
) -> Result<StagedPerson> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, about, &reasons)?;
    Ok(StagedPerson::written_or_refused(ItemOutcome::Refused {
        reasons,
        receipt,
    }))
}
