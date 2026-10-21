//! An erased dispatch target's instructions and briefing, out of the attempt
//! payloads that carry them (FIX 7076).
//!
//! An agent dispatch's payload (a Dreamer envelope whose input is an agent
//! dispatch input) snapshots its target's AGENT_DEF body, the definition's
//! instructions with it, and its context spec, the briefing with it. Both
//! are the target's: the AGENT_DEF the dispatch runs as
//! ([`agent_dispatch_actor`]), not its requester. A hard erase of that target
//! leaves both absent in every row that carries them, in every state and
//! retry generation, by one deterministic rewrite; every other input member,
//! the envelope's parent and every row field stay, so each strict reader
//! reads the erased row. Only the hard causes call in: a delete keeps the
//! text.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::agent_def::AGENT_DEF_BODY_KEYS;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_INPUT_KEYS, agent_dispatch_actor,
    decode_agent_dispatch_input, record_dispatch_input,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::encoding::{decode_record, encode_record};
use super::types::{AttemptId, AttemptRecord};

/// The input member that holds the AGENT_DEF snapshot.
const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];
/// The input member that holds the serialized context spec.
const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];
/// The AGENT_DEF body key of the definition's instructions.
const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];
/// The context spec's briefing member, as it serializes.
const KEY_BRIEFING: &str = "briefing";
const ERR_UNREWRITABLE: &str = "an agent dispatch payload's text could not be erased";

fn unrewritable() -> Error {
    Error::InvariantViolation(ERR_UNREWRITABLE)
}

/// Who owns `record`'s dispatch text: its target AGENT_DEF, the actor the
/// dispatch runs as. `None` for a row that is no agent dispatch, or whose
/// input does not decode: it names no owner.
fn dispatch_payload_actor(record: &AttemptRecord) -> Option<EntityId> {
    let input = record_dispatch_input(record)?;
    agent_dispatch_actor(&input)
        .ok()
        .map(WriteActor::entity_ref)
}

/// Leaves `record`'s dispatch instructions and briefing absent, keeping
/// every other input member, the envelope's parent and every row field.
/// `false` when the row is no agent dispatch or carries neither, so an
/// erased row is not written again. The same payload always comes out the
/// same, so each retry generation of one payload is rewritten alike.
/// `record` changes only on success.
fn erase_dispatch_payload_text(record: &mut AttemptRecord) -> Result<bool> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    let mut payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(false);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    let instructions = input.definition.instructions.is_some();
    let briefing = input
        .context_spec
        .as_ref()
        .is_some_and(|spec| spec.briefing.is_some());
    if !instructions && !briefing {
        return Ok(false);
    }
    let Value::Map(entries) = &mut payload.input else {
        return Err(unrewritable());
    };
    for (key, value) in entries {
        match key.as_str() {
            Some(KEY_DEFINITION) if instructions => {
                *value = Value::Binary(without_instructions(value)?);
            }
            Some(KEY_CONTEXT_SPEC) if briefing => {
                *value = Value::from(without_briefing(value)?);
            }
            _ => {}
        }
    }
    // The strict decoder every reader uses reads the erased input, with
    // both fields absent.
    let erased = decode_agent_dispatch_input(&payload.input)?;
    if erased.definition.instructions.is_some()
        || erased
            .context_spec
            .as_ref()
            .is_some_and(|spec| spec.briefing.is_some())
    {
        return Err(unrewritable());
    }
    record.payload = encode_dreamer_attempt_payload(&payload)?;
    Ok(true)
}

/// The AGENT_DEF body in `value` without its instructions key; every other
/// key keeps its place and its bytes.
fn without_instructions(value: &Value) -> Result<Vec<u8>> {
    let Value::Binary(body) = value else {
        return Err(unrewritable());
    };
    let mut cursor = body.as_slice();
    let Ok(Value::Map(mut members)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(unrewritable());
    };
    members.retain(|(key, _)| key.as_str() != Some(KEY_INSTRUCTIONS));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(members)).map_err(|_| unrewritable())?;
    Ok(out)
}

/// The serialized context spec in `value` with its briefing null, as a spec
/// with no briefing serializes; every other member keeps its place.
fn without_briefing(value: &Value) -> Result<String> {
    let json = value.as_str().ok_or_else(unrewritable)?;
    let mut spec: serde_json::Value = serde_json::from_str(json).map_err(|_| unrewritable())?;
    let briefing = spec.get_mut(KEY_BRIEFING).ok_or_else(unrewritable)?;
    *briefing = serde_json::Value::Null;
    serde_json::to_string(&spec).map_err(|_| unrewritable())
}

/// Whether `id` is a stored row of a type other than AGENT_DEF, which no
/// dispatch targets. A missing row may have been one.
fn names_no_agent(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_raw(txn, id)?
        .as_deref()
        .and_then(crate::batch::EntityMetadataHeader::parse)
        .is_some_and(|header| header.entity_type != crate::registry::ENTITY_TYPE_AGENT_DEF))
}

/// [`erase_attempt_payload_actors_in_txn`] for one erased actor.
///
/// # Errors
///
/// Storage errors, and a matching payload that cannot be rewritten.
pub(crate) fn erase_attempt_payload_actor_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_attempt_payload_actors_in_txn(store, txn, &BTreeSet::from([*actor]))
}

/// Leaves every attempt payload whose dispatch target is among `actors`
/// without its instructions and briefing, in the erase's transaction: one
/// pass over the whole ledger, every state and retry generation, and an
/// archived row's marker follows its row when it archived it as it stood.
/// A row that does not decode names no owner and stays; a matching row that
/// cannot be rewritten, or a storage error, fails the erase. An id stored
/// as another type than AGENT_DEF is no dispatch target and costs no scan.
///
/// # Errors
///
/// Storage errors, and a matching payload that cannot be rewritten.
pub(crate) fn erase_attempt_payload_actors_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut owners = BTreeSet::new();
    for actor in actors {
        if !names_no_agent(store, txn, actor)? {
            owners.insert(*actor);
        }
    }
    if owners.is_empty() {
        return Ok(());
    }
    let mut rewrites = Vec::new();
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if dispatch_payload_actor(&record).is_some_and(|actor| owners.contains(&actor))
            && erase_dispatch_payload_text(&mut record)?
        {
            rewrites.push((raw.into_owned(), record));
        }
    }
    // The erase authors nothing, so the plain encoder writes the row: the
    // side-row wall that could refuse a write does not stand in its way.
    for (before, record) in rewrites {
        let after = encode_record(&record)?;
        store
            .attempt_records
            .put(txn, record.id.as_bytes(), &after)?;
        crate::vault_cleanup::refresh_archived_attempt_in_txn(
            store, txn, record.id, &before, &after,
        )?;
    }
    Ok(())
}

/// A late write's fence (FIX 7076): when `record` is an agent dispatch
/// whose target bears the permanent hard-delete marker, its instructions
/// and briefing leave it before it is encoded, so a copy read before the
/// erase writes back the erased bytes. Only that marker counts: a soft
/// delete, an archive or a gone actor keeps the text. Read in the writer's
/// transaction. A marker that cannot be read, or a payload that cannot be
/// rewritten, leaves `record` as it was and is logged without its content:
/// the fence never fails the write it stands in.
pub(super) fn scrub_hard_erased_payload_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    let Some(actor) = dispatch_payload_actor(record) else {
        return;
    };
    match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &actor) {
        Ok(false) => {}
        Ok(true) => {
            if erase_dispatch_payload_text(record).is_err() {
                tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: an erased target's dispatch text could not be removed"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                "attempt payload fence: the target's hard-delete marker could not be read"
            );
        }
    }
}
