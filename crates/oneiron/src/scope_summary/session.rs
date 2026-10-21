//! A sitting's summary (FIX 7509, ARCH-0026 Dreamer row 4): queued by the
//! sitting's close, written from the turns the sitting retained, and never
//! from its own earlier body (CLM-009).
//!
//! The close only queues it: nothing is read or checked there. The sitting's
//! actor, sources and readability are judged when the attempt runs, and a
//! refusal there is the attempt's failure, never the close's.

use super::codec::{invalid, reply_summary};
use super::doors::ScopeSources;
use super::request::REQUEST_VERSION;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::side_table::{self, Raw, SideTable};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// The declaration key a sitting's summary names its sitting under.
pub(super) const SESSION_KEY: &str = "session";
/// The purpose a sitting's summary takes.
const SESSION_PURPOSE: &str = "session_recap";
const SOURCE_SET_DOMAIN: &[u8] = b"oneiron:session-summary-sources:v1";

/// A read of `crate::compaction`'s SESSION to TURN membership index, which
/// it owns: the same declaration, bound here to read a sitting's turns.
const SESSION_TURNS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::SESSION_TURNS);

/// Queues `session`'s summary in its close's writer and returns the attempt.
/// The declaration names the sitting alone; nothing is read or checked for
/// it here, so the close fails only as its other queue writes do. The dedupe
/// key is the sitting's, and a sitting closes once.
pub(crate) fn enqueue_session_summary_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    session: &EntityId,
    now: u64,
) -> Result<AttemptId> {
    // The declaration a Session target encodes to, with its purpose and no
    // prior summary: a sitting closes once, so none stands for it yet.
    let input = Value::Map(vec![
        (Value::from("v"), Value::from(REQUEST_VERSION)),
        (Value::from(SESSION_KEY), Value::from(session.to_hex())),
        (Value::from("purpose"), Value::from(SESSION_PURPOSE)),
        (Value::from("previous"), Value::Nil),
    ]);
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        wtxn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE.to_owned(),
            input,
            parent_attempt: None,
        },
        Some(format!(
            "{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE}:session:{}",
            session.to_hex()
        )),
        None,
        now,
    )?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    Ok(status.attempt.id)
}

/// Whether `input` declares a sitting's summary.
pub(super) fn is_session_declaration(input: &Value) -> bool {
    input.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, _)| key.as_str() == Some(SESSION_KEY))
    })
}

/// A sitting's summary is its own actor's, in the class a host hook reads
/// that actor as: a machine is system, the vault owner human, and any other
/// an agent. Read in `txn` when the declaration runs or is polled, never at
/// the close.
pub(super) fn requester_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    session: &EntityId,
) -> Result<WriteActor> {
    let actor = vault
        .session_lifecycle_record_in_txn(txn, session)?
        .ok_or_else(|| invalid("summary session has no lifecycle record"))?
        .key
        .actor;
    let class = match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_MACHINE) => EdgeActorClass::System,
        Some(ENTITY_TYPE_PERSON)
            if crate::memory::actor_is_vault_owner_in_txn(
                vault,
                txn,
                actor,
                EdgeActorClass::Human,
            )
            .unwrap_or(false) =>
        {
            EdgeActorClass::Human
        }
        _ => EdgeActorClass::Agent,
    };
    Ok(WriteActor::new(actor, class))
}

/// The TURNs an ended sitting retains, read in the planner's writer: every
/// membership row it has, with no count cap, less a TURN gone, deleted,
/// withdrawn or archived, and less an earlier summary's reply, which is
/// generated prose and never a source. By `(learned_at, id)`; its members
/// are its sources.
pub(super) fn session_sources_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    session: &EntityId,
) -> Result<ScopeSources> {
    let record = vault
        .session_lifecycle_record_in_txn(txn, session)?
        .ok_or_else(|| invalid("summary session has no lifecycle record"))?;
    if record.ended_at.is_none() {
        return Err(invalid("summary session has not ended"));
    }
    let mut turns = Vec::new();
    for row in SESSION_TURNS.iter_from(&vault.store, txn, session.as_bytes())? {
        let ((_, turn), _) = row?;
        if let Some(learned_at) = retained_turn_in_txn(vault, txn, &turn)? {
            turns.push((learned_at, turn));
        }
    }
    turns.sort_unstable();
    let turns: Vec<EntityId> = turns.into_iter().map(|(_, turn)| turn).collect();
    Ok(ScopeSources {
        members: turns.clone(),
        sources: turns,
    })
}

/// `turn`'s learned time while a sitting retains its words: a TURN whose row
/// stands, not withdrawn (deleted, stale or held from use) nor archived, and
/// not an earlier summary's reply.
fn retained_turn_in_txn(vault: &Vault, txn: &RoTxn<'_>, turn: &EntityId) -> Result<Option<u64>> {
    let Some(row) = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, turn)?
    else {
        return Ok(None);
    };
    if row.entity_type != ENTITY_TYPE_TURN
        || crate::ports::withdrawn_in_txn(&vault.store, txn, turn)?
        || vault.archive_tombstone_in_txn(txn, turn)?.is_some()
        || reply_summary(&row.body)?.is_some()
    {
        return Ok(None);
    }
    Ok(Some(row.learned_at))
}

/// The source set a sitting's summary was written from: its sitting and its
/// TURNs, sorted and once each, so the same set is the same id.
pub(super) fn source_set_id(session: &EntityId, turns: &[EntityId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_SET_DOMAIN);
    hasher.update(session.as_bytes());
    for turn in turns.iter().collect::<std::collections::BTreeSet<_>>() {
        hasher.update(turn.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// A sitting's summary covers TURNs of its sitting, each still live and not
/// archived; it is not served once one is not.
pub(super) fn validate_session_covers_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    session: &EntityId,
    covers: &[EntityId],
) -> Result<()> {
    for covered in covers {
        if crate::compaction::turn_session_membership_in_txn(&vault.store, txn, covered)?
            != Some(*session)
            || crate::vault::live_entity_row_in_txn(&vault.store, txn, covered)?.live_type()
                != Some(ENTITY_TYPE_TURN)
            || vault.archive_tombstone_in_txn(txn, covered)?.is_some()
        {
            return Err(invalid("summary cover is not a live TURN of its session"));
        }
    }
    Ok(())
}
