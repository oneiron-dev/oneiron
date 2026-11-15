//! The shared opening for the extraction stagers: the attempt rule and the
//! verdict's read.
//!
//! Both the Conflict stager and the Candidate stager run inside a queued
//! extraction attempt and read through the verdict's read for the stamp's
//! actor. The rule (the stamp names a queued Micro, Meso or Macro
//! consolidation attempt with a partition payload) and the read (the lane
//! key, the TURN reader, the authority proof and the reader scope, all
//! inside the batch's write) live here. They are two functions, so the
//! Candidate stager checks the attempt's Dreamer between the attempt rule
//! and the read. Each stager names its own refusal token.

use super::batch::DerivationStamp;
use crate::attempt_queue::AttemptId;
use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::error::Result;
use crate::federation::Scope;
use crate::memory::{Memory, MemoryResult};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The verdict's read for one extraction item: the stamp's actor, the
/// actor's scoped read with its TURN reader, the actor's memory, and the
/// reader scope. Every read ran inside the batch's write; nothing here
/// opened a transaction.
pub(super) struct ExtractionOpening<'v> {
    /// The stamp's actor.
    pub(super) actor: WriteActor,
    /// The verdict's read for the actor.
    pub(super) read: ScopedRead<'v>,
    /// The verdict's TURN reader, when it differs from the read.
    pub(super) turn_owned: Option<ScopedRead<'v>>,
    /// The actor's memory.
    pub(super) memory: Memory<'v>,
    /// The reader scope, when the actor is not the owner.
    pub(super) reader_scope: Option<Scope>,
}

impl ExtractionOpening<'_> {
    /// The TURN reader: the owned one, or the read when they are the same.
    pub(super) fn turn_read(&self) -> &ScopedRead<'_> {
        self.turn_owned.as_ref().unwrap_or(&self.read)
    }
}

/// The queued extraction attempt the stamp names, read inside the batch's
/// write: `None` when the stamp names no attempt, or its attempt is not in
/// the queue as a Micro, Meso or Macro consolidation attempt with a
/// partition payload.
///
/// # Errors
///
/// The store's.
pub(super) fn open_attempt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    stamp: &DerivationStamp,
) -> Result<Option<AttemptId>> {
    let Some(attempt_id) = stamp.attempt else {
        return Ok(None);
    };
    let attempt = EntityId::from_bytes_unchecked(*attempt_id.as_bytes());
    Ok(
        crate::snapshot_read::queued_extraction_branch_opt_in_txn(vault, txn, attempt)?
            .map(|_| attempt_id),
    )
}

/// The verdict's read for the stamp's actor, inside the batch's write: the
/// lane key the verdict's read lane builds for a non-owner actor, replicated
/// without opening a transaction (the lane itself opens one), with the
/// verdict's TURN reader, authority proof and reader scope. Grant time
/// judges at the committed floor, as every other derive stager's reads do.
/// `None` when the actor has no engine read.
///
/// # Errors
///
/// The refusal of the TURN reader, the authority proof or the reader scope,
/// as the verdict's read answers it: a request refusal, or the store's
/// failure as an internal error.
pub(super) fn open_verdict_read<'v>(
    vault: &'v Vault,
    txn: &heed::RoTxn<'_>,
    stamp: &DerivationStamp,
) -> MemoryResult<Option<ExtractionOpening<'v>>> {
    let actor = stamp.actor;
    let Some(key) = ScopedReadActorKey::for_engine_actor(actor) else {
        return Ok(None);
    };
    let read = vault
        .scoped_read(key.require_access_grants(Some(actor.entity_ref())))
        .with_claim_status(crate::ports::ClaimReadStatus::Recorded);
    let turn_owned = crate::snapshot_read::extraction_turn_read(&read, None)?;
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    memory.prove_read_authority_in_txn(txn)?;
    let reader_scope = crate::snapshot_read::extraction_reader_scope_in_txn(&memory, txn, None)?;
    Ok(Some(ExtractionOpening {
        actor,
        read,
        turn_owned,
        memory,
        reader_scope,
    }))
}
