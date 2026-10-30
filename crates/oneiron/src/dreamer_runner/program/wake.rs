//! The wake a landed turn owes its actor's armed programs (DOOR-141 §4): it
//! is recorded in the turn's own commit, so a crash after that commit cannot
//! lose it, and drained after the turn and at boot through the one admission
//! and its dedupe. A wake whose sealed slip lapsed stays owed, held, until
//! its rebind or its own expiry (FIX 12058).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::admit::WakeAdmission;
use super::authority::TurnProgramAuthority;
use super::types::{LandedTurnRef, TurnProgramAdmissionOutcome, TurnProgramDrain, TurnProgramWake};
use super::{ADMISSION, ARM, WAKE};

/// How many owed wakes one drain admits; [`TurnProgramDrain::more`] asks for
/// the next batch. A batch size, never a cap: every wake is drained.
const DRAIN_BATCH: usize = 32;

/// Whether `actor` has any program armed, read in the turn's writer before
/// anything else is sealed: a turn of an actor that armed none costs one
/// prefix read.
pub(crate) fn turn_programs_armed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<bool> {
    Ok(ARM
        .iter_from(vault, txn, actor.as_bytes())?
        .next()
        .transpose()?
        .is_some())
}

/// Records, in the landing turn's own writer, the wake `turn` owes each
/// program `authority`'s actor armed for it. One turn wakes one program
/// once: a later landing of the same turn (an append) owes nothing new.
/// Answers how many wakes it recorded.
pub(crate) fn record_turn_program_wakes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    authority: &TurnProgramAuthority,
    turn: &LandedTurnRef,
) -> Result<usize> {
    let mut armed = Vec::new();
    for row in ARM.iter_from(vault, &*txn, authority.actor().as_bytes())? {
        armed.push(row?.1);
    }
    let mut owed = 0;
    for arming in armed {
        if !arming.wakes_on(authority, turn) {
            continue;
        }
        let wake = TurnProgramWake {
            registration: arming.registration,
            revision: arming.revision,
            authority: authority.clone(),
            turn: *turn,
            held: None,
        };
        if WAKE.contains(vault, &*txn, &wake.key())?
            || ADMISSION.contains(vault, &*txn, &wake.admission_id())?
        {
            continue;
        }
        WAKE.put(vault, txn, &wake.key(), &wake)?;
        owed += 1;
    }
    Ok(owed)
}

/// Admits a batch of owed wakes, each in its own writer. A wake whose
/// admission fails to be judged (not refused) is logged and kept for the
/// next drain; it never blocks the others. A wake held on its lapsed slip
/// (FIX 12058) is passed by, taking no place in the batch, until its own
/// expiry: before then only its rebind admits it, in the rebind's writer.
pub(crate) fn drain_turn_program_wakes(vault: &Vault, now: u64) -> Result<TurnProgramDrain> {
    let pending = {
        let txn = vault.store.env.read_txn()?;
        let mut pending = Vec::new();
        for row in WAKE.iter_from(vault, &txn, &[])? {
            let wake = row?.1;
            if wake.held.as_ref().is_some_and(|held| now < held.expires_at) {
                continue;
            }
            pending.push(wake);
            if pending.len() > DRAIN_BATCH {
                break;
            }
        }
        pending
    };
    let rows = pending.len();
    let (mut admitted, mut refused, mut held, mut failed) = (0, 0, 0, 0);
    for wake in pending.into_iter().take(DRAIN_BATCH) {
        match vault.admit_turn_program(&wake, now) {
            Ok(WakeAdmission::Held) => held += 1,
            Ok(WakeAdmission::Decided(receipt)) => {
                if matches!(receipt.outcome, TurnProgramAdmissionOutcome::Refused { .. }) {
                    refused += 1;
                } else {
                    admitted += 1;
                }
            }
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    kind = ?error.kind(),
                    %error,
                    turn = %wake.turn.turn.to_hex(),
                    "turn program wake not admitted; it waits for the next drain"
                );
            }
        }
    }
    Ok(TurnProgramDrain {
        admitted,
        refused,
        held,
        // A batch that made no progress asks for no other.
        more: rows > DRAIN_BATCH && failed < DRAIN_BATCH,
    })
}
