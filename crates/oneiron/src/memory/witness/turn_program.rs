//! DOOR-141's two seams on the actor's surface: arming a program for this
//! actor's own future turns, and the wake a landed turn owes it, recorded in
//! that turn's own commit so a crash after the commit cannot lose it.
//!
//! Both seal the actor's authority from what this surface's host bound: the
//! caller's own verified slip, a self-hosted host action acting as the
//! owner, a managed vault's attested owner (FIX 11090), or the in-process
//! host's own caller. A transport caller that presented none (an operator
//! root acting as nobody), a code run's call and a machine-signed write seal
//! nothing.

use crate::dreamer_runner::{
    ArmTurnProgram, LandedTurnRef, TurnProgramAuthority, TurnProgramRegistration,
};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

impl Memory<'_> {
    /// Arms a pinned callable SKILL entry for this actor's own future turns
    /// (DOOR-141 setup), in the conversation `input` names or any of the
    /// actor's own. Arming starts nothing: each turn the actor lands from now
    /// on wakes the program once, under that turn's own authority. Arming
    /// the same definition again returns the standing registration.
    ///
    /// # Errors
    ///
    /// Forbidden for a caller whose authority this surface cannot seal or
    /// that no longer stands; an unknown conversation or SKILL; a SKILL that
    /// is not an active callable, or arguments its call contract refuses.
    pub fn arm_turn_program(
        &self,
        input: &ArmTurnProgram,
    ) -> MemoryResult<TurnProgramRegistration> {
        // An off-record session keeps nothing, so it arms nothing.
        let authority = self
            .turn_program_authority()
            .filter(|_| self.off_record_session.is_none())
            .ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "this caller's credential cannot arm a turn program",
                    &["Arm it with your own credential, outside an off-record session."],
                )
            })?;
        let now = self.vault.now_recorded_at();
        self.with_verified_actor_write_txn(|wtxn| {
            Ok(crate::dreamer_runner::arm_turn_program_in_txn(
                self.vault, wtxn, &authority, input, now,
            )?)
        })
    }

    /// Disarms one of this actor's programs; `true` when it was armed. A wake
    /// its turns already owed is refused at admission.
    ///
    /// # Errors
    ///
    /// The actor checks of any actor write; storage errors.
    pub fn disarm_turn_program(&self, registration: EntityId) -> MemoryResult<bool> {
        self.with_verified_actor_write_txn(|wtxn| {
            Ok(crate::dreamer_runner::disarm_turn_program_in_txn(
                self.vault,
                wtxn,
                self.actor,
                registration,
            )?)
        })
    }

    /// The authority a turn this surface lands seals for its actor's armed
    /// programs, or `None` when it seals none.
    pub(super) fn turn_program_authority(&self) -> Option<TurnProgramAuthority> {
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return None;
        }
        if let Some(action) = &self.host_action {
            return Some(TurnProgramAuthority::host_action(
                self.actor,
                self.actor_class,
                action.guard().root_slip_id(),
            ));
        }
        // A managed vault's attested owner seals his person alone; each
        // judgment asks whether the vault records him as its live owner then
        // (FIX 11090).
        if let Some(holder) = self.attested_owner_holder() {
            return Some(TurnProgramAuthority::attested_owner(holder));
        }
        if let Some(proof) = &self.read_proof {
            // The slip seals the instrument its request kept, verified again
            // at each judgment (FIX 8717); a request that kept none seals
            // nothing.
            let instrument = self.invocation_slip()?;
            return TurnProgramAuthority::slip(self.actor, self.actor_class, proof, instrument);
        }
        if self.native_invocation() {
            return Some(TurnProgramAuthority::native(self.actor, self.actor_class));
        }
        None
    }

    /// Records, in the landing turn's own writer, the wake `turn` owes each
    /// program its actor armed (DOOR-141). It never fails the turn: a wake it
    /// cannot record (no authority to seal, a read or write that fails) is
    /// logged and rolled back alone, and the turn commits as it would have.
    pub(super) fn record_turn_program_wakes_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        conversation: EntityId,
        turn: EntityId,
    ) {
        match crate::dreamer_runner::turn_programs_armed_in_txn(self.vault, &*wtxn, self.actor) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                skipped(&error, turn);
                return;
            }
        }
        let Some(authority) = self.turn_program_authority() else {
            tracing::warn!(
                turn = %turn.to_hex(),
                "a turn whose caller seals no authority wakes no armed program; the turn commits"
            );
            return;
        };
        let landed = LandedTurnRef {
            turn,
            conversation,
            landed_at: self.vault.now_recorded_at(),
        };
        let mut savepoint = match self.vault.store.env.nested_write_txn(wtxn) {
            Ok(savepoint) => savepoint,
            Err(error) => {
                skipped(&crate::Error::from(error), turn);
                return;
            }
        };
        match crate::dreamer_runner::record_turn_program_wakes_in_txn(
            self.vault,
            &mut savepoint,
            &authority,
            &landed,
        ) {
            Ok(_) => {
                if let Err(error) = savepoint.commit() {
                    skipped(&crate::Error::from(error), turn);
                }
            }
            Err(error) => skipped(&error, turn),
        }
    }
}

/// Logs one program wake the turn could not record; the turn goes on.
fn skipped(error: &crate::Error, turn: EntityId) {
    tracing::warn!(
        kind = ?error.kind(),
        %error,
        turn = %turn.to_hex(),
        "turn program wake not recorded; the turn commits"
    );
}
