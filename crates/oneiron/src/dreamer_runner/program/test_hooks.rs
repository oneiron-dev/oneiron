//! Hooks for the integration tests, compiled only under
//! `--cfg oneiron_test_support` and reached through
//! [`crate::test_doors::turn_programs`]. Not API.
//!
//! They plant an arming and the wake a landed turn owes it as the arm door
//! and the turn's writer leave them, without pinning a SKILL, and read what
//! a machine holds and decided.

use super::authority::TurnProgramAuthority;
use super::types::{
    LandedTurnRef, OwedWakeHold, ProgramRecipePin, ProgramTrigger, TurnProgramArming,
};
use super::{ADMISSION, ARM, DISARMED, WAKE};
use crate::authority::{InvocationSlipBinding, VerifiedSlip};
use crate::error::{Error, Result};
use crate::{EdgeActorClass, EntityId, Vault};

/// Arms a program for the agent `actor` in `conversation` at `armed_at`,
/// sealed by the verified slip `proof` and the instrument `binding`, then
/// records the wake TURN `turn`, landed at `landed_at`, owes it, as the
/// turn's writer does. Answers the registration.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plant_slip_wake(
    vault: &Vault,
    actor: EntityId,
    proof: &VerifiedSlip,
    binding: &InvocationSlipBinding,
    conversation: EntityId,
    turn: EntityId,
    armed_at: u64,
    landed_at: u64,
) -> Result<EntityId> {
    let authority = TurnProgramAuthority::slip(actor, EdgeActorClass::Agent, proof, binding)
        .ok_or_else(|| Error::InvalidConfig("the slip seals no turn program authority".into()))?;
    let registration = vault.new_entity_id()?;
    let definition = ProgramRecipePin {
        skill: registration,
        version: "1".into(),
        content_hash: "0".repeat(64),
        entry: "main".into(),
        contract_digest: [0; 32],
        executor: "test".into(),
        args: "{}".into(),
    };
    let arming = TurnProgramArming {
        registration,
        actor,
        actor_class: authority.class_byte(),
        conversation: Some(conversation),
        revision: definition.revision(),
        definition,
        armed_at,
        trigger: ProgramTrigger::Turn,
        sealed: None,
        next_due: None,
    };
    let landed = LandedTurnRef {
        turn,
        conversation,
        landed_at,
    };
    vault.with_write_txn_grouped(|txn| {
        ARM.put(vault, txn, &(actor, registration), &arming)?;
        let owed = super::wake::record_turn_program_wakes_in_txn(vault, txn, &authority, &landed)?;
        if owed == 1 {
            Ok(())
        } else {
            Err(Error::InvalidConfig(format!(
                "the planted arming owes {owed} wakes, not one"
            )))
        }
    })?;
    Ok(registration)
}

/// Holds the wake TURN `turn` owes `registration` on its lapsed slip, as
/// the home's admission holds one whose slip lapsed (FIX 12058): owed until
/// its rebind or its expiry, a week after its turn landed. Answers whether
/// there was a wake to hold.
pub(crate) fn hold_wake_on_lapsed_slip(
    vault: &Vault,
    turn: EntityId,
    registration: EntityId,
    held_at: u64,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut wake) = WAKE.get(vault, &*txn, &(turn, registration))? else {
            return Ok(false);
        };
        wake.held = Some(OwedWakeHold {
            reason: super::admit::AUTHORITY_LAPSED.to_owned(),
            held_at,
            expires_at: wake
                .turn
                .landed_at
                .saturating_add(super::admit::LAPSED_WAKE_HOLD_SECS),
        });
        WAKE.put(vault, txn, &(turn, registration), &wake)?;
        Ok(true)
    })
}

/// Whether this machine owes the wake TURN `turn` owes `registration`.
pub(crate) fn wake_owed_here(
    vault: &Vault,
    turn: EntityId,
    registration: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    WAKE.contains(vault, &txn, &(turn, registration))
}

/// How many decisions this machine holds for the wake TURN `turn` owes
/// `registration`: admission rows, queued or refused.
pub(crate) fn wake_decisions_here(
    vault: &Vault,
    turn: EntityId,
    registration: EntityId,
) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let all: &[u8] = &[];
    let mut decisions = 0;
    for row in ADMISSION.iter_from(vault, &txn, all)? {
        let (_, record) = row?;
        if record.wake.turn.turn == turn && record.wake.registration == registration {
            decisions += 1;
        }
    }
    Ok(decisions)
}

/// How the wake TURN `turn` owes `registration` was refused here, when it
/// was: the admission's reason. `None` when no admission refused it here,
/// either because this machine holds no decision for it or because the
/// decision queued.
pub(crate) fn wake_refusal_here(
    vault: &Vault,
    turn: EntityId,
    registration: EntityId,
) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    let all: &[u8] = &[];
    for row in ADMISSION.iter_from(vault, &txn, all)? {
        let (_, record) = row?;
        if record.wake.turn.turn == turn && record.wake.registration == registration {
            return Ok(record.refused);
        }
    }
    Ok(None)
}

/// Plants an agent arming without a wake, keeping the supplied definition
/// and its revision so separate machines can arm the same program.
pub(crate) fn plant_arming(
    vault: &Vault,
    actor: EntityId,
    conversation: EntityId,
    definition: &ProgramRecipePin,
    armed_at: u64,
) -> Result<EntityId> {
    let registration = vault.new_entity_id()?;
    let arming = TurnProgramArming {
        registration,
        actor,
        actor_class: EdgeActorClass::Agent as u8,
        conversation: Some(conversation),
        definition: definition.clone(),
        revision: definition.revision(),
        armed_at,
        trigger: ProgramTrigger::Turn,
        sealed: None,
        next_due: None,
    };
    vault.with_write_txn_grouped(|txn| ARM.put(vault, txn, &(actor, registration), &arming))?;
    Ok(registration)
}

/// Records a landed turn's wakes through the turn writer's recorder.
pub(crate) fn record_slip_turn_wakes(
    vault: &Vault,
    actor: EntityId,
    proof: &VerifiedSlip,
    binding: &InvocationSlipBinding,
    turn: LandedTurnRef,
) -> Result<usize> {
    let authority = TurnProgramAuthority::slip(actor, EdgeActorClass::Agent, proof, binding)
        .ok_or_else(|| Error::InvalidConfig("the slip seals no turn program authority".into()))?;
    vault.with_write_txn_grouped(|txn| {
        super::wake::record_turn_program_wakes_in_txn(vault, txn, &authority, &turn)
    })
}

/// Disarms through the engine door and answers its stored timestamp, or
/// none when the registration was not armed.
pub(crate) fn disarm_program(
    vault: &Vault,
    actor: EntityId,
    registration: EntityId,
) -> Result<Option<u64>> {
    let at = vault.with_write_txn_grouped(|txn| {
        if !super::arm::disarm_turn_program_in_txn(vault, txn, actor, registration)? {
            return Ok(None);
        }
        Ok(DISARMED
            .get(vault, &*txn, &(actor, registration))?
            .map(|disarm| disarm.at))
    })?;
    #[cfg(feature = "sync")]
    vault.refresh_turn_program_armings_in_live_windows();
    Ok(at)
}

/// Whether this machine still holds the registration as armed.
pub(crate) fn program_armed_here(
    vault: &Vault,
    actor: EntityId,
    registration: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    ARM.contains(vault, &txn, &(actor, registration))
}

/// Plants a one-shot timer with the same slip authority a landed turn seals.
pub(crate) fn plant_timer_arming(
    vault: &Vault,
    actor: EntityId,
    proof: &VerifiedSlip,
    binding: &InvocationSlipBinding,
    armed_at: u64,
    first_at: u64,
) -> Result<EntityId> {
    let authority = TurnProgramAuthority::slip(actor, EdgeActorClass::Agent, proof, binding)
        .ok_or_else(|| Error::InvalidConfig("the slip seals no turn program authority".into()))?;
    let registration = vault.new_entity_id()?;
    let definition = ProgramRecipePin {
        skill: registration,
        version: "1".into(),
        content_hash: "0".repeat(64),
        entry: "main".into(),
        contract_digest: [0; 32],
        executor: "test".into(),
        args: "{}".into(),
    };
    let arming = TurnProgramArming {
        registration,
        actor,
        actor_class: authority.class_byte(),
        conversation: None,
        revision: definition.revision(),
        definition,
        armed_at,
        trigger: ProgramTrigger::Timer {
            first_at,
            every_secs: 0,
        },
        sealed: Some(authority),
        next_due: Some(first_at),
    };
    vault.with_write_txn_grouped(|txn| {
        ARM.put(vault, txn, &(actor, registration), &arming)?;
        super::trigger::index_trigger_in_txn(vault, txn, &arming)
    })?;
    Ok(registration)
}

/// Whether a disarm row for this registration is kept here.
pub(crate) fn disarm_kept_here(
    vault: &Vault,
    actor: EntityId,
    registration: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    DISARMED.contains(vault, &txn, &(actor, registration))
}

/// Encodes the mirror's externally tagged `ArmingRow::Armed` envelope directly,
/// without its outbound filter. The replica module's row enum is private.
pub(crate) fn arming_row_bytes(
    vault: &Vault,
    actor: EntityId,
    registration: EntityId,
) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    let arming = ARM
        .get(vault, &txn, &(actor, registration))?
        .ok_or(Error::EntityNotFound)?;
    serde_json::to_vec(&std::collections::BTreeMap::from([("armed", arming)]))
        .map_err(|_| Error::InvalidConfig("the arming row does not encode".into()))
}
