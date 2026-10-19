//! DOOR-141 setup: an actor arms a pinned callable SKILL entry for its own
//! future turns. Arming never starts a run: only a turn that lands after it
//! wakes the program, and disarming it stops every wake not yet admitted.

use crate::error::{ArtifactError, ClaimError, Error, Result};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::skill::{SkillCallContract, SkillLifecycle, SkillRole};
use crate::{EntityId, Vault};

use super::authority::TurnProgramAuthority;
use super::types::{ArmTurnProgram, ProgramRecipePin, TurnProgramArming, TurnProgramRegistration};
use super::{ARM, WAKE};

const CONTRACT_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-contract:v1";

const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// Arms `input` for the future turns of `authority`'s actor, in the caller's
/// writer: the actor's authority must stand now, the conversation (when one
/// is named) must be a live CONVERSATION, and the SKILL an active callable
/// whose call contract the arguments meet. The definition is pinned here.
/// Arming the same definition for the same conversation again returns the
/// standing registration.
pub(crate) fn arm_turn_program_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    authority: &TurnProgramAuthority,
    input: &ArmTurnProgram,
    now: u64,
) -> Result<TurnProgramRegistration> {
    let actor = authority.actor();
    // A base agent is no one's delegated will: it arms nothing.
    if crate::dreamer_runner::authority::is_base_agent_actor(&actor)?
        || !authority.stands_in_txn(vault, txn)?
    {
        return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
            reason: "this caller's authority cannot arm a turn program",
        }));
    }
    if let Some(conversation) = input.conversation
        && crate::vault::live_entity_row_in_txn(&vault.store, txn, &conversation)?.live_type()
            != Some(ENTITY_TYPE_CONVERSATION)
    {
        return Err(Error::EntityNotFound);
    }
    let definition = pin_in_txn(vault, txn, input)?;
    let revision = definition.revision();
    for row in ARM.iter_from(vault, &*txn, actor.as_bytes())? {
        let (_, armed) = row?;
        if armed.actor_class == authority.class_byte()
            && armed.conversation == input.conversation
            && armed.revision == revision
        {
            return Ok(armed.view(false));
        }
    }
    let arming = TurnProgramArming {
        registration: vault.new_entity_id()?,
        actor,
        actor_class: authority.class_byte(),
        conversation: input.conversation,
        definition,
        revision,
        armed_at: now,
    };
    ARM.put(vault, txn, &(actor, arming.registration), &arming)?;
    Ok(arming.view(true))
}

/// Disarms one of `actor`'s programs; `true` when it was armed. A wake its
/// turns already owed is refused at admission.
pub(crate) fn disarm_turn_program_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    registration: EntityId,
) -> Result<bool> {
    ARM.delete(vault, txn, &(actor, registration))
}

/// An erased actor arms nothing and is owed nothing (FIX 3520): its armings
/// and the wakes its turns left go in the erase's own writer. Admission
/// receipts and attempt stamps stay, as every runner stamp does.
pub(crate) fn erase_turn_program_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    ARM.delete_from(vault, txn, actor.as_bytes())?;
    let mut owed = Vec::new();
    for row in WAKE.iter_from(vault, &*txn, &[])? {
        let (key, wake) = row?;
        if wake.authority.actor() == *actor {
            owed.push(key);
        }
    }
    for key in owed {
        WAKE.delete(vault, txn, &key)?;
    }
    Ok(())
}

/// Whether the SKILL `pin` names still is the program pinned: the same
/// active callable revision, content and call contract.
pub(super) fn pin_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &ProgramRecipePin,
) -> Result<bool> {
    let Some(record) = vault.get_skill_record_in_txn(txn, &pin.skill)? else {
        return Ok(false);
    };
    let Some(call) = record.call.as_ref() else {
        return Ok(false);
    };
    Ok(record.role == SkillRole::Callable
        && record.lifecycle_status == SkillLifecycle::Active
        && record.version == pin.version
        && record
            .content_hash
            .is_some_and(|hash| hash.to_hex() == pin.content_hash)
        && call.reference == pin.entry
        && contract_digest(call)? == pin.contract_digest)
}

/// The pin of `input`'s SKILL as it stands in `txn`.
fn pin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &ArmTurnProgram,
) -> Result<ProgramRecipePin> {
    let record = vault
        .get_skill_record_in_txn(txn, &input.skill)?
        .ok_or(Error::EntityNotFound)?;
    let call = record
        .call
        .as_ref()
        .ok_or(invalid("a turn program runs a callable skill"))?;
    if record.role != SkillRole::Callable || record.lifecycle_status != SkillLifecycle::Active {
        return Err(invalid("only an active callable skill can be armed"));
    }
    if !crate::skill::matches_shape(&input.args, &call.arguments) {
        return Err(invalid(
            "the arguments differ from the skill's call contract",
        ));
    }
    crate::skill_reliability::validate_executor(&input.executor)?;
    let content_hash = record
        .content_hash
        .ok_or(invalid("the skill has no content identity"))?
        .to_hex();
    let entry = call.reference.clone();
    let contract_digest = contract_digest(call)?;
    let args = serde_json::to_string(&input.args)
        .map_err(|_| invalid("the arguments cannot be encoded"))?;
    Ok(ProgramRecipePin {
        skill: input.skill,
        version: record.version,
        content_hash,
        entry,
        contract_digest,
        executor: input.executor.clone(),
        args,
    })
}

/// BLAKE3 over a call contract: its entry, arguments and returns.
fn contract_digest(call: &SkillCallContract) -> Result<[u8; 32]> {
    let arguments = serde_json::to_vec(&call.arguments)
        .map_err(|_| invalid("the call contract cannot be encoded"))?;
    let returns = serde_json::to_vec(&call.returns)
        .map_err(|_| invalid("the call contract cannot be encoded"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for part in [
        call.reference.as_bytes(),
        arguments.as_slice(),
        returns.as_slice(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(*hasher.finalize().as_bytes())
}
