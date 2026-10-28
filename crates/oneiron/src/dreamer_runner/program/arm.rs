//! DOOR-141 setup: an actor arms a pinned callable SKILL entry for its own
//! future turns. Arming never starts a run: only a turn that lands after it
//! wakes the program, and disarming it stops every wake not yet admitted.

use std::collections::BTreeSet;

use crate::batch::secret_scan::{Lifted, Part, admit_parts_in_txn};
use crate::error::{ArtifactError, ClaimError, Error, Result};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::side_table::SideKey;
use crate::skill::{SkillCallContract, SkillLifecycle, SkillRole};
use crate::{EntityId, Vault};

use super::authority::TurnProgramAuthority;
use super::erase::scrub_actor_admission_instruments_in_txn;
use super::run::{scrub_actor_step_bodies_in_txn, undecodable_actor_steps_in_txn};
use super::types::{ArmTurnProgram, ProgramRecipePin, TurnProgramArming, TurnProgramRegistration};
use super::{ARM, WAKE};

const CONTRACT_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-contract:v1";

const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// Arms `input` for the future turns of `authority`'s actor, in the caller's
/// writer: the actor's authority must stand now, the conversation (when one
/// is named) must be a live CONVERSATION, and the SKILL an active callable
/// whose call contract the arguments meet. The arguments are admitted
/// through the secret write-wall before anything is pinned (FIX 8718): each
/// secret goes to custody under the registration and leaves its handle, and
/// the pin, its revision and every copy and read of it hold only that
/// admitted text. The definition is pinned here. Arming the same definition
/// for the same conversation again returns the standing registration.
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
    // The custody origin of the arguments' secrets: the registration this
    // arming mints, unless it finds the standing one, whose secrets custody
    // already holds and whose handles they keep.
    let registration = vault.new_entity_id()?;
    let definition = pin_in_txn(vault, txn, input, registration)?;
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
        registration,
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
/// and the wakes its turns left go in the erase's own writer, and so do the
/// bodies its programs' steps keep (FIX 5710) and the signed instrument each
/// of its admissions sealed (FIX 10668). Admission receipts, attempt
/// stamps and each step's evidence stay, as every runner stamp does. An
/// owner's erase never fails on a row that does not decode (FIX 5736): an
/// arming under the actor's key, a wake keyed to one of its armings and a
/// step under one of its code runs go whole by key when their rows do not
/// decode, and the erase's receipt names how many
/// ([`turn_program_erase_details`]). A row its key does not tie to the
/// actor stays as it is.
pub(crate) fn erase_turn_program_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let scope = actor_scope_in_txn(vault, txn, actor)?;
    ARM.delete_from(vault, txn, actor.as_bytes())?;
    for key in &scope.wakes {
        WAKE.delete(vault, txn, key)?;
    }
    scrub_actor_admission_instruments_in_txn(vault, txn, actor)?;
    scrub_actor_step_bodies_in_txn(vault, txn, actor).map(drop)
}

/// What an erase of `actor` takes from the arm and wake tables, read on
/// `txn`: the wakes it owes, and how many of its arming and wake rows do
/// not decode. A wake is its own by its authority; one that does not decode
/// is its own when its key names one of its armings.
struct ActorScope {
    wakes: Vec<(EntityId, EntityId)>,
    undecodable: usize,
}

fn actor_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<ActorScope> {
    let mut registrations = BTreeSet::new();
    let mut undecodable = 0;
    for row in ARM.iter_raw_from(vault, txn, actor.as_bytes())? {
        let (key, bytes) = row?;
        let key = <(EntityId, EntityId) as SideKey>::decode_key(&key);
        if let Some((_, registration)) = key {
            registrations.insert(registration);
        }
        // Every row under its key goes; one that does not decode is counted.
        if key.is_none() || ARM.decode_value(&bytes).is_err() {
            undecodable += 1;
        }
    }
    let mut wakes = Vec::new();
    for row in WAKE.iter_raw_from(vault, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, EntityId) as SideKey>::decode_key(&key) else {
            continue;
        };
        match WAKE.decode_value(&bytes) {
            Ok(wake) if wake.authority.actor() == *actor => wakes.push(key),
            Ok(_) => {}
            Err(_) if registrations.contains(&key.1) => {
                undecodable += 1;
                wakes.push(key);
            }
            Err(_) => {}
        }
    }
    Ok(ActorScope { wakes, undecodable })
}

/// The detail an erase of `actor` names on its receipt (FIX 5736): how many
/// of its turn-program rows do not decode, which its purge removes whole.
/// None when every row decodes, so a clean erase's receipt is as it was.
///
/// # Errors
///
/// Storage errors, and a stamp whose admission names no code run.
pub(crate) fn turn_program_erase_details(vault: &Vault, actor: &EntityId) -> Result<Vec<String>> {
    let txn = vault.store.env.read_txn()?;
    let removed = actor_scope_in_txn(vault, &txn, actor)?.undecodable
        + undecodable_actor_steps_in_txn(vault, &txn, actor)?;
    Ok(if removed == 0 {
        Vec::new()
    } else {
        vec![format!("turn_program.undecodable_rows_removed:{removed}")]
    })
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

/// The pin of `input`'s SKILL as it stands in `txn`, with `input`'s
/// arguments as the secret write-wall admits them for `registration`.
fn pin_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &ArmTurnProgram,
    registration: EntityId,
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
    let args = admitted_args_in_txn(vault, txn, registration, &input.args)?;
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

/// `args` as the JSON text the secret write-wall admits for `registration`,
/// read as a body so a credential-valued member is read structurally (FIX
/// 8718): with the owner's scanning on, each secret goes to custody and
/// leaves its handle; a hit the wall cannot place refuses the arming, before
/// anything is pinned. With scanning off the text is the caller's own.
fn admitted_args_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: EntityId,
    args: &serde_json::Value,
) -> Result<String> {
    let mut body =
        serde_json::to_vec(args).map_err(|_| invalid("the arguments cannot be encoded"))?;
    admit_parts_in_txn(
        vault,
        txn,
        registration,
        &mut [("body", Part::Body(&mut body))],
        &mut Lifted::default(),
    )?;
    let admitted: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| invalid("the admitted arguments are not JSON"))?;
    serde_json::to_string(&admitted).map_err(|_| invalid("the arguments cannot be encoded"))
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
