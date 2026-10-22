//! A turn program's code run (DOOR-141 PR2): the program's own leased try,
//! lent to the one callable SKILL its pin names, and each verb write it
//! makes bound to the program's step before it runs and settled into it with
//! its receipt's answer. A slip-woken program's every call is admitted only
//! while its waking slip admits it, live (FIX 8717). A run no program binds
//! holds none of this: each path here is the one it had.

use crate::Vault;
use crate::WriteActor;
use crate::agent_def::AgentAuthorLease;
use crate::attempt_queue::AttemptRecord;
use crate::authority::VerifiedSlip;
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::replay::{CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::code_run::storage::{ExecutorStorage, stamp_response_owner_in_txn};
use crate::code_run::types::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, SelfAgentVerbCall, SelfCall,
    SelfDispatchOutcome, SelfEffect, SelfFailedResult,
};
use crate::dreamer_runner::{
    DREAMER_TURN_PROGRAM_ATTEMPT_KIND, ProgramWrite, bind_program_write_in_txn,
    note_program_write_uncertain, settle_program_write_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{HostWriteOrigin, MEMORY_CODE_FORBIDDEN};
use crate::runtime_hooks::InvocationId;
use crate::task_verb::sdk::{AgentVerb, RunVerb};

use super::{ExecutorCallSite, HostSelfDispatcher};

const PROGRAM_CALL_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-write-call:v1";

/// The refusal a program's run gets for any callable but its pinned one.
const SKILLS_CALL_UNPINNED: &str = "skills_call_unpinned";

/// The program a dispatcher's run is: its leased try, as the host read it,
/// the one callable SKILL its pin names, and the live, verified view of the
/// slip whose turn woke it, when a slip's turn did (FIX 8717).
pub(super) struct ProgramBinding {
    lease: AgentAuthorLease,
    skill: EntityId,
    proof: Option<VerifiedSlip>,
}

impl<'a> HostSelfDispatcher<'a> {
    /// Host entry for a turn program's code run (DOOR-141 PR2): `actor` is
    /// the waking actor the program attempt's stamp names, and `leased` the
    /// program's own leased try. Its pinned callable `skill` runs under that
    /// lease; no other callable, and no spawn, authoring or TASK door, opens
    /// for it. `proof` is the waking slip's live, verified view its binding
    /// read, when a slip's turn woke it: every call the run makes is
    /// admitted only while that slip admits it (FIX 8717).
    pub(crate) fn for_turn_program(
        vault: &'a Vault,
        actor: WriteActor,
        run_ref: impl Into<String>,
        leased: &AttemptRecord,
        skill: EntityId,
        proof: Option<VerifiedSlip>,
    ) -> Result<Self> {
        if leased.kind != DREAMER_TURN_PROGRAM_ATTEMPT_KIND
            || vault.program_actor_for_attempt(leased.id)? != actor
        {
            return Err(Error::InvalidClaimBody(
                "a turn program run needs its own leased try",
            ));
        }
        let lease = AgentAuthorLease::from_leased(leased)?;
        let mut dispatcher = Self::new(vault, actor, run_ref)?;
        dispatcher.program = Some(ProgramBinding {
            lease,
            skill,
            proof,
        });
        Ok(dispatcher)
    }

    /// The waking slip's live view a program's run reads and writes under:
    /// its rows' surfaces bind it, so their reads take its key and their
    /// claim writes its position check (FIX 8717). `None` for a run no slip
    /// woke.
    pub(super) fn program_proof(&self) -> Option<&VerifiedSlip> {
        self.program.as_ref()?.proof.as_ref()
    }

    /// The refusal a slip-woken program's call `name` gets when the slip
    /// does not admit it now (FIX 8717): the slip is no longer live, or its
    /// verbs do not hold the call's class, read as the credential door reads
    /// a call's (a write needs `write` and no record or channel bound, a
    /// read needs `read`). `None` for a call it admits, and for every run no
    /// slip woke.
    pub(super) fn program_authority_refusal(&self, name: &str) -> Result<Option<String>> {
        let Some(proof) = self.program_proof() else {
            return Ok(None);
        };
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Some(MEMORY_CODE_FORBIDDEN.to_owned()));
        };
        let writes = AgentVerb::from_name(name)
            .map(AgentVerb::writes)
            .or_else(|| RunVerb::from_name(name).map(RunVerb::writes))
            .unwrap_or(true);
        let claims = proof.claims();
        let admits = if writes {
            (proof.allows_verb("write") || proof.allows_verb("core:write"))
                && claims.records.is_empty()
                && claims.channels.is_empty()
        } else {
            proof.allows_verb("read") || proof.allows_verb("core:read")
        };
        if admits && vault.capability_slip_is_live(proof)? {
            return Ok(None);
        }
        Ok(Some(MEMORY_CODE_FORBIDDEN.to_owned()))
    }

    /// `door`'s answer to `call`, unless a slip-woken program's slip does
    /// not admit it now: then the door's own refusal shape, kept as any
    /// refusal of it is (FIX 8717).
    pub(super) fn program_door_call(
        &self,
        door: &dyn AgentVerbDoor,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Some(code) = self.program_authority_refusal(call.verb.as_str())? {
            return Ok(Err(AgentVerbRefusal { code }));
        }
        door.call(call, origin, invocation)
    }

    /// The program's lease, lent to its pinned callable.
    pub(super) fn program_lease(&self) -> Option<&AgentAuthorLease> {
        self.program.as_ref().map(|program| &program.lease)
    }

    /// A program's run calls its pinned callable alone; `None` for the
    /// pinned call and for every run no program binds.
    pub(super) fn program_skill_refusal(&self, call: &SelfCall) -> Option<SelfDispatchOutcome> {
        let program = self.program.as_ref()?;
        match call {
            SelfCall::SkillsCall(skill_call) if skill_call.skill == program.skill => None,
            _ => Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::SkillsCall,
                error: SKILLS_CALL_UNPINNED.to_owned(),
            })),
        }
    }

    /// The program step a verb write at `site` is: its place in its step,
    /// its receipt and its call. `None` for a run no program binds.
    pub(super) fn program_write(
        &self,
        site: ExecutorCallSite<'_>,
        ordinal: u64,
        receipt: EntityId,
        call: &SelfAgentVerbCall,
    ) -> Result<Option<ProgramWrite>> {
        let Some(program) = &self.program else {
            return Ok(None);
        };
        let input = serde_json::to_vec(&call.input)
            .map_err(|_| Error::InvalidClaimBody("a program write's call does not encode"))?;
        let call_digest = *blake3::Hasher::new()
            .update(PROGRAM_CALL_DOMAIN)
            .update(call.verb.as_str().as_bytes())
            .update(&input)
            .finalize()
            .as_bytes();
        Ok(Some(ProgramWrite {
            attempt: program.lease.attempt,
            lease_owner: program.lease.owner.clone(),
            generation: program.lease.generation,
            code_run: site.run_id,
            step_start: site.step_start,
            ordinal,
            receipt,
            call_digest,
        }))
    }

    /// Puts a verb write's receipt, for the write run `run` made. A
    /// program's write binds its step in the reservation's commit
    /// (`settles` false), under its live lease, and settles the step in the
    /// commit that keeps the answer (`settles` true), which nothing about
    /// the step can fail. Every other run's put is the one it had. A
    /// reservation names whose replies the receipt holds, `run`'s under this
    /// dispatcher's actor (FIX 5718).
    pub(super) fn put_write_receipt(
        &self,
        receipt: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        program: Option<&ProgramWrite>,
        settles: bool,
        run: EntityId,
    ) -> Result<CodeRunReplayGeneration> {
        let actor = self.actor.entity_ref();
        let (Some(write), ExecutorStorage::Canonical(vault)) = (program, &self.storage) else {
            if !settles {
                return self
                    .storage
                    .put_owned_code_run_replay_record(receipt, expected, run, actor);
            }
            return self
                .storage
                .put_code_run_replay_record_if_generation_with_heal(receipt, expected, None);
        };
        let vault: &Vault = vault;
        let now = vault.now_recorded_at();
        if !settles {
            return vault.put_code_run_replay_record_if_generation_with_heal_and(
                receipt,
                expected,
                None,
                |wtxn| {
                    stamp_response_owner_in_txn(vault, wtxn, receipt.run_id, run, actor)?;
                    bind_program_write_in_txn(vault, wtxn, write, now)
                },
            );
        }
        let digest = answer_digest(receipt);
        vault.put_code_run_replay_record_if_generation_with_heal_and(
            receipt,
            expected,
            None,
            |wtxn| {
                match digest {
                    Some(digest) => settle_program_write_in_txn(vault, wtxn, write, digest, now),
                    None => tracing::warn!(
                        receipt = %write.receipt.to_hex(),
                        "a program write's answer did not digest; its step stays issued"
                    ),
                }
                Ok(())
            },
        )
    }

    /// Whether `record` holds the program's pinned callable finished: a
    /// `self.skills.call` of the pinned SKILL that returned its result. A
    /// run no program binds holds none.
    pub(crate) fn pinned_entry_finished(&self, record: &CodeRunReplayRecord) -> bool {
        let Some(program) = &self.program else {
            return false;
        };
        record.bridge_calls.iter().any(|row| {
            row.effect == SelfEffect::SkillsCall
                && matches!(
                    decode_self_dispatch_outcome(&row.outcome),
                    Ok(SelfDispatchOutcome::SkillCall(result)) if result.skill == program.skill
                )
        })
    }

    /// A program's write found its receipt holding no answer: it is never
    /// written again, and its step is kept uncertain.
    pub(super) fn note_program_write_uncertain(&self, write: &ProgramWrite) {
        if let ExecutorStorage::Canonical(vault) = &self.storage {
            note_program_write_uncertain(vault, write, vault.now_recorded_at());
        }
    }
}

/// The digest of the answer a receipt keeps as its first row.
fn answer_digest(receipt: &CodeRunReplayRecord) -> Option<[u8; 32]> {
    let row = receipt.bridge_calls.first()?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &row.outcome).ok()?;
    Some(
        *blake3::Hasher::new()
            .update(PROGRAM_CALL_DOMAIN)
            .update(&bytes)
            .finalize()
            .as_bytes(),
    )
}
