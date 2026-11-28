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
    DREAMER_TURN_PROGRAM_ATTEMPT_KIND, ProgramWrite, answer_is_pending, bind_program_write_in_txn,
    end_project_run_in_txn, note_program_write_uncertain, settle_program_write_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{HostWriteOrigin, MEMORY_CODE_FORBIDDEN};
use crate::runtime_hooks::InvocationId;
use crate::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

use super::{ExecutorCallSite, HostSelfDispatcher};

/// What a row-placing in-core write of a slip-woken program does when its
/// slip narrows a position axis (FIX 10666; Engine 19:20, CALLS
/// FIX-10666-narrowed-in-core-write): the in-core call carries no position
/// to check, so it is refused, and the memory door that checks one takes
/// the write. FIX 20094 tests the position in the write instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NarrowedSlipInCoreWrite {
    Refuse,
}

const NARROWED_SLIP_IN_CORE_WRITE: NarrowedSlipInCoreWrite = NarrowedSlipInCoreWrite::Refuse;

/// Whether `scope` narrows where a write may land: any of its worlds,
/// facets, audience, bands or sensitivity short of the whole vault. Its
/// verbs are the call's class, judged apart.
fn narrows_position(scope: &oneiron_authority::federation::Scope) -> bool {
    let whole = oneiron_authority::federation::Scope::top();
    scope.worlds != whole.worlds
        || scope.facets != whole.facets
        || scope.audience != whole.audience
        || scope.bands != whole.bands
        || scope.sensitivity != whole.sensitivity
}

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

    /// Refuses an in-core write that places a row (a claim, a fixture
    /// claim, a supersession or an edge) for a slip-woken program whose slip
    /// narrows where its writes may land (FIX 10666): the in-core call
    /// proves no position, so the program places its claims through
    /// `vault.claims.upsert`, whose door checks the position against the
    /// slip. A run no slip woke, and a slip whose position is the whole
    /// vault, write as before.
    ///
    /// # Errors
    /// The refusal, when the slip narrows a position axis.
    pub(super) fn refuse_narrowed_program_write(&self) -> Result<()> {
        let Some(proof) = self.program_proof() else {
            return Ok(());
        };
        match NARROWED_SLIP_IN_CORE_WRITE {
            NarrowedSlipInCoreWrite::Refuse if narrows_position(proof.scope()) => Err(
                Error::Claim(crate::error::ClaimError::ActorLacksClaimAuthority {
                    reason: "a position-narrowed credential places claims through \
                             vault.claims.upsert, which checks the position",
                }),
            ),
            NarrowedSlipInCoreWrite::Refuse => Ok(()),
        }
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
        self.program_door_call_held(door, call, origin, invocation, None)
    }

    /// [`Self::program_door_call`] that hands `door` the file of `held`, the
    /// action input `call` stands for (FIX 22096).
    pub(super) fn program_door_call_held(
        &self,
        door: &dyn AgentVerbDoor,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
        held: Option<&crate::code_run::actions::ActionBlobInput>,
    ) -> Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Some(code) = self.program_authority_refusal(call.verb.as_str())? {
            return Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code,
                reason_codes: Vec::new(),
            }));
        }
        match held {
            Some(held) => door.call_held(call, origin, invocation, held),
            None => door.call(call, origin, invocation),
        }
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
                code: None,
                disk_floor: None,
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
        let call_digest = program_call_digest(call.verb.as_str(), &input);
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
        let refused = answer_refused(receipt);
        vault.put_code_run_replay_record_if_generation_with_heal_and(
            receipt,
            expected,
            None,
            |wtxn| {
                settle_answer(vault, wtxn, write, digest, refused, now);
                Ok(())
            },
        )
    }

    /// Settles a canonical write's receipt in the writer publishing its reply.
    /// The reservation already stamped its owner and bound its program step.
    pub(super) fn put_write_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &CodeRunReplayRecord,
        expected: CodeRunReplayGeneration,
        program: Option<&ProgramWrite>,
    ) -> Result<CodeRunReplayGeneration> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a canonical reply receipt needs its vault writer",
            ));
        };
        let now = vault.now_recorded_at();
        let digest = answer_digest(receipt);
        let refused = answer_refused(receipt);
        vault.put_code_run_replay_record_if_generation_in_txn(
            wtxn,
            receipt,
            Some(expected),
            None,
            |_| Ok(()),
            |wtxn| {
                if let Some(write) = program {
                    settle_answer(vault, wtxn, write, digest, refused, now);
                }
                Ok(())
            },
        )
    }

    /// Whether `record` holds the program's pinned callable finished: an
    /// entry's own root call, the first row of a step checkpoint's calls, a
    /// `self.skills.call` of the pinned SKILL that returned its result. A
    /// call of that SKILL nested inside an entry is not its root: its result
    /// never finishes the program (FIX 5878). A run no program binds holds
    /// none.
    pub(crate) fn pinned_entry_finished(&self, record: &CodeRunReplayRecord) -> bool {
        self.pinned_entry_answer(record).is_some()
    }

    /// Whether the pinned callable's finished root call ([`Self::pinned_entry_finished`])
    /// answered pending ([RSI-PROJECT-WORKFLOW]): a stage it started has not ended, so a project
    /// run keeps waking. `false` for an entry that did not finish.
    pub(crate) fn pinned_entry_pending(&self, record: &CodeRunReplayRecord) -> bool {
        self.pinned_entry_answer(record)
            .is_some_and(|answer| answer_is_pending(&answer))
    }

    /// What the pinned callable's root call returned, when an entry finished it.
    fn pinned_entry_answer(&self, record: &CodeRunReplayRecord) -> Option<serde_json::Value> {
        let program = self.program.as_ref()?;
        record.step_checkpoints.iter().find_map(|checkpoint| {
            let range = checkpoint.bridge_range()?;
            let root = record
                .bridge_calls
                .get(range.start)
                .filter(|_| !range.is_empty())?;
            if root.seq != range.start as u64 || root.effect != SelfEffect::SkillsCall {
                return None;
            }
            match decode_self_dispatch_outcome(&root.outcome) {
                Ok(SelfDispatchOutcome::SkillCall(result)) if result.skill == program.skill => {
                    Some(result.output)
                }
                _ => None,
            }
        })
    }

    /// Ends a program's project run when the door refused one of its calls for authority
    /// ([RSI-PROJECT-WORKFLOW]): a revoked Grant or a slip that no longer admits the call. A
    /// read keeps no step, so its refusal is the step that ends the run, in a writer of its own.
    /// A run no program binds, a program armed for no project and every other answer change
    /// nothing; a disarm that cannot be written is logged and the answer stands.
    pub(super) fn end_program_run_on_authority_refusal(&self, outcome: &SelfDispatchOutcome) {
        let (Some(program), ExecutorStorage::Canonical(vault)) = (&self.program, &self.storage)
        else {
            return;
        };
        if !matches!(outcome, SelfDispatchOutcome::Denied(denied) if denied.outcome == MEMORY_CODE_FORBIDDEN)
        {
            return;
        }
        let attempt = program.lease.attempt;
        if let Err(error) =
            vault.with_write_txn_grouped(|wtxn| end_project_run_in_txn(vault, wtxn, attempt))
        {
            tracing::warn!(
                kind = ?error.kind(),
                "a project run refused for authority was not disarmed; its next wake is refused"
            );
        }
    }

    /// A program's write found its receipt holding no answer: it is never
    /// written again, and its step is kept uncertain.
    pub(super) fn note_program_write_uncertain(&self, write: &ProgramWrite) {
        if let ExecutorStorage::Canonical(vault) = &self.storage {
            note_program_write_uncertain(vault, write, vault.now_recorded_at());
        }
    }
}

fn settle_answer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    write: &ProgramWrite,
    digest: Option<[u8; 32]>,
    refused: bool,
    now: u64,
) {
    match digest {
        Some(digest) => settle_program_write_in_txn(vault, wtxn, write, digest, refused, now),
        None => tracing::warn!(
            receipt = %write.receipt.to_hex(),
            "a program write's answer did not digest; its step stays issued"
        ),
    }
}

/// Whether the answer a receipt keeps as its first row is the door's refusal.
fn answer_refused(receipt: &CodeRunReplayRecord) -> bool {
    receipt.bridge_calls.first().is_some_and(|row| {
        matches!(
            decode_self_dispatch_outcome(&row.outcome),
            Ok(SelfDispatchOutcome::Denied(_))
        )
    })
}

/// The digest of the answer a receipt keeps as its first row.
fn answer_digest(receipt: &CodeRunReplayRecord) -> Option<[u8; 32]> {
    let row = receipt.bridge_calls.first()?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &row.outcome).ok()?;
    Some(program_answer_digest(&bytes))
}

/// A program write's call digest over its verb and its call input's JSON
/// (`purposes::code_run::PROGRAM_CALL`).
fn program_call_digest(verb: &str, input: &[u8]) -> [u8; 32] {
    LegacyDigest::new(purposes::code_run::PROGRAM_CALL)
        .raw(verb.as_bytes())
        .raw(input)
        .finish()
}

/// A program write's answer digest over its receipt's first outcome as
/// MessagePack (`purposes::code_run::PROGRAM_CALL`).
fn program_answer_digest(outcome: &[u8]) -> [u8; 32] {
    LegacyDigest::new(purposes::code_run::PROGRAM_CALL)
        .raw(outcome)
        .finish()
}

/// [`program_call_digest`] for the K door
/// (`test_doors::fingerprint_keep_code_run_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn program_call_digest_for_test(verb: &str, input: &[u8]) -> [u8; 32] {
    program_call_digest(verb, input)
}

/// [`program_answer_digest`] for the K door
/// (`test_doors::fingerprint_keep_code_run_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn program_answer_digest_for_test(outcome: &[u8]) -> [u8; 32] {
    program_answer_digest(outcome)
}
