//! `self.code.*` (FIX 6867, L11 G1 PR2a, PR2b, PR3b): a leased agent run's
//! repo rows.
//!
//! A call runs only on canonical storage, at an engine executor's call site,
//! from a run that holds its live lease on an agent try realizing a TASK,
//! reading on the lane its door admitted the call with. The binding is
//! rebuilt from the host's own lease at each call: the actor and the try
//! are checked against the dispatch payload, the TASK is the try's, the
//! executor run is the site's. The doors then judge the run against the
//! owner's Grant in each snapshot they read and each writer they commit
//! in. No owner proof is read and no owner door is called.
//!
//! A write row (the import, the open, the symbol declarations, the proposal,
//! the queue entry) meets the per-operation gate first, under the run's own
//! envelope naming the row and its bridge position, at the repo and ref of
//! the work it names. A refusal or a typed hold answers its repo code; any
//! other door error answers its code as a failure the script reads. Neither
//! halts the run. A proposal's catalog is the host's review policy
//! ([`HostSelfDispatcher::with_repo_review_policy`]), and its session and
//! provenance are minted by the host (`repo_sources`).

use std::cell::RefCell;
use std::sync::Arc;

use rmpv::Value;

use super::repo_sources::RepoChange;
use super::{ExecutorCallSite, HostSelfDispatcher, check_write_gate_against_vault};
use crate::claim::ScopedReadActorKey;
use crate::code_run::RepoRunCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
    SelfFailedResult,
};
use crate::error::{ArtifactError, Error, Result};
use crate::federation::{RepoAccessIntent, RepoAccessRefusal};
use crate::memory::repo_doors::{
    NO_PATHS, RepoReviewPolicy, RepoRunAnswer, RepoRunBinding, is_repo_refusal_code, repo_target,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::{ClaimSubject, EntityId, Vault};

/// The domain a run repo write's gate id is derived under.
const REPO_OPERATION_GATE_ID_DOMAIN: &str = "oneiron.self.repo.operation.v1";

impl HostSelfDispatcher<'_> {
    /// One run repo row, answered as a verb answer with the rows it read,
    /// or refused with its typed code.
    pub(super) fn dispatch_repo(
        &self,
        call: RepoRunCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let effect = call.effect();
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(denied(effect, AGENT_VERB_SESSION_BOUND));
        };
        // A run repo call names its work under the executor run it belongs
        // to: one with no executor site holds no run's work.
        let Some(site) = site else {
            return Ok(denied(effect, RepoAccessRefusal::StaleLease.public_code()));
        };
        let binding = match self.repo_run_binding(vault, site, read_as)? {
            Ok(binding) => binding,
            Err(refused) => return Ok(denied(effect, refused.public_code())),
        };
        if call.writes()
            && let Err(refused) = self.repo_operation_gate(vault, &binding, &call, site)?
        {
            return Ok(denied(effect, refused.public_code()));
        }
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        match call {
            RepoRunCall::SnapshotsGet(input) => {
                answered(effect, memory.repo_snapshots_get_for_run(&binding, input))
            }
            RepoRunCall::SnapshotsRead(input) => {
                answered(effect, memory.repo_snapshots_read_for_run(&binding, input))
            }
            RepoRunCall::SymbolsDefinitions(input) => answered(
                effect,
                memory.repo_symbols_definitions_for_run(&binding, input),
            ),
            RepoRunCall::ViewsGet(input) => {
                answered(effect, memory.repo_views_get_for_run(&binding, input))
            }
            RepoRunCall::ViewsRead(input) => {
                answered(effect, memory.repo_views_read_for_run(&binding, input))
            }
            RepoRunCall::MergeQueueObserve(input) => answered(
                effect,
                memory.repo_merge_queue_observe_for_run(&binding, input),
            ),
            RepoRunCall::SnapshotsIngest(input) => answered(
                effect,
                memory.repo_snapshots_ingest_for_run(&binding, input),
            ),
            RepoRunCall::WorkOpen(input) => {
                answered(effect, memory.repo_work_open_for_run(&binding, input))
            }
            RepoRunCall::SymbolsDeclare(input) => {
                answered(effect, memory.repo_symbols_declare_for_run(&binding, input))
            }
            RepoRunCall::SymbolsRenew(input) => {
                answered(effect, memory.repo_symbols_renew_for_run(&binding, input))
            }
            RepoRunCall::SymbolsRelease(input) => {
                answered(effect, memory.repo_symbols_release_for_run(&binding, input))
            }
            RepoRunCall::ProposalSubmit(input) => {
                let change = RepoChange {
                    path: input.path.clone(),
                    content_hash: *blake3::hash(&input.content).as_bytes(),
                };
                // A store or gate failure while the host mints the
                // proposal's attribution ends the call as any memory
                // write's does; it is not a door answer.
                let failed = RefCell::new(None);
                let answer = memory.repo_proposal_submit_for_run(
                    &binding,
                    input,
                    self.repo_review_policy.as_deref(),
                    |stamp| match self.repo_run_sources(vault, stamp, &change) {
                        Ok(sources) => sources,
                        Err(error) => {
                            *failed.borrow_mut() = Some(error);
                            Err(MemoryError::new(
                                crate::memory::MEMORY_CODE_INTERNAL,
                                "the proposal's attribution was not minted",
                                &[],
                            ))
                        }
                    },
                );
                if let Some(error) = failed.into_inner() {
                    return Err(error);
                }
                answered(effect, answer)
            }
            RepoRunCall::MergeQueueEnqueue(input) => answered(
                effect,
                memory.repo_merge_queue_enqueue_for_run(&binding, input),
            ),
            RepoRunCall::CheckoutBind(input) => {
                answered(effect, memory.repo_checkout_bind_for_run(&binding, input))
            }
            RepoRunCall::Export(input) => {
                answered(effect, memory.repo_export_for_run(&binding, input))
            }
        }
    }

    /// Binds the host's review policy for this run's repo proposals (FIX
    /// 6867). Unbound, a run's proposal is held to the vault's own review
    /// policy, and with none set the same checked queue lands it on green
    /// (FIX 8268). No guest call reaches it.
    #[must_use]
    pub fn with_repo_review_policy(mut self, policy: Arc<dyn RepoReviewPolicy>) -> Self {
        self.repo_review_policy = Some(policy);
        self
    }

    /// The host binding of this run's call, read live: the run's own leased
    /// agent try, its actor checked against the try's dispatch payload, the
    /// TASK that try realizes, and the executor run of `site`. A run with no
    /// live lease or no TASK holds no current lease; a call its door
    /// admitted with no read lane reads no repo.
    fn repo_run_binding(
        &self,
        vault: &Vault,
        site: ExecutorCallSite<'_>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<std::result::Result<RepoRunBinding, RepoAccessRefusal>> {
        if self.agent_lease.is_none() {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        }
        let lease = match self.live_run_host_binding(site.run_id) {
            Ok(lease) => lease,
            Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(_))) => {
                return Ok(Err(RepoAccessRefusal::StaleLease));
            }
            Err(error) => return Err(error),
        };
        let record = match lease.leased_record(vault) {
            Ok(record) => record,
            Err(Error::InvalidClaimBody(_)) => return Ok(Err(RepoAccessRefusal::StaleLease)),
            Err(error) => return Err(error),
        };
        let Some(task) = record
            .task_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        else {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        };
        let Some(reader) = read_as else {
            return Ok(Err(RepoAccessRefusal::NoMembership));
        };
        Ok(RepoRunBinding::new(self.actor, lease, task, reader)
            .ok_or(RepoAccessRefusal::StaleLease))
    }

    /// The per-operation gate a run repo write meets before it runs: a
    /// synthetic decision on the row, the repo and the ref, under the run's
    /// own envelope naming the row and its bridge position. The run is
    /// admitted to the repo and ref first, so no decision is recorded for a
    /// write it could not make; the door admits it again in its writer. A
    /// rejection is the gate's own, as at any memory write.
    fn repo_operation_gate(
        &self,
        vault: &Vault,
        binding: &RepoRunBinding,
        call: &RepoRunCall,
        site: ExecutorCallSite<'_>,
    ) -> Result<std::result::Result<(), RepoAccessRefusal>> {
        let effect = call.effect();
        let (repo, git_ref) = match call {
            RepoRunCall::SnapshotsIngest(input) => (input.repo, input.git_ref.clone()),
            RepoRunCall::WorkOpen(input) => (input.repo, input.git_ref.clone()),
            RepoRunCall::CheckoutBind(input) => (input.repo, input.git_ref.clone()),
            RepoRunCall::Export(input) => (input.repo, input.git_ref.clone()),
            // A row on the run's own work is gated at that work's repo and
            // ref; a work that is not this run's is refused before any
            // decision is recorded.
            _ => {
                let Some(work) = call.work() else {
                    return Err(Error::InvariantViolation(
                        "a run repo read has no write gate",
                    ));
                };
                let txn = vault.store.env.read_txn()?;
                match vault.admitted_repo_work_in_txn(
                    &txn,
                    binding,
                    work,
                    NO_PATHS,
                    RepoAccessIntent::Read,
                )? {
                    Ok(own) => (own.stamp.repo, own.stamp.git_ref),
                    Err(refused) => return Ok(Err(refused)),
                }
            }
        };
        let target = repo_target(repo, &git_ref, NO_PATHS);
        let admitted = {
            let txn = vault.store.env.read_txn()?;
            vault.admit_repo_run_in_txn(&txn, binding, &target, RepoAccessIntent::Read)?
        };
        if let Err(refused) = admitted {
            return Ok(Err(refused));
        }
        let admission = self.non_candidate_code_emission_admission()?;
        let envelope = self.write_envelope_with(
            effect,
            admission.as_ref(),
            vec![
                (Value::from("verb"), Value::from(effect.as_str())),
                (Value::from("seq"), Value::from(site.seq)),
            ],
        )?;
        let body = self.operation_gate_body(
            effect,
            ClaimSubject::Entity(repo),
            Value::Map(vec![(Value::from("ref"), Value::from(git_ref.as_str()))]),
            &envelope,
        )?;
        let id = repo_operation_gate_id(effect, site)?;
        check_write_gate_against_vault(vault, id, &body, &envelope, false, |_| Ok(()))?;
        Ok(Ok(()))
    }
}

/// The gate id of one run repo write: its row, its executor run and its
/// bridge position, so each call is its own decision.
fn repo_operation_gate_id(effect: SelfEffect, site: ExecutorCallSite<'_>) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new_derive_key(REPO_OPERATION_GATE_ID_DOMAIN);
    hasher.update(effect.as_str().as_bytes());
    hasher.update(site.run_id.as_bytes());
    hasher.update(&site.seq.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    for tweak in 0..=u8::MAX {
        let mut candidate = bytes;
        candidate[0] ^= tweak;
        if let Ok(id) = EntityId::from_bytes(candidate) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "run repo gate id derivation failed",
    ))
}

/// A door's answer as the script reads it: the output with the rows it was
/// read from, or the refusal.
fn answered<T: serde::Serialize>(
    effect: SelfEffect,
    answer: MemoryResult<RepoRunAnswer<T>>,
) -> Result<SelfDispatchOutcome> {
    let RepoRunAnswer { output, mut rows } = match answer {
        Ok(answer) => answer,
        Err(error) => return Ok(refused(effect, &error)),
    };
    rows.sort_unstable();
    rows.dedup();
    let output = serde_json::to_value(&output)
        .map_err(|_| Error::InvariantViolation("run repo answer encode"))?;
    Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
        output,
        rows: Some(rows),
        observations: Vec::new(),
    }))
}

/// A typed repo refusal is a denial; any other door error a failure the
/// script reads, by its code.
fn refused(effect: SelfEffect, error: &MemoryError) -> SelfDispatchOutcome {
    if is_repo_refusal_code(&error.code) {
        return denied(effect, &error.code);
    }
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect,
        error: error.code.clone(),
    })
}

fn denied(effect: SelfEffect, code: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
        effect,
        outcome: code.to_owned(),
        reason_codes: Vec::new(),
    })
}
