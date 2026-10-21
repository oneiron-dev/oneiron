//! `self.code.proposal_submit` and `self.code.merge_queue.enqueue` (FIX
//! 6867, G1 PR2b): a leased run's one whole-file change against its own
//! work, kept as an immutable proposal at the work's pinned base, and the
//! queue entry that takes the run's exact stored proposals.
//!
//! Each is judged once more in its final writer under one admission
//! ([`RepoPublishAdmission`]): the run's Grant for an edit of every changed
//! path, the lease its work was bound with, and the run's own current
//! declaration, the same one the proposal was made under. A declaration
//! made, replaced, released or expired since is a stale lease; one the TASK
//! never had invents no requirement. Symbols order the queue and veto
//! nothing: an overlap waits.
//!
//! The host, never the guest, supplies the review policy, the actor's
//! session and the gated provenance. With no policy bound the proposal is
//! held to the vault's own review policy (FIX 8268), and with none set the
//! same checked queue lands it on green; with no model witness it answers
//! `repo_provenance_required` and the work is kept. Owner doors are
//! unchanged.

use std::collections::BTreeSet;

use super::symbols::symbol_run;
use super::work::{RepoOwnWork, open_local_repo, resolve_repo_queue_target};
use super::{
    NO_PATHS, RepoMergeQueueEnqueueInput, RepoMergeQueueEnqueueOutput, RepoProposalSubmitInput,
    RepoProposalSubmitOutput, RepoQueueEntryView, RepoRunAnswer, RepoRunBinding, RepoRunStamp,
    refusal_error, repo_target,
};
use crate::code_document::CodeOpProvenance;
use crate::code_symbol::{CodeSymbolManifest, code_symbol_entity_id};
use crate::codebase::RepoRef;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::federation::{RepoAccessIntent, RepoAccessRefusal, RepoTarget};
use crate::git_wire::GitOid;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::merge_queue::{
    MergeBatch, MergeFile, MergeProposal, MergeQueue, RepoQueueOrder, RepoQueuePredecessor,
};
use crate::repo_mutation::mount::RepoMountRef;
use crate::repo_mutation::proposal::{
    RepoProposal, RepoProposalOperation, RepoProposalReview, RepoProposalStatus,
};
use crate::repo_mutation::{RepoMutationOperation, RepoMutationRequest};
use crate::task_verb::SymbolLease;
use crate::{EntityId, Vault};

/// The code a run's proposal answered while the host bound no review policy
/// for its repo (CALL "FIX 6867 review policy and provenance"). Superseded
/// by FIX 8268: no review policy now means the vault's default, so no
/// proposal answers it; it stays a typed hold code older answers carry.
pub const REPO_REVIEW_POLICY_REQUIRED: &str = "repo_review_policy_required";

/// The code a run's proposal answers while its host holds no witness of the
/// model request the run is serving. No author is made up.
pub const REPO_PROVENANCE_REQUIRED: &str = "repo_provenance_required";

/// The host's review policy for a run's proposals. A host binds it; no
/// guest field reaches it. The stock one holds every proposal to the
/// vault's review policy (FIX 8268); a host catalog is an explicit
/// requirement beside it.
pub trait RepoReviewPolicy: Send + Sync {
    /// The review proposals to `repo` under `project` are held to.
    ///
    /// # Errors
    /// A read that fails: the proposal is not made, and never reviewless.
    fn review(&self, project: EntityId, repo: EntityId) -> Result<RepoProposalReview>;
}

/// The attribution the host mints for a run's proposal: the actor's
/// session, a gated `repo.provenance` claim naming the real actor, model,
/// request and work, and the operation's provenance. Attribution, never
/// authority; no field is the guest's.
pub struct RepoRunSources {
    pub(crate) session: EntityId,
    pub(crate) provenance_claim: EntityId,
    pub(crate) op_provenance: CodeOpProvenance,
}

/// The CALL "acceptance transfers the publication right", held at a run's
/// submission: what its proposal or queue entry is judged on in its final
/// writer. The run's Grant must admit an edit of every changed path, its
/// lease must be the one its work was bound with, and its own current
/// declaration must be `declaration`. Once the queue accepts the exact
/// candidate, the queue finishes it; no later check of the worker applies.
pub(crate) struct RepoPublishAdmission {
    declaration: Option<EntityId>,
}

impl RepoPublishAdmission {
    /// The declaration the act is made under, if the run has one.
    pub(crate) const fn declaration(&self) -> Option<EntityId> {
        self.declaration
    }

    /// Judges the act on `target` in `txn`: the run's current declaration,
    /// or the refusal.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    fn admit_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        target: &RepoTarget,
        now: u64,
    ) -> Result<std::result::Result<Option<SymbolLease>, RepoAccessRefusal>> {
        if let Err(refused) =
            vault.readmit_repo_work_in_txn(txn, binding, own, target, RepoAccessIntent::Edit)?
        {
            return Ok(Err(refused));
        }
        let current = run_declaration(vault, txn, binding, &own.stamp, now)?;
        if current.as_ref().map(|lease| lease.declaration_id) != self.declaration {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        }
        Ok(Ok(current))
    }
}

/// The run's own current declaration of its TASK, read in `txn`.
fn run_declaration(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &RepoRunBinding,
    stamp: &RepoRunStamp,
    now: u64,
) -> Result<Option<SymbolLease>> {
    crate::task_verb::run_declaration_in_txn(
        vault,
        txn,
        binding.task,
        binding.actor.entity_ref(),
        &symbol_run(stamp),
        now,
    )
}

/// The CALL "FIX 6867 run-only overlap granularity": the symbols a
/// whole-file change touches are every symbol the repo's stored manifest
/// records on a changed path, and every symbol of the run's declaration. It
/// may wait behind more work than it overlaps; it never vetoes.
///
/// # Errors
/// A manifest symbol whose id does not derive.
pub(crate) fn repo_touched_symbols(
    manifest: Option<&CodeSymbolManifest>,
    paths: &[String],
    declaration: Option<&SymbolLease>,
) -> Result<BTreeSet<String>> {
    let mut touched = declaration
        .map(|lease| lease.symbols.clone())
        .unwrap_or_default();
    if let Some(manifest) = manifest {
        for symbol in &manifest.symbols {
            if paths.contains(&symbol.path) {
                touched.insert(code_symbol_entity_id(&manifest.repo_ref, symbol)?.to_hex());
            }
        }
    }
    Ok(touched)
}

/// Whether the provenance claim `claim`, read in `txn`, is the one the host
/// minted for this actor's change in `work`.
///
/// # Errors
/// A claim that is not there, or names another actor or work.
fn require_run_provenance_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
    actor: EntityId,
    work: EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &claim)?
        .ok_or(Error::EntityNotFound)?;
    let body = crate::claim::decode_claim_body(
        raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("provenance claim header"))?,
        true,
    )?;
    let field = |map: &rmpv::Value, key: &str| -> Option<String> {
        map.as_map()?
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str().map(str::to_owned))
    };
    let lineage = body.value.as_map().and_then(|entries| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some("diff_lineage_receipt"))
            .map(|(_, value)| value)
    });
    if field(&body.value, "actor") != Some(actor.to_hex())
        || lineage.and_then(|lineage| field(lineage, "work")) != Some(work.to_hex())
    {
        return Err(Error::InvariantViolation(
            "a run's provenance claim names another actor or work",
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// `self.code.proposal_submit` for a run: one whole-file change of a path
    /// the Grant edits, against the run's own work, kept as an immutable
    /// Proposed proposal whose base is the work's pinned commit. The host's
    /// review policy names the catalog and `sources` mints the actor's
    /// session and provenance, after the run is admitted and before the
    /// proposal's writer, which judges the run, its declaration and that
    /// provenance again. Nothing lands, is approved or is queued.
    pub fn repo_proposal_submit_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoProposalSubmitInput,
        policy: Option<&dyn RepoReviewPolicy>,
        sources: impl FnOnce(&RepoRunStamp) -> MemoryResult<RepoRunSources>,
    ) -> MemoryResult<RepoRunAnswer<RepoProposalSubmitOutput>> {
        let own = self.repo_own_work(
            binding,
            input.work,
            [input.path.as_str()],
            RepoAccessIntent::Edit,
        )?;
        let now = self.vault.now_recorded_at();
        let admission = self.repo_publish_admission(binding, &own, input.declaration, now)?;
        // Unbound, the vault's own review policy (FIX 8268).
        let review = match policy {
            Some(policy) => policy.review(own.stamp.project, own.stamp.repo)?,
            None => RepoProposalReview::VaultDefault,
        };
        let membership = &own.admitted.membership;
        let RepoRef::LocalFolder { path: folder, .. } = &membership.repo_ref else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let Some(repo) = open_local_repo(self.vault, &membership.repo_ref) else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let green = GitOid::parse_hex(own.stamp.base_green.as_str())?;
        let base = self.vault.capture_repo_snapshot_at_commit(&repo, &green)?;
        let sources = sources(&own.stamp)?;
        let request = RepoMutationRequest::new(
            RepoRef::LocalFolder {
                path: folder.clone(),
                commit: own.stamp.base_green.clone(),
            },
            RepoMutationOperation::CommitFile {
                path: input.path.clone(),
                content: input.content,
                message: input.message,
            },
        )
        .with_write_actor(binding.actor)
        .with_session_id(sources.session)
        .with_provenance_claim_id(sources.provenance_claim)
        .with_op_provenance(sources.op_provenance);
        let stamp = RepoRunStamp {
            symbol_fence: admission.declaration(),
            ..own.stamp.clone()
        };
        let target = repo_target(own.stamp.repo, &own.stamp.git_ref, [input.path.as_str()]);
        let proposed =
            self.vault
                .propose_repo_mutation_for_run(request, review, base, stamp, |txn| {
                    if let Err(refused) =
                        admission.admit_in_txn(self.vault, txn, binding, &own, &target, now)?
                    {
                        return Ok(Err(refused));
                    }
                    require_run_provenance_in_txn(
                        self.vault,
                        txn,
                        sources.provenance_claim,
                        binding.actor.entity_ref(),
                        own.stamp.work,
                    )?;
                    Ok(Ok(()))
                })?;
        let proposal = proposed.map_err(refusal_error)?;
        Ok(RepoRunAnswer {
            rows: vec![own.stamp.repo],
            output: RepoProposalSubmitOutput {
                proposal: proposal.id,
                work: input.work,
                path: proposal.ordinary_file()?.0.to_owned(),
                base_green: own.stamp.base_green.clone(),
                base_snapshot: bytes_to_hex_lower(&proposal.pre_action_fork_hash),
                session: proposal.session,
                provenance_claim: proposal.provenance_claim,
                declaration: admission.declaration(),
                status: proposal.status,
            },
        })
    }

    /// `self.code.merge_queue.enqueue` for a run: its own stored proposals of
    /// one work, exactly as stored, queued as one batch at the work's green
    /// through the queue's one batch formation. The batch writer judges the
    /// run, each proposal and the declaration again, and keeps the live
    /// declarations of other TASKs that overlapped it then, which it waits
    /// behind; it is never refused for them. A proposal another run made, or
    /// one made under a declaration the run no longer holds, is not taken.
    pub fn repo_merge_queue_enqueue_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoMergeQueueEnqueueInput,
    ) -> MemoryResult<RepoRunAnswer<RepoMergeQueueEnqueueOutput>> {
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let rows = input
            .proposals
            .iter()
            .map(|id| self.repo_run_proposal(binding, &own, *id))
            .collect::<MemoryResult<Vec<_>>>()?;
        let paths: Vec<String> = rows
            .iter()
            .flat_map(|row| row.paths().into_iter().map(str::to_owned))
            .collect();
        let target = repo_target(own.stamp.repo, &own.stamp.git_ref, &paths);
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.vault
                .readmit_repo_work_in_txn(&txn, binding, &own, &target, RepoAccessIntent::Edit)?
                .map_err(refusal_error)?;
        }
        let now = self.vault.now_recorded_at();
        let admission = self.repo_publish_admission(binding, &own, input.declaration, now)?;
        if rows.iter().any(|row| {
            row.run.as_ref().and_then(|stamp| stamp.symbol_fence) != admission.declaration()
        }) {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        let membership = &own.admitted.membership;
        let pointers =
            resolve_repo_queue_target(self.vault, &membership.repo_ref, &own.stamp.git_ref)?
                .map_err(refusal_error)?;
        if pointers.green != own.stamp.base_green {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the queue's green moved past this work's pin; nothing rebases",
                &["Open a fresh work at the current green and propose the change again."],
            ));
        }
        let queue = MergeQueue::open(self.vault, membership.repo_ref.clone())?;
        let candidates = rows
            .iter()
            .map(|row| self.repo_run_candidate(row, &own.stamp.base_green))
            .collect::<MemoryResult<Vec<_>>>()?;
        let manifest = self.vault.get_code_symbol_manifest(&own.stamp.repo)?;
        let accepted: Vec<EntityId> = rows.iter().map(|row| row.id).collect();
        let formed = queue.enqueue_for_run(candidates, |txn| {
            let declaration =
                match admission.admit_in_txn(self.vault, txn, binding, &own, &target, now)? {
                    Ok(declaration) => declaration,
                    Err(refused) => return Ok(Err(refused)),
                };
            for row in &rows {
                let current = self.vault.repo_proposal_in_txn(txn, row.id)?;
                if !current.as_ref().is_some_and(|current| {
                    unqueued_candidate(current)
                        && current.files == row.files
                        && current.pre_action_fork_hash == row.pre_action_fork_hash
                        && current.run == row.run
                }) {
                    return Err(crate::contract_oracle::invalid(
                        "a proposal of this entry is no longer an unqueued candidate",
                    ));
                }
            }
            let symbols = repo_touched_symbols(manifest.as_ref(), &paths, declaration.as_ref())?;
            let predecessors = crate::task_verb::symbol_blockers_in_txn(
                self.vault,
                txn,
                binding.task,
                &symbols,
                now,
            )?
            .into_iter()
            .map(|(task, declaration)| RepoQueuePredecessor { task, declaration })
            .collect();
            Ok(Ok(RepoQueueOrder {
                work: input.work,
                task: binding.task,
                holder: binding.actor.entity_ref(),
                proposals: accepted,
                declaration: declaration.map(|lease| lease.declaration_id),
                symbols,
                predecessors,
                sequence: 0,
            }))
        })?;
        let batch = formed.map_err(refusal_error)?;
        let (entry, blockers) = self.repo_entry_view(binding, &queue, batch, now)?;
        let mut answer_rows = vec![own.stamp.repo];
        answer_rows.extend(blockers);
        Ok(RepoRunAnswer {
            rows: answer_rows,
            output: entry,
        })
    }

    /// The queue entries accepted from the run's work `work` in the queue of
    /// `repo_ref`, each with what it waits behind now, and the blockers they
    /// list (FIX 6949).
    pub(super) fn repo_queue_entries(
        &self,
        binding: &RepoRunBinding,
        repo_ref: &RepoRef,
        work: EntityId,
    ) -> MemoryResult<(Vec<RepoQueueEntryView>, Vec<EntityId>)> {
        let queue = MergeQueue::open(self.vault, repo_ref.clone())?;
        let now = self.vault.now_recorded_at();
        let mut entries = Vec::new();
        let mut listed = Vec::new();
        for batch in queue.run_batches_of(work)? {
            let (entry, blockers) = self.repo_entry_view(binding, &queue, batch, now)?;
            entries.push(entry);
            listed.extend(blockers);
        }
        Ok((entries, listed))
    }

    /// The run's declaration an act is made under: its TASK's current
    /// declaration of this run, whichever the guest named. Naming another,
    /// or one that is released, replaced or expired, is a stale lease.
    fn repo_publish_admission(
        &self,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        named: Option<EntityId>,
        now: u64,
    ) -> MemoryResult<RepoPublishAdmission> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let current = run_declaration(self.vault, &txn, binding, &own.stamp, now)?
            .map(|lease| lease.declaration_id);
        if named.is_some() && named != current {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        Ok(RepoPublishAdmission {
            declaration: current,
        })
    }

    /// The stored proposal `id`, when the run made it in its work `own`
    /// under the same lease and it is still an unqueued candidate. Another
    /// run's, an owner's or an unknown proposal is no membership, so no id is
    /// an existence oracle; this run's made under an older lease of its try
    /// is a stale lease.
    fn repo_run_proposal(
        &self,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        id: EntityId,
    ) -> MemoryResult<RepoProposal> {
        let not_ours = || refusal_error(RepoAccessRefusal::NoMembership);
        let row = self.vault.repo_proposal(id)?.ok_or_else(not_ours)?;
        let Some(stamp) = &row.run else {
            return Err(not_ours());
        };
        if stamp.work != own.stamp.work
            || stamp.executor_run != binding.executor_run
            || stamp.task != binding.task
            || row.actor.id() != Some(binding.actor.entity_ref())
        {
            return Err(not_ours());
        }
        if !own.admitted.holds(stamp) {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        if !unqueued_candidate(&row)
            || stamp.base_green != own.stamp.base_green
            || row.pre_action_fork_hash != own.stamp.base_snapshot
        {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the proposal is not an unqueued candidate of this work",
                &["Submit the change again from this work."],
            ));
        }
        Ok(row)
    }

    /// The queue's input for a run's stored proposal: its path and reviewed
    /// bytes, and the bytes it replaces read from its own retained base. No
    /// byte comes from the request.
    fn repo_run_candidate(
        &self,
        row: &RepoProposal,
        base_green: &str,
    ) -> MemoryResult<MergeProposal> {
        let pointer = RepoRef::parse(&row.repo)?;
        let base = self
            .vault
            .mount_repo_ref(&pointer, RepoMountRef::Fork(row.pre_action_fork_hash))?;
        let (path, content) = row.ordinary_file()?;
        let expected = base.read_file(path)?.map(<[u8]>::to_vec);
        Ok(MergeProposal {
            id: row.id.to_hex(),
            base_green: base_green.to_owned(),
            files: vec![MergeFile {
                path: path.to_owned(),
                expected,
                content: Some(content.to_vec()),
                metadata_edit: None,
            }],
        })
    }

    /// A run's queue entry as it reads it, with the blockers its lane reads.
    fn repo_entry_view(
        &self,
        binding: &RepoRunBinding,
        queue: &MergeQueue<'_>,
        batch: MergeBatch,
        now: u64,
    ) -> MemoryResult<(RepoQueueEntryView, Vec<EntityId>)> {
        let blockers = queue.run_batch_blockers(&batch, now)?;
        let blockers = self.repo_lane_readable(binding, blockers)?;
        let order = batch.run_order.ok_or(Error::InvariantViolation(
            "a run's queue entry lost its order",
        ))?;
        Ok((
            RepoQueueEntryView {
                batch: batch.id,
                work: order.work,
                proposals: order.proposals,
                declaration: order.declaration,
                state: batch.state,
                base_green: batch.base_green,
                expected_head: batch.expected_head,
                landed_head: batch.landed_head,
                blockers: blockers.clone(),
            },
            blockers,
        ))
    }
}

/// Whether `row` is a one-file change no batch has taken yet.
fn unqueued_candidate(row: &RepoProposal) -> bool {
    row.operation == RepoProposalOperation::CommitFile
        && row.merge_stack.is_none()
        && row.operation_seq.is_none()
        && matches!(
            row.status,
            RepoProposalStatus::Proposed | RepoProposalStatus::Approved
        )
}
