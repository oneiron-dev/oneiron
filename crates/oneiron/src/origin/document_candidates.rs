//! Accepted-push candidate intake (FIX 6869, G4 PR2).
//!
//! The merge queue's one drain asks, once a pass, for this store's retained
//! received refs that carry no resolved candidate, and matches each one
//! after its publication landed. Matching proves the push again through the
//! shared admitted-push check, then resolves its base EXACTLY (CALL L
//! `resolve_push_candidate_base`): the recorded old tip is the stable
//! projection of one tested revision of this store, the checked commit of
//! this queue's approved imported Baseline, or the incoming tip of an
//! earlier push a tested revision consumed completely. No text, live head,
//! trailer or ref name stands in. One pushed ref update becomes ONE fork
//! and ONE Proposed bundle carrying every file, co-committed with the
//! candidate. Every other outcome is a typed hold that keeps the source;
//! the receive result never changes and nothing is approved or queued.
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::document_candidate_types::{
    CodePushCandidate, CodePushCandidateHold, CodePushCandidateState, ReceivedCandidateRef,
    ReceivedRefIngress, ResolvedPushCandidate,
};
use super::document_ingress::{CODE_OPERATIONS, ProvenanceRefKey};
use super::publication::OriginPublicationStatus;
use crate::code_revision::{CodeRevision, CodeRevisionFork};
use crate::codebase::entity_id_from_hash_material;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo, lock_repository};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SESSION;
use crate::repo_mutation::proposal::RepoProposedFile;
use crate::repo_mutation::{
    PreparedRepoProposal, ReceivedFilesProposalInput, received_proposal_id,
};
use crate::{EntityId, TimeRange, Vault};

mod files;
mod reads;
use files::prepare_push_candidate_documents;

type Held<T> = std::result::Result<T, CodePushCandidateHold>;

/// A submodule link's Git mode.
const MODE_GITLINK: u32 = 0o160_000;

fn hold<T>(state: CodePushCandidateState, reason: &str) -> Result<Option<Held<T>>> {
    Ok(Some(Err(CodePushCandidateHold {
        state,
        reason: reason.to_owned(),
    })))
}

/// What the queue's intake knows of its own store: the local folder its
/// proposals pin, its sealed green revision and its sealed checked
/// Baseline, each read from its own rows.
pub(crate) struct CandidateQueue {
    pub(crate) folder: String,
    pub(crate) green: Option<CodeRevision>,
    pub(crate) baseline: Option<EntityId>,
}

/// One candidate ready to attach: its frozen resolution, its fork and its
/// ONE prepared all-files proposal.
pub(crate) struct PreparedPushCandidate {
    candidate: CodePushCandidate,
    fork: CodeRevisionFork,
    proposal: PreparedRepoProposal,
}

/// The base a candidate resolved to, and the push it stands on.
struct PushCandidateBase {
    revision: CodeRevision,
    anchor: Option<EntityId>,
}

/// The deterministic candidate id of one pushed ref.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn push_candidate_id(
    store: &str,
    provenance: EntityId,
    ref_name: &str,
) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:push-candidate:v1",
        &[store.as_bytes(), provenance.as_bytes(), ref_name.as_bytes()],
    )
}

/// The source digest: the proven store, push, ref, tips and each
/// operation's identity, path, hashes, modes and document flag. Erasable
/// actor labels stay out; they are judged again from the source on use.
fn source_digest(row: &ReceivedRefIngress, provenance: EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:push-candidate-source:v1");
    hasher.update(provenance.as_bytes());
    let source = &row.source;
    for part in [
        source.object_store.as_str(),
        source.ref_name.as_str(),
        source.old_oid.as_deref().unwrap_or(""),
        source.new_oid.as_deref().unwrap_or(""),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(&(row.operations.len() as u64).to_be_bytes());
    for operation in &row.operations {
        for part in [
            operation.operation_id.as_str(),
            operation.session_id.as_str(),
            operation.path.as_str(),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher.update(&operation.before_hash);
        hasher.update(&operation.after_hash);
        hasher.update(&operation.old_mode.unwrap_or(0).to_be_bytes());
        hasher.update(&operation.new_mode.unwrap_or(0).to_be_bytes());
        hasher.update(&[u8::from(operation.document_edit)]);
    }
    *hasher.finalize().as_bytes()
}

/// The candidate digest a complete-push link carries: its source digest
/// and its frozen resolution, never its changing progress.
fn candidate_digest(candidate: &CodePushCandidate) -> Result<[u8; 32]> {
    let resolved = rmp_serde::to_vec_named(&candidate.resolved)
        .map_err(|_| Error::InvariantViolation("push candidate encoding failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:push-candidate-digest:v1");
    hasher.update(&candidate.source_digest);
    hasher.update(&resolved);
    Ok(*hasher.finalize().as_bytes())
}

impl Vault {
    /// Every retained received ref of the object store `store` that has no
    /// resolved candidate yet, held ones included, in key order.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn pending_received_code_candidates(
        &self,
        store: &str,
    ) -> Result<Vec<ReceivedCandidateRef>> {
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for row in CODE_OPERATIONS.iter_from(&self.store, &txn, &[])? {
            let (key, row) = row?;
            if row.source.object_store == store
                && row
                    .candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.resolved.is_none())
            {
                pending.push(ReceivedCandidateRef {
                    object_store: row.source.object_store,
                    provenance: key.provenance,
                    ref_name: row.source.ref_name,
                });
            }
        }
        Ok(pending)
    }

    /// The retained received ref `ref_name` of the push `provenance`, in
    /// `txn`. A pure read.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_code_ingress_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        ref_name: &str,
    ) -> Result<Option<ReceivedRefIngress>> {
        CODE_OPERATIONS.get(
            &self.store,
            txn,
            &ProvenanceRefKey::of(provenance, ref_name),
        )
    }

    /// Matches one retained received ref under the repository writer and
    /// writes its candidate: an attachment, or a changed hold. Answers
    /// whether a durable transition was written; an unchanged hold, an
    /// in-flight publication or an attached candidate writes nothing.
    ///
    /// # Errors
    /// An object store or store failure. A hold is no error.
    pub(crate) fn match_received_code_candidate(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        queue: &CandidateQueue,
        source: &ReceivedCandidateRef,
    ) -> Result<bool> {
        let _guard = lock_repository(repo.common_dir())?;
        let key = ProvenanceRefKey::of(source.provenance, &source.ref_name);
        let row = {
            let txn = self.store.env.read_txn()?;
            CODE_OPERATIONS.get(&self.store, &txn, &key)?
        };
        let Some(row) = row else {
            return Ok(false);
        };
        if row.source.object_store != repo.identity().as_hex()
            || row
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.resolved.is_some())
        {
            return Ok(false);
        }
        let id = push_candidate_id(
            &row.source.object_store,
            source.provenance,
            &row.source.ref_name,
        )?;
        let digest = source_digest(&row, source.provenance);
        let decided =
            self.decide_push_candidate(wire, repo, queue, source.provenance, &row, id, digest)?;
        let Some(decided) = decided else {
            return Ok(false);
        };
        let mut wtxn = self.store.env.write_txn()?;
        let written = match decided {
            Err(held) => self.attach_received_code_hold_in_txn(
                &mut wtxn,
                &key,
                &row,
                CodePushCandidate {
                    candidate: id,
                    source_digest: digest,
                    resolved: None,
                    hold: Some(held),
                },
            )?,
            Ok(prepared) => {
                self.attach_received_code_candidate_in_txn(&mut wtxn, &key, &row, &prepared)?
            }
        };
        if written {
            wtxn.commit()?;
        }
        Ok(written)
    }

    /// Decides one candidate: `None` while its publication is in flight,
    /// a typed hold, or the prepared attachment.
    #[allow(clippy::too_many_arguments)]
    fn decide_push_candidate(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        queue: &CandidateQueue,
        provenance: EntityId,
        row: &ReceivedRefIngress,
        id: EntityId,
        digest: [u8; 32],
    ) -> Result<Option<Held<PreparedPushCandidate>>> {
        use CodePushCandidateState::{HeldReviewPolicy, HeldShape};
        let source = &row.source;
        let Some(new_hex) = &source.new_oid else {
            return hold(HeldShape, "ref_deleted");
        };
        let Some(old_hex) = &source.old_oid else {
            return hold(CodePushCandidateState::HeldBase, "no_old_tip");
        };
        let new = GitOid::parse_hex(new_hex.clone())?;
        let old = GitOid::parse_hex(old_hex.clone())?;
        let kinds = wire.object_info(repo, &[old.clone(), new.clone()])?;
        if kinds.get(&new).map(String::as_str) != Some("commit")
            || kinds.get(&old).map(String::as_str) != Some("commit")
        {
            return hold(HeldShape, "not_a_commit");
        }
        let repo_id = super::lfs::lfs_repo_id(&source.object_store)?;
        let Some(record) = self.find_origin_publication(repo_id, |record| {
            record.provenance_claim_id == provenance
                && record.ref_name.as_str() == source.ref_name
                && record.new_oid == new
        })?
        else {
            return Ok(None);
        };
        match record.status {
            OriginPublicationStatus::Prepared => return Ok(None),
            OriginPublicationStatus::Published => {}
            OriginPublicationStatus::Failed | OriginPublicationStatus::Conflicted => {
                return hold(HeldShape, "publication_not_published");
            }
        }
        let (record, new_tree) = match self.require_admitted_push(
            wire,
            repo,
            record.publication_id,
            &record.ref_name,
            &new,
        ) {
            Ok(admitted) => admitted,
            Err(Error::Refused(_)) => return hold(HeldShape, "push_not_admitted"),
            Err(error) => return Err(error),
        };
        let Some(pusher) = record.actor_id.id() else {
            return hold(HeldShape, "pusher_erased");
        };
        // CALL R `received_candidate_queue_readiness`: exactly zero
        // changed files keeps the source and holds; nothing empty queues.
        if row.operations.is_empty() {
            return hold(HeldShape, "no_change");
        }
        if wire.merge_base(repo, old.as_str(), new.as_str())? != old {
            return hold(HeldShape, "non_fast_forward");
        }
        let base = match self.resolve_push_candidate_base(wire, repo, queue, &old)? {
            Ok(base) => base,
            Err(held) => return Ok(Some(Err(held))),
        };
        let catalog = {
            let txn = self.store.env.read_txn()?;
            let owners = crate::policy_model::owners_in_txn(self, &txn)?;
            self.owner_review_catalog_in_txn(&txn, &owners, &queue.folder)?
        };
        let Some(catalog) = catalog else {
            return hold(HeldReviewPolicy, "repo_review_policy_required");
        };
        let tested = base
            .revision
            .tested_queue
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "a resolved base is a tested revision",
            ))?;
        let proposal = received_proposal_id(id)?;
        let files = match prepare_push_candidate_documents(
            wire,
            repo,
            &base.revision,
            row,
            &old,
            &new_tree,
            proposal,
        )? {
            Ok(files) => files,
            Err(held) => return Ok(Some(Err(held))),
        };
        let fork_session = entity_id_from_hash_material(
            b"oneiron:push-candidate-session:v1",
            &[id.as_bytes(), base.revision.revision_id.as_bytes()],
        )?;
        let message = format!(
            "Received push to {}: {}..{}",
            source.ref_name,
            &old.as_str()[..12],
            &new.as_str()[..12]
        );
        let input = ReceivedFilesProposalInput {
            candidate: id,
            proposal,
            folder: queue.folder.clone(),
            base_commit: GitOid::parse_hex(tested.commit.clone())?,
            pusher,
            session: fork_session,
            provenance,
            message,
            files: files
                .iter()
                .map(|file| RepoProposedFile {
                    path: file.0.path.clone(),
                    content: file.1.clone(),
                    source_operation: Some(file.0.source_operation),
                    metadata_edit: Some(file.0.metadata_edit.clone()),
                })
                .collect(),
            catalog,
            created_at: row.received_at,
        };
        let prepared = match self.prepare_received_files_proposal(repo, input)? {
            Ok(prepared) => prepared,
            Err(_) => return hold(HeldShape, "base_snapshot_refused"),
        };
        Ok(Some(Ok(PreparedPushCandidate {
            candidate: CodePushCandidate {
                candidate: id,
                source_digest: digest,
                resolved: Some(ResolvedPushCandidate {
                    base_revision: base.revision.revision_id,
                    base_commit: tested.commit.clone(),
                    base_inventory_digest: tested.inventory_digest,
                    snapshot_anchor: base.anchor,
                    publication: record.publication_id,
                    new_tree: new_tree.as_str().to_owned(),
                    fork_session,
                    proposal_id: proposal,
                    resolved_at: row.received_at,
                    files: files.into_iter().map(|file| file.0).collect(),
                }),
                hold: None,
            },
            fork: CodeRevisionFork::new(
                fork_session,
                base.revision.session_id,
                base.revision.revision_id,
                row.received_at,
            ),
            proposal: prepared,
        })))
    }

    /// CALL L `resolve_push_candidate_base`: the ONE tested revision of this
    /// store the old tip `old` names exactly, whose checked tree is the old
    /// tip's tree. A recorded export, the queue's approved imported
    /// Baseline, or a sealed complete earlier push; none, or more than one,
    /// holds. No same-text, live-head or ref fallback.
    fn resolve_push_candidate_base(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        queue: &CandidateQueue,
        old: &GitOid,
    ) -> Result<Held<PushCandidateBase>> {
        use CodePushCandidateState::{HeldBase, HeldPredecessor};
        let held = |state, reason: &str| {
            Ok(Err(CodePushCandidateHold {
                state,
                reason: reason.to_owned(),
            }))
        };
        let store = repo.identity().as_hex();
        let mut bases: BTreeSet<EntityId> = self
            .exported_engine_revisions(repo, old)?
            .into_iter()
            .collect();
        if let Some(baseline) = queue.baseline
            && self
                .resolve_code_revision_import_anchor(baseline)?
                .is_some_and(|manifest| {
                    manifest.anchor.source_commit == old.as_str()
                        && manifest.anchor.object_store == store
                })
        {
            bases.insert(baseline);
        }
        let mut next = queue.green.clone();
        for _ in 0..crate::limits::MAX_ANCESTOR_DEPTH {
            let Some(revision) = next else {
                break;
            };
            if revision.tested_queue.as_ref().is_some_and(|tested| {
                tested
                    .received_pushes
                    .iter()
                    .any(|link| link.new_commit == old.as_str())
            }) {
                bases.insert(revision.revision_id);
                break;
            }
            next = match revision.parent_revision_id {
                Some(parent) => self.get_code_revision(&parent)?,
                None => None,
            };
        }
        let mut found = bases.into_iter();
        let (Some(id), None) = (found.next(), found.next()) else {
            if self.received_predecessor_pending(&store, old)? {
                return held(HeldPredecessor, "predecessor_unsealed");
            }
            return held(HeldBase, "no_exact_base_or_ambiguous_base");
        };
        let Some(revision) = self.get_code_revision(&id)? else {
            return held(HeldBase, "base_revision_missing");
        };
        let Some(tested) = &revision.tested_queue else {
            return held(HeldBase, "base_not_tested");
        };
        let old_tree = wire
            .commit_trees(repo, std::slice::from_ref(old))?
            .remove(old)
            .ok_or(Error::EntityNotFound)?;
        if tested.store != store || tested.tree != old_tree.as_str() {
            return held(HeldBase, "old_tree_differs");
        }
        let anchor = self
            .resolve_code_revision_import_anchor(revision.revision_id)?
            .map(|manifest| crate::code_revision::manifest_id(&manifest.digest))
            .transpose()?;
        Ok(Ok(PushCandidateBase { revision, anchor }))
    }

    /// Whether an earlier received ref of `store` resolved to the incoming
    /// tip `old`: the push it continues has no sealed revision yet.
    fn received_predecessor_pending(&self, store: &str, old: &GitOid) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        for row in CODE_OPERATIONS.iter_from(&self.store, &txn, &[])? {
            let (_, row) = row?;
            if row.source.object_store == store
                && row.source.new_oid.as_deref() == Some(old.as_str())
                && row
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.resolved.is_some())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Writes a changed hold on the source row in `wtxn`; an identical one
    /// writes nothing. A row that moved, or resolved meanwhile, is kept.
    fn attach_received_code_hold_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: &ProvenanceRefKey,
        expected: &ReceivedRefIngress,
        candidate: CodePushCandidate,
    ) -> Result<bool> {
        let Some(mut current) = CODE_OPERATIONS.get(&self.store, wtxn, key)? else {
            return Ok(false);
        };
        if current.source != expected.source
            || current.operations != expected.operations
            || current
                .candidate
                .as_ref()
                .is_some_and(|held| held.resolved.is_some() || *held == candidate)
        {
            return Ok(false);
        }
        current.candidate = Some(candidate);
        CODE_OPERATIONS.put(&self.store, wtxn, key, &current)?;
        Ok(true)
    }

    /// Co-commits the candidate's fork SESSION and fork, its ONE Proposed
    /// bundle and the source row's attachment in `wtxn`, after reading the
    /// source and its publication again. A resolution is frozen: once
    /// attached it is never rebound.
    ///
    /// # Errors
    /// A source or publication that moved, an identity holding another
    /// record, or a store failure.
    fn attach_received_code_candidate_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: &ProvenanceRefKey,
        expected: &ReceivedRefIngress,
        prepared: &PreparedPushCandidate,
    ) -> Result<bool> {
        let Some(mut current) = CODE_OPERATIONS.get(&self.store, wtxn, key)? else {
            return Ok(false);
        };
        if current.source != expected.source || current.operations != expected.operations {
            return Err(Error::ConcurrentWrite("a received ref source changed"));
        }
        if current
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.resolved.is_some())
        {
            return Ok(false);
        }
        let resolved = prepared
            .candidate
            .resolved
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "an attachment carries its resolution",
            ))?;
        if !self
            .origin_publication_in_txn(wtxn, resolved.publication)?
            .is_some_and(|record| record.status == OriginPublicationStatus::Published)
        {
            return Err(Error::ConcurrentWrite(
                "a received push's publication moved",
            ));
        }
        let fork = &prepared.fork;
        match self
            .store
            .port_entity_record(wtxn, &fork.fork_session_id)?
            .map(|record| record.entity_type)
        {
            None => {
                let at = fork.forked_at;
                let body = format!("push candidate {}", prepared.candidate.candidate.to_hex());
                self.batch_in()
                    .put(
                        &fork.fork_session_id,
                        ENTITY_TYPE_SESSION,
                        TimeRange { start: at, end: at },
                        at,
                        body.as_bytes(),
                    )
                    .apply(wtxn)?;
            }
            Some(ENTITY_TYPE_SESSION) => {}
            Some(_) => {
                return Err(Error::CorruptedIndex(
                    "a push candidate session identity is occupied",
                ));
            }
        }
        crate::code_revision::attach_code_revision_fork_in_txn(&self.store, wtxn, fork)?;
        // The attachment first: the bundle's own writer proves its source
        // from it, in this same transaction.
        current.candidate = Some(prepared.candidate.clone());
        CODE_OPERATIONS.put(&self.store, wtxn, key, &current)?;
        self.persist_received_files_proposal_in_txn(wtxn, &prepared.proposal)?;
        Ok(true)
    }
}
