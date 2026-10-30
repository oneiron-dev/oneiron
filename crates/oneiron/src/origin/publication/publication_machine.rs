//! State machine: stage, advance, CAS, finish/refuse/finalize T2, availability gate, pin release and orphan sweep.

use std::collections::BTreeSet;

use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::{
    GitOid, GitWire, GitWireCommitOutcome, GitWireRejection, GitWireRepo, lock_repository,
};
use crate::origin::lfs::LfsOid;
use crate::scan_check::{EngineScan, ScanCount};

#[cfg(test)]
use super::publication_codec::origin_publication_id;
use super::publication_codec::{
    CAS_INTENT, CasIntentKey, KEEP_OWNER, OriginPublicationRow, PUBLICATIONS, VISIBLE_REF,
    bounded_failure, keep_owner_key, origin_publication_claim_id, origin_publication_intent_claim,
    publication_claim_body, visible_ref_key,
};
#[cfg(test)]
use super::publication_journal::validate_origin_publication_request;
use super::publication_journal::{OriginAdvance, origin_receipt};
use super::publication_types::{
    ORIGIN_PUBLICATION_INTENT_PREDICATE, ORIGIN_PUBLICATION_PREDICATE, OriginActor,
    OriginCensusDisposition, OriginKeepRefKind, OriginPublicationReceipt, OriginPublicationRecord,
    OriginPublicationRequest, OriginPublicationStatus,
};
// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// What admission made of one publication request.
pub(super) enum OriginAdmission {
    /// The request's own publication, durable and `Prepared`.
    Staged(OriginPublicationRecord),
    /// The `Published` publication that already made the request's move,
    /// whose value the ref carries.
    Resolved(OriginPublicationRecord),
}

/// The refusal naming what a request for `owner`'s move needs beyond what
/// `owner` certified, or `None` when its proof covers the request. The
/// owner's tip is always certified.
pub(in crate::origin) fn obligations_beyond_owner<'a>(
    owner: &OriginPublicationRecord,
    objects: impl Iterator<Item = &'a GitOid>,
    lfs_objects: impl Iterator<Item = &'a (LfsOid, u64)>,
) -> Option<Error> {
    let certified: BTreeSet<&GitOid> = owner
        .required_objects
        .iter()
        .chain(std::iter::once(&owner.new_oid))
        .collect();
    let certified_lfs: BTreeSet<&(LfsOid, u64)> = owner.required_lfs_oids.iter().collect();
    let objects: BTreeSet<String> = objects
        .filter(|oid| !certified.contains(oid))
        .map(|oid| oid.as_str().to_owned())
        .collect();
    let lfs_objects: BTreeSet<String> = lfs_objects
        .filter(|pair| !certified_lfs.contains(pair))
        .map(|(oid, size)| format!("{}:{size}", oid.to_hex()))
        .collect();
    if objects.is_empty() && lfs_objects.is_empty() {
        return None;
    }
    Some(Error::Code(CodeError::OriginPublicationBeyondOwner {
        objects: objects.into_iter().collect(),
        lfs_objects: lfs_objects.into_iter().collect(),
    }))
}

impl Vault {
    /// Exposes the real Prepared boundary to the sibling smart-HTTP crash test.
    #[cfg(test)]
    pub(in crate::origin) fn prepare_origin_publication_for_test(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
    ) -> Result<OriginPublicationRecord> {
        validate_origin_publication_request(request)?;
        self.validate_origin_repo(request.repo_id, &request.repo)?;
        let _guard = lock_repository(request.repo.common_dir())?;
        let publication_id = origin_publication_id(request)?;
        self.stage_origin_publication(git, request, publication_id)
    }

    /// [`Vault::admit_origin_publication`] for a request whose move no
    /// publication has made yet.
    #[cfg(test)]
    pub(super) fn stage_origin_publication(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
        publication_id: EntityId,
    ) -> Result<OriginPublicationRecord> {
        match self.admit_origin_publication(git, request, publication_id)? {
            OriginAdmission::Staged(record) => Ok(record),
            OriginAdmission::Resolved(_) => Err(Error::ConcurrentWrite(
                "origin CAS intent already published",
            )),
        }
    }

    /// Admits one request: stages the objects and makes the intent durable,
    /// or answers it with the publication that already made its move. No
    /// public ref moves.
    pub(super) fn admit_origin_publication(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
        publication_id: EntityId,
    ) -> Result<OriginAdmission> {
        let _guard = lock_repository(request.repo.common_dir())?;
        let provenance =
            self.get_claim(&request.provenance_claim_id)?
                .ok_or(Error::InvariantViolation(
                    "origin publication requires a durable provenance claim",
                ))?;
        if provenance.lifecycle != ClaimLifecycleStatus::Active
            || provenance.predicate == ORIGIN_PUBLICATION_PREDICATE
            || !self.claim_settled_and_active(&request.provenance_claim_id)?
        {
            return Err(Error::InvariantViolation(
                "origin publication provenance is not an active source claim",
            ));
        }
        if provenance.predicate == super::smart_http::RECEIVE_PACK_ADMISSION_PREDICATE {
            return Err(Error::InvariantViolation(
                "receive-pack admission alone is not outcome evidence",
            ));
        }
        if provenance.predicate == super::smart_http::RECEIVE_PACK_OUTCOME_PREDICATE
            || self.has_receive_pack_evidence(request.provenance_claim_id)?
        {
            self.validate_receive_pack_publication(request)?;
        } else if provenance.predicate != ORIGIN_PUBLICATION_INTENT_PREDICATE
            || provenance.subject != origin_publication_intent_claim(request)?.subject
            || provenance.value != origin_publication_intent_claim(request)?.value
        {
            return Err(Error::InvariantViolation(
                "origin publication source does not authorize this actor and ref intent",
            ));
        }
        let record = OriginPublicationRecord {
            publication_id,
            repo_id: request.repo_id,
            ref_name: request.ref_name.clone(),
            expected_old_oid: request.expected_old_oid.clone(),
            new_oid: request.new_oid.clone(),
            required_objects: request.required_objects.clone(),
            required_lfs_oids: request.required_lfs_oids.clone(),
            provenance_claim_id: request.provenance_claim_id,
            publication_claim_id: None,
            actor_id: OriginActor::Actor(request.actor_id),
            status: OriginPublicationStatus::Prepared,
            failure: None,
            occurred: request.occurred,
            created_at: request.learned_at,
            finished_at: None,
        };
        // Reconcile a colliding owner before creating anything for this caller.
        // A Published owner keeps the consumed triple's CAS row for good (T2):
        // a different provenance is not a second effect, but the ref carrying
        // the owner's value is the owner's answer to it.
        let intent_key = CasIntentKey::new(&record);
        let owner = {
            let rtxn = self.store.env.read_txn()?;
            CAS_INTENT.get(&self.store, &rtxn, &intent_key)?
        };
        if let Some(owner) = owner {
            let previous = self
                .origin_publication(owner)?
                .ok_or(Error::CorruptedIndex(
                    "origin CAS intent has no publication",
                ))?;
            if previous.status == OriginPublicationStatus::Prepared {
                self.advance_prepared_origin_publication(
                    git,
                    &request.repo,
                    previous,
                    request.learned_at,
                )?;
            }
            match self.origin_publication(owner)? {
                Some(row) if row.status == OriginPublicationStatus::Prepared => {
                    return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
                }
                Some(row) if row.status == OriginPublicationStatus::Published => {
                    return self
                        .resolve_to_published_owner(git, request, row)
                        .map(OriginAdmission::Resolved);
                }
                _ => {}
            }
        }
        // A missing tip cannot be pinned. Still commit an intent, then refuse
        // through the same terminal transaction as every other missing object.
        if git.reachable_objects_present(&request.repo, &request.new_oid, &[])? {
            self.pin_origin_object(
                git,
                &request.repo,
                OriginKeepRefKind::Publication,
                &publication_id.to_hex(),
                &request.new_oid,
                request.learned_at,
            )?;
        }
        // Independent dependencies are not necessarily reachable from the tip.
        // Keep them until this publication stops owning the visible-ref slot.
        let mut count = self.start_obligation_count(&request.repo_id)?;
        for oid in &request.required_objects {
            count.row();
            if oid != &request.new_oid && git.object_exists(&request.repo, oid)? {
                self.pin_origin_object(
                    git,
                    &request.repo,
                    OriginKeepRefKind::Publication,
                    &publication_id.to_hex(),
                    oid,
                    request.learned_at,
                )?;
            }
        }
        count.finish(self);
        let row = OriginPublicationRow::from_record(&record);
        PUBLICATIONS.encode_value(&row)?;
        self.with_write_txn_grouped(|wtxn| {
            if CAS_INTENT.contains(&self.store, wtxn, &intent_key)?
                || PUBLICATIONS.contains(&self.store, wtxn, &publication_id)?
            {
                return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
            }
            CAS_INTENT.put(&self.store, wtxn, &intent_key, &publication_id)?;
            PUBLICATIONS.put(&self.store, wtxn, &publication_id, &row)?;
            Ok(())
        })?;
        Ok(OriginAdmission::Staged(record))
    }

    /// Answers a request for a move a `Published` publication already made,
    /// under another source (ARCH-0068 RA2). Only the ref already carrying
    /// the owner's value resolves, and only when the owner's proof covers
    /// everything the request needs and still holds: observed, never re-run.
    /// No ref effect runs, no publication is minted, and the owner's record
    /// and permit are unchanged. The name's visible slot names the owner
    /// again, so the value the ref carries is the one it advertises.
    fn resolve_to_published_owner(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
        owner: OriginPublicationRecord,
    ) -> Result<OriginPublicationRecord> {
        if owner.repo_id != request.repo_id
            || owner.ref_name != request.ref_name
            || owner.expected_old_oid != request.expected_old_oid
            || owner.new_oid != request.new_oid
        {
            return Err(Error::CorruptedIndex(
                "origin CAS intent names another move",
            ));
        }
        if let Some(refusal) = obligations_beyond_owner(
            &owner,
            request.required_objects.iter(),
            request.required_lfs_oids.iter(),
        ) {
            return Err(refusal);
        }
        if git.read_ref(&request.repo, &request.ref_name)?.as_ref() != Some(&owner.new_oid) {
            return Err(Error::ConcurrentWrite(
                "origin CAS intent already published",
            ));
        }
        // A later publication of the ref may have released the owner's
        // independent dependencies. Protect them again before the owner's
        // proof is read and its slot restored.
        self.repin_origin_dependencies(git, &request.repo, &owner, request.learned_at)?;
        if self
            .origin_availability_failure(git, &request.repo, &owner)?
            .is_some()
        {
            return Err(Error::ConcurrentWrite(
                "origin publication awaits readable objects",
            ));
        }
        let intent_key = CasIntentKey::new(&owner);
        self.with_write_txn_grouped(|wtxn| {
            let current = PUBLICATIONS
                .get(&self.store, wtxn, &owner.publication_id)?
                .ok_or(Error::CorruptedIndex(
                    "origin CAS intent has no publication",
                ))?
                .into_record()?;
            if current.status != OriginPublicationStatus::Published
                || CAS_INTENT.get(&self.store, wtxn, &intent_key)? != Some(owner.publication_id)
            {
                return Err(Error::ConcurrentWrite("origin CAS owner changed"));
            }
            VISIBLE_REF.put(
                &self.store,
                wtxn,
                &visible_ref_key(&owner.repo_id, &owner.ref_name),
                &owner.publication_id,
            )?;
            Ok(())
        })?;
        self.note_origin_ref_moved(owner.ref_name.as_str());
        Ok(owner)
    }

    /// Drives one `Prepared` record to a terminal state.
    ///
    /// This is the SAME path a first attempt and a census recovery take, which
    /// is what makes "every crash window has exactly one disposition" true
    /// rather than aspirational: there is no second implementation that could
    /// decide differently.
    pub(super) fn advance_prepared_origin_publication(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        let _guard = lock_repository(repo.common_dir())?;
        let record = self
            .origin_publication(record.publication_id)?
            .ok_or(Error::CorruptedIndex("origin publication disappeared"))?;
        if record.status.is_terminal() {
            return Ok(OriginAdvance {
                record,
                already_applied: true,
                wire: None,
                disposition: OriginCensusDisposition::NoChange,
            });
        }
        let live = git.read_ref(repo, &record.ref_name)?;
        let already_applied = live.as_ref() == Some(&record.new_oid);
        // An erased actor's publication starts no effect (FIX 3877).
        if !already_applied && let Some(failure) = self.origin_new_effect_refusal(repo, &record) {
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                GitWireRejection::Unauthorized,
                failure,
                learned_at,
            );
        }
        if !already_applied && live != record.expected_old_oid {
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                GitWireRejection::RefMoved,
                "live ref no longer equals the expected value",
                learned_at,
            );
        }
        if let Some(failure) = self.origin_availability_failure(git, repo, &record)? {
            if already_applied {
                // The effect may have happened. Missing bytes cannot prove it
                // failed; retain intent and protection, and do not advertise.
                return Ok(OriginAdvance {
                    record,
                    already_applied,
                    wire: None,
                    disposition: OriginCensusDisposition::NoChange,
                });
            }
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                GitWireRejection::ObjectsUnavailable,
                &failure,
                learned_at,
            );
        }
        self.compare_and_swap_origin_ref(git, repo, record, already_applied, learned_at)
    }

    /// The one ref advance, and the one place a conflict is decided.
    fn compare_and_swap_origin_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        already_applied: bool,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        let outcome = git.update_ref_cas(
            repo,
            &record.ref_name,
            record.expected_old_oid.as_ref(),
            &record.new_oid,
            learned_at,
        )?;
        self.finish_origin_cas_outcome(git, repo, record, already_applied, learned_at, outcome)
    }

    /// The effect is external. A receipt is not a substitute for the live-ref
    /// proof, including when GitWire answered from its own durable journal.
    pub(super) fn finish_origin_cas_outcome(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        already_applied: bool,
        learned_at: u64,
        outcome: GitWireCommitOutcome,
    ) -> Result<OriginAdvance> {
        let _guard = lock_repository(repo.common_dir())?;
        // A moved ref is another writer, and another writer is a conflict.
        // Retrying it is exactly how the second writer would clobber the first,
        // so neither arm below ever loops.
        if let GitWireCommitOutcome::Rejected { reason, .. } = outcome {
            let failure = match reason {
                GitWireRejection::RefMoved => {
                    "compare-and-swap found a value on the ref that nobody decided against"
                }
                GitWireRejection::ObjectsUnavailable => {
                    "the git wire found required objects unavailable"
                }
                GitWireRejection::Unauthorized => {
                    "origin authority epoch no longer permits this publication"
                }
                GitWireRejection::EffectUnconfirmed => {
                    return Err(Error::ConcurrentWrite("origin CAS effect is uncertain"));
                }
            };
            let mut refused =
                self.refuse_origin_publication(git, repo, record, reason, failure, learned_at)?;
            refused.wire = Some(outcome);
            return Ok(refused);
        }
        // Never certify a sticky or stale GitWire receipt as live evidence.
        if git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid) {
            return Err(Error::ConcurrentWrite(
                "origin CAS live-ref proof is uncertain",
            ));
        }
        let record = self.finalize_origin_publication(record, learned_at)?;
        // Publication is already durable. Cleanup failure is a safe leak for
        // census, not a reason to report a landed ref as a rejected push.
        let _ = self.release_origin_publication_pin(git, repo, &record, learned_at);
        Ok(OriginAdvance {
            record,
            already_applied,
            wire: Some(outcome),
            disposition: if already_applied {
                OriginCensusDisposition::FinalizedPublished
            } else {
                OriginCensusDisposition::RetriedAndPublished
            },
        })
    }

    /// Pins again each independent dependency of a `Published` record that
    /// is still readable: a later publication of its ref may have released
    /// them, and resolution is about to make the record certify its ref's
    /// value again.
    pub(in crate::origin) fn repin_origin_dependencies(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<()> {
        for oid in &record.required_objects {
            if oid != &record.new_oid && git.object_exists(repo, oid)? {
                self.pin_origin_object(
                    git,
                    repo,
                    OriginKeepRefKind::Publication,
                    &record.publication_id.to_hex(),
                    oid,
                    learned_at,
                )?;
            }
        }
        Ok(())
    }

    /// Re-drives the ref effect of an already-`Published` publication.
    ///
    /// The record is not restated — it is already durable and already true.
    /// What runs again is the git wire's own journaled effect, which replays
    /// when the repository agrees, rolls a crash-interrupted advance forward
    /// when it is merely behind, and refuses when the repository carries a
    /// value nobody decided against.
    pub(super) fn redrive_published_origin_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationReceipt> {
        let already_applied =
            git.read_ref(repo, &record.ref_name)?.as_ref() == Some(&record.new_oid);
        if self
            .origin_availability_failure(git, repo, &record)?
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "published origin ref no longer has its required objects",
            ));
        }
        let outcome = git.update_ref_cas(
            repo,
            &record.ref_name,
            record.expected_old_oid.as_ref(),
            &record.new_oid,
            learned_at,
        )?;
        if outcome.is_applied()
            && git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid)
        {
            return Err(Error::ConcurrentWrite(
                "origin replay live-ref proof is uncertain",
            ));
        }
        if outcome.is_applied() {
            // Both a fresh advance and a replay can finish leaked cleanup.
            // Failure here keeps a safe root for census; it does not undo the
            // already-durable publication or reject a successful landing.
            let _ = self.release_origin_publication_pin(git, repo, &record, learned_at);
        }
        if matches!(
            outcome,
            GitWireCommitOutcome::Rejected {
                reason: GitWireRejection::EffectUnconfirmed,
                ..
            }
        ) {
            return Err(Error::ConcurrentWrite("origin replay effect is uncertain"));
        }
        origin_receipt(record, already_applied, Some(outcome))
    }

    /// The finalize transaction: the claim, the `Published` mark and the
    /// advertisement row are ONE atomic write or none of them.
    pub(super) fn finalize_origin_publication(
        &self,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationRecord> {
        let claim_id = origin_publication_claim_id(&record.publication_id)?;
        let mut published = record;
        published.status = OriginPublicationStatus::Published;
        published.publication_claim_id = Some(claim_id);
        published.failure = None;
        published.finished_at = Some(learned_at);
        self.finish_origin_publication(published, learned_at)
    }

    /// T2: read-check-write using only this transaction. No external calls.
    pub(super) fn finish_origin_publication(
        &self,
        terminal: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationRecord> {
        if !terminal.status.is_terminal() {
            return Err(Error::InvariantViolation(
                "origin finalize requires a terminal state",
            ));
        }
        let intent_key = CasIntentKey::new(&terminal);
        let owner_key = keep_owner_key(
            &terminal.repo_id,
            &terminal.new_oid,
            OriginKeepRefKind::Publication,
            &terminal.publication_id.to_hex(),
        );
        self.with_write_txn_grouped(|wtxn| {
            let current = PUBLICATIONS
                .get(&self.store, wtxn, &terminal.publication_id)?
                .ok_or(Error::CorruptedIndex("origin finalize has no prepared row"))?
                .into_record()?;
            if current.status.is_terminal() {
                if current.status == terminal.status {
                    return Ok(current);
                }
                return Err(Error::InvariantViolation(
                    "origin finalize cannot overwrite terminal state",
                ));
            }
            let mut expected = terminal.clone();
            expected.status = current.status;
            expected.publication_claim_id = current.publication_claim_id;
            expected.failure = current.failure.clone();
            expected.finished_at = current.finished_at;
            if expected != current {
                return Err(Error::InvariantViolation(
                    "origin finalize changed prepared intent",
                ));
            }
            let owner = CAS_INTENT
                .get(&self.store, wtxn, &intent_key)?
                .ok_or(Error::CorruptedIndex("origin finalize has no CAS intent"))?;
            if owner != terminal.publication_id {
                return Err(Error::InvariantViolation(
                    "origin finalize does not own CAS intent",
                ));
            }
            if terminal.status == OriginPublicationStatus::Published {
                let claim_id = terminal
                    .publication_claim_id
                    .ok_or(Error::InvariantViolation(
                        "origin publication has no claim id",
                    ))?;
                let body = publication_claim_body(&terminal)?;
                self.put_reserved_claim_in_txn(
                    wtxn,
                    &claim_id,
                    &body,
                    terminal.occurred,
                    learned_at,
                )?;
                let change_id = self.put_origin_change_in_txn(wtxn, &terminal, learned_at)?;
                // Transfer reachability to the durable change-index before releasing
                // the temporary publication owner. The physical root already exists.
                KEEP_OWNER.put(
                    &self.store,
                    wtxn,
                    &keep_owner_key(
                        &terminal.repo_id,
                        &terminal.new_oid,
                        OriginKeepRefKind::Change,
                        &change_id.to_hex(),
                    ),
                    &learned_at.to_le_bytes(),
                )?;
                VISIBLE_REF.put(
                    &self.store,
                    wtxn,
                    &visible_ref_key(&terminal.repo_id, &terminal.ref_name),
                    &terminal.publication_id,
                )?;
            }
            PUBLICATIONS.put(
                &self.store,
                wtxn,
                &terminal.publication_id,
                &OriginPublicationRow::from_record(&terminal),
            )?;
            // A refused move may be tried again; a published one is consumed.
            if terminal.status != OriginPublicationStatus::Published {
                CAS_INTENT.delete(&self.store, wtxn, &intent_key)?;
            }
            KEEP_OWNER.delete(&self.store, wtxn, &owner_key)?;
            Ok(terminal)
        })
        .inspect(|finished| self.note_origin_publication_finished(finished))
    }

    /// Records a bounded refusal. The public ref is left exactly as it was.
    fn refuse_origin_publication(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        reason: GitWireRejection,
        failure: &str,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        // A refusal decided before the wire ran must not leave an earlier
        // uncertain attempt at this move runnable by generic recovery. Voided
        // first: a crash before the refusal re-decides on the same evidence.
        git.void_prepared_ref_move(
            repo,
            &record.ref_name,
            record.expected_old_oid.as_ref(),
            &record.new_oid,
        )?;
        let status = if reason == GitWireRejection::RefMoved {
            OriginPublicationStatus::Conflicted
        } else {
            OriginPublicationStatus::Failed
        };
        let mut refused = record;
        refused.status = status;
        refused.failure = Some(bounded_failure(failure));
        refused.finished_at = Some(learned_at);
        let refused = self.finish_origin_publication(refused, learned_at)?;
        // A terminal refusal remains a refusal even if physical cleanup leaks.
        let _ = self.release_origin_publication_pin(git, repo, &refused, learned_at);
        Ok(OriginAdvance {
            record: refused,
            already_applied: false,
            wire: None,
            disposition: if status == OriginPublicationStatus::Conflicted {
                OriginCensusDisposition::MarkedConflicted
            } else {
                OriginCensusDisposition::MarkedFailed
            },
        })
    }

    /// Why this publication may not become visible, or `None` when it may.
    ///
    /// The tip is proved WHOLE, not merely present: a commit whose tree or
    /// parent is missing is a head that fails checkout, which is the one
    /// outcome the advertisement invariant forbids. Historical publications are
    /// not exclusions: object loss or corruption can invalidate an older proof.
    pub(super) fn origin_availability_failure(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
    ) -> Result<Option<String>> {
        // A past publication is not evidence that its objects are still
        // readable. Walk the whole graph, including on replay and advertisement.
        if !git.reachable_objects_present(repo, &record.new_oid, &[])? {
            return Ok(Some(format!(
                "the object graph reachable from {} is not whole in this object store",
                record.new_oid.as_str()
            )));
        }
        let mut count = self.start_obligation_count(&record.repo_id)?;
        for oid in &record.required_objects {
            count.row();
            if !git.object_exists(repo, oid)? {
                return Ok(Some(format!(
                    "required git object {} is not present in this object store",
                    oid.as_str()
                )));
            }
        }
        for (oid, size) in &record.required_lfs_oids {
            count.row();
            if !self.has_lfs_object(*oid, *size)? {
                return Ok(Some(format!(
                    "required lfs object {} at {size} bytes is not stored in this vault",
                    oid.to_hex()
                )));
            }
            // The check reads the object's whole manifest, so it first takes
            // room for it from the host, by the row it found stored, and
            // holds it through the check. A wait that runs out is an error
            // and decides nothing. An object whose manifest row is gone has
            // nothing to read, so it is not readable, as the check would find.
            let readable = match self.lfs_manifest_read_room(*oid)? {
                Some(_room) => match self.verify_lfs_object(*oid, *size) {
                    Ok(readable) => readable,
                    Err(Error::CorruptedIndex(_)) => false,
                    Err(error) => return Err(error),
                },
                None => false,
            };
            if !readable {
                return Ok(Some(format!(
                    "required lfs object {} is not locally readable at {size} bytes",
                    oid.to_hex()
                )));
            }
        }
        count.finish(self);
        Ok(None)
    }

    /// T2 already removed the logical owner. Retry physical retirement after
    /// commit, under the same coordinator used by pinning. Never delete a root
    /// while another logical owner exists.
    pub(super) fn release_origin_publication_pin(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<()> {
        if record.status == OriginPublicationStatus::Prepared {
            return Ok(());
        }
        // Held throughout, so no push is accepted between what is read below
        // and the release it decides.
        let _coordinator = lock_repository(repo.common_dir())?;
        self.unpin_origin_object(
            git,
            repo,
            OriginKeepRefKind::Publication,
            &record.publication_id.to_hex(),
            &record.new_oid,
            learned_at,
        )?;
        let owns_visible_slot = {
            let rtxn = self.store.env.read_txn()?;
            VISIBLE_REF
                .get(
                    &self.store,
                    &rtxn,
                    &visible_ref_key(&record.repo_id, &record.ref_name),
                )?
                .is_some_and(|id| id == record.publication_id)
        };
        let released = record.status != OriginPublicationStatus::Published
            || !owns_visible_slot
            || git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid);
        // A push of this record's own move that is still pending lands on this
        // record, and its proof needs every dependency: they stay rooted until
        // that push settles.
        if released
            && !(record.status == OriginPublicationStatus::Published
                && record
                    .required_objects
                    .iter()
                    .any(|oid| oid != &record.new_oid)
                && self.receive_pack_move_pending(repo.repo_root(), record)?)
        {
            for oid in &record.required_objects {
                if oid != &record.new_oid {
                    self.unpin_origin_object(
                        git,
                        repo,
                        OriginKeepRefKind::Publication,
                        &record.publication_id.to_hex(),
                        oid,
                        learned_at,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// A crash after pinning but before T1 has an owner but no journal row.
    /// The coordinator spans both stage operations, so a missing row cannot
    /// belong to a live runner paused between pinning and T1.
    pub(super) fn sweep_orphan_origin_publication_owners(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
        learned_at: u64,
    ) -> Result<()> {
        let _guard = lock_repository(repo.common_dir())?;
        // Every kind's owners share the repository's prefix, and a change
        // owner stays as long as its change: it is the root that keeps a
        // published commit readable once no ref reaches it (RA4). So the
        // scan reads the repository's change history, and never refuses for
        // its length (rule 5).
        let (owners, count) = {
            let rtxn = self.store.env.read_txn()?;
            let mut count = ScanCount::start(
                &self.store,
                &rtxn,
                EngineScan::KeepOwnerRows,
                repo_id.as_bytes(),
            )?;
            let mut owners = Vec::new();
            for row in KEEP_OWNER.iter_from(&self.store, &rtxn, repo_id.as_bytes())? {
                count.row();
                let (key, _) = row?;
                if key.kind != OriginKeepRefKind::Publication.as_str() {
                    continue;
                }
                // Only publication-id owners belong to this journal. Other
                // callers of the general pin door keep their own owner keys.
                let Ok(id) = EntityId::from_hex(&key.owner_key) else {
                    continue;
                };
                if !PUBLICATIONS.contains(&self.store, &rtxn, &id)? {
                    owners.push((GitOid::parse_hex(&key.oid)?, key.owner_key));
                }
            }
            (owners, count)
        };
        count.finish(self);
        for (oid, owner) in owners {
            self.unpin_origin_object(
                git,
                repo,
                OriginKeepRefKind::Publication,
                &owner,
                &oid,
                learned_at,
            )?;
        }
        Ok(())
    }
}
