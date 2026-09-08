//! State machine: stage, advance, CAS, finish/refuse/finalize T2, availability gate, pin release and orphan sweep.

use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitWire, GitWireCommitOutcome, GitWireRejection, GitWireRepo, lock_repository,
};

#[cfg(test)]
use super::publication_codec::origin_publication_id;
use super::publication_codec::{
    bounded_failure, cas_intent_key, decode_publication_row, encode_publication_row,
    keep_owner_key, origin_publication_claim_id, origin_publication_intent_claim,
    publication_claim_body, publication_key, row_entity_id, visible_ref_key,
};
#[cfg(test)]
use super::publication_journal::validate_origin_publication_request;
use super::publication_journal::{OriginAdvance, origin_receipt};
use super::publication_types::{
    ORIGIN_KEEP_OWNER_KEY_PREFIX, ORIGIN_KEY_SEPARATOR, ORIGIN_PUBLICATION_INTENT_PREDICATE,
    ORIGIN_PUBLICATION_MAX_ROWS, ORIGIN_PUBLICATION_PREDICATE, OriginCensusDisposition,
    OriginKeepRefKind, OriginPublicationReceipt, OriginPublicationRecord, OriginPublicationRequest,
    OriginPublicationStatus,
};
// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

impl Vault {
    /// Exposes the real Prepared boundary to the sibling smart-HTTP crash test.
    #[cfg(test)]
    pub(crate) fn prepare_origin_publication_for_test(
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

    /// Stages the objects and makes the intent durable. No public ref moves.
    pub(super) fn stage_origin_publication(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
        publication_id: EntityId,
    ) -> Result<OriginPublicationRecord> {
        let _guard = lock_repository(request.repo.common_dir())?;
        let provenance =
            self.get_claim(&request.provenance_claim_id)?
                .ok_or(Error::InvariantViolation(
                    "origin publication requires a durable provenance claim",
                ))?;
        if provenance.lifecycle != ClaimLifecycleStatus::Active
            || provenance.predicate == ORIGIN_PUBLICATION_PREDICATE
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
            || provenance.subject != origin_publication_intent_claim(request).subject
            || provenance.value != origin_publication_intent_claim(request).value
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
            actor_id: request.actor_id,
            status: OriginPublicationStatus::Prepared,
            failure: None,
            occurred: request.occurred,
            created_at: request.learned_at,
            finished_at: None,
        };
        // Reconcile a colliding owner before creating anything for this caller.
        // Completed Published rows retain the consumed triple after T2 removes
        // the in-flight index. A different provenance is not a second effect.
        let intent_key = cas_intent_key(&record);
        let owner = {
            let rtxn = self.store.env.read_txn()?;
            self.store
                .vault_meta
                .get(&rtxn, &intent_key)?
                .map(|raw| {
                    let bytes = raw
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("origin CAS intent owner"))?;
                    row_entity_id(bytes)
                })
                .transpose()?
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
            if self.origin_publication(owner)?.is_some_and(|row| {
                matches!(
                    row.status,
                    OriginPublicationStatus::Prepared | OriginPublicationStatus::Published
                )
            }) {
                return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
            }
        }
        if self
            .origin_publication_rows(Some(record.repo_id))?
            .iter()
            .any(|row| {
                row.publication_id != publication_id
                    && row.status == OriginPublicationStatus::Published
                    && cas_intent_key(row) == intent_key
            })
        {
            return Err(Error::ConcurrentWrite(
                "origin CAS intent already published",
            ));
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
        for oid in &request.required_objects {
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
        let key = publication_key(&publication_id);
        let row = encode_publication_row(&record)?;
        self.with_write_txn(|wtxn| {
            if self.store.vault_meta.get(wtxn, &intent_key)?.is_some()
                || self.store.vault_meta.get(wtxn, &key)?.is_some()
            {
                return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
            }
            self.store
                .vault_meta
                .put(wtxn, &intent_key, publication_id.as_bytes())?;
            self.store.vault_meta.put(wtxn, &key, &row)?;
            Ok(())
        })?;
        Ok(record)
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
        if !already_applied && live != record.expected_old_oid {
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                OriginPublicationStatus::Conflicted,
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
                OriginPublicationStatus::Failed,
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
            let (status, failure) = match reason {
                GitWireRejection::RefMoved => (
                    OriginPublicationStatus::Conflicted,
                    "compare-and-swap found a value on the ref that nobody decided against"
                        .to_owned(),
                ),
                GitWireRejection::ObjectsUnavailable => (
                    OriginPublicationStatus::Failed,
                    "the git wire found required objects unavailable".to_owned(),
                ),
                GitWireRejection::EffectUnconfirmed => {
                    return Err(Error::ConcurrentWrite("origin CAS effect is uncertain"));
                }
            };
            let mut refused =
                self.refuse_origin_publication(git, repo, record, status, &failure, learned_at)?;
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
        let record_key = publication_key(&terminal.publication_id);
        let intent_key = cas_intent_key(&terminal);
        let owner_key = keep_owner_key(
            &terminal.repo_id,
            &terminal.new_oid,
            OriginKeepRefKind::Publication,
            &terminal.publication_id.to_hex(),
        );
        self.with_write_txn(|wtxn| {
            let raw = self
                .store
                .vault_meta
                .get(wtxn, &record_key)?
                .ok_or(Error::CorruptedIndex("origin finalize has no prepared row"))?;
            let current = decode_publication_row(&raw)?;
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
            let owner = self
                .store
                .vault_meta
                .get(wtxn, &intent_key)?
                .ok_or(Error::CorruptedIndex("origin finalize has no CAS intent"))?;
            if owner.as_ref() != terminal.publication_id.as_bytes() {
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
                self.put_claim_in_txn(wtxn, &claim_id, &body, terminal.occurred, learned_at)?;
                self.store.vault_meta.put(
                    wtxn,
                    &visible_ref_key(&terminal.repo_id, &terminal.ref_name),
                    terminal.publication_id.as_bytes(),
                )?;
            }
            self.store
                .vault_meta
                .put(wtxn, &record_key, &encode_publication_row(&terminal)?)?;
            self.store.vault_meta.delete(wtxn, &intent_key)?;
            self.store.vault_meta.delete(wtxn, &owner_key)?;
            Ok(terminal)
        })
    }

    /// Records a bounded refusal. The public ref is left exactly as it was.
    fn refuse_origin_publication(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        status: OriginPublicationStatus,
        failure: &str,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
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
        for oid in &record.required_objects {
            if !git.object_exists(repo, oid)? {
                return Ok(Some(format!(
                    "required git object {} is not present in this object store",
                    oid.as_str()
                )));
            }
        }
        for (oid, size) in &record.required_lfs_oids {
            if !self.has_lfs_object(*oid, *size)? {
                return Ok(Some(format!(
                    "required lfs object {} at {size} bytes is not stored in this vault",
                    oid.to_hex()
                )));
            }
            match self.verify_lfs_object(*oid, *size) {
                Ok(true) => {}
                Ok(false) | Err(Error::CorruptedIndex(_)) => {
                    return Ok(Some(format!(
                        "required lfs object {} is not locally readable at {size} bytes",
                        oid.to_hex()
                    )));
                }
                Err(error) => return Err(error),
            }
        }
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
            self.store
                .vault_meta
                .get(&rtxn, &visible_ref_key(&record.repo_id, &record.ref_name))?
                .is_some_and(|id| id.as_ref() == record.publication_id.as_bytes())
        };
        if record.status != OriginPublicationStatus::Published
            || !owns_visible_slot
            || git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid)
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
        let mut prefix = ORIGIN_KEEP_OWNER_KEY_PREFIX.to_vec();
        prefix.extend_from_slice(repo_id.as_bytes());
        prefix.push(ORIGIN_KEY_SEPARATOR);
        let owners = {
            let rtxn = self.store.env.read_txn()?;
            let mut owners = Vec::new();
            for (index, entry) in self
                .store
                .vault_meta
                .prefix_iter(&rtxn, &prefix)?
                .enumerate()
            {
                if index >= ORIGIN_PUBLICATION_MAX_ROWS {
                    return Err(Error::IndexOverflow("origin keep owner rows"));
                }
                let (key, _) = entry?;
                let suffix = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|_| Error::CorruptedIndex("origin keep owner key"))?;
                let fields = suffix.splitn(3, '\0').collect::<Vec<_>>();
                if fields.len() != 3 || fields[1] != OriginKeepRefKind::Publication.as_str() {
                    continue;
                }
                // Only publication-id owners belong to this journal. Other
                // callers of the general pin door keep their own owner keys.
                let Ok(id) = EntityId::from_hex(fields[2]) else {
                    continue;
                };
                if self
                    .store
                    .vault_meta
                    .get(&rtxn, &publication_key(&id))?
                    .is_none()
                {
                    owners.push((GitOid::parse_hex(fields[0])?, fields[2].to_owned()));
                }
            }
            owners
        };
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
