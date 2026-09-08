//! Journaled ref publication: the one transactional path and its finishing rules.

use super::argv::FrozenGitArgv;
use super::config::GIT_WIRE_MAX_PUBLICATIONS;
use super::failure::{invalid, uncertain};
use super::record::{
    StoredGitWireRecord, finish_state, new_record, observed_from_stored, publications_from_stored,
    receipt_from_stored, ref_record_key, rejection_from_stored,
};
use super::wire_stage::object_keep_ref_name;
use super::{
    GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire, GitWireCommitOutcome,
    GitWireFailure, GitWireOperation, GitWireRecordState, GitWireRejection, GitWireRepo,
    GitWireResult, ObservedGitRef, lock_repository,
};
use crate::error::Result;

impl GitWire<'_> {
    /// Publishes refs through the one transactional path, under the repository
    /// coordinator and a durable intent written before git runs.
    ///
    /// A durable terminal record replays only while the postcondition it
    /// recorded still holds, so `set R=A; set R=B; set R=A` re-runs the third
    /// call instead of answering it from the first receipt.
    pub fn publish_refs(
        &self,
        repo: &GitWireRepo,
        publications: Vec<GitRefPublication>,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        validate_publications(&publications)?;
        let _guard = lock_repository(&repo.common_dir)?;
        let key = ref_record_key(repo.identity(), &publications);
        if let Some(outcome) = self.replay_terminal(repo, &key)? {
            return Ok(outcome);
        }
        // Anything left here is a prepared row from an interrupted attempt at
        // exactly this effect: finish that intent rather than restating it.
        if let Some(prepared) = self.load_record(repo, &key)? {
            return self.finish_record(repo, prepared, now);
        }
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed_before = self.read_refs(repo, &names)?;
        let record = new_record(
            repo,
            key,
            GitWireOperation::PublishRefs,
            &publications,
            &observed_before,
            now,
        );
        self.put_record(repo, &record)?;
        self.finish_record(repo, record, now)
    }

    /// Compare-and-set one ref against the value it was decided against.
    pub fn update_ref_cas(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let publication = GitRefPublication::update(
            name.clone(),
            GitRefExpectation::from_observed(expected),
            next.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Writes a ref, binding the value it currently holds into the effect.
    ///
    /// The observation is taken under the coordinator and becomes part of the
    /// key and the compare-and-set, so an unconditional-looking write is still
    /// a decision against a specific state and can never replay onto a
    /// different one.
    pub fn set_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        let observed = self.read_ref(repo, name)?;
        let publication = GitRefPublication::update(
            name.clone(),
            GitRefExpectation::from_observed(observed.as_ref()),
            next.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Deletes a ref, compare-and-set against `expected` or against the value
    /// observed now.
    pub fn delete_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        let expectation = match expected {
            Some(oid) => GitRefExpectation::Value(oid.clone()),
            None => GitRefExpectation::from_observed(self.read_ref(repo, name)?.as_ref()),
        };
        let publication = GitRefPublication::delete(name.clone(), expectation);
        self.publish_refs(repo, vec![publication], now)
    }

    /// Pins an object with a protected keep-ref so it survives maintenance.
    pub fn write_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let name = object_keep_ref_name(oid)?;
        let _guard = lock_repository(&repo.common_dir)?;
        let observed = self.read_ref(repo, &name)?;
        let publication = GitRefPublication::update(
            name,
            GitRefExpectation::from_observed(observed.as_ref()),
            oid.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Releases an object's keep-ref.
    pub fn delete_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let name = object_keep_ref_name(oid)?;
        self.delete_ref(repo, &name, None, now)
    }

    // -- shared finishing path --------------------------------------------

    /// Replays a durable terminal record, but only while its recorded
    /// postcondition still holds in the repository.
    fn replay_terminal(
        &self,
        repo: &GitWireRepo,
        key: &[u8; 32],
    ) -> Result<Option<GitWireCommitOutcome>> {
        let Some(stored) = self.load_record(repo, key)? else {
            return Ok(None);
        };
        let state = GitWireRecordState::parse(&stored.state)?;
        match state {
            GitWireRecordState::Prepared => Ok(None),
            GitWireRecordState::Failed => Ok(Some(GitWireCommitOutcome::Rejected {
                receipt: receipt_from_stored(&stored)?,
                reason: rejection_from_stored(&stored)?,
            })),
            GitWireRecordState::Applied => {
                if self.postcondition_holds(repo, &stored)? {
                    return Ok(Some(GitWireCommitOutcome::Replayed(receipt_from_stored(
                        &stored,
                    )?)));
                }
                self.drop_record(repo, key)?;
                Ok(None)
            }
        }
    }

    /// Whether every ref the record claimed to have left behind still carries
    /// the claimed value. This is what makes a stored claim a current claim.
    fn postcondition_holds(
        &self,
        repo: &GitWireRepo,
        stored: &StoredGitWireRecord,
    ) -> Result<bool> {
        let recorded = observed_from_stored(&stored.observed_after)?;
        if recorded.is_empty() {
            return Ok(false);
        }
        let names = recorded
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        let current = self.read_refs(repo, &names)?;
        Ok(current == recorded)
    }

    /// Drives one `Prepared` record to its resolution, or leaves it prepared
    /// and reports uncertainty. Shared by publication, staged commit, and
    /// recovery, so all three obey exactly one rule set.
    pub(super) fn finish_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        match GitWireOperation::parse(&record.operation)? {
            GitWireOperation::PublishRefs => self.finish_publication_record(repo, record, now),
            GitWireOperation::WorktreeAdd
            | GitWireOperation::WorktreeRemove
            | GitWireOperation::WorktreePrune => self.finish_worktree_record(repo, record, now),
            _ => Err(invalid("git wire record names a non-journaled operation")),
        }
    }

    fn finish_publication_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let publications = publications_from_stored(&record.publications)?;
        if publications.is_empty() {
            return Err(invalid("git wire publication record publishes no ref"));
        }
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if publications_satisfied(&publications, &observed) {
            return self.finish_already_published(repo, record, &publications, observed, now);
        }
        if !publications_expected(&publications, &observed) {
            return self.reject(repo, record, GitWireRejection::RefMoved, now);
        }
        if !self.publication_objects_available(repo, &publications)? {
            return self.reject(repo, record, GitWireRejection::ObjectsUnavailable, now);
        }
        self.apply_publication(repo, record, &publications, now)
    }

    /// A record whose refs already carry their targets. Availability is still
    /// verified, and verified whole: an already-advanced ref is never a reason
    /// to certify an object set nobody checked, and the advance proves nothing
    /// about the graph the target needs, so the walk may skip none of it. When
    /// that proof fails this reports uncertainty and leaves the record
    /// `Prepared`, keeping both the recovery intent and the staged keep-refs.
    fn finish_already_published(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        observed: Vec<ObservedGitRef>,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        if !self.publication_objects_available(repo, publications)? {
            return Err(uncertain(
                "git wire refs already advanced onto an incomplete object set".to_owned(),
            ));
        }
        self.release_keep_refs(repo, &record)?;
        let applied = finish_state(record, GitWireRecordState::Applied, observed, now);
        let stored = self.transition(repo, applied)?;
        Ok(GitWireCommitOutcome::Applied(receipt_from_stored(&stored)?))
    }

    fn apply_publication(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let mut batch = publications.to_vec();
        batch.extend(self.keep_ref_releases(repo, &record)?);
        let argv = FrozenGitArgv::publish_refs(&batch);
        match self.run_publication(repo, &argv)? {
            Ok(_) => self.confirm_publication(repo, record, publications, now),
            Err(failure) => {
                self.classify_publication_failure(repo, record, publications, failure, now)
            }
        }
    }

    fn confirm_publication(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if !publications_satisfied(publications, &observed) {
            return Err(uncertain(
                "git wire publication reported success but the refs disagree".to_owned(),
            ));
        }
        let applied = finish_state(record, GitWireRecordState::Applied, observed, now);
        let stored = self.transition(repo, applied)?;
        Ok(GitWireCommitOutcome::Applied(receipt_from_stored(&stored)?))
    }

    /// Separates the three outcomes a failed transaction can have: the refs
    /// moved under us, the refs are untouched but git failed, or git failed for
    /// an unknown reason. Only the first is terminal; the others keep the
    /// prepared intent so recovery can retry.
    fn classify_publication_failure(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        failure: GitWireFailure,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if !publications_expected(publications, &observed) {
            return self.reject(repo, record, GitWireRejection::RefMoved, now);
        }
        Err(failure.error(GitWireOperation::PublishRefs))
    }

    fn reject(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        reason: GitWireRejection,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        self.release_keep_refs(repo, &record)?;
        let mut failed = finish_state(record, GitWireRecordState::Failed, Vec::new(), now);
        failed.failure = Some(reason.as_failure().as_str().to_owned());
        let stored = self.transition(repo, failed)?;
        let receipt = receipt_from_stored(&stored)?;
        if receipt.state == GitWireRecordState::Applied {
            return Ok(GitWireCommitOutcome::Replayed(receipt));
        }
        Ok(GitWireCommitOutcome::Rejected {
            receipt,
            reason: rejection_from_stored(&stored)?,
        })
    }

    /// Verifies that every published object is present *with its full reachable
    /// graph*.
    ///
    /// The only frontier this walk may stop at is one this same pass has
    /// already proved complete. A ref's previous value is not such a proof:
    /// that the value exists, or that a ref still carries it, says nothing
    /// about the graph underneath it, and excluding it hides every missing
    /// object at or below that frontier -- including objects the new tip
    /// itself needs, since a new commit shares almost all of its graph with
    /// the value it replaces. A ref that has already advanced onto the target
    /// is weaker evidence still, because it no longer even carries the value
    /// that would be excluded.
    fn publication_objects_available(
        &self,
        repo: &GitWireRepo,
        publications: &[GitRefPublication],
    ) -> Result<bool> {
        let mut proved: Vec<GitOid> = Vec::new();
        for publication in publications {
            let Some(next) = publication.next() else {
                continue;
            };
            // Sound because this pass walked that exact tip under this
            // repository's coordinator and found its whole graph present.
            if proved.contains(next) {
                continue;
            }
            if !self.reachable_objects_present(repo, next, &[])? {
                return Ok(false);
            }
            proved.push(next.clone());
        }
        Ok(true)
    }

    fn keep_ref_releases(
        &self,
        repo: &GitWireRepo,
        record: &StoredGitWireRecord,
    ) -> Result<Vec<GitRefPublication>> {
        if record.keep_refs.is_empty() {
            return Ok(Vec::new());
        }
        let mut names = Vec::with_capacity(record.keep_refs.len());
        for name in &record.keep_refs {
            names.push(GitRefName::parse_full(name.clone())?);
        }
        let observed = self.read_refs(repo, &names)?;
        Ok(observed
            .into_iter()
            .filter(|entry| entry.oid.is_some())
            .map(|entry| GitRefPublication::delete(entry.name, GitRefExpectation::Any))
            .collect())
    }

    fn release_keep_refs(&self, repo: &GitWireRepo, record: &StoredGitWireRecord) -> Result<()> {
        let releases = self.keep_ref_releases(repo, record)?;
        if releases.is_empty() {
            return Ok(());
        }
        let argv = FrozenGitArgv::publish_refs(&releases);
        match self.run_publication(repo, &argv)? {
            Ok(_) => Ok(()),
            Err(failure) => Err(failure.error(GitWireOperation::PublishRefs)),
        }
    }
}

fn validate_publications(publications: &[GitRefPublication]) -> Result<()> {
    if publications.is_empty() || publications.len() > GIT_WIRE_MAX_PUBLICATIONS {
        return Err(invalid(
            "git wire publication set must be non-empty and bounded",
        ));
    }
    for (index, publication) in publications.iter().enumerate() {
        if publications[..index]
            .iter()
            .any(|earlier| earlier.name == publication.name)
        {
            return Err(invalid("git wire publication set names one ref twice"));
        }
    }
    Ok(())
}

fn publications_satisfied(publications: &[GitRefPublication], observed: &[ObservedGitRef]) -> bool {
    publications.iter().all(|publication| {
        observed
            .iter()
            .find(|entry| entry.name == publication.name)
            .is_some_and(|entry| publication.satisfied_by(entry.oid.as_ref()))
    })
}

fn publications_expected(publications: &[GitRefPublication], observed: &[ObservedGitRef]) -> bool {
    publications.iter().all(|publication| {
        observed
            .iter()
            .find(|entry| entry.name == publication.name)
            .is_some_and(|entry| publication.expected().holds_for(entry.oid.as_ref()))
    })
}
