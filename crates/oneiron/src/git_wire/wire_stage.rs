//! Two-phase staging: stage, commit-prepared, recovery, and keep-ref naming.

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::record::{
    hex_lower, new_record, prepared_from_stored, receipt_from_stored, rejection_from_stored,
    stage_record_key,
};
use super::wire_reads::parse_oid_output;
use super::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire,
    GitWireCommitOutcome, GitWireOperation, GitWirePlan, GitWirePlannedOid, GitWirePrepared,
    GitWireReceipt, GitWireRecordState, GitWireRepo, GitWireResult, lock_repository,
};
use crate::error::Result;

impl GitWire<'_> {
    /// Phase one: runs every object write outside any vault write transaction,
    /// protects the result with keep-refs, and journals the prepared intent.
    ///
    /// The stage key is claimed, so re-staging an identical plan returns the
    /// existing capability instead of repeating the effect. No advertised ref
    /// moves here; only the engine's own keep-refs are written, and only after
    /// the durable intent exists.
    pub fn stage(
        &self,
        repo: &GitWireRepo,
        plan: &GitWirePlan,
        now: u64,
    ) -> GitWireResult<GitWirePrepared> {
        plan.validate()?;
        let _guard = lock_repository(&repo.common_dir)?;
        let key = stage_record_key(repo.identity(), &plan.plan_hash()?);
        if let Some(stored) = self.load_record(repo, &key)? {
            return Ok(prepared_from_stored(&stored));
        }
        let written = self.write_plan_objects(repo, plan)?;
        let publications = resolve_plan_publications(plan, &written)?;
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed_before = self.read_refs(repo, &names)?;
        let keep_refs = stage_keep_ref_names(&key, &publications)?;
        let mut record = new_record(
            repo,
            key,
            GitWireOperation::PublishRefs,
            &publications,
            &observed_before,
            now,
        );
        record.keep_refs = keep_refs
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        self.put_record(repo, &record)?;
        self.hold_keep_refs(repo, &keep_refs, &publications)?;
        Ok(prepared_from_stored(&record))
    }

    /// Phase two: finishes the prepared record the capability names.
    ///
    /// The capability carries no values: the durable row is re-read and its
    /// capability hash must match, so a forged or stale handle publishes
    /// nothing.
    pub fn commit_prepared(
        &self,
        repo: &GitWireRepo,
        prepared: &GitWirePrepared,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        if prepared.repo_identity != repo.identity() {
            return Err(invalid(
                "git wire prepared capability belongs to another repository",
            ));
        }
        let stored = self
            .load_record(repo, &prepared.record_key)?
            .ok_or_else(|| invalid("git wire prepared capability has no durable record"))?;
        if stored.capability_hash() != prepared.capability_hash {
            return Err(invalid("git wire prepared capability is stale or forged"));
        }
        match GitWireRecordState::parse(&stored.state)? {
            GitWireRecordState::Applied => Ok(GitWireCommitOutcome::Replayed(receipt_from_stored(
                &stored,
            )?)),
            GitWireRecordState::Failed => Ok(GitWireCommitOutcome::Rejected {
                receipt: receipt_from_stored(&stored)?,
                reason: rejection_from_stored(&stored)?,
            }),
            GitWireRecordState::Prepared => self.finish_record(repo, stored, now),
        }
    }

    fn write_plan_objects(&self, repo: &GitWireRepo, plan: &GitWirePlan) -> Result<Vec<GitOid>> {
        let mut written = Vec::with_capacity(plan.objects.len());
        for write in &plan.objects {
            let argv = write.argv()?;
            let output = self.run_mutation(repo, &argv)?;
            written.push(parse_oid_output(&output.stdout)?);
        }
        Ok(written)
    }

    fn hold_keep_refs(
        &self,
        repo: &GitWireRepo,
        keep_refs: &[GitRefName],
        publications: &[GitRefPublication],
    ) -> Result<()> {
        let mut batch = Vec::new();
        for (name, publication) in keep_refs.iter().zip(publications) {
            let Some(next) = publication.next() else {
                continue;
            };
            batch.push(GitRefPublication::update(
                name.clone(),
                GitRefExpectation::Any,
                next.clone(),
            ));
        }
        if batch.is_empty() {
            return Ok(());
        }
        let argv = FrozenGitArgv::publish_refs(&batch);
        match self.run_publication(repo, &argv)? {
            Ok(_) => Ok(()),
            Err(failure) => Err(failure.error(GitWireOperation::PublishRefs)),
        }
    }

    /// Finishes every prepared record of one repository.
    ///
    /// Recovery runs under the same coordinator as every writer, so two
    /// recoverers cannot both drive one record, and it uses exactly the same
    /// rules as a live commit: roll forward only on a complete match, reject
    /// only on a proven expectation violation, and preserve the intent on any
    /// uncertainty.
    pub fn recover(&self, repo: &GitWireRepo, now: u64) -> GitWireResult<Vec<GitWireReceipt>> {
        let _guard = lock_repository(&repo.common_dir)?;
        let mut receipts = Vec::new();
        for record in self.prepared_records(repo)? {
            let outcome = self.finish_record(repo, record, now)?;
            receipts.push(outcome.receipt().clone());
        }
        Ok(receipts)
    }
}

fn resolve_plan_publications(
    plan: &GitWirePlan,
    written: &[GitOid],
) -> Result<Vec<GitRefPublication>> {
    let mut publications = Vec::with_capacity(plan.publications.len());
    for planned in &plan.publications {
        let next = match planned.next {
            None => None,
            Some(GitWirePlannedOid::Written(index)) => Some(
                written
                    .get(index)
                    .ok_or_else(|| invalid("git wire plan handle is out of range"))?
                    .clone(),
            ),
            Some(GitWirePlannedOid::Existing(index)) => Some(
                plan.existing
                    .get(index)
                    .ok_or_else(|| invalid("git wire plan handle is out of range"))?
                    .clone(),
            ),
        };
        publications.push(GitRefPublication {
            name: planned.name.clone(),
            expected: planned.expected.clone(),
            next,
        });
    }
    Ok(publications)
}

fn stage_keep_ref_names(
    key: &[u8; 32],
    publications: &[GitRefPublication],
) -> Result<Vec<GitRefName>> {
    let scope = hex_lower(key);
    let mut names = Vec::with_capacity(publications.len());
    for index in 0..publications.len() {
        names.push(GitRefName::parse_full(format!(
            "{GIT_WIRE_KEEP_REF_PREFIX}stage/{scope}/{index}"
        ))?);
    }
    Ok(names)
}

pub(super) fn object_keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", oid.as_str()))
}
