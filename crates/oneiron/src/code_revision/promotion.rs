//! Session provenance claims and promotion guarded by verified revision history.
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SESSION;
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;

/// Host-recorded inputs for a code-touching session. No prompt payload is put in Git.
pub struct CodeSessionRun {
    pub session: EntityId,
    pub actor: EntityId,
    pub model: String,
    pub prompt_hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub params_hash: [u8; 32],
    pub version: String,
    pub diff_lineage_receipt: Value,
}
impl Vault {
    pub fn record_code_session_run(&self, run: &CodeSessionRun, now: u64) -> Result<EntityId> {
        if self.get_entity_type(&run.session)? != Some(ENTITY_TYPE_SESSION)
            || self.get_entity_type(&run.actor)?.is_none()
            || run.model.trim().is_empty()
            || run.version.trim().is_empty()
            || !matches!(&run.diff_lineage_receipt, Value::Map(entries) if !entries.is_empty())
        {
            return Err(Error::InvalidClaimBody("invalid code session provenance"));
        }
        let hash = |value: &[u8; 32]| Value::from(crate::entity_id::bytes_to_hex_lower(value));
        let mut body = ClaimBody::new(
            crate::repo_mutation::REPO_PROVENANCE_PREDICATE,
            ClaimSubject::Entity(run.session),
            Value::Map(vec![
                (Value::from("actor"), Value::from(run.actor.to_hex())),
                (Value::from("session"), Value::from(run.session.to_hex())),
                (Value::from("model"), Value::from(run.model.clone())),
                (Value::from("prompt_hash"), hash(&run.prompt_hash)),
                (
                    Value::from("derivation_envelope"),
                    Value::Map(vec![
                        (Value::from("content_hash"), hash(&run.content_hash)),
                        (Value::from("model_id"), Value::from(run.model.clone())),
                        (Value::from("version"), Value::from(run.version.clone())),
                        (Value::from("params_hash"), hash(&run.params_hash)),
                    ]),
                ),
                (
                    Value::from("diff_lineage_receipt"),
                    run.diff_lineage_receipt.clone(),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        // This typed host door records a run's provenance, not a code approval.
        // File promotion still requires independent review and authenticated folds.
        body.source = Some(crate::claim::ClaimSource::Observed);
        let id = EntityId::now();
        self.with_write_txn(|txn| {
            self.put_reserved_claim_in_txn(
                txn,
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
        })?;
        Ok(id)
    }
}

impl Vault {
    /// A final code state requires review coverage of every changed file plus
    /// authenticated session and document folds. Approval booleans are not capabilities.
    pub fn promote_code_revision(&self, revision: EntityId, proposal: EntityId) -> Result<()> {
        self.promote_code_revision_with_reviews(revision, &[proposal])
    }
    pub fn promote_code_revision_with_reviews(
        &self,
        revision_id: EntityId,
        proposal_ids: &[EntityId],
    ) -> Result<()> {
        self.check_code_revision_reviews(revision_id, proposal_ids, true)
    }

    pub(crate) fn require_code_revision_promotion(&self, revision_id: EntityId) -> Result<()> {
        let reviews = self.code_revision_promotions(revision_id)?;
        self.check_code_revision_reviews(revision_id, &reviews, false)
    }

    fn check_code_revision_reviews(
        &self,
        revision_id: EntityId,
        proposal_ids: &[EntityId],
        persist: bool,
    ) -> Result<()> {
        if proposal_ids.is_empty() {
            return Err(Error::InvalidClaimBody("promotion needs reviews"));
        }
        let mut reviews = std::collections::BTreeMap::new();
        for id in proposal_ids {
            let proposal = self.repo_proposal(*id)?.ok_or(Error::EntityNotFound)?;
            if proposal.status != crate::repo_mutation::proposal::RepoProposalStatus::Applied {
                return Err(Error::InvalidClaimBody(
                    "code promotion requires applied reviews",
                ));
            }
            let edit = self
                .code_file_edit_receipt(*id)?
                .ok_or(Error::InvalidClaimBody("review has no document operation"))?;
            if edit.session_id != proposal.session
                || edit.actor.entity_ref() != proposal.actor
                || edit.edit.path != proposal.path
                || reviews.insert(edit.document_id, (proposal, edit)).is_some()
            {
                return Err(Error::InvalidClaimBody(
                    "duplicate or mismatched promotion review",
                ));
            }
        }
        let mut txn = self.store.env.write_txn()?;
        let revision = super::storage::get_code_revision_in_txn(&self.store, &txn, &revision_id)?
            .ok_or(Error::EntityNotFound)?;
        super::frontier::verify_code_revision_frontier_in_txn(
            &self.store,
            &txn,
            &revision.session_id,
        )?;
        let head = super::frontier::get_code_revision_frontier_in_txn(
            &self.store,
            &txn,
            &revision.session_id,
        )?
        .ok_or(Error::EntityNotFound)?;
        if persist && head.revision_id != revision_id {
            return Err(Error::ConcurrentWrite(
                "only current code head can be promoted",
            ));
        }
        let revisions = super::storage::collect_code_revisions_by_index_prefix(
            &self.store,
            &txn,
            &super::keys::code_revision_session_index_prefix(&revision.session_id),
        )?;
        super::frontier::verify_code_revision_session_trace_in_txn(
            &self.store,
            &txn,
            &revision.session_id,
            &revisions,
        )?;
        super::integrity::verify_code_revision_integrity_in_txn(&self.store, &txn, &revision)?;
        let parent = revision
            .parent_revision_id
            .map(|id| {
                super::storage::get_code_revision_in_txn(&self.store, &txn, &id)?
                    .ok_or(Error::EntityNotFound)
            })
            .transpose()?;
        if parent.as_ref().is_some_and(|p| {
            p.file_frontiers
                .keys()
                .any(|id| !revision.file_frontiers.contains_key(id))
        }) {
            return Err(Error::InvalidClaimBody(
                "file removal needs an explicit reviewed operation",
            ));
        }
        for (id, file) in &revision.file_frontiers {
            if parent
                .as_ref()
                .is_some_and(|p| p.file_frontiers.get(id) == Some(file))
            {
                continue;
            }
            let (proposal, edit) = reviews
                .remove(id)
                .ok_or(Error::InvalidClaimBody("changed file lacks review"))?;
            if proposal.session != revision.session_id
                || Some(proposal.provenance_claim) != revision.provenance_claim_id
                || edit.after != *file
            {
                return Err(Error::InvalidClaimBody(
                    "promotion does not match reviewed document frontier",
                ));
            }
        }
        if !reviews.is_empty() {
            return Err(Error::InvalidClaimBody(
                "review does not cover a changed file",
            ));
        }
        let mut ids: Vec<_> = proposal_ids.iter().map(EntityId::to_hex).collect();
        ids.sort();
        let encoded =
            rmp_serde::to_vec(&ids).map_err(|_| Error::CorruptedIndex("promotion encode"))?;
        let key = [
            b"code_revision:promotion:v1:".as_slice(),
            revision_id.as_bytes(),
        ]
        .concat();
        if let Some(old) = self.store.vault_meta.get(&txn, &key)? {
            if old.as_ref() != encoded {
                return Err(Error::ConcurrentWrite("revision promotion is immutable"));
            }
        } else if persist {
            self.store.vault_meta.put(&mut txn, &key, &encoded)?;
        } else {
            return Err(Error::InvalidClaimBody(
                "revision promotion receipt missing",
            ));
        }
        if persist {
            txn.commit()?;
        }
        Ok(())
    }
    pub fn code_revision_promotions(&self, revision: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(
            &txn,
            &[
                b"code_revision:promotion:v1:".as_slice(),
                revision.as_bytes(),
            ]
            .concat(),
        )?
        else {
            return Ok(Vec::new());
        };
        let ids: Vec<String> =
            rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("promotion decode"))?;
        ids.iter().map(|id| EntityId::from_hex(id)).collect()
    }
}
