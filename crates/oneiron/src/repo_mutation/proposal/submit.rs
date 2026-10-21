//! The one checked proposer (moved from `proposal.rs`, FIX 6867 G1 PR2b):
//! the trusted and owner proposals take their base from the current
//! checkout, a run's from the immutable commit its work is pinned at
//! (PREMISE 3), and both are validated, kept under custody and written by
//! the same code. No proposal lands a file here.

use super::*;
use crate::memory::repo_doors::RepoRunStamp;
use crate::repo_mutation::snapshot::RepoPinnedBase;

/// Where a proposal's pre-action base comes from.
pub(in crate::repo_mutation) enum ProposalBase {
    /// The trusted and owner proposer: the live checkout, captured under the
    /// repo lock, whose HEAD must be the request's pinned commit.
    CurrentCheckout,
    /// A run's proposal: the tree of the commit its work is pinned at, read
    /// from the object store; that commit must be the request's pin.
    Pinned(RepoPinnedBase),
}

impl Vault {
    /// The one checked proposer: validates the request, takes the base,
    /// keeps custody, then writes the journal claims, the base snapshot and
    /// the proposal in one transaction whose first act is `check`. A
    /// refusal there writes nothing. A run's stamp and class are on the row
    /// before that write; the trusted and owner proposer write none.
    pub(in crate::repo_mutation) fn propose_repo_mutation_checked<R>(
        &self,
        request: RepoMutationRequest,
        catalog: LensCatalog,
        base: ProposalBase,
        run: Option<RepoRunStamp>,
        check: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoProposal, R>> {
        validate_operation(&request.operation)?;
        crate::repo_mutation::trailer::validate_repo_provenance_request(self, &request)?;
        let (Some(actor), Some(session), Some(provenance_claim)) = (
            request.actor_id,
            request.session_id,
            request.provenance_claim_id,
        ) else {
            return Err(invalid(
                "code proposal requires actor, session and provenance",
            ));
        };
        request.op_provenance.validate()?;
        let op_provenance = request.op_provenance.clone();
        let request_class = request.actor_class;
        let (path, content, message, operation) = match request.operation {
            RepoMutationOperation::CommitFile {
                path,
                content,
                message,
            } => (path, content, message, RepoProposalOperation::CommitFile),
            RepoMutationOperation::ResolveConflictFile {
                branch_subject,
                open_conflict_claim_id,
                branch_name,
                path,
                content,
                message,
            } => (
                path,
                content,
                message,
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                },
            ),
            _ => return Err(invalid("code proposal supports one file operation")),
        };
        if content.len() > 32 * 1024 * 1024 || catalog.lenses.is_empty() {
            return Err(invalid(
                "proposal requires bounded content and review lenses",
            ));
        }
        // Empty triage validates the host's catalog without inventing a verdict.
        triage_critiques(&catalog, &[], &[])?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo = admitted_repo_ref(&request.repo_ref, &repo_root)?;
        let _guard = lock_repository(&git_common_dir(&repo_root)?)?;
        self.recover_prepared_repo_mutations_locked(&repo, &repo_root)?;
        let (fork, snapshot) = match base {
            ProposalBase::CurrentCheckout => capture_repo_snapshot(self, &repo_root)?,
            ProposalBase::Pinned(pinned) => (pinned.fork_hash, pinned.encoded),
        };
        let pre_action = crate::repo_mutation::snapshot::decode_snapshot(&snapshot)?;
        require_pinned_head(&repo, pre_action.head.as_deref())?;
        admit_custody(
            &SnapshotCustody::of(self, &repo_root)?,
            &pre_action,
            &path,
            &content,
            &message,
        )?;
        let row = RepoProposal {
            id: EntityId::now(),
            repo: repo.canonical(),
            actor: actor_erase::ProposalActor::Actor(actor),
            session,
            provenance_claim,
            op_provenance,
            path,
            content,
            message,
            operation,
            merge_stack: None,
            pre_action_fork_hash: fork,
            catalog,
            critiques: Vec::new(),
            status: RepoProposalStatus::Proposed,
            settlement: None,
            operation_seq: None,
            created_at: now_millis() / 1000,
            run,
            actor_class: request_class.map(|class| class as u8),
        };
        validate_conflict(self, &row, &repo_root)?;
        let mut body = ClaimBody::new(
            "repo.proposed_diff",
            ClaimSubject::Entity(session),
            Value::Map(vec![
                (Value::from("actor"), Value::from(actor.to_hex())),
                (Value::from("path"), Value::from(row.path.clone())),
                (
                    Value::from("operation"),
                    Value::from(row.request()?.operation.kind()),
                ),
                (
                    Value::from("operation_hash"),
                    Value::Binary(
                        blake3::hash(
                            &rmp_serde::to_vec_named(&(
                                &row.operation,
                                &row.path,
                                &row.content,
                                &row.message,
                            ))
                            .map_err(|_| invalid("proposal operation encoding failed"))?,
                        )
                        .as_bytes()
                        .to_vec(),
                    ),
                ),
                (
                    Value::from("content_hash"),
                    Value::Binary(blake3::hash(&row.content).as_bytes().to_vec()),
                ),
                (
                    Value::from("pre_action_fork_hash"),
                    Value::Binary(fork.to_vec()),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Generated);
        body.evidence = Some(Value::Map(vec![(
            Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(actor.as_bytes().to_vec()),
        )]));
        let session_claim_id = actor_erase::session_claim_id(session, row.id)?;
        let mut session_claim = ClaimBody::new(
            "repo.session",
            ClaimSubject::Entity(session),
            Value::Map(vec![
                (Value::from("actor"), Value::from(actor.to_hex())),
                (Value::from("session"), Value::from(session.to_hex())),
                (
                    Value::from("provenance_claim_id"),
                    Value::from(provenance_claim.to_hex()),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        session_claim.source = Some(ClaimSource::Observed);
        session_claim.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        session_claim.evidence = body.evidence.clone();
        let mut txn = self.store.env.write_txn()?;
        if let Err(refused) = check(&txn)? {
            return Ok(Err(refused));
        }
        crate::repo_mutation::trailer::validate_repo_provenance_request_in_txn(
            self,
            &txn,
            &row.request()?,
        )?;
        validate_conflict_in_txn(self, &txn, &row)?;
        if !crate::ports::EntityStoreRead::port_entity_present(
            &self.store,
            &txn,
            &session_claim_id,
        )? {
            put_journal_claim(
                self,
                &mut txn,
                session_claim_id,
                Some(actor),
                &session_claim,
                row.created_at,
            )?;
        }
        if !crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &actor)? {
            return Err(Error::EntityNotFound);
        }
        put_journal_claim(self, &mut txn, row.id, Some(actor), &body, row.created_at)?;
        let snapshot_row = SNAPSHOT.decode_value(&snapshot)?;
        SNAPSHOT.put(
            &self.store,
            &mut txn,
            &repo_mutation_snapshot_key(fork),
            &snapshot_row,
        )?;
        store(self, &mut txn, &row)?;
        txn.commit()?;
        Ok(Ok(row))
    }
}
