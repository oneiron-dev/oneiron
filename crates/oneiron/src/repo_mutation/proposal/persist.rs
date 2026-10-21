//! One proposal's persistence (moved from `submit.rs`, G4 PR2): its
//! journal claims, built before the writer, and the claims, base snapshot
//! and row it writes in its caller's writer. Every proposer shares it.

use super::*;

/// One proposal's rows as its writer persists them: the row, its encoded
/// base snapshot and its two journal claims.
pub(in crate::repo_mutation) struct PreparedRepoProposal {
    pub(in crate::repo_mutation) row: RepoProposal,
    snapshot: Vec<u8>,
    body: ClaimBody,
    session_claim_id: EntityId,
    session_claim: ClaimBody,
}

impl PreparedRepoProposal {
    /// The journal claims `row` writes over its base `snapshot`.
    ///
    /// # Errors
    /// An erased proposer, or a claim that does not encode.
    pub(in crate::repo_mutation) fn new(row: RepoProposal, snapshot: Vec<u8>) -> Result<Self> {
        let actor = row.actor.live()?;
        let session = row.session;
        let provenance_claim = row.provenance_claim;
        let fork = row.pre_action_fork_hash;
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
        Ok(Self {
            row,
            snapshot,
            body,
            session_claim_id,
            session_claim,
        })
    }

    /// Writes the claims, the base snapshot and the row in `txn`, after
    /// validating the provenance and conflict bindings in it.
    ///
    /// # Errors
    /// A binding that does not hold, an absent actor, or a store failure.
    pub(in crate::repo_mutation) fn persist_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let row = &self.row;
        let actor = row.actor.live()?;
        crate::repo_mutation::trailer::validate_repo_provenance_request_in_txn(
            vault,
            txn,
            &row.request()?,
        )?;
        validate_conflict_in_txn(vault, txn, row)?;
        if !crate::ports::EntityStoreRead::port_entity_present(
            &vault.store,
            txn,
            &self.session_claim_id,
        )? {
            put_journal_claim(
                vault,
                txn,
                self.session_claim_id,
                Some(actor),
                &self.session_claim,
                row.created_at,
            )?;
        }
        if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &actor)? {
            return Err(Error::EntityNotFound);
        }
        put_journal_claim(vault, txn, row.id, Some(actor), &self.body, row.created_at)?;
        let snapshot_row = SNAPSHOT.decode_value(&self.snapshot)?;
        SNAPSHOT.put(
            &vault.store,
            txn,
            &repo_mutation_snapshot_key(row.pre_action_fork_hash),
            &snapshot_row,
        )?;
        store(vault, txn, row)
    }
}
