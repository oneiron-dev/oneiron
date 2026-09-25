//! Inert subject-fact restore and explicit current-owner activation.
//! Foreign rows never supply the local owner act or become a live anchor by import.
use super::*;
use crate::batch::EntityMetadataHeader;
use crate::claim::decode_claim_body;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::live_entity_row_in_txn;

pub(crate) fn is_subject_model_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_ACTOR_SUBJECT_REF | PREDICATE_PERSON_SUBSTRATE
    )
}

/// Archive data is demoted, not re-authored as a local observation. The owning
/// readers ignore Proposed and Rejected rows, including their retained history.
pub(crate) fn imported_subject_body(body: &ClaimBody) -> Result<ClaimBody> {
    if !is_subject_model_predicate(&body.predicate)
        || body.world.is_some()
        || body.rel.is_some()
        || body.scope.is_some()
    {
        return Err(invalid(
            "archive subject fact must be an unscoped base fact",
        ));
    }
    if body.predicate == PREDICATE_ACTOR_SUBJECT_REF {
        validate_actor_subject_claim_structure(body)?;
    } else {
        validate_person_substrate_claim_structure(body)?;
    }
    let mut body = body.clone();
    body.source = Some(ClaimSource::Imported);
    if body.approval != ClaimApprovalStatus::Rejected {
        body.approval = ClaimApprovalStatus::Proposed;
    }
    Ok(body)
}

/// A host-authenticated owner reviews this exact proposal and supersession set.
/// Fields are private: foreign archive bytes cannot construct an approval token.
#[derive(Debug, Clone)]
pub struct SubjectRestoreReview {
    claim_id: EntityId,
    body: ClaimBody,
    digest: [u8; 32],
    writer: WriteActor,
    priors: Vec<(EntityId, [u8; 32])>,
}
impl SubjectRestoreReview {
    pub fn claim_id(&self) -> EntityId {
        self.claim_id
    }
    pub fn proposal(&self) -> &ClaimBody {
        &self.body
    }
    pub fn superseded_claim_ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.priors.iter().map(|(id, _)| *id)
    }
}
impl Vault {
    pub(crate) fn restore_subject_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let expected = imported_subject_body(body)?;
        if &expected != body {
            return Err(invalid(
                "archive subject restore requires Imported and Proposed or Rejected",
            ));
        }
        validate_subject_model_claim_in_txn(&self.store, txn, body)?;
        require_live_references(self, txn, body)?;
        self.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    }

    /// Prepare an explicit subject-identity review. Import itself never invokes
    /// this door. Owner authority is checked again at the approval transaction.
    pub fn request_subject_restore_review(
        &self,
        id: EntityId,
        writer: &WriteActor,
    ) -> Result<SubjectRestoreReview> {
        let txn = self.store.env.read_txn()?;
        validate_writer_in_txn(self, &txn, *writer)?;
        self.verify_owner_write_actor_in_txn(&txn, writer)?;
        let (body, digest) = pending_subject(self, &txn, &id)?;
        let priors = prior_fingerprints(self, &txn, &body, crate::unix_seconds_now())?;
        Ok(SubjectRestoreReview {
            claim_id: id,
            body,
            digest,
            writer: *writer,
            priors,
        })
    }

    /// Approve exactly the reviewed foreign fact as a NEW local approval now.
    /// Source stays Imported. No archived author, grant or historical approval
    /// is revived, and the supersession and owner stamp commit together.
    pub fn approve_subject_restore_review(
        &self,
        review: &SubjectRestoreReview,
    ) -> Result<EntityId> {
        let mut txn = self.store.env.write_txn()?;
        validate_writer_in_txn(self, &txn, review.writer)?;
        self.verify_owner_write_actor_in_txn(&txn, &review.writer)?;
        let (mut body, digest) = pending_subject(self, &txn, &review.claim_id)?;
        let now = crate::unix_seconds_now();
        if digest != review.digest || prior_fingerprints(self, &txn, &body, now)? != review.priors {
            return Err(invalid("subject restore review is stale"));
        }
        body.approval = ClaimApprovalStatus::Approved;
        body.valid_from = Some(now);
        body.valid_to = None;
        body.evidence = Some(Value::Map(vec![
            ("local_owner_review".into(), writer_evidence(review.writer)),
            (
                "archived_proposal_sha256".into(),
                Value::from(hex_digest(review.digest)),
            ),
            ("approved_at".into(), Value::from(now)),
        ]));
        write_head_in_txn(self, &mut txn, &review.claim_id, &body, now)?;
        txn.commit()?;
        Ok(review.claim_id)
    }
}
fn pending_subject(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(ClaimBody, [u8; 32])> {
    if vault.store.off_record_sessions.contains_entity(id)?
        || !live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
    {
        return Err(Error::EntityNotFound);
    }
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("subject restore header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(invalid("subject restore target must be a claim"));
    }
    let body = decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)?;
    let expected = imported_subject_body(&body)?;
    if body != expected
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(invalid(
            "subject restore requires a pending imported active fact",
        ));
    }
    require_live_references(vault, txn, &body)?;
    Ok((body, digest(&raw)))
}
fn require_live_references(vault: &Vault, txn: &heed::RoTxn<'_>, body: &ClaimBody) -> Result<()> {
    validate_subject_model_claim_in_txn(&vault.store, txn, body)?;
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid("subject restore requires an entity subject"));
    };
    let mut refs = vec![subject];
    if body.predicate == PREDICATE_ACTOR_SUBJECT_REF {
        refs.push(validate_actor_subject_claim_structure(body)?.1);
    }
    for id in refs {
        if vault.store.off_record_sessions.contains_entity(&id)?
            || !live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
        {
            return Err(Error::EntityNotFound);
        }
    }
    Ok(())
}
fn prior_fingerprints(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    at: u64,
) -> Result<Vec<(EntityId, [u8; 32])>> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid("subject restore requires an entity subject"));
    };
    let heads = if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        person_substrate_bodies_in_txn(vault, txn, &subject, at, true)?
    } else {
        replacement_heads_in_txn(vault, txn, &subject, &body.predicate, at)?
    };
    let mut rows = Vec::new();
    for (id, _) in heads {
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        rows.push((id, digest(&raw)));
    }
    rows.sort_by_key(|(id, _)| *id);
    Ok(rows)
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
fn hex_digest(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
