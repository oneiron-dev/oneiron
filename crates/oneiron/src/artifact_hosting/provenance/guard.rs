//! Birth ledger admission at the shared local and replicated put chokepoint.
use super::*;
use crate::claim::ClaimBody;
use crate::store::Store;

const DEPENDENCY_PENDING: &str = "artifact birth dependency pending";

#[cfg(feature = "sync")]
pub(crate) fn artifact_birth_dependency_pending(error: &Error) -> bool {
    matches!(error, Error::Artifact(ArtifactError::InvalidArtifactBirth(reason)) if *reason == DEPENDENCY_PENDING)
}

pub(crate) fn guard_artifact_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    incoming: Option<&ClaimBody>,
) -> Result<()> {
    if let Some(raw) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("artifact birth row header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM && raw.len() > ENTITY_METADATA_HEADER_LEN {
            let old = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if old.predicate == PREDICATE && incoming != Some(&old) {
                return invalid("artifact birth is immutable");
            }
        }
    }
    if let Some(claim) = incoming.filter(|claim| claim.predicate == PREDICATE) {
        let ClaimSubject::Entity(artifact) = claim.subject else {
            return invalid("birth subject must be an entity");
        };
        if birth_id(artifact)? != id {
            return invalid("birth ledger id must match the artifact");
        }
        let birth = ArtifactBirthEnvelope::decode(&claim.value)?;
        let input = store
            .entities
            .get(txn, birth.prompt_ref.as_bytes())?
            .ok_or_else(|| error(DEPENDENCY_PENDING))?;
        if input.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("birth input header"));
        }
        if blake3::hash(&input[ENTITY_METADATA_HEADER_LEN..]).as_bytes() != &birth.content_hash {
            return invalid("prompt input hash mismatch");
        }
        let expected = match birth.trigger {
            ArtifactTrigger::Task(id) => Some((id, vec![ENTITY_TYPE_TASK])),
            ArtifactTrigger::Skill(id) => Some((id, vec![ENTITY_TYPE_SKILL])),
            ArtifactTrigger::Ask(id) => Some((
                id,
                vec![
                    ENTITY_TYPE_MESSAGE,
                    crate::registry::ENTITY_TYPE_ASSET_TEXT,
                    crate::registry::ENTITY_TYPE_ASSET,
                ],
            )),
            ArtifactTrigger::Run(_) => None,
        };
        if let Some((target, kinds)) = expected {
            let raw = store
                .entities
                .get(txn, target.as_bytes())?
                .ok_or_else(|| error(DEPENDENCY_PENDING))?;
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| !kinds.contains(&header.entity_type))
            {
                return invalid("trigger kind mismatch");
            }
        }

        let evidence = claim
            .evidence
            .as_ref()
            .and_then(Value::as_map)
            .ok_or_else(|| error("birth requires attributed evidence"))?;
        let field = |name: &str| {
            evidence
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        };
        let actor_class = field(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
            .and_then(Value::as_u64)
            .ok_or_else(|| error("birth requires an actor class"))?;
        let made_by = field(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)
            .and_then(Value::as_map)
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|(key, _)| key.as_str() == Some("made_by"))
            })
            .map(|(_, value)| value);
        if claim.source.is_none() || made_by != Some(&claim.value) {
            return invalid("birth provenance envelope mismatch");
        }
        if (actor_class != crate::edge::EdgeActorClass::Human as u64
            || claim.source == Some(ClaimSource::Generated)
            || birth.purpose != ArtifactPurpose::Deliverable)
            && claim.approval != ClaimApprovalStatus::Proposed
        {
            return invalid("generated artifact births must remain proposed");
        }
    }
    match crate::registry::artifact_family_kind(kind) {
        Some(ArtifactFamilyKind::Code) => {
            crate::code_artifact::decode_code_artifact_body(data)?;
        }
        Some(ArtifactFamilyKind::Blob) => {
            crate::blob_artifact::decode_blob_artifact_body(data)?;
        }
        None => {}
    }
    if crate::registry::artifact_family_kind(kind).is_some()
        && store.entities.get(txn, id.as_bytes())?.is_none()
    {
        let ledger = birth_id(id)?;
        if let Some(raw) = store.entities.get(txn, ledger.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("birth ledger header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return invalid("birth ledger is not a claim");
            }
            let claim = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
            if claim.subject != ClaimSubject::Entity(id) || claim.predicate != PREDICATE {
                return invalid("birth ledger binding mismatch");
            }
            ArtifactBirthEnvelope::decode(&claim.value)?;
        } else if store.vault_meta.get(txn, &birth_permit_key(id))?.as_deref()
            != Some(blake3::hash(data).as_bytes().as_slice())
        {
            return invalid(DEPENDENCY_PENDING);
        }
    }
    Ok(())
}

// A transaction-local capability. The typed creator removes it before commit;
// the claim ledger is the only committed birth source of truth.
pub(super) fn birth_permit_key(id: EntityId) -> Vec<u8> {
    [b"artifact:birth:pending:v1:".as_slice(), id.as_bytes()].concat()
}
