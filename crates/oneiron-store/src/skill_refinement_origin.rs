//! The permanent origin facts of a refinement candidate: the hash of the
//! first native Proposed claim or Candidate skill bytes, keyed by entity id,
//! and the provenance markers that make a claim or skill a refinement. The
//! skill hub (`skill_hub::refinement_admission`) checks admission against
//! them; the store's put projections stage them.
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub fn declares_refinement(body: &crate::write_envelope::claim_body::ClaimBody) -> bool {
    body.evidence.as_ref().is_some_and(|evidence| {
        evidence.as_map().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("provenance") && value.as_str() == Some("claim-refinement")
            })
        })
    })
}
pub fn declares_skill_refinement(
    record: &crate::write_envelope::skill_record::SkillRecord,
) -> bool {
    record.provenance.as_map().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            key.as_str() == Some("source") && value.as_str() == Some("shared-skill-delta")
        })
    })
}
