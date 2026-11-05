//! FACET write checks: the local identity-body refusal, immutable substrate
//! identity and retired privacy axes.
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_FACET;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// The one local identity-body refusal. PERSON holds identity; a FACET is a
/// scenario mask, so a FACET body shaped as a persona or relationship is
/// refused on every local door (put apply and checkpoint restore).
pub fn validate_local_identity_body(entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type == ENTITY_TYPE_FACET
        && crate::write_envelope::person_identity::is_identity_facet_body(body)
    {
        return Err(Error::InvalidClaimBody(
            "FACET cannot carry PERSON identity",
        ));
    }
    Ok(())
}
