//! Stable CLAIM scope identifiers and their MessagePack representation.
use super::ClaimSubject;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::PERSON_SUBSTRATE_FACET;
use oneiron_contracts::error::{Error, Result};
use rmpv::Value;

/// Reserved value for base reality. Defined in `oneiron-contracts`.
pub use oneiron_contracts::claim::base_world_id;
/// Reserved project value; projects are ids, not a new engine entity kind.
pub fn default_project_id() -> EntityId {
    EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        .expect("project scope id")
}
/// Stable substrate mask identity. Replaying PERSON creation mints the same mask.
pub fn substrate_facet_id(person: EntityId) -> Result<EntityId> {
    EntityId::derive(PERSON_SUBSTRATE_FACET, &[person.as_bytes()])
}
/// Engine-internal predicate of the vault default facet: subject the owner
/// PERSON, value the FACET id as 16 binary bytes. A later set supersedes the
/// earlier one, and claims sync, so every device reads the same default.
pub const PREDICATE_VAULT_DEFAULT_FACET: &str = "vault.default_facet";

pub fn subject_facet(subject: ClaimSubject) -> Result<EntityId> {
    substrate_facet_id(match subject {
        ClaimSubject::Entity(id) => id,
        ClaimSubject::Edge { source, .. } => source,
    })
}
pub fn scope_id(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidClaimBody("scope id must be binary"));
    };
    EntityId::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidClaimBody("scope id must be 16 bytes"))?,
    )
    .map_err(|_| Error::InvalidClaimBody("invalid scope id"))
}
pub fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}
