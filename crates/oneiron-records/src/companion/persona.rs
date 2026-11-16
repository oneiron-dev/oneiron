//! Moved from `crates/oneiron/src/companion/persona.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::ScopeId;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

/// Reproducible derivation inputs. This is provenance, never authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaMadeBy {
    #[serde(
        serialize_with = "serialize_inputs",
        deserialize_with = "deserialize_inputs"
    )]
    pub inputs: Vec<EntityId>,
    pub process: String,
    pub at: u64,
    /// The exact revision of each input this was derived from, as its writer
    /// read it ([`ScopedRead::persona_input_bases`]). An input with no entry
    /// records no basis; a change written before bases existed carries none,
    /// and its wire form is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<PersonaInputBasis>,
}

/// One derivation input at the exact revision its writer read: the input's
/// live revision in the entity revision ledger, which retains it when the
/// input is replaced, so a reader can still read it with
/// `PointRead::id(input).at(ReadMode::Pinned(revision))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaInputBasis {
    #[serde(
        serialize_with = "serialize_input",
        deserialize_with = "deserialize_input"
    )]
    pub input: EntityId,
    #[serde(
        serialize_with = "serialize_revision",
        deserialize_with = "deserialize_revision"
    )]
    pub revision: RevisionRef,
}

pub fn serialize_inputs<S: serde::Serializer>(
    inputs: &[EntityId],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    inputs
        .iter()
        .copied()
        .map(ScopeId)
        .collect::<Vec<_>>()
        .serialize(serializer)
}

pub fn deserialize_inputs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<EntityId>, D::Error> {
    Vec::<ScopeId>::deserialize(deserializer).map(|ids| ids.into_iter().map(|id| id.0).collect())
}

pub fn serialize_input<S: serde::Serializer>(
    input: &EntityId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    ScopeId(*input).serialize(serializer)
}

pub fn deserialize_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<EntityId, D::Error> {
    ScopeId::deserialize(deserializer).map(|id| id.0)
}

pub fn serialize_revision<S: serde::Serializer>(
    revision: &RevisionRef,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&revision.to_hex())
}

pub fn deserialize_revision<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RevisionRef, D::Error> {
    let text = String::deserialize(deserializer)?;
    RevisionRef::from_hex(&text)
        .map_err(|_| serde::de::Error::custom("persona input basis is not a revision reference"))
}
