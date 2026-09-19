//! Required record-position Scope stamps and the versioned CLAIM wire upgrade.
use super::{ClaimBody, ClaimSubject};
use crate::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use crate::{
    EntityId,
    error::{Error, Result},
};
use rmpv::Value;
use std::collections::BTreeSet;
#[cfg(test)]
mod tests;

/// Reserved value for base reality. This is a scope member, never an entity row.
pub fn base_world_id() -> EntityId {
    EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).expect("base scope id")
}
/// Reserved project value; projects are ids, not a new engine entity kind.
pub fn default_project_id() -> EntityId {
    EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        .expect("project scope id")
}
/// Stable substrate mask identity. Replaying PERSON creation mints the same mask.
pub fn substrate_facet_id(person: EntityId) -> EntityId {
    let mut h = blake3::Hasher::new_derive_key("oneiron/person-substrate-facet/v1");
    h.update(person.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&h.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 0x80;
    bytes[8] = (bytes[8] & 63) | 0x80;
    EntityId::from_bytes(bytes).expect("derived UUID")
}
pub(super) fn subject_facet(subject: ClaimSubject) -> EntityId {
    substrate_facet_id(match subject {
        ClaimSubject::Entity(id) => id,
        ClaimSubject::Edge { source, .. } => source,
    })
}
pub(super) fn scope_id(value: &Value) -> Result<EntityId> {
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
pub(super) fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

impl ClaimBody {
    /// The positively stamped record position used by the common Scope evaluator.
    pub fn record_scope(&self, verb_class: &str) -> Scope {
        let sensitivity = match super::claim_sensitivity_band(self) {
            Some(0) => SensitivityCeiling::AtMost(Sensitivity::Public),
            Some(1) => SensitivityCeiling::AtMost(Sensitivity::Private),
            Some(2) => SensitivityCeiling::AtMost(Sensitivity::Sensitive),
            Some(3) => SensitivityCeiling::AtMost(Sensitivity::Restricted),
            _ => SensitivityCeiling::Bottom,
        };
        Scope {
            worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(
                self.world.unwrap_or_else(base_world_id),
            )])),
            facets: ScopeAxis::Some(BTreeSet::from([ScopeId(self.scope_facet)])),
            bands: ScopeAxis::Some(BTreeSet::from([crate::registry::ENTITY_TYPE_CLAIM])),
            audience: ScopeAxis::Some(BTreeSet::from([ScopeId(self.scope_project)])),
            verbs: ScopeAxis::Some(BTreeSet::from([verb_class.to_owned()])),
            sensitivity,
        }
    }
}

/// Only the open-time sweep calls this. A network/raw write never upgrades missing keys.
pub(crate) fn upgrade_pre_scope_body(data: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(data);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("legacy claim map"))?
    else {
        return Err(Error::InvalidClaimBody("legacy claim map"));
    };
    if cursor.position() != data.len() as u64 {
        return Err(Error::InvalidClaimBody("legacy trailing bytes"));
    }
    let mut keys = BTreeSet::new();
    if entries
        .iter()
        .any(|(k, _)| k.as_str().is_none_or(|k| !keys.insert(k.to_owned())))
    {
        return Err(Error::InvalidClaimBody("legacy duplicate key"));
    }
    if keys.contains("scopeVersion") {
        super::decode_claim_body(data, true)?;
        return Ok(data.to_vec());
    }
    // A partial new stamp is corruption, not an old-version row.
    if [
        "worldId",
        "scopeFacetId",
        "scopeRelationshipId",
        "scopeProjectId",
        "scopeSensitivity",
    ]
    .iter()
    .any(|k| keys.contains(*k))
    {
        return Err(Error::InvalidClaimBody("partial scope stamp"));
    }
    let subject = entries
        .iter()
        .find(|(k, _)| k.as_str() == Some("subj"))
        .ok_or(Error::InvalidClaimBody("missing subject"))?;
    let Value::Binary(bytes) = &subject.1 else {
        return Err(Error::InvalidClaimBody("invalid subject"));
    };
    let facet = subject_facet(ClaimSubject::decode(bytes)?);
    let take = |entries: &mut Vec<(Value, Value)>, name: &str| {
        entries
            .iter()
            .position(|(k, _)| k.as_str() == Some(name))
            .map(|i| entries.remove(i).1)
    };
    let world = take(&mut entries, "world").unwrap_or_else(|| id_value(base_world_id()));
    let rel = take(&mut entries, "rel")
        .map(|v| Value::Array(vec![v]))
        .unwrap_or_else(|| Value::from("all"));
    let legacy_scope = entries
        .iter()
        .find(|(k, _)| k.as_str() == Some("scope"))
        .map(|(_, v)| v);
    let field = |names: &[&str]| -> Option<Value> {
        let Value::Map(map) = legacy_scope? else {
            return None;
        };
        map.iter()
            .find(|(k, _)| k.as_str().is_some_and(|k| names.contains(&k)))
            .map(|(_, v)| v.clone())
    };
    let facet = field(&["facet", "facet_ref", "facetRef"])
        .and_then(|v| match v {
            Value::Binary(_) => scope_id(&v).ok(),
            _ => v.as_str().and_then(|s| EntityId::from_hex(s).ok()),
        })
        .unwrap_or(facet);
    let project = match field(&["corpus_id"]) {
        None => id_value(default_project_id()),
        Some(Value::String(text)) => id_value(
            EntityId::from_hex(
                text.as_str()
                    .ok_or(Error::InvalidClaimBody("invalid legacy project"))?,
            )
            .map_err(|_| Error::InvalidClaimBody("invalid legacy project"))?,
        ),
        Some(value) => value,
    };
    entries.extend([
        ("worldId".into(), world),
        ("scopeFacetId".into(), id_value(facet)),
        ("scopeRelationshipId".into(), rel),
        ("scopeProjectId".into(), project),
        ("scopeVersion".into(), 2u64.into()),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("scope sweep encode"))?;
    let body = super::decode_claim_body(&out, true)?;
    super::encode_claim_body(&body)
}
