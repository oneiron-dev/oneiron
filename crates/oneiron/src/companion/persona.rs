//! PERSON identity baselines and deterministic replay of recorded changes.
//!
//! Payloads are caller-owned JSON, not engine prompts. Only explicit scenario
//! variants live on FACET. Compilation is a projection, never a second store.

use super::codec::{companion_value_from_json, companion_value_to_json, invalid_companion};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, ScopedRead, decode_claim_body,
};
use crate::error::{Error, Result};
use crate::federation::{ScopeId, Sensitivity};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::{EdgeKind, EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

/// Identity changes are ordinary lifecycle-managed claims on the PERSON.
pub const PERSONA_CHANGE_PREDICATE: &str = "persona.change";
const BASELINE_KEY: &str = "persona_definition";
const SCENARIO_KEY: &str = "persona_scenario";

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
}

fn serialize_inputs<S: serde::Serializer>(
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

fn deserialize_inputs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<EntityId>, D::Error> {
    Vec::<ScopeId>::deserialize(deserializer).map(|ids| ids.into_iter().map(|id| id.0).collect())
}

/// An object merge patch. Null removes a field; objects merge recursively.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaChange {
    pub patch: JsonValue,
    pub made_by: PersonaMadeBy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeWire {
    schema_version: u8,
    patch: JsonValue,
    made_by: PersonaMadeBy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineWire {
    schema_version: u8,
    baseline: JsonValue,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioWire {
    schema_version: u8,
    person_ref: ScopeId,
    patch: JsonValue,
}

/// A read projection from PERSON, active changes, and an optional scenario mask.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledPersona {
    pub person: EntityId,
    pub scenario: Option<EntityId>,
    pub value: JsonValue,
    pub made_by: PersonaMadeBy,
}

fn object(value: &JsonValue) -> Result<()> {
    if !value.is_object() {
        return Err(invalid_companion("persona payload must be a JSON object"));
    }
    Ok(())
}

impl PersonaChange {
    /// Produces the value of a `persona.change` CLAIM. The ordinary claim write
    /// door owns actor authorization, scope, approval, and lifecycle.
    pub fn to_claim_value(&self) -> Result<Value> {
        object(&self.patch)?;
        if self.made_by.process.trim().is_empty() || self.made_by.inputs.is_empty() {
            return Err(invalid_companion(
                "persona change requires made_by inputs and process",
            ));
        }
        to_value(&ChangeWire {
            schema_version: 1,
            patch: self.patch.clone(),
            made_by: self.made_by.clone(),
        })
    }

    fn from_claim_value(value: &Value) -> Result<Self> {
        let wire: ChangeWire = from_value(value)?;
        if wire.schema_version != 1 {
            return Err(invalid_companion("unsupported persona change version"));
        }
        let change = Self {
            patch: wire.patch,
            made_by: wire.made_by,
        };
        change.to_claim_value()?;
        Ok(change)
    }
}

fn to_value(value: &impl Serialize) -> Result<Value> {
    let json =
        serde_json::to_value(value).map_err(|_| invalid_companion("persona value is not JSON"))?;
    let value = companion_value_from_json(&json)?;
    validate_json(&value, 0)?;
    Ok(value)
}

fn validate_json(value: &Value, depth: usize) -> Result<()> {
    if depth > 128 {
        return Err(invalid_companion("persona JSON is too deeply nested"));
    }
    match value {
        Value::Binary(_) | Value::Ext(_, _) => {
            return Err(invalid_companion("persona JSON cannot carry binary values"));
        }
        Value::F32(number) if !number.is_finite() => {
            return Err(invalid_companion("persona JSON number is not finite"));
        }
        Value::F64(number) if !number.is_finite() => {
            return Err(invalid_companion("persona JSON number is not finite"));
        }
        Value::String(text) if text.as_str().is_none() => {
            return Err(invalid_companion("persona JSON string is not UTF-8"));
        }
        Value::Map(entries) => {
            let mut keys = BTreeSet::new();
            for (key, value) in entries {
                let key = key
                    .as_str()
                    .ok_or_else(|| invalid_companion("persona JSON key is not text"))?;
                if !keys.insert(key) {
                    return Err(invalid_companion("duplicate persona JSON key"));
                }
                validate_json(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_json(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    // The public companion projector redacts binary values. Compilation must
    // instead reject them: redacting to null would turn data into a deletion.
    validate_json(value, 0)?;
    serde_json::from_value(companion_value_to_json(value))
        .map_err(|_| invalid_companion("invalid persona value"))
}

fn body_fields(data: &[u8]) -> Result<Vec<(Value, Value)>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut cursor = std::io::Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("invalid persona record body"))?;
    if cursor.position() != data.len() as u64 {
        return Err(invalid_companion("trailing persona record bytes"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_companion("persona record body must be a map"));
    };
    let mut keys = BTreeSet::new();
    for (key, _) in &entries {
        if !keys.insert(
            key.as_str()
                .ok_or_else(|| invalid_companion("persona record key must be text"))?,
        ) {
            return Err(invalid_companion("duplicate persona record key"));
        }
    }
    Ok(entries)
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
        .ok_or_else(|| invalid_companion("persona record field is missing"))
}

fn put_field(entries: &mut Vec<(Value, Value)>, name: &str, value: Value) {
    entries.retain(|(key, _)| key.as_str() != Some(name));
    entries.push((name.into(), value));
}

fn encode_fields(entries: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|_| invalid_companion("persona record encoding failed"))?;
    Ok(bytes)
}

impl Vault {
    /// Sets a PERSON's baseline atomically, retaining unrelated identity fields.
    /// Changing the baseline does not mint a mask or rewrite any recorded change.
    pub fn put_persona_baseline(
        &self,
        person: &EntityId,
        baseline: &JsonValue,
        at: u64,
    ) -> Result<()> {
        object(baseline)?;
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&txn, person.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .into_owned();
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("persona PERSON header"))?;
        if header.entity_type != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let mut entries = body_fields(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        put_field(
            &mut entries,
            BASELINE_KEY,
            to_value(&BaselineWire {
                schema_version: 1,
                baseline: baseline.clone(),
            })?,
        );
        let bytes = encode_fields(entries)?;
        self.batch_in()
            .put(
                person,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                at,
                &bytes,
            )
            .apply(&mut txn)?;
        txn.commit()?;
        Ok(())
    }

    /// Creates or updates an explicit scenario mask belonging to this PERSON.
    pub fn put_persona_scenario(
        &self,
        person: &EntityId,
        facet: &EntityId,
        patch: &JsonValue,
        sensitivity: Sensitivity,
        at: u64,
    ) -> Result<()> {
        object(patch)?;
        let mut txn = self.store.env.write_txn()?;
        let person_raw = self
            .store
            .entities
            .get(&txn, person.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&person_raw)
            .ok_or(Error::CorruptedIndex("persona PERSON header"))?;
        if header.entity_type != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let mut entries = if let Some(raw) = self.store.entities.get(&txn, facet.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("persona FACET header"))?;
            if header.entity_type != ENTITY_TYPE_FACET {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let entries = body_fields(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let prior: ScenarioWire = from_value(field(&entries, SCENARIO_KEY)?)?;
            if prior.person_ref.0 != *person || prior.schema_version != 1 {
                return Err(invalid_companion("scenario PERSON binding cannot change"));
            }
            entries
        } else {
            Vec::new()
        };
        put_field(&mut entries, "kind", "scenario".into());
        put_field(&mut entries, "sensitivity", sensitivity.as_str().into());
        put_field(
            &mut entries,
            SCENARIO_KEY,
            to_value(&ScenarioWire {
                schema_version: 1,
                person_ref: ScopeId(*person),
                patch: patch.clone(),
            })?,
        );
        let bytes = encode_fields(entries)?;
        self.batch_in()
            .put(
                facet,
                ENTITY_TYPE_FACET,
                TimeRange { start: at, end: at },
                at,
                &bytes,
            )
            .edge(person, EdgeKind::HasFacet, facet, 1.0)
            .apply(&mut txn)?;
        txn.commit()?;
        Ok(())
    }
}

fn merge_patch(target: &mut JsonValue, patch: &JsonValue) {
    if let JsonValue::Object(fields) = patch {
        if !target.is_object() {
            *target = JsonValue::Object(serde_json::Map::new());
        }
        let JsonValue::Object(target) = target else {
            return;
        };
        for (key, value) in fields {
            if value.is_null() {
                target.remove(key);
            } else {
                merge_patch(target.entry(key.clone()).or_insert(JsonValue::Null), value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

impl ScopedRead<'_> {
    /// Replays approved identity changes on the current PERSON baseline. Pending, retracted,
    /// superseded, scoped-away and unauthorized changes cannot enter the result.
    /// The optional scenario is applied last and must belong to this PERSON.
    pub fn compile_persona(
        &self,
        person: &EntityId,
        scenario: Option<EntityId>,
    ) -> Result<CompiledPersona> {
        let (kind, baseline_at, data) = self
            .get_entity_parts(person)?
            .ok_or(Error::EntityNotFound)?;
        if kind != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(kind));
        }
        let baseline: BaselineWire = from_value(field(&body_fields(&data)?, BASELINE_KEY)?)?;
        if baseline.schema_version != 1 {
            return Err(invalid_companion("unsupported persona baseline version"));
        }
        object(&baseline.baseline)?;
        let mut value = baseline.baseline;
        let mut changes = Vec::new();
        for id in self.vault().claims_for_subject(person)? {
            let Some((_, _, data)) = self.get_entity_parts(&id)? else {
                continue;
            };
            let body = decode_claim_body(&data, true)?;
            if body.predicate != PERSONA_CHANGE_PREDICATE
                || body.subject != ClaimSubject::Entity(*person)
                || body.approval == ClaimApprovalStatus::Proposed
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
                || body.world.is_some()
                || body.rel.is_some()
                || body.scope_project != crate::claim::default_project_id()
                || (body.scope_facet != crate::claim::substrate_facet_id(*person)
                    && !crate::claim::session_claim_producer(&body).is_some_and(|actor| {
                        body.scope_facet == crate::claim::substrate_facet_id(actor)
                    }))
            {
                continue;
            }
            let change = PersonaChange::from_claim_value(&body.value)?;
            changes.push((change.made_by.at, id, change));
        }
        changes.sort_by_key(|(at, id, _)| (*at, *id));
        let mut inputs = vec![*person];
        let mut at = baseline_at;
        for (changed_at, id, change) in changes {
            merge_patch(&mut value, &change.patch);
            inputs.push(id);
            at = at.max(changed_at);
        }
        if let Some(facet) = scenario {
            let (kind, learned_at, data) = self
                .get_entity_parts(&facet)?
                .ok_or(Error::EntityNotFound)?;
            if kind != ENTITY_TYPE_FACET {
                return Err(Error::InvalidEntityType(kind));
            }
            let entries = body_fields(&data)?;
            let mask: ScenarioWire = from_value(field(&entries, SCENARIO_KEY)?)?;
            if mask.schema_version != 1
                || mask.person_ref.0 != *person
                || field(&entries, "kind")?.as_str() != Some("scenario")
                || !self
                    .edges_out(person)?
                    .value
                    .unwrap_or_default()
                    .iter()
                    .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == facet)
            {
                return Err(invalid_companion("scenario does not belong to PERSON"));
            }
            object(&mask.patch)?;
            merge_patch(&mut value, &mask.patch);
            inputs.push(facet);
            at = at.max(learned_at);
        }
        Ok(CompiledPersona {
            person: *person,
            scenario,
            value,
            made_by: PersonaMadeBy {
                inputs,
                process: "persona.merge-patch.v1".to_owned(),
                at,
            },
        })
    }
}

#[cfg(test)]
mod tests;
