//! PERSON identity baselines and deterministic replay of recorded changes.
//!
//! Payloads are caller-owned JSON, not engine prompts. Only explicit scenario
//! variants live on FACET. Compilation is a projection, never a second store.

use super::codec::invalid_companion;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, PointRead, ReadRow, ScopedRead,
    ScopedReadReceipt, decode_claim_body,
};
use crate::error::{Error, Result};
use crate::federation::{ScopeId, Sensitivity};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::serialize::msgpack_value_from_json;
use crate::{EdgeKind, EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Identity changes are ordinary lifecycle-managed claims on the PERSON.
pub const PERSONA_CHANGE_PREDICATE: &str = "persona.change";
use crate::serialize::person_identity::BASELINE_KEY;
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

use crate::serialize::person_identity::BaselineWire;

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
    /// Every scoped read the projection made, folded: the changes and scenario
    /// facts this reader could not see are counted here, never silently lost.
    pub receipt: ScopedReadReceipt,
}

use crate::serialize::person_identity::object;

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
    let value = msgpack_value_from_json(&json)?;
    validate_json(&value, 0)?;
    Ok(value)
}

use crate::serialize::person_identity::{from_value, validate_json};

pub(crate) use crate::write_envelope::person_identity::body_fields;

use crate::serialize::person_identity::field;
pub(crate) use crate::serialize::person_identity::validated_persona_baseline;

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
        let mut txn = self.store.env.write_txn()?;
        self.put_persona_baseline_in_txn(&mut txn, person, baseline, at)?;
        txn.commit()?;
        Ok(())
    }

    /// Transactional baseline write for authorized composite operations.
    pub(crate) fn put_persona_baseline_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        person: &EntityId,
        baseline: &JsonValue,
        at: u64,
    ) -> Result<()> {
        object(baseline)?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &*txn, person)?
            .ok_or(Error::EntityNotFound)?;
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
            .apply(txn)?;
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
        let person_raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, person)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&person_raw)
            .ok_or(Error::CorruptedIndex("persona PERSON header"))?;
        if header.entity_type != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let mut entries = if let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, facet)?
        {
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
        let baseline = self.read(&[PointRead::id(*person)], None)?.single();
        let mut receipt = baseline.receipt;
        let Some(ReadRow {
            entity_type: kind,
            learned_at: baseline_at,
            body: Some(data),
            ..
        }) = baseline.value
        else {
            return Err(Error::EntityNotFound);
        };
        if kind != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(kind));
        }
        let mut value = validated_persona_baseline(&data)?;
        let mut changes = Vec::new();
        let claims: Vec<_> = self
            .vault()
            .claims_for_subject(person)?
            .into_iter()
            .map(PointRead::id)
            .collect();
        let claims = self.read(&claims, None)?;
        receipt.restrict_with(&claims.receipt);
        for row in claims.value.into_iter().flatten() {
            let ReadRow {
                id,
                body: Some(data),
                ..
            } = row
            else {
                continue;
            };
            let body = decode_claim_body(&data, true)?;
            let producer_facet = crate::claim::session_claim_producer(&body)
                .map(crate::claim::substrate_facet_id)
                .transpose()?;
            if body.predicate != PERSONA_CHANGE_PREDICATE
                || body.subject != ClaimSubject::Entity(*person)
                || body.approval == ClaimApprovalStatus::Proposed
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
                || body.world.is_some()
                || body.rel.is_some()
                || body.scope_project != crate::claim::default_project_id()
                || (body.scope_facet != crate::claim::substrate_facet_id(*person)?
                    && producer_facet != Some(body.scope_facet))
                || !self.vault().claim_critical_confirm_settled(&id)?
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
            let parts = self.read(&[PointRead::id(facet)], None)?.single();
            receipt.restrict_with(&parts.receipt);
            let Some(ReadRow {
                entity_type: kind,
                learned_at,
                body: Some(data),
                ..
            }) = parts.value
            else {
                return Err(Error::EntityNotFound);
            };
            if kind != ENTITY_TYPE_FACET {
                return Err(Error::InvalidEntityType(kind));
            }
            let entries = body_fields(&data)?;
            let mask: ScenarioWire = from_value(field(&entries, SCENARIO_KEY)?)?;
            let edges = self.edges_out(person)?;
            receipt.restrict_with(&edges.receipt);
            if mask.schema_version != 1
                || mask.person_ref.0 != *person
                || field(&entries, "kind")?.as_str() != Some("scenario")
                || !edges
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
            receipt,
        })
    }
}

#[cfg(test)]
mod tests;
