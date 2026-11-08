//! PERSON identity baselines and deterministic replay of recorded changes.
//!
//! Payloads are caller-owned JSON, not engine prompts. Only explicit scenario
//! variants live on FACET. Compilation is a projection, never a second store.

use super::codec::invalid_companion;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, PointRead, ReadRow, ScopedRead,
    ScopedReadReceipt, ScopedReadResult, decode_claim_body,
};
use crate::error::{Error, Result};
use crate::federation::{ScopeId, Sensitivity};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::serialize::msgpack_value_from_json;
use crate::vault::entity_revision::{ReadMode, RevisionRef, revision_for_mode_in_txn};
use crate::{EdgeKind, EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};

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

/// A replayed change whose recorded basis for one input is not the basis this
/// replay applied it over. Advisory only: the change still applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonaReplayConflict {
    /// The `persona.change` claim.
    pub change: EntityId,
    pub input: EntityId,
    /// The revision the change recorded for `input`.
    pub recorded: RevisionRef,
    /// The revision of `input` this replay applied the change over. `None`:
    /// this reader reads no revision of it now, or `input` is a change of this
    /// PERSON that the replay did not apply before this one.
    pub current: Option<RevisionRef>,
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

fn serialize_input<S: serde::Serializer>(
    input: &EntityId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    ScopeId(*input).serialize(serializer)
}

fn deserialize_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<EntityId, D::Error> {
    ScopeId::deserialize(deserializer).map(|id| id.0)
}

fn serialize_revision<S: serde::Serializer>(
    revision: &RevisionRef,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&revision.to_hex())
}

fn deserialize_revision<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RevisionRef, D::Error> {
    let text = String::deserialize(deserializer)?;
    RevisionRef::from_hex(&text)
        .map_err(|_| serde::de::Error::custom("persona input basis is not a revision reference"))
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
    /// The live revision each of `made_by.inputs` was read at, in that order,
    /// each in the snapshot its words were read in (FIX 4817): a reader that
    /// wore this value can tell whether every input still reads at it.
    pub input_revisions: Vec<Option<RevisionRef>>,
    /// Every scoped read the projection made, folded: the changes and scenario
    /// facts this reader could not see are counted here, never silently lost.
    pub receipt: ScopedReadReceipt,
    /// Advisory, in replay order: each recorded input basis of an applied
    /// change that differs from the basis this replay applied it over. Every
    /// change applied regardless; a change with no recorded basis reports none.
    pub replay_conflicts: Vec<PersonaReplayConflict>,
}

/// An explicit scenario mask its PERSON owns, as one scoped read proved it
/// (FIX 4571): the mask's patch, when its FACET was learned, the live
/// revision the FACET read at, and the receipts of the FACET and edge reads
/// that proved it, in that order.
struct OwnedScenario {
    patch: JsonValue,
    learned_at: u64,
    revision: Option<RevisionRef>,
    receipts: [ScopedReadReceipt; 2],
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
        let mut based = BTreeSet::new();
        if !self
            .made_by
            .bases
            .iter()
            .all(|basis| self.made_by.inputs.contains(&basis.input) && based.insert(basis.input))
        {
            return Err(invalid_companion(
                "persona change bases must name distinct made_by inputs",
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

/// An admitted row and its live revision, read in one snapshot.
type RowWithRevision = (ReadRow, Option<RevisionRef>);

impl ScopedRead<'_> {
    /// Reads `reads` through this lane and names, in the same snapshot, the
    /// live revision of each row it admits: the basis a persona input records
    /// and the basis a replay applies a change over.
    fn read_live_bases(
        &self,
        reads: &[PointRead<'_>],
    ) -> Result<ScopedReadResult<Vec<Option<RowWithRevision>>>> {
        let store = self.store_read();
        self.read_projected(reads, None, |txn, rows| {
            rows.into_iter()
                .map(|row| {
                    row.map(|row| -> Result<RowWithRevision> {
                        let revision =
                            revision_for_mode_in_txn(&store, txn, &row.id, ReadMode::Live)?;
                        Ok((row, revision))
                    })
                    .transpose()
                })
                .collect::<Result<Vec<_>>>()
        })
    }

    /// The live revision of each input this reader reads now, for a change
    /// derived from them to record as [`PersonaMadeBy::bases`]. An input this
    /// reader cannot read, or one with no ledger revision, gets no basis: none
    /// is invented. The receipt counts the inputs withheld from this reader.
    pub fn persona_input_bases(
        &self,
        inputs: &[EntityId],
    ) -> Result<ScopedReadResult<Vec<PersonaInputBasis>>> {
        let reads: Vec<_> = inputs.iter().copied().map(PointRead::id).collect();
        Ok(self.read_live_bases(&reads)?.map(|rows| {
            let mut bases: Vec<PersonaInputBasis> = Vec::new();
            for (row, revision) in rows.into_iter().flatten() {
                if let Some(revision) = revision
                    && !bases.iter().any(|basis| basis.input == row.id)
                {
                    bases.push(PersonaInputBasis {
                        input: row.id,
                        revision,
                    });
                }
            }
            bases
        }))
    }

    /// Whether `facet` is an explicit persona scenario `person` owns, as
    /// [`Self::compile_persona`] recognizes one under this read (FIX 4571):
    /// a FACET of kind scenario whose schema-1 mask names `person` and holds
    /// an object patch, reached by `person`'s own HasFacet edge. A facet this
    /// read cannot read or prove is none.
    #[must_use]
    pub fn owns_persona_scenario(&self, person: &EntityId, facet: EntityId) -> bool {
        self.owned_persona_scenario(person, facet).is_ok()
    }

    /// `facet` as an explicit scenario mask `person` owns, read and checked
    /// under this read: the one recognition [`Self::compile_persona`] and
    /// [`Self::owns_persona_scenario`] share (FIX 4571).
    fn owned_persona_scenario(&self, person: &EntityId, facet: EntityId) -> Result<OwnedScenario> {
        let parts = self.read_live_bases(&[PointRead::id(facet)])?.single();
        let Some((
            ReadRow {
                entity_type: kind,
                learned_at,
                body: Some(data),
                ..
            },
            revision,
        )) = parts.value
        else {
            return Err(Error::EntityNotFound);
        };
        if kind != ENTITY_TYPE_FACET {
            return Err(Error::InvalidEntityType(kind));
        }
        let entries = body_fields(&data)?;
        let mask: ScenarioWire = from_value(field(&entries, SCENARIO_KEY)?)?;
        let edges = self.edges_out(person)?;
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
        Ok(OwnedScenario {
            patch: mask.patch,
            learned_at,
            revision,
            receipts: [parts.receipt, edges.receipt],
        })
    }

    /// Replays approved identity changes on the current PERSON baseline. Pending, retracted,
    /// superseded, scoped-away and unauthorized changes cannot enter the result.
    /// The optional scenario is applied last and must belong to this PERSON,
    /// as [`Self::owns_persona_scenario`] recognizes one (FIX 4571).
    /// Each input keeps the revision its read saw (FIX 4817).
    ///
    /// Each applied change's recorded input bases are checked against the
    /// basis this replay applies it over: the PERSON's revision read with its
    /// baseline, a change of this PERSON's revision once the replay applied
    /// it, and any other input's live revision as this lane reads it. A
    /// difference is reported in `replay_conflicts`; it never skips or refuses
    /// the change.
    pub fn compile_persona(
        &self,
        person: &EntityId,
        scenario: Option<EntityId>,
    ) -> Result<CompiledPersona> {
        let baseline = self.read_live_bases(&[PointRead::id(*person)])?.single();
        let mut receipt = baseline.receipt;
        let Some((
            ReadRow {
                entity_type: kind,
                learned_at: baseline_at,
                body: Some(data),
                ..
            },
            person_revision,
        )) = baseline.value
        else {
            return Err(Error::EntityNotFound);
        };
        if kind != ENTITY_TYPE_PERSON {
            return Err(Error::InvalidEntityType(kind));
        }
        let mut value = validated_persona_baseline(&data)?;
        // Every input's live revision as this lane read it, the PERSON's with
        // its baseline. Changes of this PERSON answer from `applied` instead.
        let mut read_bases = BTreeMap::from([(*person, person_revision)]);
        let mut person_changes: BTreeSet<EntityId> = BTreeSet::new();
        let mut changes = Vec::new();
        let claims: Vec<_> = self
            .vault()
            .claims_for_subject(person)?
            .into_iter()
            .map(PointRead::id)
            .collect();
        let claims = self.read_live_bases(&claims)?;
        receipt.restrict_with(&claims.receipt);
        for (row, revision) in claims.value.into_iter().flatten() {
            read_bases.insert(row.id, revision);
            let ReadRow {
                id,
                body: Some(data),
                ..
            } = row
            else {
                continue;
            };
            let body = decode_claim_body(&data, true)?;
            if body.predicate == PERSONA_CHANGE_PREDICATE
                && body.subject == ClaimSubject::Entity(*person)
            {
                person_changes.insert(id);
            }
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
            changes.push((change.made_by.at, id, revision, change));
        }
        changes.sort_by_key(|(at, id, ..)| (*at, *id));
        // Recorded inputs no read above reached pass the same lane; one this
        // reader cannot read has no current basis, and the receipt counts it.
        let unread: BTreeSet<EntityId> = changes
            .iter()
            .flat_map(|(.., change)| change.made_by.bases.iter().map(|basis| basis.input))
            .filter(|input| !read_bases.contains_key(input))
            .collect();
        if !unread.is_empty() {
            let reads: Vec<_> = unread.iter().copied().map(PointRead::id).collect();
            let rows = self.read_live_bases(&reads)?;
            receipt.restrict_with(&rows.receipt);
            for (input, row) in unread.into_iter().zip(rows.value) {
                read_bases.insert(input, row.and_then(|(_, revision)| revision));
            }
        }
        let mut inputs = vec![*person];
        let mut input_revisions = vec![person_revision];
        let mut bases: Vec<PersonaInputBasis> = person_revision
            .map(|revision| PersonaInputBasis {
                input: *person,
                revision,
            })
            .into_iter()
            .collect();
        let mut applied: BTreeMap<EntityId, Option<RevisionRef>> = BTreeMap::new();
        let mut replay_conflicts = Vec::new();
        let mut at = baseline_at;
        for (changed_at, id, revision, change) in changes {
            for recorded in &change.made_by.bases {
                let current = if person_changes.contains(&recorded.input) {
                    applied.get(&recorded.input).copied().flatten()
                } else {
                    read_bases.get(&recorded.input).copied().flatten()
                };
                if current != Some(recorded.revision) {
                    replay_conflicts.push(PersonaReplayConflict {
                        change: id,
                        input: recorded.input,
                        recorded: recorded.revision,
                        current,
                    });
                }
            }
            merge_patch(&mut value, &change.patch);
            inputs.push(id);
            input_revisions.push(revision);
            bases.extend(revision.map(|revision| PersonaInputBasis {
                input: id,
                revision,
            }));
            applied.insert(id, revision);
            at = at.max(changed_at);
        }
        if let Some(facet) = scenario {
            let owned = self.owned_persona_scenario(person, facet)?;
            for read in &owned.receipts {
                receipt.restrict_with(read);
            }
            merge_patch(&mut value, &owned.patch);
            inputs.push(facet);
            input_revisions.push(owned.revision);
            bases.extend(owned.revision.map(|revision| PersonaInputBasis {
                input: facet,
                revision,
            }));
            at = at.max(owned.learned_at);
        }
        Ok(CompiledPersona {
            person: *person,
            scenario,
            value,
            made_by: PersonaMadeBy {
                inputs,
                process: "persona.merge-patch.v1".to_owned(),
                at,
                bases,
            },
            input_revisions,
            receipt,
            replay_conflicts,
        })
    }
}

#[cfg(test)]
mod tests;
