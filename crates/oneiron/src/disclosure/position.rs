//! Record exposure, source inheritance, and positive invariant proof.
//!
//! A missing POSITION axis is unknown (top), not bottom. Bottom positions
//! pass every ceiling, so using bottom as a decode-error sentinel leaks.

use super::scope::{
    SENSITIVITY_PUBLIC, SENSITIVITY_SENSITIVE, ScopeCeiling, ScopeIdAxis, ScopeKindAxis,
    ScopePosition, decode_scope_position_value,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSource, claim_sensitivity_band};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;
use heed::RoTxn;
use rmpv::Value;
use std::collections::{HashMap, HashSet};

/// Explicit project stamp in a claim scope or transcript body.
pub const CLAIM_SCOPE_PROJECT_ID_KEY: &str = "scopeProjectId";
/// Positive invariant declaration. Declaration alone is never proof.
pub const CLAIM_SCOPE_INVARIANT_KEY: &str = "invariant";
/// Full, five-axis position stamp; all keys are required by its codec.
pub const RECORD_SCOPE_POSITION_KEY: &str = "scope_position";
const MAX_SOURCE_DEPTH: usize = 32;
const MAX_SOURCE_RECORDS: usize = 256;

/// One read path for claims, transcript turns/messages and other records.
pub(super) fn record_scope_position(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<ScopePosition> {
    position_with_sources(
        store,
        txn,
        id,
        entity_type,
        claim_body,
        &mut SourceWalk::default(),
        0,
    )
}

#[derive(Default)]
struct SourceWalk {
    active: HashSet<EntityId>,
    positions: HashMap<EntityId, ScopePosition>,
    reads: usize,
}

fn unknown_position(entity_type: u8) -> ScopePosition {
    ScopePosition {
        worlds: ScopeIdAxis::All,
        facets: ScopeIdAxis::All,
        kinds: ScopeKindAxis::Some(vec![entity_type]),
        projects: ScopeIdAxis::All,
        sensitivity: SENSITIVITY_SENSITIVE,
    }
}

fn position_with_sources(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
    visited: &mut SourceWalk,
    depth: usize,
) -> Result<ScopePosition> {
    if let Some(position) = visited.positions.get(id) {
        return Ok(position.clone());
    }
    if depth >= MAX_SOURCE_DEPTH
        || visited.reads >= MAX_SOURCE_RECORDS
        || !visited.active.insert(*id)
    {
        return Ok(unknown_position(entity_type));
    }
    visited.reads += 1;
    let result = position_inner(store, txn, id, entity_type, claim_body, visited, depth);
    visited.active.remove(id);
    if let Ok(position) = &result {
        visited.positions.insert(*id, position.clone());
    }
    result
}

fn position_inner(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
    visited: &mut SourceWalk,
    depth: usize,
) -> Result<ScopePosition> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(unknown_position(entity_type));
    };
    let Some(payload) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(unknown_position(entity_type));
    };
    let decoded;
    let mut sources = edge_targets(store, txn, id, EdgeKind::DerivedFrom)?;
    let mut source_required = false;
    let full_stamp;
    let mut position = if entity_type == ENTITY_TYPE_CLAIM {
        let body = match claim_body {
            Some(body) => body,
            None => {
                decoded = crate::claim::decode_claim_body(payload, true).ok();
                let Some(body) = decoded.as_ref() else {
                    return Ok(unknown_position(entity_type));
                };
                body
            }
        };
        let refs = evidence_refs(body.evidence.as_ref());
        let Ok(refs) = refs else {
            return Ok(unknown_position(entity_type));
        };
        sources.extend(refs);
        source_required = matches!(
            body.source,
            Some(
                ClaimSource::Generated
                    | ClaimSource::Inferred
                    | ClaimSource::ToolOutput
                    | ClaimSource::Imported
            )
        );
        full_stamp = has_key(body.scope.as_ref(), RECORD_SCOPE_POSITION_KEY);
        let mut value = own_position(body.scope.as_ref(), entity_type);
        if !full_stamp || has_key(body.scope.as_ref(), "sensitivity") {
            value.sensitivity = value
                .sensitivity
                .max(claim_sensitivity_band(body).unwrap_or(3));
        }
        if !has_key(body.scope.as_ref(), RECORD_SCOPE_POSITION_KEY) {
            // Base is an ordinary world, not the universal or bottom world.
            value.worlds =
                ScopeIdAxis::Some(vec![body.world.unwrap_or_else(EntityId::scope_base_world)]);
        } else if let Some(world) = body.world {
            value.worlds = union_ids(value.worlds, ScopeIdAxis::Some(vec![world]));
        }
        value
    } else {
        let mut cursor = std::io::Cursor::new(payload);
        let value = rmpv::decode::read_value(&mut cursor).ok();
        if cursor.position() != payload.len() as u64 {
            return Ok(unknown_position(entity_type));
        }
        full_stamp = has_key(value.as_ref(), RECORD_SCOPE_POSITION_KEY);
        let mut position = own_position(value.as_ref(), entity_type);
        if !has_key(value.as_ref(), RECORD_SCOPE_POSITION_KEY) {
            position.worlds = match lookup(value.as_ref(), "world_ref") {
                Ok(None) => ScopeIdAxis::Some(vec![EntityId::scope_base_world()]),
                Ok(Some(value)) => {
                    entity_ref(value).map_or(ScopeIdAxis::All, |id| ScopeIdAxis::Some(vec![id]))
                }
                Err(()) => ScopeIdAxis::All,
            };
        }
        if entity_type == ENTITY_TYPE_TURN {
            match lookup(value.as_ref(), "facet_ref") {
                Ok(Some(value)) => {
                    position.facets = entity_ref(value).map_or(ScopeIdAxis::All, |id| {
                        if !full_stamp && position.facets == ScopeIdAxis::All {
                            ScopeIdAxis::Some(vec![id])
                        } else {
                            union_ids(position.facets.clone(), ScopeIdAxis::Some(vec![id]))
                        }
                    });
                }
                Err(()) => position.facets = ScopeIdAxis::All,
                Ok(None) => {}
            }
        }
        if entity_type == ENTITY_TYPE_MESSAGE {
            // A message never escapes its transcript turn's exposure. Its
            // unstamped axes are inherited, not guessed public: no live sole
            // TURN parent means an unknown/private position.
            let parents = edge_targets(store, txn, id, EdgeKind::PartOf)?;
            if parents.len() != 1 {
                return Ok(unknown_position(entity_type));
            }
            let parent = store.entities.get(txn, parents[0].as_bytes())?;
            if parent
                .as_ref()
                .and_then(|raw| EntityMetadataHeader::parse(raw))
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_TURN)
            {
                return Ok(unknown_position(entity_type));
            }
            position = inherited_message_position();
            sources.extend(parents);
        }
        position
    };
    let facets = edge_targets(store, txn, id, EdgeKind::FacetOf)?;
    if !facets.is_empty() {
        // An explicit full position may not hide a stored facet relation.
        position.facets = if !full_stamp && position.facets == ScopeIdAxis::All {
            ScopeIdAxis::Some(facets)
        } else {
            union_ids(position.facets, ScopeIdAxis::Some(facets))
        };
    }
    position = super::exposure_floor::apply_floor(store, txn, id, payload, position)?;
    sources.sort_unstable();
    sources.dedup();
    if source_required && sources.is_empty() {
        return Ok(unknown_position(entity_type));
    }
    for source in sources {
        let Some(raw) = store.entities.get(txn, source.as_bytes())? else {
            return Ok(unknown_position(entity_type));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(unknown_position(entity_type));
        };
        let inherited = position_with_sources(
            store,
            txn,
            &source,
            header.entity_type,
            None,
            visited,
            depth + 1,
        )?;
        // Exposure accumulates. Intersecting record positions would make
        // disjoint private evidence bottom, which passes EVERY clearance.
        position.worlds = union_ids(position.worlds, inherited.worlds);
        position.facets = union_ids(position.facets, inherited.facets);
        position.projects = union_ids(position.projects, inherited.projects);
        position.sensitivity = position.sensitivity.max(inherited.sensitivity);
    }
    Ok(position)
}

fn own_position(scope: Option<&Value>, entity_type: u8) -> ScopePosition {
    match lookup(scope, RECORD_SCOPE_POSITION_KEY) {
        Ok(Some(value)) => {
            let Ok(mut position) = decode_scope_position_value(value) else {
                return unknown_position(entity_type);
            };
            // The kind byte is store truth, never the caller's asserted kind.
            position.kinds = ScopeKindAxis::Some(vec![entity_type]);
            position
        }
        Err(()) => unknown_position(entity_type),
        Ok(None) => {
            let mut position = unknown_position(entity_type);
            position.sensitivity = match lookup(scope, "sensitivity") {
                Ok(Some(value)) => crate::claim::sensitivity_band_from_value(value).unwrap_or(3),
                _ => SENSITIVITY_SENSITIVE,
            };
            position.projects = match lookup(scope, CLAIM_SCOPE_PROJECT_ID_KEY) {
                Ok(Some(value)) => {
                    entity_ref(value).map_or(ScopeIdAxis::All, |id| ScopeIdAxis::Some(vec![id]))
                }
                _ => ScopeIdAxis::All,
            };
            position
        }
    }
}

pub(super) fn union_ids(left: ScopeIdAxis, right: ScopeIdAxis) -> ScopeIdAxis {
    match (left, right) {
        (ScopeIdAxis::All, _) | (_, ScopeIdAxis::All) => ScopeIdAxis::All,
        (ScopeIdAxis::Bottom, other) | (other, ScopeIdAxis::Bottom) => other,
        (ScopeIdAxis::Some(mut left), ScopeIdAxis::Some(right)) => {
            left.extend(right);
            left.sort_unstable();
            left.dedup();
            ScopeIdAxis::Some(left)
        }
    }
}

pub(super) fn edge_targets(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(id, kind);
    let mut targets = Vec::new();
    for row in store.edges_out.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let (_, _, target) = crate::edge::parse_strict_edge_record_key(&key)?;
        targets.push(target);
    }
    targets.sort_unstable();
    targets.dedup();
    Ok(targets)
}

fn entity_ref(value: &Value) -> Option<EntityId> {
    match value {
        Value::Binary(bytes) => EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok(),
        Value::String(hex) => EntityId::from_hex(hex.as_str()?).ok(),
        _ => None,
    }
}

fn lookup<'a>(map: Option<&'a Value>, key: &str) -> std::result::Result<Option<&'a Value>, ()> {
    let Some(map) = map else {
        return Ok(None);
    };
    let Value::Map(entries) = map else {
        return Err(());
    };
    let mut found = None;
    for (name, value) in entries {
        if name.as_str() == Some(key) && found.replace(value).is_some() {
            return Err(());
        }
    }
    Ok(found)
}
fn has_key(map: Option<&Value>, key: &str) -> bool {
    !matches!(lookup(map, key), Ok(None))
}

/// Reads the actual evidence refs, not the claim's subject. Duplicate and
/// malformed evidence is a refusal; absent evidence supplies no proof.
fn evidence_refs(evidence: Option<&Value>) -> std::result::Result<Vec<EntityId>, ()> {
    let evidence = match lookup(evidence, "candidate_evidence")? {
        Some(value) => Some(value),
        None => evidence,
    };
    let Some(refs) = lookup(evidence, "refs")? else {
        return Ok(Vec::new());
    };
    let Value::Array(refs) = refs else {
        return Err(());
    };
    if refs.len() > MAX_SOURCE_RECORDS {
        return Err(());
    }
    refs.iter()
        .map(|value| entity_ref(value).ok_or(()))
        .collect()
}

/// Positive proof: explicit invariant + public effective position + a
/// non-empty, intact public source chain. Subjects never serve as evidence.
pub(super) fn claim_is_invariant(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let decoded;
    let body = match claim_body {
        Some(body) => body,
        None => {
            let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
                return Ok(false);
            };
            decoded = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(|payload| crate::claim::decode_claim_body(payload, true).ok());
            let Some(body) = decoded.as_ref() else {
                return Ok(false);
            };
            body
        }
    };
    if !matches!(lookup(body.scope.as_ref(), CLAIM_SCOPE_INVARIANT_KEY), Ok(Some(value)) if value.as_str() == Some("invariant"))
    {
        return Ok(false);
    }
    let Ok(mut sources) = evidence_refs(body.evidence.as_ref()) else {
        return Ok(false);
    };
    sources.extend(edge_targets(store, txn, id, EdgeKind::DerivedFrom)?);
    if sources.is_empty() {
        return Ok(false);
    }
    let position = record_scope_position(store, txn, id, entity_type, Some(body))?;
    Ok(position.sensitivity == SENSITIVITY_PUBLIC && ScopeCeiling::public().admits(&position))
}

/// The union is a union of admitted SETS, not the axis-wise hull of two
/// ceilings. The latter would erase private world/project/facet restrictions.
pub(super) fn scope_admits_record(
    store: &Store,
    txn: &RoTxn<'_>,
    ceiling: &ScopeCeiling,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    let position = record_scope_position(store, txn, id, entity_type, claim_body)?;
    Ok(ScopeCeiling::public().admits(&position)
        || ceiling.admits(&position)
        || claim_is_invariant(store, txn, id, entity_type, claim_body)?)
}

/// Extraction-time stamp. Sources contribute exposure, never authority.
/// The same reader rechecks the live chain on admission after this write.
pub(crate) fn inherited_claim_scope(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &ClaimBody,
    refs: &[EntityId],
) -> Result<Value> {
    let mut position = own_position(body.scope.as_ref(), ENTITY_TYPE_CLAIM);
    if !has_key(body.scope.as_ref(), RECORD_SCOPE_POSITION_KEY) {
        position.worlds =
            ScopeIdAxis::Some(vec![body.world.unwrap_or_else(EntityId::scope_base_world)]);
    }
    if !has_key(body.scope.as_ref(), "sensitivity")
        && !has_key(body.scope.as_ref(), RECORD_SCOPE_POSITION_KEY)
    {
        position.sensitivity = if refs.is_empty() {
            SENSITIVITY_SENSITIVE
        } else {
            SENSITIVITY_PUBLIC
        };
    }
    for source in refs {
        let inherited = match store.entities.get(txn, source.as_bytes())? {
            Some(raw) => match EntityMetadataHeader::parse(&raw) {
                Some(header) => {
                    record_scope_position(store, txn, source, header.entity_type, None)?
                }
                None => unknown_position(ENTITY_TYPE_TURN),
            },
            None => unknown_position(ENTITY_TYPE_TURN),
        };
        position.worlds = union_ids(position.worlds, inherited.worlds);
        position.facets = union_ids(position.facets, inherited.facets);
        position.projects = union_ids(position.projects, inherited.projects);
        position.sensitivity = position.sensitivity.max(inherited.sensitivity);
    }
    let mut entries = match body.scope.clone() {
        Some(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    entries.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            Some(RECORD_SCOPE_POSITION_KEY | "sensitivity")
        )
    });
    let bytes = super::scope::encode_scope_position_body(&position)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| crate::error::Error::InvariantViolation("position encoding failed"))?;
    entries.push((Value::from(RECORD_SCOPE_POSITION_KEY), value));
    entries.push((
        Value::from("sensitivity"),
        Value::from(position.sensitivity),
    ));
    Ok(Value::Map(entries))
}

pub(super) fn payload_position(entity_type: u8, payload: &[u8]) -> ScopePosition {
    if entity_type == ENTITY_TYPE_MESSAGE {
        // Only the canonical witness door writes MESSAGE bodies; the read
        // additionally requires and inherits the verified TURN parent.
        return inherited_message_position();
    }
    if entity_type == ENTITY_TYPE_CLAIM {
        let Ok(body) = crate::claim::decode_claim_body(payload, true) else {
            return unknown_position(entity_type);
        };
        let mut position = own_position(body.scope.as_ref(), entity_type);
        if !has_key(body.scope.as_ref(), RECORD_SCOPE_POSITION_KEY) {
            position.worlds =
                ScopeIdAxis::Some(vec![body.world.unwrap_or_else(EntityId::scope_base_world)]);
        }
        position
    } else {
        let mut cursor = std::io::Cursor::new(payload);
        let value = rmpv::decode::read_value(&mut cursor).ok();
        if cursor.position() != payload.len() as u64 {
            return unknown_position(entity_type);
        }
        let mut position = own_position(value.as_ref(), entity_type);
        if !has_key(value.as_ref(), RECORD_SCOPE_POSITION_KEY) {
            position.worlds = match lookup(value.as_ref(), "world_ref") {
                Ok(None) => ScopeIdAxis::Some(vec![EntityId::scope_base_world()]),
                Ok(Some(value)) => {
                    entity_ref(value).map_or(ScopeIdAxis::All, |id| ScopeIdAxis::Some(vec![id]))
                }
                Err(()) => ScopeIdAxis::All,
            };
        }
        position
    }
}

pub(super) fn accumulate_exposure(position: &mut ScopePosition, inherited: ScopePosition) {
    position.worlds = union_ids(position.worlds.clone(), inherited.worlds);
    position.facets = union_ids(position.facets.clone(), inherited.facets);
    position.projects = union_ids(position.projects.clone(), inherited.projects);
    position.sensitivity = position.sensitivity.max(inherited.sensitivity);
}

fn inherited_message_position() -> ScopePosition {
    ScopePosition {
        worlds: ScopeIdAxis::Bottom,
        facets: ScopeIdAxis::Bottom,
        kinds: ScopeKindAxis::Some(vec![ENTITY_TYPE_MESSAGE]),
        projects: ScopeIdAxis::Bottom,
        sensitivity: SENSITIVITY_PUBLIC,
    }
}
