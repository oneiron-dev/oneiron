//! Turns raw store bytes into hydrated [`super::types::ContextEntity`] rows and
//! JSON field payloads.

use std::collections::HashMap;
use std::io::Cursor;

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, claim_surfaceable};
use crate::companion::{
    CompanionLifecycleEvent, CompanionScope, CompanionSubject, ENTITY_TYPE_COMPANION_REGISTER,
    decode_companion_record_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::{Vault, le_bytes_to_f32_vec};

use super::builder::HydrateOptions;
use super::edge_walk::load_entity_edges;
use super::types::ContextEntity;

/// Hydrates one entity for the context pack.
///
/// Type-0 (CLAIM) records pass through the D19 status gate here too — pack
/// NEIGHBORS never run through the pipeline, so this is their only gate
/// (results were gated in the pipeline already; their decoded bodies arrive
/// via `options.claim_bodies` and are NOT re-decoded). Fail-closed: a type-0
/// record whose body is missing or fails the pinned CLAIM ABI decode is
/// excluded — it never surfaces with empty fields — and counted in
/// `claims_suppressed`, exactly like a status-gated claim. Bodies of every
/// other type byte stay opaque and are projected through the generic
/// best-effort field decode, unchanged.
pub(super) fn hydrate_entity(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    score: f32,
    options: HydrateOptions<'_>,
    claims_suppressed: &mut usize,
) -> Result<Option<ContextEntity>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };

    let mut gated_claim_body: Option<&ClaimBody> = None;
    let decoded_here: Option<ClaimBody>;
    if header.entity_type == ENTITY_TYPE_CLAIM {
        match options.claim_bodies.and_then(|cache| cache.get(&id)) {
            // Pipeline-gated result: already decoded once and surfaceable.
            Some(body) => gated_claim_body = Some(body),
            None => {
                // Neighbor (or cache miss): decode once for gate +
                // projection; reads allow reserved `edge.*` predicates.
                decoded_here = raw
                    .get(ENTITY_METADATA_HEADER_LEN..)
                    .and_then(|body| crate::claim::decode_claim_body(body, true).ok());
                match &decoded_here {
                    Some(body) if claim_surfaceable(body) => gated_claim_body = Some(body),
                    _ => {
                        *claims_suppressed += 1;
                        return Ok(None);
                    }
                }
            }
        }
    }

    let fields = if options.hydrate_fields {
        Some(match gated_claim_body {
            Some(body) => claim_fields_to_json(body),
            None => decode_entity_fields(&raw, header.entity_type).unwrap_or_default(),
        })
    } else {
        None
    };

    let (short_id, content_hash) =
        read_short_id(&vault.store, rtxn, &id)?.unwrap_or_else(|| (id.to_hex(), 0));

    let edges = if options.include_edges {
        Some(load_entity_edges(
            &vault.store,
            rtxn,
            &id,
            options.edge_cache,
            options.clamp,
        )?)
    } else {
        None
    };

    let vector = if options.include_vectors {
        read_vector(vault, rtxn, &id)?
    } else {
        None
    };

    Ok(Some(ContextEntity {
        id,
        short_id,
        content_hash,
        entity_type: header.entity_type,
        score,
        fields,
        edges,
        vector,
    }))
}

/// Projects an already-decoded CLAIM body into the hydrated-fields map —
/// the same shape `decode_entity_fields` produces from the raw MessagePack
/// map (pinned D11 short keys; `subj` is binary on disk so it projects as
/// JSON null; `stale` appears only when `true`, mirroring the encoder which
/// omits `false`). Reusing the gate's decode means the body is MessagePack-
/// decoded once per result for gate + projection (AC 9).
fn claim_fields_to_json(body: &ClaimBody) -> HashMap<String, serde_json::Value> {
    let mut out = HashMap::new();
    out.insert(
        "pred".to_owned(),
        serde_json::Value::String(body.predicate.clone()),
    );
    out.insert("val".to_owned(), rmpv_to_json(&body.value));
    out.insert("conf".to_owned(), serde_json::json!(body.confidence));
    if let Some(salience) = body.salience {
        out.insert("sal".to_owned(), serde_json::json!(salience));
    }
    if let Some(evidence) = &body.evidence {
        out.insert("evid".to_owned(), rmpv_to_json(evidence));
    }
    if let Some(valid_from) = body.valid_from {
        out.insert("from".to_owned(), serde_json::json!(valid_from));
    }
    if let Some(valid_to) = body.valid_to {
        out.insert("to".to_owned(), serde_json::json!(valid_to));
    }
    if let Some(source) = body.source {
        out.insert(
            "src".to_owned(),
            serde_json::Value::String(source.as_str().to_owned()),
        );
    }
    if body.world.is_some() {
        // On-disk `world` is a 16-byte binary id (ONE-1117); the generic
        // projection renders binary as null, and so does this one — same as
        // `subj` below. Only present when the claim carries a world scope.
        out.insert("world".to_owned(), serde_json::Value::Null);
    }
    if body.rel.is_some() {
        // On-disk `rel` is MessagePack binary and renders as JSON null.
        out.insert("rel".to_owned(), serde_json::Value::Null);
    }
    // On-disk `subj` is MessagePack binary; the generic projection renders
    // binary as null, and so does this one.
    out.insert("subj".to_owned(), serde_json::Value::Null);
    if let Some(scope) = &body.scope {
        out.insert("scope".to_owned(), rmpv_to_json(scope));
    }
    out.insert(
        "appr".to_owned(),
        serde_json::Value::String(body.approval.as_str().to_owned()),
    );
    out.insert(
        "life".to_owned(),
        serde_json::Value::String(body.lifecycle.as_str().to_owned()),
    );
    if body.stale {
        out.insert("stale".to_owned(), serde_json::Value::Bool(true));
    }
    out
}

fn decode_entity_fields(raw: &[u8], entity_type: u8) -> Option<HashMap<String, serde_json::Value>> {
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Some(HashMap::new());
    }

    let payload = &raw[ENTITY_METADATA_HEADER_LEN..];
    if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
        return decode_companion_register_fields(payload);
    }

    let mut cursor = Cursor::new(payload);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let rmpv::Value::Map(entries) = value else {
        return None;
    };

    let mut out = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            continue;
        };
        out.insert(key.to_owned(), rmpv_to_json(&value));
    }

    Some(out)
}

fn decode_companion_register_fields(raw: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    let record = decode_companion_record_body(raw).ok()?;
    let mut out = HashMap::new();
    out.insert(
        "kind".to_owned(),
        serde_json::Value::String(record.kind().as_str().to_owned()),
    );
    out.insert("scope".to_owned(), companion_scope_to_json(&record.scope));
    out.insert(
        "subject".to_owned(),
        companion_subject_to_json(&record.subject),
    );
    out.insert(
        "lifecycle".to_owned(),
        serde_json::Value::String(record.lifecycle.as_str().to_owned()),
    );
    out.insert(
        "export".to_owned(),
        serde_json::Value::String(record.export_classification.as_str().to_owned()),
    );
    out.insert(
        "provenance".to_owned(),
        serde_json::json!({
            "actor_ref": record.provenance.actor_ref.to_hex(),
            "actor_class": record.provenance.actor_class as u8,
            "source": record.provenance.source.as_str(),
            "approval": record.provenance.approval.as_str(),
        }),
    );
    out.insert(
        "lifecycle_events".to_owned(),
        companion_lifecycle_events_to_json(&record.lifecycle_events),
    );
    Some(out)
}

fn companion_lifecycle_events_to_json(events: &[CompanionLifecycleEvent]) -> serde_json::Value {
    serde_json::Value::Array(
        events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "kind": event.kind.as_str(),
                    "at": event.at,
                })
            })
            .collect(),
    )
}

fn companion_scope_to_json(scope: &CompanionScope) -> serde_json::Value {
    match scope {
        CompanionScope::Neutral => serde_json::json!({ "kind": "neutral" }),
        CompanionScope::Personal { person_ref } => {
            serde_json::json!({ "kind": "personal", "person_ref": person_ref.to_hex() })
        }
        CompanionScope::SharedVault { vault_id } => {
            serde_json::json!({ "kind": "shared_vault", "vault_id": vault_id })
        }
    }
}

fn companion_subject_to_json(subject: &CompanionSubject) -> serde_json::Value {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            serde_json::json!({ "kind": "persona", "persona_ref": persona_ref.to_hex() })
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => serde_json::json!({
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": source_ref.to_hex(),
                "target_ref": target_ref.to_hex(),
            }
        }),
    }
}

fn rmpv_to_json(value: &rmpv::Value) -> serde_json::Value {
    match value {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(v) => serde_json::Value::Bool(*v),
        rmpv::Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                serde_json::json!(i)
            } else if let Some(u) = v.as_u64() {
                serde_json::json!(u)
            } else {
                serde_json::Value::Null
            }
        }
        rmpv::Value::F32(v) => serde_json::json!(v),
        rmpv::Value::F64(v) => serde_json::json!(v),
        rmpv::Value::String(v) => {
            serde_json::Value::String(v.as_str().unwrap_or_default().to_owned())
        }
        rmpv::Value::Binary(_) => serde_json::Value::Null,
        rmpv::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(rmpv_to_json).collect())
        }
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                map.insert(key.to_owned(), rmpv_to_json(value));
            }
            serde_json::Value::Object(map)
        }
        rmpv::Value::Ext(_, _) => serde_json::Value::Null,
    }
}

fn read_short_id(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<(String, u8)>> {
    // ARCH-0019 row n4: `short_ids_reverse` is the entity-id-keyed direction
    // (entity_id -> short_id ‖ content_hash).
    let Some(value) = store.short_ids_reverse.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    if value.len() < 2 {
        return Ok(None);
    }

    let Some((&hash, short_id_bytes)) = value.split_last() else {
        return Ok(None);
    };
    let Ok(short_id) = std::str::from_utf8(short_id_bytes) else {
        return Ok(None);
    };

    Ok(Some((short_id.to_owned(), hash)))
}

pub(super) fn read_vector(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<f32>>> {
    let Some(raw) = vault.store.vectors.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let vector = le_bytes_to_f32_vec(&raw, vault.config.dimensions)
        .map_err(|_| Error::CorruptedIndex("entity vector"))?;

    if vector.len() != vault.config.dimensions {
        return Err(Error::CorruptedIndex("entity vector"));
    }

    Ok(Some(vector))
}
