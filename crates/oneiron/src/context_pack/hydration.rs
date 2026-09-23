//! Turns raw store bytes into hydrated [`super::types::ContextEntity`] rows and
//! JSON field payloads.

use std::collections::HashMap;
use std::io::Cursor;

use heed::RoTxn;

use crate::Vault;
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

use super::builder::HydrateOptions;
use super::edge_walk::load_entity_edges;
use super::types::ContextEntity;

/// A final scoped filter may run after hydration's snapshot. Never authorize
/// old projected bytes using a newly changed row. Clipped text is safe only
/// when it is still a prefix of the currently authorized value.
pub(crate) fn context_entity_matches_read_snapshot(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &ContextEntity,
    raw: &[u8],
) -> Result<bool> {
    // The scoped caller supplies the admitted source frontier, not necessarily LIVE.
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != entity.entity_type {
        return Ok(false);
    }
    if let Some(fields) = &entity.fields {
        let current = if header.entity_type == ENTITY_TYPE_CLAIM {
            claim_fields_to_json(&crate::claim::decode_claim_body(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                true,
            )?)
        } else {
            decode_entity_fields(&raw[ENTITY_METADATA_HEADER_LEN..], header.entity_type)
                .unwrap_or_default()
        };
        for (key, value) in fields {
            if key == super::WORLD_STALE_FIELD {
                continue;
            }
            let Some(now) = current.get(key) else {
                return Ok(false);
            };
            if value == now {
                continue;
            }
            let safe_prefix = value.as_str().zip(now.as_str()).is_some_and(|(old, now)| {
                let old = old
                    .strip_suffix('…')
                    .or_else(|| old.strip_suffix("..."))
                    .unwrap_or(old);
                now.starts_with(old)
            });
            if !safe_prefix {
                return Ok(false);
            }
        }
    }
    if let Some(vector) = &entity.vector {
        if let Some(revision) = entity.source_revision_ref
            && vault.indexed_revision_in_txn(txn, &entity.id)?
                != Some(crate::vault::RevisionRef(revision))
        {
            return Ok(false);
        }
        if read_vector(vault, txn, &entity.id)?.as_ref() != Some(vector) {
            return Ok(false);
        }
    }
    Ok(true)
}

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
    let Some(live_raw) = crate::ports::EntityStore::port_entity_get(vault, rtxn, &id)
        .map_err(|error| match error {
            Error::CorruptedIndex("entity header") => {
                Error::CorruptedIndex("entity metadata header")
            }
            other => other,
        })?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    if let crate::vault::ReadMode::Pinned(revision) = options.read_mode
        && !crate::vault::entity_revision::entity_owns_revision_in_txn(
            &vault.store,
            rtxn,
            &id,
            revision,
        )?
    {
        return Ok(None);
    }
    let Some(raw) = crate::vault::entity_revision::read_entity_revision_in_txn(
        vault,
        rtxn,
        &id,
        options.read_mode,
    )?
    else {
        return Ok(None);
    };
    // A history pin cannot restore a claim inadmissible at the current door.
    if raw != live_raw && live_raw[0] == ENTITY_TYPE_CLAIM {
        match crate::claim::decode_claim_body(&live_raw[ENTITY_METADATA_HEADER_LEN..], true) {
            Ok(body) if claim_surfaceable(&body) => {}
            _ => {
                *claims_suppressed += 1;
                return Ok(None);
            }
        }
    }

    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };

    if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
        && !crate::note::note_body_readable(
            &vault.store,
            rtxn,
            &raw[ENTITY_METADATA_HEADER_LEN..],
            None,
        )?
    {
        return Ok(None);
    }

    let mut gated_claim_body: Option<&ClaimBody> = None;
    let decoded_here: Option<ClaimBody>;
    if header.entity_type == ENTITY_TYPE_CLAIM {
        match options
            .claim_bodies
            .filter(|_| raw == live_raw)
            .and_then(|cache| cache.get(&id))
        {
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

    let critical = gated_claim_body.is_some_and(|body| {
        options.policy.criticality_for_predicate(&body.predicate)
            == crate::gate::PolicyCriticality::Critical
    });
    if gated_claim_body.is_some() && options.criticality.is_some_and(|tier| tier != critical) {
        return Ok(None);
    }

    let fields = if options.hydrate_fields {
        Some(match gated_claim_body {
            Some(body) => claim_fields_to_json(body),
            None => {
                let body = crate::note::live_body_in_txn(
                    &vault.store,
                    rtxn,
                    &id,
                    header.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?;
                let mut fields =
                    decode_entity_fields(&body, header.entity_type).unwrap_or_default();
                if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
                    fields.insert(
                        "markdown".to_owned(),
                        serde_json::Value::String(vault.note_text_in_txn(rtxn, id)?),
                    );
                }
                fields
            }
        })
    } else {
        None
    };

    let (short_id, _) = read_short_id(&vault.store, rtxn, &id)?.unwrap_or_else(|| (id.to_hex(), 0));
    let content_hash =
        (xxhash_rust::xxh32::xxh32(&raw[ENTITY_METADATA_HEADER_LEN..], 0) % 256) as u8;

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

    let source_revision = match options.read_mode {
        crate::vault::ReadMode::Pinned(revision) => Some(revision),
        mode => {
            crate::vault::entity_revision::revision_for_mode_in_txn(&vault.store, rtxn, &id, mode)?
        }
    };
    // The single vector row belongs to the indexed frontier, not necessarily
    // the live body or a historical pin. No revision state means an unversioned
    // current row; explicit pins always carry a source revision here.
    let vector = if options.include_vectors
        && match source_revision {
            Some(revision) => vault.indexed_revision_in_txn(rtxn, &id)? == Some(revision),
            None => true,
        } {
        read_vector(vault, rtxn, &id)?
    } else {
        None
    };

    Ok(Some(ContextEntity {
        id,
        short_id,
        content_hash,
        source_revision_ref: source_revision.map(|revision| revision.0),
        entity_type: header.entity_type,
        score,
        critical,
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
    if let Some(class) = body.made_by_class() {
        out.insert(
            "made_by".to_owned(),
            serde_json::Value::String(
                match class {
                    crate::provenance::made_by::MadeByClass::Stated => "stated",
                    crate::provenance::made_by::MadeByClass::Concluded => "concluded",
                }
                .to_owned(),
            ),
        );
    }
    if let Some(world) = body.world {
        // Board fences use identity from this authorized snapshot, not a later read.
        out.insert(
            "world".to_owned(),
            serde_json::Value::String(world.to_hex()),
        );
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

fn decode_entity_fields(
    payload: &[u8],
    entity_type: u8,
) -> Option<HashMap<String, serde_json::Value>> {
    if payload.is_empty() {
        return Some(HashMap::new());
    }

    if entity_type == ENTITY_TYPE_COMPANION_REGISTER
        || (entity_type == crate::registry::ENTITY_TYPE_FACET
            && crate::companion::is_identity_facet_body(payload))
    {
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
        "sensitivity".to_owned(),
        serde_json::Value::String(record.sensitivity.as_str().to_owned()),
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

pub(super) fn rmpv_to_json(value: &rmpv::Value) -> serde_json::Value {
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
    match crate::ports::ShortIdStoreRead::port_short_id_reference(store, rtxn, id) {
        Err(Error::CorruptedIndex(_)) => Ok(None),
        result => result,
    }
}

pub(super) fn read_vector(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<f32>>> {
    crate::ports::RetrievalIndex::port_retrieval_vector_get(vault, rtxn, id).map_err(|error| {
        match error {
            Error::CorruptedIndex(_) => Error::CorruptedIndex("entity vector"),
            other => other,
        }
    })
}
