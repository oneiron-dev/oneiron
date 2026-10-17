//! Turns raw store bytes into hydrated [`super::types::ContextEntity`] rows and
//! JSON field payloads.

use std::collections::HashMap;
use std::io::Cursor;

use heed::RoTxn;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, claim_surfaceable};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::StoreRead;

use super::builder::HydrateOptions;
use super::edge_walk::load_entity_edges;
use super::types::ContextEntity;

/// A final scoped filter may run after hydration's snapshot. Never authorize
/// old projected bytes using a newly changed row. Clipped text is safe only
/// when it is still a prefix of the currently authorized value.
pub(crate) fn context_entity_matches_read_snapshot(
    vault: &Vault,
    store: &impl crate::store::ManifestDbs,
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
            decode_entity_fields(&raw[ENTITY_METADATA_HEADER_LEN..]).unwrap_or_default()
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
            && !pins_indexed_frontier(
                vault,
                store,
                txn,
                &entity.id,
                header.entity_type,
                crate::vault::RevisionRef(revision),
            )?
        {
            return Ok(false);
        }
        if read_vector(vault, store, txn, &entity.id)?.as_ref() != Some(vector) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether two decoded claim bodies are one body. `ClaimBody`'s derived
/// equality is not reflexive over a NaN in an opaque value, and takes 0.0
/// for -0.0, so floats are compared by their bits and every other field as
/// derived. An encoding is no witness: a string that is not UTF-8 encodes as
/// a binary of its bytes.
pub(crate) fn same_claim_body(left: &ClaimBody, right: &ClaimBody) -> bool {
    use rmpv::Value;
    let rest = |body: &ClaimBody| ClaimBody {
        value: Value::Nil,
        confidence: 0.0,
        salience: None,
        evidence: None,
        scope: None,
        ..body.clone()
    };
    let same_option = |left: Option<&Value>, right: Option<&Value>| match (left, right) {
        (Some(left), Some(right)) => same_value(left, right),
        (left, right) => left.is_none() && right.is_none(),
    };
    same_value(&left.value, &right.value)
        && left.confidence.to_bits() == right.confidence.to_bits()
        && left.salience.map(f32::to_bits) == right.salience.map(f32::to_bits)
        && same_option(left.evidence.as_ref(), right.evidence.as_ref())
        && same_option(left.scope.as_ref(), right.scope.as_ref())
        && rest(left) == rest(right)
}

/// [`same_claim_body`] for an opaque value: a float by its bits.
fn same_value(left: &rmpv::Value, right: &rmpv::Value) -> bool {
    use rmpv::Value;
    match (left, right) {
        (Value::F32(left), Value::F32(right)) => left.to_bits() == right.to_bits(),
        (Value::F64(left), Value::F64(right)) => left.to_bits() == right.to_bits(),
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| same_value(l, r))
        }
        (Value::Map(left), Value::Map(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|((lk, lv), (rk, rv))| same_value(lk, rk) && same_value(lv, rv))
        }
        _ => left == right,
    }
}

/// Hydrates one entity for the context pack.
///
/// Type-0 (CLAIM) records pass through the D19 status gate here too — pack
/// NEIGHBORS never run through the pipeline, so this is their only gate
/// (results were gated in the pipeline already; their decoded bodies arrive
/// via `options.claim_bodies` and are NOT re-decoded). Fail-closed: a type-0
/// record whose body is missing or fails the pinned CLAIM ABI decode is
/// excluded — it never surfaces with empty fields — and counted in
/// `claims_suppressed`, exactly like a status-gated claim, and so is one whose
/// body the write door refuses. Bodies of every other type byte stay opaque
/// and are projected through the generic best-effort field decode, unchanged;
/// one the write door refuses hydrates no field.
pub(super) fn hydrate_entity(
    vault: &Vault,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    score: f32,
    options: HydrateOptions<'_>,
    claims_suppressed: &mut usize,
) -> Result<Option<ContextEntity>> {
    let Some(live_raw) = vault
        .live_entity_in_txn(store, rtxn, &id)
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
    // A TURN's pin may be the text revision a recall served it under, which
    // its row does not own.
    if let crate::vault::ReadMode::Pinned(revision) = options.read_mode
        && !crate::vault::entity_revision::entity_owns_revision_in_txn(store, rtxn, &id, revision)?
        && crate::vault::entity_revision::turn_row_for_text_revision_in_txn(
            vault, store, rtxn, &id, revision,
        )?
        .is_none()
    {
        return Ok(None);
    }
    let Some(raw) = crate::vault::entity_revision::read_entity_revision_from_store_in_txn(
        vault,
        store,
        rtxn,
        &id,
        options.read_mode,
    )?
    else {
        return Ok(None);
    };
    // A history pin cannot restore a claim inadmissible at the current door,
    // its live support included, as the scoped read lane admits a pin.
    if raw != live_raw && live_raw[0] == ENTITY_TYPE_CLAIM {
        match crate::claim::decode_claim_body(&live_raw[ENTITY_METADATA_HEADER_LEN..], true) {
            Ok(body)
                if claim_surfaceable(&body)
                    && crate::claim::has_live_support_in_txn(store, rtxn, &body)? => {}
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
        && !crate::note::note_body_readable(store, rtxn, &raw[ENTITY_METADATA_HEADER_LEN..], None)?
    {
        return Ok(None);
    }

    let mut gated_claim_body: Option<&ClaimBody> = None;
    let decoded_here: Option<ClaimBody>;
    if header.entity_type == ENTITY_TYPE_CLAIM {
        // Decoded once for gate + projection; reads allow reserved `edge.*`
        // predicates.
        decoded_here = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|body| crate::claim::decode_claim_body(body, true).ok());
        // The gate's verdict stands for the body in hand only when it is the
        // body the gate read, in retrieval's own snapshot. A pin's words, or
        // a row no verdict covers (a neighbor), are judged here. An unpinned
        // row whose body is another was written since retrieval read it, and
        // no verdict in this run stands for it: it is not served.
        let cached = options.claim_bodies.and_then(|cache| cache.get(&id));
        let pinned = matches!(options.read_mode, crate::vault::ReadMode::Pinned(_));
        let judged_here = cached.is_none() || pinned || raw != live_raw;
        match (cached, &decoded_here) {
            // Pipeline-gated result: the body the gate admitted.
            (Some(cached), Some(body)) if same_claim_body(cached, body) => {
                gated_claim_body = Some(cached);
            }
            (_, Some(body)) if judged_here && claim_surfaceable(body) => {
                gated_claim_body = Some(body);
            }
            _ => {
                *claims_suppressed += 1;
                return Ok(None);
            }
        }
    }

    // Live support is read where the claim is served: the gate read a
    // result's in retrieval's snapshot, and validation reads no neighbor's.
    // A claim whose cited sources are gone by now is not served, as a result
    // or a neighbor, from the cache or decoded here.
    if let Some(body) = gated_claim_body
        && !crate::claim::has_live_support_in_txn(store, rtxn, body)?
    {
        *claims_suppressed += 1;
        return Ok(None);
    }

    // The clamp's sweeps judge a claim on the body the gate read or on its
    // live row, and a pin may serve another: the body served is judged too.
    if let (Some(clamp), Some(body)) = (options.clamp, gated_claim_body)
        && !super::retained_copies::clamp_admits(
            clamp,
            store.base(),
            rtxn,
            &id,
            ENTITY_TYPE_CLAIM,
            Some(body),
        )?
    {
        return Ok(None);
    }

    // A claim the write door refuses, stored while the owner's scan was off,
    // is withheld as an undecodable one is: no read can follow this door's
    // projection and its writers exactly (a float's width, a dropped key), so
    // none of such a body is served.
    if gated_claim_body.is_some()
        && crate::batch::export::write_door_refuses_body(&raw[ENTITY_METADATA_HEADER_LEN..])
    {
        *claims_suppressed += 1;
        return Ok(None);
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
            // A NOTE's live prose is in its document, which its row pin does
            // not hold: words a reranker scored are the pinned row's. A row
            // the write door refuses hydrates no field, as below.
            None if options.words_pinned => {
                let body = &raw[ENTITY_METADATA_HEADER_LEN..];
                if crate::batch::export::write_door_refuses_body(body) {
                    HashMap::new()
                } else {
                    decode_entity_fields(body).unwrap_or_default()
                }
            }
            None => {
                let body = crate::note::live_body_in_txn(
                    &vault.store,
                    rtxn,
                    &id,
                    header.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?;
                let markdown = if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
                    Some(vault.note_text_in_txn(rtxn, id)?)
                } else {
                    None
                };
                // A body the write door refuses (a note's text is its body
                // too) hydrates no field, as one no decoder reads hydrates none.
                let refused = crate::batch::export::write_door_refuses_body(&body)
                    || markdown.as_ref().is_some_and(|text| {
                        crate::batch::export::write_door_refuses_body(text.as_bytes())
                    });
                if refused {
                    HashMap::new()
                } else {
                    let mut fields = decode_entity_fields(&body).unwrap_or_default();
                    if let Some(markdown) = markdown {
                        fields.insert("markdown".to_owned(), serde_json::Value::String(markdown));
                    }
                    fields
                }
            }
        })
    } else {
        None
    };

    let (short_id, _) = read_short_id(store, rtxn, &id)?.unwrap_or_else(|| (id.to_hex(), 0));
    let content_hash =
        (xxhash_rust::xxh32::xxh32(&raw[ENTITY_METADATA_HEADER_LEN..], 0) % 256) as u8;

    let edges = if options.include_edges {
        Some(load_entity_edges(
            store,
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
        mode => crate::vault::entity_revision::revision_for_mode_in_txn(store, rtxn, &id, mode)?,
    };
    // The single vector row belongs to the indexed frontier, not necessarily
    // the live body or a historical pin. No revision state means an unversioned
    // current row; explicit pins always carry a source revision here.
    let vector = if options.include_vectors
        && match source_revision {
            Some(revision) => {
                pins_indexed_frontier(vault, store, rtxn, &id, header.entity_type, revision)?
            }
            None => true,
        } {
        read_vector(vault, store, rtxn, &id)?
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

/// Whether `revision` pins the indexed frontier the vector row belongs to:
/// the indexed revision itself or, for a TURN, the text revision of the
/// words it holds there, which a reranked turn is served at. Another of the
/// TURN's own row revisions is history, and reads none of its words.
fn pins_indexed_frontier(
    vault: &Vault,
    store: &impl crate::store::ManifestDbs,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    revision: crate::vault::RevisionRef,
) -> Result<bool> {
    let Some(indexed) = vault.indexed_revision_from_in_txn(store, rtxn, id)? else {
        return Ok(false);
    };
    if indexed == revision {
        return Ok(true);
    }
    if entity_type != crate::registry::ENTITY_TYPE_TURN
        || crate::vault::entity_revision::entity_owns_revision_in_txn(store, rtxn, id, revision)?
    {
        return Ok(false);
    }
    Ok(crate::vault::entity_revision::served_turn_text_in_txn(
        vault,
        store,
        rtxn,
        id,
        crate::vault::ReadMode::Indexed,
        false,
    )?
    .is_some_and(|text| text.revision == revision))
}

/// Projects an already-decoded CLAIM body into the hydrated-fields map —
/// the same shape `decode_entity_fields` produces from the raw MessagePack
/// map (pinned D11 short keys; `subj` is binary on disk so it projects as
/// JSON null; `stale` appears only when `true`, mirroring the encoder which
/// omits `false`). Reusing the gate's decode means the body is MessagePack-
/// decoded once per result for gate + projection (AC 9).
fn claim_fields_to_json(body: &ClaimBody) -> HashMap<String, serde_json::Value> {
    // Parts that read as a secret together, before this projection drops a
    // float's width, project as null.
    let secret = crate::batch::export::claim_reads_as_secret(body);
    let project = |value: &rmpv::Value| {
        if secret {
            serde_json::Value::Null
        } else {
            rmpv_to_json(value)
        }
    };
    let mut out = HashMap::new();
    out.insert(
        "pred".to_owned(),
        if secret {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(body.predicate.clone())
        },
    );
    out.insert("val".to_owned(), project(&body.value));
    out.insert("conf".to_owned(), serde_json::json!(body.confidence));
    if let Some(salience) = body.salience {
        out.insert("sal".to_owned(), serde_json::json!(salience));
    }
    if let Some(evidence) = &body.evidence {
        out.insert("evid".to_owned(), project(evidence));
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
        out.insert("scope".to_owned(), project(scope));
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

fn decode_entity_fields(payload: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    if payload.is_empty() {
        return Some(HashMap::new());
    }

    let mut cursor = Cursor::new(payload);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    // A body that reads as a secret whole, before this projection drops a
    // float's width and in the bytes it was stored as, hydrates no field.
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, payload) {
        return Some(HashMap::new());
    }
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

fn read_short_id(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(String, u8)>> {
    match crate::ports::ShortIdStoreRead::port_short_id_reference(store, rtxn, id) {
        Err(Error::CorruptedIndex(_)) => Ok(None),
        result => result,
    }
}

pub(super) fn read_vector(
    vault: &Vault,
    store: &impl crate::store::ManifestDbs,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<f32>>> {
    vault
        .vector_in_txn(store, rtxn, id)
        .map_err(|error| match error {
            Error::CorruptedIndex(_) => Error::CorruptedIndex("entity vector"),
            other => other,
        })
}
