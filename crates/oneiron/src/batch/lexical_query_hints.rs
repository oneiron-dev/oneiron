use super::*;

use std::collections::{HashSet, VecDeque};
use std::str;

use heed::RwTxn;
use xxhash_rust::xxh3::xxh3_128;

use crate::affect::Vad;
use crate::claim::ClaimSubject;
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::ppr;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

/// Which builder a raw put arrived through.
///
/// `Vault::batch()` is the PUBLIC door: it also refuses non-public entity
/// types, and everything reaching it is a body a caller handed the engine.
/// `Vault::batch_in()` is the crate's own transactional builder — the facades,
/// the ladder and the sweeps write their already-validated rows through it,
/// including rows they are writing BECAUSE something expired.
///
/// Almost every check below applies to both. The one that cannot is the
/// born-expired deadline: the expiry lane's whole job is to write to a task
/// whose deadline has passed, so applying it there would make settling an
/// expired task impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RawPutDoor {
    Public,
    Internal,
}

pub(super) fn validate_public_raw_put(
    entity_type: u8,
    data: &[u8],
    learned_at: u64,
    door: RawPutDoor,
) -> Result<()> {
    match entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            let body = crate::claim::validate_claim_body_and_decode(data, false)?;
            if body.source.is_some() && !is_legacy_raw_claim_compatibility_body(&body) {
                return Err(Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE));
            }
        }
        // A NOTE body carries `author_ref`, so a caller who hand-writes one
        // forges another actor's attribution — and no raw put can be made to
        // carry the mandatory same-transaction `AuthoredBy` +
        // `About`/`ClaimOf` edges either. Attribution is engine-stamped, so
        // this door refuses the type outright instead of validating a body it
        // cannot bind to an actor; `put_authored_note`, reached only from
        // `MemoryFacade::author_take`, is the one NOTE writer.
        crate::registry::ENTITY_TYPE_NOTE => {
            return Err(Error::InvalidNoteBody(
                ERR_RAW_NOTE_PUT_REQUIRES_AUTHOR_TAKE,
            ));
        }
        ENTITY_TYPE_SKILL => crate::skill::validate_skill_record_bytes(data)?,
        ENTITY_TYPE_AGENT_DEF => crate::agent_def::validate_agent_definition_bytes(data)?,
        // STO-03: the Habit streak counters are derived from the check-in
        // children, so no public writer may name them. The sync-only
        // replicated door deliberately does NOT run this check — it accepts a
        // peer's Habit envelope and then has the tail pass REPLACE the
        // inbound counters from the local reducer, so a peer cannot mint a
        // streak either.
        ENTITY_TYPE_TASK => {
            crate::habit::reject_public_streak_fields(data)?;
            // Coherence the DECODER already demands: a terminal claiming
            // `countered` names its counter, and one naming a counter claims
            // it. Held here as well as there, because a body that fails only
            // on the way out has already persisted — and then every later
            // read of that task fails instead of the write that made it
            // wrong. Both doors run it: an engine settle body is coherent by
            // construction, so this costs the internal path nothing and
            // closes the raw path completely.
            crate::task_verb::reject_incoherent_task_terminal(data)?;
            // A deadline already past is a task born expired, and the facade
            // refuses one. The PUBLIC raw door joins that invariant, against
            // the same clock the row is stamped with — the facade compares
            // `ttl.deadline_at` to the `now` it writes as `learned_at`, so
            // comparing to `learned_at` here asks the identical question of a
            // body that never passed through it.
            //
            // Not the internal door: see [`RawPutDoor`]. Not the sync door
            // either, which skips this function entirely — a peer's row is
            // already written on the peer, storage convergence outranks the
            // invariant, and the board derives `Expired`, which is the truth
            // about that row.
            if door == RawPutDoor::Public {
                crate::task_verb::reject_born_expired_task_deadline(data, learned_at)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_authored_note_body(author: &EntityId, data: &[u8]) -> Result<()> {
    let body = crate::note::decode_note_body(data)?;
    if body.author_ref != *author {
        return Err(Error::InvalidNoteBody(
            "NOTE author_ref must be the verified bound actor",
        ));
    }
    Ok(())
}

pub(super) fn validate_habit_checkin_body(data: &[u8]) -> Result<()> {
    match crate::habit::task_role_from_body_bytes(data)? {
        TaskRole::HabitCheckin => Ok(()),
        _ => Err(Error::InvalidTaskBody(
            "habit check-in writes require HabitCheckin role",
        )),
    }
}

pub(super) fn is_legacy_raw_claim_compatibility_body(body: &crate::claim::ClaimBody) -> bool {
    // Code-revision integrity uses legacy raw CLAIM records as provenance anchors.
    body.predicate == "code.revision"
        && matches!(body.subject, crate::claim::ClaimSubject::Entity(_))
        && body.approval == crate::claim::ClaimApprovalStatus::Auto
        && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
}

#[expect(
    clippy::too_many_arguments,
    reason = "batch builder helper mirrors the public candidate API shape"
)]
pub(super) fn push_claim_candidate_with_lexical_hints(
    ops: &mut Vec<BatchOp>,
    validation_error: &mut Option<Error>,
    id: &EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
    hints: &[&str],
) {
    let normalized_hints = match crate::claim::normalize_lexical_query_hints(hints) {
        Ok(hints) => hints,
        Err(err) => {
            if validation_error.is_none() {
                *validation_error = Some(err);
            }
            Vec::new()
        }
    };

    ops.push(BatchOp::ClaimCandidate {
        id: *id,
        candidate: Box::new(candidate),
        envelope: envelope.clone(),
        occurred,
        learned_at,
        internal_lexical_query_hint: false,
    });

    let mut hint_ids = Vec::with_capacity(normalized_hints.len());
    for hint in normalized_hints {
        let hint_id = match lexical_query_hint_claim_id(id, &hint) {
            Ok(hint_id) => hint_id,
            Err(err) => {
                if validation_error.is_none() {
                    *validation_error = Some(err);
                }
                continue;
            }
        };
        hint_ids.push(hint_id);
        let hint_candidate = ClaimCandidate::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(*id),
            crate::claim::encode_lexical_query_hint_value(id, &hint),
            1.0,
        )
        .with_stale(true);
        ops.push(BatchOp::ClaimCandidate {
            id: hint_id,
            candidate: Box::new(hint_candidate),
            envelope: envelope.clone(),
            occurred,
            learned_at,
            internal_lexical_query_hint: true,
        });
        ops.push(BatchOp::Text {
            id: hint_id,
            fields: vec![("query_hint".to_owned(), hint)],
        });
    }
    ops.push(BatchOp::ReconcileLexicalQueryHints {
        source: *id,
        keep: hint_ids,
    });
}

pub(super) fn lexical_query_hint_claim_id(
    source_claim_id: &EntityId,
    hint: &str,
) -> Result<EntityId> {
    let mut material = Vec::with_capacity(
        b"oneiron.lexical-query-hint.v1".len()
            + ENTITY_ID_LEN
            + std::mem::size_of::<u64>()
            + hint.len(),
    );
    material.extend_from_slice(b"oneiron.lexical-query-hint.v1");
    material.extend_from_slice(source_claim_id.as_bytes());
    material.extend_from_slice(&(hint.len() as u64).to_le_bytes());
    material.extend_from_slice(hint.as_bytes());

    let mut bytes = xxh3_128(&material).to_le_bytes();
    bytes[..2].copy_from_slice(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX);
    bytes[ENTITY_ID_LEN - 1] &= 0x7F;
    EntityId::from_bytes(bytes)
        .map_err(|_| Error::InvariantViolation("lexical query hint id derivation failed"))
}

pub(super) fn lexical_query_hint_for_replayed_put(
    id: &EntityId,
    entity_type: u8,
    replicated: bool,
    data: &[u8],
) -> Result<Option<(EntityId, String)>> {
    if !replicated
        || entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || !id
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(data, true)?;
    if body.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
        return Ok(None);
    }
    crate::claim::lexical_query_hint_target(&body)?;
    let hint = crate::claim::decode_lexical_query_hint_value(&body.value)?;
    Ok(Some((hint.target, hint.query)))
}

pub(super) fn lexical_query_hint_target_is_ready(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<bool> {
    let Some(body) = stored_claim_body(store, wtxn, target)? else {
        return Ok(false);
    };
    Ok(body.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT
        && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
}

pub(super) struct LexicalHintTextIndexing<'a> {
    pub(super) analyzer: &'a crate::analyzer::MultilingualAnalyzer,
    pub(super) manifest_checked: &'a mut bool,
    pub(super) trusted: bool,
}

pub(super) fn materialize_lexical_query_hint_text_if_target_ready(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text_indexing: &mut LexicalHintTextIndexing<'_>,
    hint_id: EntityId,
    target: &EntityId,
    query_hint: String,
) -> Result<bool> {
    if !lexical_query_hint_target_is_ready(store, wtxn, target)? {
        return Ok(false);
    }
    let weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_edge(
        store,
        wtxn,
        hint_id,
        EdgeKind::ClaimOf,
        *target,
        weight,
        Vad::NEUTRAL,
    )?;
    ppr::invalidate_ppr_for_edge(store, wtxn, &hint_id, target)?;

    if store.text_forward.get(wtxn, hint_id.as_bytes())?.is_none() {
        if !text_indexing.trusted {
            return Err(Error::CorruptedIndex(
                "text index handshake bypassed on populated index",
            ));
        }
        if !*text_indexing.manifest_checked {
            crate::vault::ensure_text_index_manifest_matches_wtxn(
                store,
                wtxn,
                text_indexing.analyzer,
            )?;
            *text_indexing.manifest_checked = true;
        }
        crate::bm25::index_text(
            store,
            wtxn,
            text_indexing.analyzer,
            &hint_id,
            &[("query_hint".to_owned(), query_hint)],
        )?;
    }
    Ok(true)
}

pub(super) fn materialize_lexical_query_hints_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text_indexing: &mut LexicalHintTextIndexing<'_>,
    target: &EntityId,
) -> Result<bool> {
    let mut had_graph_mutation = false;
    for hint_id in legacy_lexical_query_hint_claim_ids_for_target(store, wtxn, target)? {
        let Some(body) = stored_claim_body(store, wtxn, &hint_id)? else {
            continue;
        };
        let hint = crate::claim::decode_lexical_query_hint_value(&body.value)?;
        if materialize_lexical_query_hint_text_if_target_ready(
            store,
            wtxn,
            text_indexing,
            hint_id,
            target,
            hint.query,
        )? {
            had_graph_mutation = true;
        }
    }
    Ok(had_graph_mutation)
}

#[derive(Default)]
pub(super) struct DeletedLexicalQueryHints {
    pub(super) had_vector: bool,
    pub(super) had_graph_mutation: bool,
    pub(super) deleted: Vec<(EntityId, Vec<EntityId>)>,
}

pub(super) fn delete_lexical_query_hint_claims_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
    keep: &HashSet<EntityId>,
) -> Result<DeletedLexicalQueryHints> {
    let mut result = DeletedLexicalQueryHints::default();
    let mut pending_targets = VecDeque::from([*target]);
    let mut visited_targets = HashSet::new();
    while let Some(current_target) = pending_targets.pop_front() {
        if !visited_targets.insert(current_target) {
            continue;
        }
        for hint_id in lexical_query_hint_claim_ids_for_target(store, wtxn, &current_target)? {
            if hint_id == *target {
                continue;
            }
            if keep.contains(&hint_id) {
                pending_targets.push_back(hint_id);
                continue;
            }
            let (existed, had_vector, had_graph_mutation, neighbors) =
                deindex_entity_without_lexical_query_hint_cascade(store, wtxn, &hint_id)?;
            if existed {
                pending_targets.push_back(hint_id);
                result.deleted.push((hint_id, neighbors));
            }
            result.had_vector |= had_vector;
            result.had_graph_mutation |= had_graph_mutation;
        }
    }
    Ok(result)
}

pub(super) fn lexical_query_hint_claim_ids_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut hint_ids = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, target.as_bytes())? {
        let (key, value) = entry?;
        let edge = parse_strict_edge_record(&key, &value)?;
        if edge.kind != EdgeKind::ClaimOf {
            continue;
        }
        let source = edge.target;
        let Some(raw) = store.entities.get(wtxn, source.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        if body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
            hint_ids.push(source);
        }
    }

    if stored_entity_is_claim_type(store, wtxn, target)? {
        for hint_id in legacy_lexical_query_hint_claim_ids_for_target(store, wtxn, target)? {
            hint_ids.push(hint_id);
        }
    }
    hint_ids.sort_unstable();
    hint_ids.dedup();
    Ok(hint_ids)
}

pub(super) fn legacy_lexical_query_hint_claim_ids_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut candidates = Vec::new();
    let mut prefix = Vec::with_capacity(1 + crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX.len());
    prefix.push(crate::registry::ENTITY_TYPE_CLAIM);
    prefix.extend_from_slice(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX);
    for entry in store.type_index.prefix_iter(wtxn, &prefix)? {
        let (key, _) = entry?;
        if key.len() != 1 + ENTITY_ID_LEN {
            return Err(Error::CorruptedIndex("type index key"));
        }
        let candidate = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("type index key"))?,
        )
        .map_err(|_| Error::CorruptedIndex("type index key"))?;
        candidates.push(candidate);
    }

    let mut hint_ids = Vec::new();
    for candidate in candidates {
        let Some(body) = stored_claim_body(store, wtxn, &candidate)? else {
            continue;
        };
        if body.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
            continue;
        }
        let Ok(Some(hint_target)) = crate::claim::lexical_query_hint_target(&body) else {
            continue;
        };
        if hint_target == *target {
            hint_ids.push(candidate);
        }
    }
    Ok(hint_ids)
}

pub(super) fn stored_entity_is_lexical_query_hint_claim(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(body) = stored_claim_body(store, wtxn, id)? else {
        return Ok(false);
    };
    Ok(body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT)
}

pub(super) fn stored_entity_is_claim_type(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    Ok(header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
}

pub(super) fn stored_claim_body(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<crate::claim::ClaimBody>> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(None);
    };
    Ok(Some(body))
}
