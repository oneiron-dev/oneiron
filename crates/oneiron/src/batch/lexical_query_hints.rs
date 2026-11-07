use super::*;

use std::collections::{HashSet, VecDeque};
use std::str;

use heed::{RoTxn, RwTxn};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK};
use crate::store::EngineScan;
use crate::store::Store;
use crate::store::ppr_cache_invalidation as ppr;
use crate::store::scan_count::ScanCount;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::task_body::TaskRole;
use oneiron_contracts::affect::Vad;

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
/// The MESSAGE-kind refusal every raw put but the witness door gets
/// (ONE-1686, RT-04).
pub(super) const ERR_RAW_MESSAGE_PUT_REQUIRES_WITNESS: &str = "MESSAGE rows are written by the witness door, which binds author, type, content, metadata, \
     visibility and order to an authenticated actor under the approval ceiling";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RawPutDoor {
    Public,
    Internal,
    /// The ONE-1686 witness MESSAGE door
    /// ([`super::BatchBuilder::put_witness_message`]).
    ///
    /// Reachable only by presenting a `gate::WitnessMessageAuthorization`,
    /// whose sole constructor is the approval-ceiling door itself, so this arm
    /// is a capability rather than a flag a caller can set. It exists because
    /// the MESSAGE refusal below has to close BOTH raw doors — the public one
    /// and the crate's internal one — and the witness program writes its rows
    /// through `batch_in()` like every other engine door.
    WitnessMessage,
    /// The FIX 7777 archive MESSAGE door
    /// ([`super::BatchBuilder::put_archived_message`]).
    ///
    /// Reachable only by presenting a `memory::ArchivedMessageAdmission`,
    /// whose sole constructor proves the body a canonical envelope an import
    /// marked: a capability, like the witness arm, never a caller's flag.
    ArchivedMessage,
}

/// [`validate_public_raw_put`] through the public door, for a bound raw
/// put its off-record session stages in the room (FIX 8119): the refusals
/// the same put meets on base.
pub(crate) fn validate_staged_raw_put(entity_type: u8, data: &[u8], learned_at: u64) -> Result<()> {
    validate_public_raw_put(entity_type, data, learned_at, RawPutDoor::Public)
}

pub(super) fn validate_public_raw_put(
    entity_type: u8,
    data: &[u8],
    learned_at: u64,
    door: RawPutDoor,
) -> Result<()> {
    match entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            // The actual write transaction validates the class descriptor;
            // this builder-only preflight reads the envelope's source/predicate.
            let body = crate::claim::decode_claim_body(data, false)?;
            if body.source.is_some() && !is_legacy_raw_claim_compatibility_body(&body) {
                return Err(Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE));
            }
            // The source rule alone does not refuse a source-less expression
            // preference. Its lifecycle still belongs to the typed door.
            if crate::write_envelope::claim_predicate::is_expression_preference_predicate(
                &body.predicate,
            ) {
                return Err(Error::InvalidClaimBody(
                    "expression preference lifecycle is owned by set_expression_preference",
                ));
            }
        }
        // A NOTE body carries `author_ref`, so a caller who hand-writes one
        // forges another actor's attribution — and no raw put can be made to
        // carry the mandatory same-transaction `AuthoredBy` +
        // `About`/`ClaimOf` edges either. Attribution is engine-stamped, so
        // this door refuses the type outright instead of validating a body it
        // cannot bind to an actor; `put_authored_note`, reached only from
        // `Memory::author_take`, is the one NOTE writer for this vault's
        // actors, and `put_archived_note`, whose capability proves an
        // imported author, the archive import's (FIX 7777).
        crate::registry::ENTITY_TYPE_NOTE => {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                ERR_RAW_NOTE_PUT_REQUIRES_AUTHOR_TAKE,
            )));
        }
        // ONE-1686 (RT-04): a MESSAGE body IS the six-axis witness envelope —
        // author, message type, content, metadata, visibility, order — and the
        // approval-ceiling door authorizes exactly those axes against an
        // authenticated actor and the policy snapshot the write commits under.
        // A raw put carries no actor to bind and mints no `AuthoredBy` edge, so
        // it could author an unattributed `system` row, hide a row from the
        // transcript, stamp any type or claim any position with nothing
        // checking. Same posture as the NOTE refusal above, and it closes BOTH
        // doors — `Vault::put_entity`/`Vault::batch()` and the crate's internal
        // `Vault::batch_in()` — because a second engine-tier door disagreeing
        // about the same body is not a seam, it is a hole. The witness door
        // says so by name, with the ceiling's own proof in hand.
        crate::registry::ENTITY_TYPE_MESSAGE
            if !matches!(
                door,
                RawPutDoor::WitnessMessage | RawPutDoor::ArchivedMessage
            ) =>
        {
            return Err(Error::Record(RecordError::InvalidWitnessMessageBody(
                ERR_RAW_MESSAGE_PUT_REQUIRES_WITNESS,
            )));
        }
        ENTITY_TYPE_SKILL => {
            crate::write_envelope::skill_record::validate_skill_record_bytes(data)?
        }
        ENTITY_TYPE_AGENT_DEF => {
            crate::store::agent_definition_codec::validate_agent_definition_bytes(data)?
        }
        // STO-03: the Habit streak counters are derived from the check-in
        // children, so no public writer may name them. The sync-only
        // replicated door deliberately does NOT run this check — it accepts a
        // peer's Habit envelope and then has the tail pass REPLACE the
        // inbound counters from the local reducer, so a peer cannot mint a
        // streak either.
        ENTITY_TYPE_TASK => {
            crate::write_envelope::task_body::reject_public_streak_fields(data)?;
            // Coherence the DECODER already demands: a terminal claiming
            // `countered` names its counter, and one naming a counter claims
            // it. Held here as well as there, because a body that fails only
            // on the way out has already persisted — and then every later
            // read of that task fails instead of the write that made it
            // wrong. Both doors run it: an engine settle body is coherent by
            // construction, so this costs the internal path nothing and
            // closes the raw path completely.
            crate::store::task_body_checks::reject_incoherent_task_terminal(data)?;
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
                crate::store::task_body_checks::reject_born_expired_task_deadline(
                    data, learned_at,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_authored_note_body(author: &EntityId, data: &[u8]) -> Result<()> {
    let body = crate::store::note_body::decode_note_body_using(
        data,
        crate::store::note_body::NoteKind::wire,
    )?;
    if !body.author_ref.is(*author) {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "NOTE author_ref must be the verified bound actor",
        )));
    }
    Ok(())
}

pub(super) fn validate_habit_checkin_body(data: &[u8]) -> Result<()> {
    match crate::write_envelope::task_body::task_role_from_body_bytes(data)? {
        TaskRole::HabitCheckin => Ok(()),
        _ => Err(Error::Record(RecordError::InvalidTaskBody(
            "habit check-in writes require HabitCheckin role",
        ))),
    }
}

pub(super) fn is_legacy_raw_claim_compatibility_body(
    body: &crate::write_envelope::claim_body::ClaimBody,
) -> bool {
    // Code-revision integrity uses legacy raw CLAIM records as provenance anchors.
    body.predicate == "code.revision"
        && matches!(
            body.subject,
            crate::write_envelope::claim_body::ClaimSubject::Entity(_)
        )
        && body.approval == oneiron_contracts::claim::ClaimApprovalStatus::Auto
        && body.lifecycle == oneiron_contracts::claim::ClaimLifecycleStatus::Active
}

/// Refuses a candidate whose predicate belongs to a family that owns its own
/// supersession chain through a typed door.
///
/// `companion.expression.*` is the only such family today. Writing one of its
/// heads means closing whichever head the family's own precedence rules pick;
/// a candidate written through a general batch door supersedes on
/// `subject+scope+predicate` or on nothing at all, so it forks the chain that
/// a later typed retraction walks back.
///
/// The typed door does NOT come through here — it builds its
/// [`BatchOp::ClaimCandidate`] directly and applies it, which is the same
/// crate-private allowance the reserved namespaces get. The guard sits on the
/// PUBLIC builder doors, where an outside caller reaches the candidate path,
/// and on the crate-private candidate put that the code-run traps reach.
pub(crate) fn reject_family_owned_candidate(candidate: &ClaimCandidate) -> Result<()> {
    if crate::write_envelope::claim_predicate::is_expression_preference_predicate(
        candidate.predicate(),
    ) {
        return Err(Error::InvalidClaimBody(
            "expression preference lifecycle is owned by set_expression_preference",
        ));
    }
    Ok(())
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
    if validation_error.is_none()
        && let Err(err) = reject_family_owned_candidate(&candidate)
    {
        *validation_error = Some(err);
    }
    let normalized_hints =
        match crate::write_envelope::claim_body::lexical_query_hint::normalize_lexical_query_hints(
            hints,
        ) {
            Ok(hints) => hints,
            Err(err) => {
                if validation_error.is_none() {
                    *validation_error = Some(err);
                }
                Vec::new()
            }
        };
    // A machine signature binds the parent's transcript, not a derived stale
    // hint CLAIM's. Signed machine claims still land; their hints stay empty.
    let normalized_hints = if envelope.machine_signature().is_some() {
        Vec::new()
    } else {
        normalized_hints
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
            crate::write_envelope::claim_body::lexical_query_hint::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(*id),
            crate::write_envelope::claim_body::lexical_query_hint::encode_lexical_query_hint_value(
                id, &hint,
            ),
            1.0,
        )
        .with_stale(true);
        ops.push(BatchOp::ClaimCandidate {
            id: hint_id,
            candidate: Box::new(hint_candidate),
            envelope: envelope.for_lexical_hint(),
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

pub(super) use crate::write_envelope::claim_body::lexical_query_hint::lexical_query_hint_claim_id;

pub(super) fn lexical_query_hint_for_replayed_put(
    id: &EntityId,
    entity_type: u8,
    replicated: bool,
    data: &[u8],
) -> Result<Option<(EntityId, String)>> {
    if !replicated || entity_type != crate::registry::ENTITY_TYPE_CLAIM || !id.has_derived_stamp() {
        return Ok(None);
    }
    let body = crate::write_envelope::claim_body::decode_claim_body(data, true)?;
    Ok(
        crate::write_envelope::claim_body::lexical_query_hint::canonical_lexical_query_hint(
            id, &body,
        )?
        .map(|hint| (hint.target, hint.query)),
    )
}

pub(super) fn lexical_query_hint_target_is_ready(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<bool> {
    let Some(body) = stored_claim_body(store, wtxn, target)? else {
        return Ok(false);
    };
    Ok(body.predicate
        != crate::write_envelope::claim_body::lexical_query_hint::PREDICATE_LEXICAL_QUERY_HINT
        && body.lifecycle == oneiron_contracts::claim::ClaimLifecycleStatus::Active)
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
        crate::store::text_index::index_text(
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
    for hint_id in lexical_query_hint_claim_ids_for_target(store, wtxn, target)? {
        let Some(body) = stored_claim_body(store, wtxn, &hint_id)? else {
            continue;
        };
        let hint =
            crate::write_envelope::claim_body::lexical_query_hint::decode_lexical_query_hint_value(
                &body.value,
            )?;
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
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
    keep: &HashSet<EntityId>,
) -> Result<DeletedLexicalQueryHints> {
    let store = write.store;
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
                deindex_entity_without_lexical_query_hint_cascade(write, wtxn, &hint_id)?;
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

/// Every hint CLAIM of `target`, attached or still waiting for it. Only a
/// CLAIM is a hint target, so any other row has none. For a CLAIM the whole
/// CLAIM type stream is read; a row with the derive stamp is kept when its
/// body is a lexical query hint for `target` stored under its own derived
/// id. Past the scan's threshold row it raises one check and reads on, so no
/// hint of `target` is left behind.
pub(super) fn lexical_query_hint_claim_ids_for_target(
    store: &Store,
    wtxn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut hint_ids = Vec::new();
    if !stored_entity_is_claim_type(store, wtxn, target)? {
        return Ok(hint_ids);
    }
    let mut rows = ScanCount::start(store, wtxn, EngineScan::LexicalHintRows, &[])?;
    for candidate in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        wtxn,
        crate::registry::ENTITY_TYPE_CLAIM,
        None,
    )? {
        let candidate = candidate?;
        if !candidate.has_derived_stamp() {
            continue;
        }
        rows.row();
        let Some(body) = stored_claim_body(store, wtxn, &candidate)? else {
            continue;
        };
        let Ok(Some(hint)) =
            crate::write_envelope::claim_body::lexical_query_hint::canonical_lexical_query_hint(
                &candidate, &body,
            )
        else {
            continue;
        };
        if hint.target == *target {
            hint_ids.push(candidate);
        }
    }
    rows.defer(store);
    hint_ids.sort_unstable();
    hint_ids.dedup();
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
    Ok(body.predicate
        == crate::write_envelope::claim_body::lexical_query_hint::PREDICATE_LEXICAL_QUERY_HINT)
}

fn stored_entity_is_claim_type(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    Ok(header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
}

pub(super) fn stored_claim_body(
    store: &Store,
    wtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<crate::write_envelope::claim_body::ClaimBody>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let Ok(body) = crate::write_envelope::claim_body::decode_claim_body(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        true,
    ) else {
        return Ok(None);
    };
    Ok(Some(body))
}
