//! DTO to/from engine converters plus the forget paging helper.

use oneiron::{
    CalendarEventView, CalendarSel, ClaimListFilter, Memory, MemoryError, RecallScope,
    StructuralEdgeSpec, StructuralPutInput, TextIndexField, TimeRange, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};

use super::boundary::{
    BoundaryResult, FORGET_PAGE_SIZE, ts_from_engine, ts_opt_to_engine, ts_to_engine,
};
use super::dtos::{
    NapiCalendarEventView, NapiCalendarRange, NapiCalendarSel, NapiClaimView, NapiCommitReceipt,
    NapiEntityRefReceipt, NapiEntityView, NapiGateReceipt, NapiMemoryItem, NapiMemoryPack,
    NapiMemoryProvenance, NapiRecallScope, NapiRetrievalMeta, NapiScopeHonesty,
    NapiStructuralPutInput, NapiWitnessReceipt, NapiWitnessTurn,
};

// ── conversions ─────────────────────────────────────────────────────────

pub(super) fn calendar_selectors_to_engine(
    selectors: Option<Vec<NapiCalendarSel>>,
) -> Vec<CalendarSel> {
    selectors
        .unwrap_or_default()
        .into_iter()
        .map(|selector| CalendarSel {
            system: selector.system,
        })
        .collect()
}

pub(super) fn calendar_range_to_engine(
    range: Option<NapiCalendarRange>,
) -> BoundaryResult<Option<TimeRange>> {
    range
        .map(|range| {
            Ok(TimeRange {
                start: ts_to_engine(range.start, "range.start")?,
                end: ts_to_engine(range.end, "range.end")?,
            })
        })
        .transpose()
}

pub(super) fn calendar_event_from_engine(
    view: CalendarEventView,
) -> BoundaryResult<NapiCalendarEventView> {
    Ok(NapiCalendarEventView {
        event_ref: view.event_ref,
        name: view.name,
        start_utc: view
            .start_utc
            .map(|value| ts_from_engine(value, "start_utc"))
            .transpose()?,
        end_utc: view
            .end_utc
            .map(|value| ts_from_engine(value, "end_utc"))
            .transpose()?,
        calendar_systems: view.calendar_systems,
        blocks_time: view.blocks_time,
    })
}

/// Converts a host turn into the engine turn.
///
/// ONE-1686: this is a CONVENIENCE boundary, not a gate. It rejects the two
/// shapes whose engine refusal a host could not otherwise read off its own
/// input — an unknown author string and a non-object `metadata` — and leaves
/// every other axis to the engine's witness ceiling door, which runs inside the
/// write transaction and answers for EVERY caller (uniffi, HTTP, in-process
/// Rust), not just this one. Re-implementing the ceiling here would create a
/// second set of bounds to drift out of sync with the authoritative one, and
/// would still not protect the callers that never cross this boundary.
pub(super) fn witness_turn_to_engine(turn: &NapiWitnessTurn) -> BoundaryResult<WitnessTurn> {
    let mut messages = Vec::with_capacity(turn.messages.len());
    for message in &turn.messages {
        let author = WitnessAuthor::parse(&message.author).ok_or_else(|| {
            format!(
                "author must be one of user, companion, system; got {:?}",
                message.author
            )
        })?;
        if message
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.is_object())
        {
            return Err(format!(
                "metadata must be a JSON object; message at order {} carries {}",
                message.order,
                match message.metadata.as_ref() {
                    Some(serde_json::Value::Array(_)) => "an array",
                    Some(serde_json::Value::Null) => "null",
                    _ => "a scalar",
                }
            ));
        }
        messages.push(WitnessMessage {
            id: message.id.clone(),
            author,
            message_type: message.message_type.clone(),
            content: message.content.clone(),
            metadata: message.metadata.clone(),
            is_visible: message.is_visible.unwrap_or(true),
            order: message.order,
        });
    }
    Ok(WitnessTurn {
        conversation_ref: turn.conversation_ref.clone(),
        turn_ref: turn.turn_ref.clone(),
        messages,
        occurred_at: ts_to_engine(turn.occurred_at, "occurred_at")?,
    })
}

pub(super) fn commit_receipt_from_engine(receipt: oneiron::CommitReceipt) -> NapiCommitReceipt {
    NapiCommitReceipt {
        claim_short_id: receipt.claim_short_id,
        approval: receipt.approval,
        superseded_short_id: receipt.superseded_short_id,
        receipt_ref: receipt.receipt_ref,
    }
}

/// Retracts EVERY active claim matching `subject_ref` + `predicate`, not just
/// the first page. Each retract moves its claim out of the `active`
/// lifecycle, so re-listing `active` excludes the already-retracted claims and
/// the loop drains to an empty page with no offset bookkeeping. Engine-typed
/// so it is unit-testable without the N-API runtime.
pub(super) fn forget_active_matches(
    facade: &Memory<'_>,
    subject_ref: &str,
    predicate: &str,
) -> std::result::Result<Vec<oneiron::CommitReceipt>, MemoryError> {
    let mut receipts = Vec::new();
    loop {
        let matches = facade.claim_list(&ClaimListFilter {
            subject_ref: Some(subject_ref.to_owned()),
            predicate: Some(predicate.to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: FORGET_PAGE_SIZE,
        })?;
        if matches.is_empty() {
            break;
        }
        for claim in matches {
            receipts.push(facade.claim_retract(&claim.claim_ref)?);
        }
    }
    Ok(receipts)
}

pub(super) fn entity_view_from_engine(view: oneiron::EntityView) -> BoundaryResult<NapiEntityView> {
    Ok(NapiEntityView {
        id_hex: view.id_hex,
        short_ref: view.short_ref,
        kind: view.kind,
        occurred_start: ts_from_engine(view.occurred_start, "occurred_start")?,
        occurred_end: ts_from_engine(view.occurred_end, "occurred_end")?,
        learned_at: ts_from_engine(view.learned_at, "learned_at")?,
        body: view.body,
    })
}

pub(super) fn claim_view_from_engine(view: oneiron::ClaimView) -> BoundaryResult<NapiClaimView> {
    Ok(NapiClaimView {
        claim_ref: view.claim_ref,
        short_ref: view.short_ref,
        predicate: view.predicate,
        subject_ref: view.subject_ref,
        value: view.value,
        confidence: f64::from(view.confidence),
        approval: view.approval,
        lifecycle: view.lifecycle,
        source: view.source,
        world_ref: view.world_ref,
        scope: view.scope,
        valid_from: view
            .valid_from
            .map(|v| ts_from_engine(v, "valid_from"))
            .transpose()?,
        valid_to: view
            .valid_to
            .map(|v| ts_from_engine(v, "valid_to"))
            .transpose()?,
        salience: view.salience.map(f64::from),
        stale: view.stale,
    })
}

pub(super) fn entity_ref_receipt_from_engine(
    receipt: oneiron::EntityRefReceipt,
) -> NapiEntityRefReceipt {
    NapiEntityRefReceipt {
        entity_ref: receipt.entity_ref,
        id_hex: receipt.id_hex,
        receipt_ref: receipt.receipt_ref,
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 edge-weight narrowing at the N-API boundary is intentional"
)]
pub(super) fn structural_put_to_engine(
    input: &NapiStructuralPutInput,
) -> BoundaryResult<StructuralPutInput> {
    Ok(StructuralPutInput {
        id: input.id.clone(),
        kind: input.kind.clone(),
        body: input.body.clone(),
        text_fields: input.text_fields.as_ref().map(|fields| {
            fields
                .iter()
                .map(|field| TextIndexField {
                    field: field.field.clone(),
                    value: field.value.clone(),
                })
                .collect()
        }),
        edges: input.edges.as_ref().map(|edges| {
            edges
                .iter()
                .map(|edge| StructuralEdgeSpec {
                    edge_kind: edge.edge_kind.clone(),
                    target_ref: edge.target_ref.clone(),
                    weight: edge.weight.map(|w| w as f32),
                })
                .collect()
        }),
        occurred_at: ts_to_engine(input.occurred_at, "occurred_at")?,
        learned_at: ts_opt_to_engine(input.learned_at, "learned_at")?,
    })
}

/// Projects an engine witness receipt onto the boundary DTO.
pub(super) fn witness_receipt_from_engine(
    receipt: oneiron::memory::WitnessReceipt,
) -> NapiWitnessReceipt {
    NapiWitnessReceipt {
        turn_short_id: receipt.turn_short_id,
        message_short_ids: receipt.message_short_ids,
        receipt_ref: receipt.receipt_ref,
    }
}

/// Projects one engine gate receipt onto the boundary DTO.
pub(super) fn gate_receipt_from_engine(
    record: oneiron::memory::MemoryReceipt,
) -> BoundaryResult<NapiGateReceipt> {
    Ok(NapiGateReceipt {
        receipt_ref: record.receipt_ref,
        outcome: record.outcome,
        created_at: ts_from_engine(record.created_at, "created_at")?,
        reason_codes: record.reason_codes,
        actor_class: record.actor_class,
        actor_ref: record.actor_ref,
        content_kind: record.content_kind,
        claim_ref: record.claim_ref,
    })
}

/// Projects one engine memory item onto the boundary DTO.
pub(super) fn memory_item_from_engine(item: oneiron::memory::MemoryItem) -> NapiMemoryItem {
    NapiMemoryItem {
        short_id: item.short_id,
        kind: item.kind,
        predicate: item.predicate,
        value_text: item.value_text,
        confidence: f64::from(item.confidence),
        hedge_bucket: item.hedge_bucket,
        provenance: NapiMemoryProvenance {
            source: item.provenance.source,
            source_revision_ids: item.provenance.source_revision_ids,
            evidence_turn_ids: item.provenance.evidence_turn_ids,
        },
        world: item.world,
        facet: item.facet,
        salience: item.salience.map(f64::from),
    }
}

/// Projects an engine memory pack onto the boundary DTO.
///
/// The pack crosses UNCHANGED apart from field spelling: same items, same
/// scope honesty, same retrieval accounting, same `packVersion`. There is no
/// wrapper rerank, no truncation, and no synthesized field.
pub(super) fn memory_pack_from_engine(
    pack: oneiron::memory::MemoryPack,
) -> BoundaryResult<NapiMemoryPack> {
    Ok(NapiMemoryPack {
        items: pack
            .items
            .into_iter()
            .map(memory_item_from_engine)
            .collect(),
        scope_honesty: NapiScopeHonesty {
            out_of_scope_worlds: pack.scope_honesty.out_of_scope_worlds,
        },
        retrieval_meta: NapiRetrievalMeta {
            sparse: pack.retrieval_meta.sparse,
            total_candidates: ts_from_engine(
                pack.retrieval_meta.total_candidates,
                "total_candidates",
            )?,
            claims_returned: ts_from_engine(
                pack.retrieval_meta.claims_returned,
                "claims_returned",
            )?,
            deep_pending: pack.retrieval_meta.deep_pending,
        },
        pack_version: pack.pack_version,
        rendered: pack.rendered,
    })
}

/// Lowers the boundary recall scope onto the engine's.
pub(super) fn recall_scope_to_engine(scope: Option<NapiRecallScope>) -> RecallScope {
    scope.map_or_else(RecallScope::default, |scope| RecallScope {
        world_ref: scope.world_ref,
        facet: scope.facet,
    })
}
