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
    NapiCalendarEventView, NapiCalendarRange, NapiCalendarSel, NapiCitedMessage, NapiClaimView,
    NapiCommitOutcome, NapiCommitReceipt, NapiDreamerParkedJobView, NapiEntityRefReceipt,
    NapiEntityView, NapiGateReceipt, NapiMemoryItem, NapiMemoryPack, NapiMemoryProvenance,
    NapiMemoryStaleStamp, NapiQuoteSpan, NapiReadReceipt, NapiReadScope, NapiRecallResidence,
    NapiRecallResidenceHit, NapiRecallScope, NapiRecordRef, NapiRecordRefusal, NapiRetrievalMeta,
    NapiScopeHonesty, NapiStructuralPutInput, NapiTemporalHint, NapiTurnProgramWakeOutcome,
    NapiWitnessAssertions, NapiWitnessReceipt, NapiWitnessTurn,
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
        origin: view.origin,
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
            metadata: message.metadata.clone().map(super::js_json::js_json),
            is_visible: message.is_visible.unwrap_or(true),
            order: message.order,
            quote: message.quote.as_ref().map(quote_to_engine).transpose()?,
        });
    }
    let thread_audience = turn
        .thread_audience
        .as_ref()
        .map(|ids| {
            ids.iter()
                .map(|id| {
                    oneiron::EntityId::from_hex(id)
                        .map_err(|_| format!("thread_audience holds an invalid id {id:?}"))
                })
                .collect::<BoundaryResult<std::collections::BTreeSet<_>>>()
        })
        .transpose()?;
    Ok(WitnessTurn {
        conversation_ref: turn.conversation_ref.clone(),
        turn_ref: turn.turn_ref.clone(),
        thread_audience,
        messages,
        occurred_at: ts_to_engine(turn.occurred_at, "occurred_at")?,
        assertions: turn
            .assertions
            .as_ref()
            .map(NapiWitnessAssertions::to_engine)
            .unwrap_or_default(),
    })
}

/// One quote as the JS boundary carries it (OF-460): the quoted MESSAGE's
/// id parsed, and each bound checked a whole Unicode scalar index in the
/// unsigned 32-bit range before it narrows. The engine's witness proves the
/// span against the message in its own write.
fn quote_to_engine(quote: &NapiQuoteSpan) -> BoundaryResult<oneiron::conversation_dag::QuoteSpan> {
    let message = oneiron::EntityId::from_hex(&quote.message).map_err(|_| {
        format!(
            "quote.message must be the quoted MESSAGE's 32-hex id; got {:?}",
            quote.message
        )
    })?;
    let bound = |value: f64, field: &str| -> BoundaryResult<u32> {
        if !value.is_finite()
            || value.fract() != 0.0
            || !(0.0..=f64::from(u32::MAX)).contains(&value)
        {
            return Err(format!(
                "quote.{field} must be a whole Unicode scalar index from 0 to {}",
                u32::MAX
            ));
        }
        // A whole number in the u32 range narrows exactly.
        Ok(value as u32)
    };
    Ok(oneiron::conversation_dag::QuoteSpan {
        message,
        start: bound(quote.start, "start")?,
        end: bound(quote.end, "end")?,
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

/// One batch element's outcome: its landed receipt, or its typed refusal
/// with the refusal's own receipt (OF-063).
pub(super) fn commit_outcome_from_engine(
    outcome: oneiron::memory::CommitOutcome,
) -> NapiCommitOutcome {
    match outcome {
        oneiron::memory::CommitOutcome::Landed(receipt) => NapiCommitOutcome {
            outcome: "landed".to_owned(),
            receipt_ref: Some(receipt.receipt_ref.clone()),
            receipt: Some(commit_receipt_from_engine(receipt)),
            refusal: None,
        },
        oneiron::memory::CommitOutcome::Refused {
            refusal,
            receipt_ref,
        } => NapiCommitOutcome {
            outcome: "refused".to_owned(),
            receipt: None,
            refusal: Some(NapiRecordRefusal {
                reason: refusal.reason.as_str().to_owned(),
                code: refusal.code,
                message: refusal.message,
                suggestions: refusal.suggestions,
                field: refusal.field,
            }),
            receipt_ref,
        },
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
        if matches.value.is_empty() {
            break;
        }
        for claim in matches.value {
            receipts.push(facade.claim_retract(&claim.claim_ref)?);
        }
    }
    Ok(receipts)
}

/// One receipt scope, its entity types as their registry kinds (FIX 8117),
/// spelled as every wire spells them (FIX 10762): a pack's own type the
/// static registry does not name travels as its decimal byte, never narrowed
/// or widened.
fn read_scope_from_engine(scope: oneiron::claim::ReadScope) -> BoundaryResult<NapiReadScope> {
    Ok(NapiReadScope {
        entity_types: scope.entity_kinds(),
        max_sensitivity_band: u32::from(scope.max_sensitivity_band),
        include_stale: scope.include_stale,
        min_confidence: f64::from(scope.min_confidence),
        min_salience: f64::from(scope.min_salience),
        deny_all: scope.deny_all,
    })
}

/// The engine's read receipt, field for field.
pub(super) fn read_receipt_from_engine(
    receipt: oneiron::claim::ScopedReadReceipt,
) -> BoundaryResult<NapiReadReceipt> {
    Ok(NapiReadReceipt {
        requested: read_scope_from_engine(receipt.requested)?,
        actor_ceiling: read_scope_from_engine(receipt.actor_ceiling)?,
        applied: read_scope_from_engine(receipt.applied)?,
        narrowed_axes: receipt.narrowed_axes,
        suppressed_count: u32::try_from(receipt.suppressed_count)
            .map_err(|_| "suppressed_count does not fit a 32-bit count".to_owned())?,
        replan_hint: receipt.replan_hint,
    })
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
        body: super::js_json::js_json(input.body.clone()),
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
        wake_outcome: receipt.wake_outcome.map(wake_outcome_from_engine),
    }
}

/// Projects a turn's program-wake outcome onto the boundary DTO, spelled as
/// the engine's wire spells it.
fn wake_outcome_from_engine(
    outcome: oneiron::memory::TurnProgramWakeOutcome,
) -> NapiTurnProgramWakeOutcome {
    use oneiron::memory::TurnProgramWakeOutcome;
    let (newly_recorded, reason) = match outcome {
        TurnProgramWakeOutcome::NotArmed => (None, None),
        TurnProgramWakeOutcome::Evaluated { newly_recorded } => (Some(newly_recorded), None),
        TurnProgramWakeOutcome::Unpersisted { reason } => (None, Some(reason.as_str().to_owned())),
    };
    NapiTurnProgramWakeOutcome {
        outcome: outcome.as_str().to_owned(),
        newly_recorded,
        reason,
    }
}

/// Projects one engine gate receipt onto the boundary DTO.
pub(super) fn gate_receipt_from_engine(
    record: oneiron::memory::MemoryReceipt,
) -> BoundaryResult<NapiGateReceipt> {
    Ok(NapiGateReceipt {
        receipt_ref: record.receipt_ref,
        kind: record.kind,
        outcome: record.outcome,
        created_at: ts_from_engine(record.created_at, "created_at")?,
        reason_codes: record.reason_codes,
        actor_class: record.actor_class,
        actor_ref: record.actor_ref,
        content_kind: record.content_kind,
        claim_ref: record.claim_ref,
        claim: record.claim.map(record_ref_from_engine),
        fields: record.fields.into_iter().collect(),
    })
}

/// Projects one engine Dreamer park (DOOR-144 A) onto the boundary DTO; its
/// cause keeps the engine's own wire label.
pub(super) fn parked_job_from_engine(
    parked: oneiron::memory::DreamerParkedAttemptView,
) -> BoundaryResult<NapiDreamerParkedJobView> {
    let cause = match serde_json::to_value(parked.cause) {
        Ok(serde_json::Value::String(cause)) => cause,
        _ => return Err("a Dreamer park cause did not write as its label".to_owned()),
    };
    Ok(NapiDreamerParkedJobView {
        job_ref: parked.job_ref,
        cause,
        parked_at: ts_from_engine(parked.parked_at, "parked_at")?,
    })
}

/// Projects one engine typed record ref (OF-063) onto the boundary DTO.
fn record_ref_from_engine(record: oneiron::lens::RecordRef) -> NapiRecordRef {
    NapiRecordRef {
        kind: record.kind,
        id: record.id,
        short_id: record.short_id,
        label: record.label,
    }
}

/// Projects one engine memory item onto the boundary DTO.
pub(super) fn memory_item_from_engine(item: oneiron::memory::MemoryItem) -> NapiMemoryItem {
    NapiMemoryItem {
        short_id: item.short_id,
        source_revision_ref: item.source_revision_ref,
        kind: item.kind,
        predicate: item.predicate,
        value_text: item.value_text,
        confidence: f64::from(item.confidence),
        hedge_bucket: item.hedge_bucket,
        confidence_basis: item.confidence_basis.map(|basis| basis.as_str().to_owned()),
        provenance: NapiMemoryProvenance {
            source: item.provenance.source,
            source_revision_ids: item.provenance.source_revision_ids,
            evidence_turn_ids: item.provenance.evidence_turn_ids,
        },
        stale: item.stale.map(|stamp| NapiMemoryStaleStamp {
            stale_since: stamp.stale_since.map(|value| value as f64),
            age_secs: stamp.age_secs.map(|value| value as f64),
            reason: stamp.reason,
            pact_epoch: stamp.pact_epoch as f64,
        }),
        world: item.world,
        facet: item.facet,
        salience: item.salience.map(f64::from),
        reactions: item.reactions,
        cited_messages: item
            .cited_messages
            .into_iter()
            .map(|cited| NapiCitedMessage {
                short_id: cited.short_id,
                value_text: cited.value_text,
                record: cited.record.map(record_ref_from_engine),
            })
            .collect(),
        conversation_id: item.conversation_id,
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
            census_capped: pack.scope_honesty.census_capped,
        },
        retrieval_meta: NapiRetrievalMeta {
            quality: match pack.retrieval_meta.quality {
                oneiron::retrieval_quality::RetrievalQuality::Full => "full",
                oneiron::retrieval_quality::RetrievalQuality::Degraded => "degraded",
                oneiron::retrieval_quality::RetrievalQuality::Passthrough => "passthrough",
            }
            .to_owned(),
            degradation: pack
                .retrieval_meta
                .degradation
                .into_iter()
                .map(|reason| {
                    match reason {
                        oneiron::retrieval_quality::RetrievalDegradation::PprCacheMiss => {
                            "ppr_cache_miss"
                        }
                        oneiron::retrieval_quality::RetrievalDegradation::EmbeddingTimeout => {
                            "embedding_timeout"
                        }
                        oneiron::retrieval_quality::RetrievalDegradation::Bm25Stale => "bm25_stale",
                        oneiron::retrieval_quality::RetrievalDegradation::TemporalSignalSkipped => {
                            "temporal_signal_skipped"
                        }
                    }
                    .to_owned()
                })
                .collect(),
            confidence_adjustment: serde_json::to_value(pack.retrieval_meta.confidence_adjustment)
                .map_err(|error| error.to_string())?
                .as_f64()
                .ok_or_else(|| "invalid confidence adjustment".to_owned())?,
            rerank: pack
                .retrieval_meta
                .rerank
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| error.to_string())?,
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
            partial: pack.retrieval_meta.partial,
            temporal_hints: pack
                .retrieval_meta
                .temporal_hints
                .into_iter()
                .map(|hint| {
                    Ok(NapiTemporalHint {
                        phrase: hint.phrase,
                        status: hint.status.as_str().to_owned(),
                        start: hint
                            .start
                            .map(|start| ts_from_engine(start, "temporal hint start"))
                            .transpose()?,
                        end: hint
                            .end
                            .map(|end| ts_from_engine(end, "temporal hint end"))
                            .transpose()?,
                    })
                })
                .collect::<BoundaryResult<_>>()?,
            limit_clamped: pack.retrieval_meta.limit_clamped,
        },
        pack_version: pack.pack_version,
        rendered: pack.rendered,
        narrowing: read_receipt_from_engine(*pack.narrowing)?,
        retrieval_run_id: pack.retrieval_run_id.map(|id| id.as_bytes().to_vec()),
        residence: pack.residence.map(recall_residence_from_engine),
    })
}

/// Projects an opened device's recall residence onto the boundary DTO.
fn recall_residence_from_engine(
    residence: oneiron::memory::RecallResidence,
) -> NapiRecallResidence {
    NapiRecallResidence {
        source: match residence.source {
            oneiron::memory::RecallResidenceSource::Home => "home",
            oneiron::memory::RecallResidenceSource::LocalOnly => "local_only",
        }
        .to_owned(),
        complete: residence.complete,
        capped: residence.capped,
        hits: residence
            .hits
            .into_iter()
            .map(|hit| NapiRecallResidenceHit {
                id: hit.id,
                score: f64::from(hit.score),
                window: hit.window,
            })
            .collect(),
    }
}

/// Lowers the boundary media query onto the engine's wire type; an unknown
/// kind is the caller's `BAD_REQUEST`. The legacy `NapiVault` context pack
/// lowers its `media` here too, so both carry the one served shape.
pub(crate) fn recall_media_to_engine(
    media: super::dtos::NapiRecallMedia,
) -> Result<oneiron::code_run::vault_read::ContextPackMediaQuery, oneiron::memory::MemoryError> {
    use oneiron::code_run::vault_read::MediaQueryKind;
    let kinds = media
        .kinds
        .unwrap_or_default()
        .into_iter()
        .map(|kind| match kind.as_str() {
            "text" => Ok(MediaQueryKind::Text),
            "image" => Ok(MediaQueryKind::Image),
            "audio" => Ok(MediaQueryKind::Audio),
            _ => Err(oneiron::memory::MemoryError::bad_request(format!(
                "media.kinds: unknown kind {kind:?}; use text, image or audio"
            ))),
        })
        .collect::<Result<_, _>>()?;
    Ok(oneiron::code_run::vault_read::ContextPackMediaQuery {
        space: media.space,
        mime: media.mime,
        bytes_b64: media.bytes_b64,
        kinds,
    })
}

/// Lowers the boundary query affect onto the engine's; the recall door
/// refuses a non-finite or out-of-range value with `BAD_REQUEST`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 affect narrowing at the N-API boundary is intentional"
)]
pub(super) fn query_affect_to_engine(
    affect: super::dtos::NapiQueryAffect,
) -> oneiron::task_verb::sdk::QueryAffect {
    oneiron::task_verb::sdk::QueryAffect {
        valence: affect.valence as f32,
        arousal: affect.arousal as f32,
        dominance: affect.dominance as f32,
    }
}

/// Lowers the boundary recall scope onto the engine's.
pub(super) fn recall_scope_to_engine(scope: Option<NapiRecallScope>) -> RecallScope {
    scope.map_or_else(RecallScope::default, |scope| RecallScope {
        world_ref: scope.world_ref,
        facet: scope.facet,
        kinds: scope.kinds,
        // Omitted or empty selects every project the caller reads (FIX 8115).
        project_refs: scope.project_refs.unwrap_or_default(),
        ..Default::default()
    })
}
