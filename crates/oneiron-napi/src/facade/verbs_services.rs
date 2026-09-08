//! Structural/blob/retrieval/outbound/calendar verbs of the actor surface.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use napi_derive::napi;
use oneiron::{
    AdmitImportedClaimInput, BlobArtifactInput, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest,
    CompanionRecordInput, ConsolidationAttemptInput, Effort, HabitCheckinInput, NeighborOpts,
    OutboundDraftInput,
};

use super::boundary::{
    BoundaryResult, boundary_error, decode_blob_base64, facade_error, narrow_to_f32,
    outbound_schedule_context_to_engine, ts_from_engine, ts_opt_to_engine, ts_to_engine,
};
use super::bridge::ActorScopedVault;
use super::convert::{
    calendar_event_from_engine, calendar_range_to_engine, calendar_selectors_to_engine,
    commit_receipt_from_engine, entity_ref_receipt_from_engine, memory_pack_from_engine,
    recall_scope_to_engine, structural_put_to_engine,
};
use super::dtos::{
    NapiAdmitImportedClaimInput, NapiBlobArtifactInput, NapiBlobVersionView, NapiCalendarEventView,
    NapiCalendarFreebusyInterval, NapiCalendarInviteInput, NapiCalendarRange,
    NapiCalendarSearchRequest, NapiCalendarSel, NapiClaimInput, NapiCommitReceipt,
    NapiCompanionRecordInput, NapiConsolidationJobInput, NapiDreamerJobRef, NapiDreamerJobView,
    NapiEntityRefReceipt, NapiHabitCheckinInput, NapiLexicalHit, NapiMemoryPack, NapiNeighborHit,
    NapiNeighborOpts, NapiOutboundDraftInput, NapiOutboundIntentReceipt, NapiRecallScope,
    NapiStructuralPutInput,
};
use super::numeric::claim_input_to_engine;

#[napi]
impl ActorScopedVault {
    /// Structural CREATE carrying text-index fields and edges (B2).
    ///
    /// Create-only (ONE-1889): an id that already holds a stored entity is
    /// refused by the engine, whatever its stored kind. The typed refusal
    /// propagates unchanged — it is never translated into success and never
    /// retried as an overwrite. Mutating a stored entity is its typed verb's
    /// job; there is no force or overwrite option here.
    #[napi]
    pub fn put_structural(
        &self,
        input: NapiStructuralPutInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = structural_put_to_engine(&input).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .put_structural(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Appends one habit check-in child (pinned `role` key stamped by the
    /// facade; `ChildOf` edge written by the pack contract).
    #[napi]
    pub fn put_habit_checkin(
        &self,
        input: NapiHabitCheckinInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = HabitCheckinInput {
            habit_ref: input.habit_ref,
            id: input.id,
            data: input.data,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_habit_checkin(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Registers a companion persona record (personal scope), optionally
    /// retiring it (migration of inactive companions).
    #[napi]
    pub fn put_companion_record(
        &self,
        input: NapiCompanionRecordInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = CompanionRecordInput {
            id: input.id,
            owner_ref: input.owner_ref,
            persona_ref: input.persona_ref,
            value: input.value,
            source: input.source,
            retired_at: ts_opt_to_engine(input.retired_at, "retired_at").map_err(boundary_error)?,
            learned_at: ts_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_companion_record(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Admits one imported-evidence claim through the registered ingest
    /// source's trust ceiling (B1a; unknown sources fail closed).
    #[napi]
    pub fn admit_imported_claim(
        &self,
        input: NapiAdmitImportedClaimInput,
    ) -> napi::Result<NapiCommitReceipt> {
        let engine_input = AdmitImportedClaimInput {
            source_id: input.source_id,
            source_record_id: input.source_record_id,
            id: input.id,
            subject_ref: input.subject_ref,
            predicate: input.predicate,
            value: input.value,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .admit_imported_claim(&engine_input)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Registers a blob artifact (B8 blob door).
    #[napi]
    pub fn put_blob_artifact(
        &self,
        input: NapiBlobArtifactInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = BlobArtifactInput {
            id: input.id,
            name: input.name,
            media_type: input.media_type,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_blob_artifact(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Appends one content-addressed blob version. Content crosses as a
    /// standard base64 string (buffer-free S1 ABI, B8).
    #[napi]
    pub fn append_blob_version(
        &self,
        artifact_ref: String,
        bytes_base64: String,
        run_ref: Option<String>,
        occurred_at: i64,
        learned_at: Option<i64>,
    ) -> napi::Result<NapiBlobVersionView> {
        let bytes = decode_blob_base64(&bytes_base64).map_err(boundary_error)?;
        let view = self
            .facade()?
            .append_blob_version(
                &artifact_ref,
                &bytes,
                run_ref.as_deref(),
                ts_to_engine(occurred_at, "occurred_at").map_err(boundary_error)?,
                ts_opt_to_engine(learned_at, "learned_at").map_err(boundary_error)?,
            )
            .map_err(facade_error)?;
        Ok(NapiBlobVersionView {
            artifact_ref: view.artifact_ref,
            version: ts_from_engine(view.version, "version").map_err(boundary_error)?,
            content_hash_hex: view.content_hash_hex,
            claim_ref: view.claim_ref,
            created_at: ts_from_engine(view.created_at, "created_at").map_err(boundary_error)?,
        })
    }

    /// BM25 text query over the engine index. The standard N-API query
    /// (8 KiB) and result (1,000) caps apply.
    #[napi]
    pub fn query_bm25(&self, query: String, limit: u32) -> napi::Result<Vec<NapiLexicalHit>> {
        crate::validate_query_len(&query).map_err(boundary_error)?;
        let limit = crate::parse_search_limit(limit).map_err(boundary_error)?;
        let hits = self
            .facade()?
            .query_bm25(&query, limit)
            .map_err(facade_error)?;
        Ok(hits
            .into_iter()
            .map(|hit| NapiLexicalHit {
                short_id: hit.short_id,
                kind: hit.kind,
                score: f64::from(hit.score),
                snippet: hit.snippet,
            })
            .collect())
    }

    /// Weighted-edge neighborhood, filtered engine-side.
    #[napi]
    pub fn neighbors(
        &self,
        entity_ref: String,
        opts: NapiNeighborOpts,
    ) -> napi::Result<Vec<NapiNeighborHit>> {
        let hits = self
            .facade()?
            .neighbors(
                &entity_ref,
                &NeighborOpts {
                    edge_kind: opts.edge_kind,
                    min_weight: opts
                        .min_weight
                        .map(narrow_to_f32)
                        .transpose()
                        .map_err(boundary_error)?,
                    limit: opts.limit as usize,
                },
            )
            .map_err(facade_error)?;
        Ok(hits
            .into_iter()
            .map(|hit| NapiNeighborHit {
                short_id: hit.short_id,
                kind: hit.kind,
                edge_kind: hit.edge_kind,
                weight: f64::from(hit.weight),
                direction: hit.direction,
            })
            .collect())
    }

    /// Effort-dialed retrieval into an S6 memory pack. `effort` is
    /// `minimal` | `standard` | `deep`; no lease handle exists on this
    /// surface yet (OF-131), so `deep` returns the typed `LEASE_REQUIRED`
    /// error until the LLMB chain lands the issuer.
    #[napi]
    pub fn recall(
        &self,
        query: String,
        effort: String,
        scope: Option<NapiRecallScope>,
        limit: u32,
        format: Option<String>,
    ) -> napi::Result<NapiMemoryPack> {
        crate::validate_query_len(&query).map_err(boundary_error)?;
        let limit = crate::parse_search_limit(limit).map_err(boundary_error)?;
        let effort = Effort::parse(&effort).ok_or_else(|| {
            boundary_error(format!(
                "unknown effort {effort:?}; use minimal, standard, or deep"
            ))
        })?;
        let scope = recall_scope_to_engine(scope);
        let pack = self
            .facade()?
            .recall(&query, effort, &scope, limit, format.as_deref(), None)
            .map_err(facade_error)?;
        memory_pack_from_engine(pack).map_err(boundary_error)
    }

    /// Enqueues one Dreamer consolidation job; long work returns a job
    /// ref to poll (W2 — no async FFI).
    #[napi]
    pub fn enqueue_consolidation(
        &self,
        input: NapiConsolidationJobInput,
    ) -> napi::Result<NapiDreamerJobRef> {
        let engine_input = ConsolidationAttemptInput {
            scope: input.scope,
            input: input.input,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            now: ts_opt_to_engine(input.now, "now").map_err(boundary_error)?,
        };
        let job = self
            .facade()?
            .enqueue_consolidation(&engine_input)
            .map_err(facade_error)?;
        Ok(NapiDreamerJobRef {
            job_ref: job.job_ref,
            state: job.state,
            existing: job.existing,
        })
    }

    /// Polls one Dreamer job's status; `null` for unknown job refs.
    #[napi]
    pub fn dreamer_job_status(&self, job_ref: String) -> napi::Result<Option<NapiDreamerJobView>> {
        let view = self
            .facade()?
            .dreamer_attempt_status(&job_ref)
            .map_err(facade_error)?;
        view.map(|view| {
            Ok(NapiDreamerJobView {
                job_ref: view.job_ref,
                state: view.state,
                kind: view.kind,
                lease_owner: view.lease_owner,
                attempt_count: view.attempt_count,
                run_id: view.run_id,
                last_error: view.last_error,
                created_at: ts_from_engine(view.created_at, "created_at")
                    .map_err(boundary_error)?,
                updated_at: ts_from_engine(view.updated_at, "updated_at")
                    .map_err(boundary_error)?,
            })
        })
        .transpose()
    }

    /// Seed-write entry point (EF-301 consumer): every element is FORCED
    /// proposed regardless of source, individually gated, with receipts.
    #[napi]
    pub fn seed_claims(&self, claims: Vec<NapiClaimInput>) -> napi::Result<Vec<NapiCommitReceipt>> {
        let mut engine_claims = Vec::with_capacity(claims.len());
        for claim in &claims {
            engine_claims.push(claim_input_to_engine(claim).map_err(facade_error)?);
        }
        let receipts = self
            .facade()?
            .seed_claims(&engine_claims)
            .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Schedules one outbound intent through the OF-327 chokepoint: durable
    /// idempotent enqueue + gate check under a Hold window. The bridge
    /// never delivers; receipts surface via `receipts()`.
    #[napi]
    pub fn schedule_outbound(
        &self,
        draft: NapiOutboundDraftInput,
    ) -> napi::Result<NapiOutboundIntentReceipt> {
        // The clock-authority conversion runs FIRST and fails closed: an
        // invalid offset/label/level is rejected at the boundary, before any
        // TASK or attempt row can be written.
        let schedule_context =
            outbound_schedule_context_to_engine(&draft).map_err(boundary_error)?;
        let engine_draft = OutboundDraftInput {
            verb: draft.verb,
            channel: draft.channel,
            target: draft.target,
            on_behalf_of: draft.on_behalf_of,
            content_ref: draft.content_ref,
            idempotency_key: draft.idempotency_key,
            dedupe_key: draft.dedupe_key,
            trigger: draft.trigger,
            trigger_ref: draft.trigger_ref,
            job_ref: draft.job_ref,
            occurred_at: ts_opt_to_engine(draft.occurred_at, "occurred_at")
                .map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .schedule_outbound_with_context(&engine_draft, &schedule_context)
            .map_err(facade_error)?;
        Ok(NapiOutboundIntentReceipt {
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
            gate_outcome: receipt.gate_outcome,
            gate_decision_ref: receipt.gate_decision_ref,
            gate_reason_codes: receipt.gate_reason_codes,
            deduped: receipt.deduped,
        })
    }

    /// Reads one calendar EVENT under the bound actor's read scope; `null`
    /// when the id is unknown, unreadable, or not a calendar EVENT.
    #[napi]
    pub fn calendar_read(&self, event_ref: String) -> napi::Result<Option<NapiCalendarEventView>> {
        self.facade()?
            .calendar_read(&CalendarReadRequest { event_ref })
            .map_err(facade_error)?
            .map(calendar_event_from_engine)
            .transpose()
            .map_err(boundary_error)
    }

    /// Searches calendar EVENTs under the bound actor's read scope.
    #[napi]
    pub fn calendar_search(
        &self,
        request: NapiCalendarSearchRequest,
    ) -> napi::Result<Vec<NapiCalendarEventView>> {
        let engine_request = CalendarSearchRequest {
            calendars: calendar_selectors_to_engine(request.calendars),
            range: calendar_range_to_engine(request.range)
                .map_err(boundary_error)?
                .map(|range| CalendarRangeDto {
                    start: range.start,
                    end: range.end,
                }),
            text: request.text,
            limit: request.limit,
        };
        self.facade()?
            .calendar_search(&engine_request)
            .map_err(facade_error)?
            .into_iter()
            .map(calendar_event_from_engine)
            .collect::<BoundaryResult<Vec<_>>>()
            .map_err(boundary_error)
    }

    /// Projects busy-only occupancy over an inclusive UTC window.
    #[napi]
    pub fn calendar_freebusy(
        &self,
        calendars: Option<Vec<NapiCalendarSel>>,
        range: NapiCalendarRange,
    ) -> napi::Result<Vec<NapiCalendarFreebusyInterval>> {
        let engine_range = calendar_range_to_engine(Some(range))
            .map_err(boundary_error)?
            .ok_or_else(|| boundary_error("range is required".to_owned()))?;
        self.facade()?
            .calendar_freebusy(&calendar_selectors_to_engine(calendars), engine_range)
            .map_err(facade_error)?
            .into_iter()
            .map(|interval| {
                Ok(NapiCalendarFreebusyInterval {
                    start_utc: ts_from_engine(interval.start_utc, "start_utc")?,
                    end_utc: ts_from_engine(interval.end_utc, "end_utc")?,
                })
            })
            .collect::<BoundaryResult<Vec<_>>>()
            .map_err(boundary_error)
    }

    /// Schedules one calendar invite through the ordinary outbound gate. The
    /// bridge never delivers; receipts surface via `receipts()`.
    #[napi]
    pub fn calendar_invite(
        &self,
        input: NapiCalendarInviteInput,
    ) -> napi::Result<NapiOutboundIntentReceipt> {
        let method = CalendarInviteSurfaceMethod::parse(&input.method).ok_or_else(|| {
            boundary_error(format!(
                "method must be one of REQUEST, CANCEL; got {:?}",
                input.method
            ))
        })?;
        let receipt = self
            .facade()?
            .calendar_invite(&CalendarInviteSurfaceInput {
                method,
                uid: input.uid,
                sequence: input.sequence,
                ics_blob_ref: input.ics_blob_ref,
                recipient: input.recipient,
            })
            .map_err(facade_error)?;
        Ok(NapiOutboundIntentReceipt {
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
            gate_outcome: receipt.gate_outcome,
            gate_decision_ref: receipt.gate_decision_ref,
            gate_reason_codes: receipt.gate_reason_codes,
            deduped: receipt.deduped,
        })
    }

    /// Reads one blob version's bytes (hash-verified engine-side) as a
    /// standard base64 string; `null` when the version does not exist.
    #[napi]
    pub fn read_blob_version(
        &self,
        artifact_ref: String,
        version: i64,
    ) -> napi::Result<Option<String>> {
        let bytes = self
            .facade()?
            .read_blob_version(
                &artifact_ref,
                ts_to_engine(version, "version").map_err(boundary_error)?,
            )
            .map_err(facade_error)?;
        Ok(bytes.map(|bytes| BASE64_STANDARD.encode(bytes)))
    }
}
