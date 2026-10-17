//! Lift and lower codecs between this crate's UniFFI records and the engine
//! types the shared `oneiron_remote::OneironClient` takes and returns.
//!
//! Every generated verb lowers its foreign arguments into the row's engine
//! input, calls the client's typed method for that row, and lifts the engine
//! output back. A conversion is selected by its source and target types, never
//! by verb name. A row whose types have generated records
//! (`facade_types_generated.rs`) converts through the wire shape the record
//! and the engine type share: [`lower_record`] and [`lift_record`]. A row whose
//! type the facade inventory cannot read crosses as [`WireJson`] whole:
//! [`decode`] parses it into the row's engine input type, so that type's own
//! serde shape validates it, and [`encode`] writes the typed output back.
//! Widths are checked, never wrapped: a negative foreign timestamp is a
//! `BAD_REQUEST`, an engine value past the foreign width an `INTERNAL`.

use base64::Engine as _;
use oneiron::claim::{ScopedReadReceipt, ScopedReadResult};
use oneiron::dreamer_runner::maintenance::identity;
use oneiron::memory as engine;
use oneiron::retrieval_quality as quality;
use oneiron::task_verb::sdk;

use crate::dto::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, CitedMessage, ClaimInput,
    ClaimListFilter, ClaimView, ClaimViews, CommitReceipt, ConsolidationJobInput, DeleteReceipt,
    DreamerJobRef, DreamerJobView, Effort, EntityRead, EntityRefReceipt, EntityView, EntityViews,
    FacadeReceipt, ForgetSelector, HabitCheckinInput, LexicalHit, LexicalHits, MemoryItem,
    MemoryPack, MemoryProvenance, MentionProvenance, NeighborHit, NeighborHits, NeighborOpts,
    OutboundDraftInput, OutboundIntentReceipt, PendingWrite, QuoteSpan, ReadReceipt, ReadScope,
    RecallMedia, RecallScope, RerankReport, RerankSkip, RetrievalDegradation, RetrievalMeta, RetrievalQuality,
    SafeDeleteReason, ScopeHonesty, StructuralPutInput, TemporalHint, WireJson, WitnessAuthor,
    WitnessMessage, WitnessReceipt, WitnessTurn,
};
use crate::error::OneironError;

/// Lowers a foreign value into the engine type `T`.
pub(crate) trait Lower<T> {
    fn lower(self) -> Result<T, OneironError>;
}

/// Lifts the engine value `T` into a foreign value.
pub(crate) trait Lift<T>: Sized {
    fn lift(value: T) -> Result<Self, OneironError>;
}

// ── refusals ────────────────────────────────────────────────────────────

fn failure(code: &str, message: String, suggestion: &str) -> OneironError {
    OneironError::Failure {
        code: code.to_owned(),
        message,
        suggestions: vec![suggestion.to_owned()],
        attempted: None,
        replacement: None,
        schema_ref: None,
    }
}

fn bad_request(message: String, suggestion: &str) -> OneironError {
    failure(engine::MEMORY_CODE_BAD_REQUEST, message, suggestion)
}

fn internal(message: String) -> OneironError {
    failure(
        engine::MEMORY_CODE_INTERNAL,
        message,
        "This is an Oneiron SDK bug; please report it.",
    )
}

// ── the WireJson leaf ───────────────────────────────────────────────────

/// Parses one verb's `WireJson` input into that verb's engine input type.
#[allow(
    dead_code,
    reason = "the generator's door for a row whose input type the facade inventory cannot read; this table has none"
)]
pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    verb: &str,
    input: &WireJson,
) -> Result<T, OneironError> {
    serde_json::from_str(&input.canonical_json).map_err(|error| {
        bad_request(
            format!("{verb}'s input is not the documented shape: {error}"),
            "Send the verb's documented input as one JSON value.",
        )
    })
}

/// Writes one verb's typed engine output as one JSON value.
#[allow(
    dead_code,
    reason = "the generator's door for a row whose result type the facade inventory cannot read; this table has none"
)]
pub(crate) fn encode<T: serde::Serialize>(
    verb: &str,
    output: &T,
) -> Result<WireJson, OneironError> {
    serde_json::to_string(output)
        .map(|canonical_json| WireJson { canonical_json })
        .map_err(|error| internal(format!("could not encode {verb}'s result: {error}")))
}

impl Lower<serde_json::Value> for WireJson {
    fn lower(self) -> Result<serde_json::Value, OneironError> {
        serde_json::from_str(&self.canonical_json).map_err(|error| {
            bad_request(
                format!("a WireJson value is not one complete JSON value: {error}"),
                "Send exactly one JSON value as canonical_json.",
            )
        })
    }
}

impl Lift<serde_json::Value> for WireJson {
    fn lift(value: serde_json::Value) -> Result<Self, OneironError> {
        serde_json::to_string(&value)
            .map(|canonical_json| Self { canonical_json })
            .map_err(|error| internal(format!("could not encode a JSON value: {error}")))
    }
}

/// A `WireJson` field of a generated record is written as the JSON value it
/// carries, not as its text, so the record's serde shape is the engine's.
impl serde::Serialize for WireJson {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: serde_json::Value =
            serde_json::from_str(&self.canonical_json).map_err(serde::ser::Error::custom)?;
        serde::Serialize::serialize(&value, serializer)
    }
}

/// Any one JSON value reads as the `WireJson` carrying its canonical text.
impl<'de> serde::Deserialize<'de> for WireJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        serde_json::to_string(&value)
            .map(|canonical_json| Self { canonical_json })
            .map_err(serde::de::Error::custom)
    }
}

// ── generated records ───────────────────────────────────────────────────
//
// `facade_types_generated.rs` mirrors each engine type a facade row reaches
// with the engine type's own serde wire shape. A row converts at its boundary
// through that shape: the record is written as JSON and read as the engine
// type, so the engine type's own serde validates it, and the engine output is
// written as JSON and read as the record. Nested types need no conversion of
// their own.

/// Lowers one verb's generated input record into that verb's engine input.
pub(crate) fn lower_record<R: serde::Serialize, T: serde::de::DeserializeOwned>(
    verb: &str,
    record: R,
) -> Result<T, OneironError> {
    let value = serde_json::to_value(record).map_err(|error| {
        bad_request(
            format!("{verb}'s input could not be written as JSON: {error}"),
            "Send the verb's documented input; a WireJson field holds one JSON value.",
        )
    })?;
    serde_json::from_value(value).map_err(|error| {
        bad_request(
            format!("{verb}'s input is not the documented shape: {error}"),
            "Send the verb's documented input.",
        )
    })
}

/// The engine input of a verb whose input record has no fields.
pub(crate) fn lower_empty<T: serde::de::DeserializeOwned>(verb: &str) -> Result<T, OneironError> {
    serde_json::from_value(serde_json::Value::Object(serde_json::Map::new()))
        .map_err(|error| internal(format!("{verb}'s empty input does not read: {error}")))
}

/// Lifts one verb's engine output into its generated result record.
pub(crate) fn lift_record<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    verb: &str,
    output: &T,
) -> Result<R, OneironError> {
    let value = serde_json::to_value(output)
        .map_err(|error| internal(format!("could not encode {verb}'s result: {error}")))?;
    serde_json::from_value(value).map_err(|error| {
        internal(format!(
            "{verb}'s result does not read as its UniFFI record: {error}"
        ))
    })
}

// ── widths ──────────────────────────────────────────────────────────────

fn unsigned_seconds(field: &str, value: i64) -> Result<u64, OneironError> {
    u64::try_from(value).map_err(|_| {
        bad_request(
            format!("{field} must be a non-negative whole number of Unix seconds"),
            "Pass whole Unix seconds; the SDK performs no unit conversion.",
        )
    })
}

fn optional_seconds(field: &str, value: Option<i64>) -> Result<Option<u64>, OneironError> {
    value
        .map(|value| unsigned_seconds(field, value))
        .transpose()
}

/// An omitted write time is stamped with the current Unix second at the call
/// boundary, the rule the napi and Python bindings share.
fn stamped_seconds(field: &str, value: Option<i64>) -> Result<u64, OneironError> {
    match value {
        Some(value) => unsigned_seconds(field, value),
        None => Ok(oneiron_remote::unix_seconds_now()),
    }
}

fn signed_seconds(field: &str, value: u64) -> Result<i64, OneironError> {
    i64::try_from(value)
        .map_err(|_| internal(format!("{field} {value} is past the signed 64-bit range")))
}

fn optional_signed(field: &str, value: Option<u64>) -> Result<Option<i64>, OneironError> {
    value.map(|value| signed_seconds(field, value)).transpose()
}

fn count(field: &str, value: usize) -> Result<u64, OneironError> {
    u64::try_from(value)
        .map_err(|_| internal(format!("{field} {value} is past the unsigned 64-bit range")))
}

impl Lower<usize> for u32 {
    fn lower(self) -> Result<usize, OneironError> {
        usize::try_from(self).map_err(|_| {
            bad_request(
                format!("{self} does not fit this platform's count width"),
                "Request a smaller count.",
            )
        })
    }
}

// ── containers ──────────────────────────────────────────────────────────

impl<T, U> Lower<Vec<U>> for Vec<T>
where
    T: Lower<U>,
{
    fn lower(self) -> Result<Vec<U>, OneironError> {
        self.into_iter().map(Lower::lower).collect()
    }
}

impl<T, U> Lower<Option<U>> for Option<T>
where
    T: Lower<U>,
{
    fn lower(self) -> Result<Option<U>, OneironError> {
        self.map(Lower::lower).transpose()
    }
}

impl<T, U> Lift<Vec<T>> for Vec<U>
where
    U: Lift<T>,
{
    fn lift(value: Vec<T>) -> Result<Self, OneironError> {
        value.into_iter().map(U::lift).collect()
    }
}

impl<T, U> Lift<Option<T>> for Option<U>
where
    U: Lift<T>,
{
    fn lift(value: Option<T>) -> Result<Self, OneironError> {
        value.map(U::lift).transpose()
    }
}

// ── witness ─────────────────────────────────────────────────────────────

impl Lower<engine::WitnessMessage> for WitnessMessage {
    fn lower(self) -> Result<engine::WitnessMessage, OneironError> {
        Ok(engine::WitnessMessage {
            id: self.id,
            author: match self.author {
                WitnessAuthor::User => engine::WitnessAuthor::User,
                WitnessAuthor::Companion => engine::WitnessAuthor::Companion,
                WitnessAuthor::System => engine::WitnessAuthor::System,
            },
            message_type: self.message_type,
            content: self.content,
            metadata: self.metadata.lower()?,
            is_visible: self.is_visible.unwrap_or(true),
            order: self.order,
        })
    }
}

impl Lower<engine::WitnessTurn> for WitnessTurn {
    fn lower(self) -> Result<engine::WitnessTurn, OneironError> {
        Ok(engine::WitnessTurn {
            conversation_ref: self.conversation_ref,
            turn_ref: self.turn_ref,
            quote: self.quote.lower()?,
            messages: self.messages.lower()?,
            occurred_at: stamped_seconds("occurred_at", self.occurred_at)?,
        })
    }
}

impl Lower<oneiron::conversation_dag::QuoteSpan> for QuoteSpan {
    fn lower(self) -> Result<oneiron::conversation_dag::QuoteSpan, OneironError> {
        let message = oneiron::EntityId::from_hex(&self.message).map_err(|_| {
            bad_request(
                "quote.message must be the quoted MESSAGE's 32-hex id".to_owned(),
                "Name the quoted message by its 32-hex id.",
            )
        })?;
        Ok(oneiron::conversation_dag::QuoteSpan {
            message,
            start: self.start,
            end: self.end,
        })
    }
}

impl Lift<engine::WitnessReceipt> for WitnessReceipt {
    fn lift(value: engine::WitnessReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            turn_short_id: value.turn_short_id,
            message_short_ids: value.message_short_ids,
            receipt_ref: value.receipt_ref,
        })
    }
}

// ── claims ──────────────────────────────────────────────────────────────

impl Lower<engine::ClaimInput> for ClaimInput {
    fn lower(self) -> Result<engine::ClaimInput, OneironError> {
        Ok(engine::ClaimInput {
            id: self.id,
            predicate: self.predicate,
            subject_ref: self.subject_ref,
            value: self.value.lower()?,
            confidence: self.confidence,
            source: self.source,
            world_ref: self.world_ref,
            relationship_ref: self.relationship_ref,
            scope: self.scope.lower()?,
            valid_from: optional_seconds("valid_from", self.valid_from)?,
            valid_to: optional_seconds("valid_to", self.valid_to)?,
            occurred_at: optional_seconds("occurred_at", self.occurred_at)?,
            learned_at: optional_seconds("learned_at", self.learned_at)?,
            salience: self.salience,
        })
    }
}

impl Lower<sdk::CommitRequest> for Vec<ClaimInput> {
    fn lower(self) -> Result<sdk::CommitRequest, OneironError> {
        Ok(sdk::CommitRequest {
            claims: self.lower()?,
        })
    }
}

impl Lower<sdk::ClaimRefRequest> for String {
    fn lower(self) -> Result<sdk::ClaimRefRequest, OneironError> {
        Ok(sdk::ClaimRefRequest { claim_ref: self })
    }
}

impl Lower<sdk::ForgetRequest> for ForgetSelector {
    fn lower(self) -> Result<sdk::ForgetRequest, OneironError> {
        match (self.short_ref, self.subject_ref, self.predicate) {
            (Some(claim_ref), None, None) => Ok(sdk::ForgetRequest::Claim(sdk::ClaimRefRequest {
                claim_ref,
            })),
            (None, Some(subject_ref), Some(predicate)) => {
                Ok(sdk::ForgetRequest::Predicate(sdk::ForgetPredicateRequest {
                    subject_ref,
                    predicate,
                }))
            }
            _ => Err(bad_request(
                "forget names one claim short_ref, or a subject_ref with a predicate".to_owned(),
                "Set short_ref alone, or subject_ref and predicate together.",
            )),
        }
    }
}

impl Lower<engine::ClaimListFilter> for ClaimListFilter {
    fn lower(self) -> Result<engine::ClaimListFilter, OneironError> {
        Ok(engine::ClaimListFilter {
            subject_ref: self.subject_ref,
            predicate: self.predicate,
            lifecycle: self.lifecycle,
            limit: self.limit.lower()?,
        })
    }
}

impl Lift<engine::CommitReceipt> for CommitReceipt {
    fn lift(value: engine::CommitReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            claim_short_id: value.claim_short_id,
            approval: value.approval,
            superseded_short_id: value.superseded_short_id,
            receipt_ref: value.receipt_ref,
        })
    }
}

impl Lift<engine::ClaimView> for ClaimView {
    fn lift(view: engine::ClaimView) -> Result<Self, OneironError> {
        Ok(Self {
            claim_ref: view.claim_ref,
            short_ref: view.short_ref,
            predicate: view.predicate,
            subject_ref: view.subject_ref,
            value: WireJson::lift(view.value)?,
            confidence: view.confidence,
            approval: view.approval,
            lifecycle: view.lifecycle,
            source: view.source,
            world_ref: view.world_ref,
            scope: Lift::lift(view.scope)?,
            valid_from: optional_signed("valid_from", view.valid_from)?,
            valid_to: optional_signed("valid_to", view.valid_to)?,
            salience: view.salience,
            stale: view.stale,
        })
    }
}

// ── deletion and consent ────────────────────────────────────────────────

impl Lower<sdk::SafeDeleteRequest> for (String, SafeDeleteReason) {
    fn lower(self) -> Result<sdk::SafeDeleteRequest, OneironError> {
        let (entity_ref, reason) = self;
        Ok(sdk::SafeDeleteRequest {
            entity_ref,
            reason: match reason {
                SafeDeleteReason::UserDelete => engine::SafeDeleteReason::UserDelete,
                SafeDeleteReason::UserHardDelete => engine::SafeDeleteReason::UserHardDelete,
                SafeDeleteReason::GdprDelete => engine::SafeDeleteReason::GdprDelete,
                SafeDeleteReason::PolicyDelete => engine::SafeDeleteReason::PolicyDelete,
            },
        })
    }
}

impl Lower<sdk::ReceiptsRequest> for u32 {
    fn lower(self) -> Result<sdk::ReceiptsRequest, OneironError> {
        Ok(sdk::ReceiptsRequest {
            limit: Some(self.lower()?),
        })
    }
}

impl Lift<engine::DeleteReceipt> for DeleteReceipt {
    fn lift(value: engine::DeleteReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            existed: value.existed,
            reason: value.reason,
            receipt_ref: value.receipt_ref,
        })
    }
}

impl Lift<engine::PendingWrite> for PendingWrite {
    fn lift(value: engine::PendingWrite) -> Result<Self, OneironError> {
        Ok(Self {
            claim_ref: value.claim_ref,
            decision_ref: value.decision_ref,
            created_at: signed_seconds("created_at", value.created_at)?,
            reason_codes: value.reason_codes,
            dreamer_run_id: value.dreamer_run_id,
        })
    }
}

impl Lift<engine::MemoryReceipt> for FacadeReceipt {
    fn lift(value: engine::MemoryReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            receipt_ref: value.receipt_ref,
            outcome: value.outcome,
            created_at: signed_seconds("created_at", value.created_at)?,
            reason_codes: value.reason_codes,
            actor_class: value.actor_class,
            actor_ref: value.actor_ref,
            content_kind: value.content_kind,
            claim_ref: value.claim_ref,
        })
    }
}

// ── reads and their receipts ────────────────────────────────────────────

impl Lower<sdk::HydrateRequest> for Vec<String> {
    fn lower(self) -> Result<sdk::HydrateRequest, OneironError> {
        Ok(sdk::HydrateRequest { refs: self })
    }
}

impl Lower<sdk::EntityRequest> for String {
    fn lower(self) -> Result<sdk::EntityRequest, OneironError> {
        Ok(sdk::EntityRequest { entity_ref: self })
    }
}

impl Lower<sdk::QueryBm25Request> for (String, u32) {
    fn lower(self) -> Result<sdk::QueryBm25Request, OneironError> {
        let (query, limit) = self;
        Ok(sdk::QueryBm25Request {
            query,
            limit: limit.lower()?,
        })
    }
}

impl Lower<engine::NeighborOpts> for NeighborOpts {
    fn lower(self) -> Result<engine::NeighborOpts, OneironError> {
        Ok(engine::NeighborOpts {
            edge_kind: self.edge_kind,
            min_weight: self.min_weight,
            limit: self.limit.lower()?,
        })
    }
}

impl Lower<sdk::NeighborsRequest> for (String, NeighborOpts) {
    fn lower(self) -> Result<sdk::NeighborsRequest, OneironError> {
        let (entity_ref, opts) = self;
        Ok(sdk::NeighborsRequest {
            entity_ref,
            opts: opts.lower()?,
        })
    }
}

impl Lift<oneiron::claim::ReadScope> for ReadScope {
    fn lift(scope: oneiron::claim::ReadScope) -> Result<Self, OneironError> {
        Ok(Self {
            entity_types: scope.entity_types.map(|types| types.into_iter().collect()),
            max_sensitivity_band: scope.max_sensitivity_band,
            include_stale: scope.include_stale,
            min_confidence: scope.min_confidence,
            min_salience: scope.min_salience,
            deny_all: scope.deny_all,
        })
    }
}

impl Lift<ScopedReadReceipt> for ReadReceipt {
    fn lift(receipt: ScopedReadReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            requested: ReadScope::lift(receipt.requested)?,
            actor_ceiling: ReadScope::lift(receipt.actor_ceiling)?,
            applied: ReadScope::lift(receipt.applied)?,
            narrowed_axes: receipt.narrowed_axes,
            suppressed_count: count("suppressed_count", receipt.suppressed_count)?,
            replan_hint: receipt.replan_hint,
        })
    }
}

impl Lift<engine::EntityView> for EntityView {
    fn lift(view: engine::EntityView) -> Result<Self, OneironError> {
        Ok(Self {
            id_hex: view.id_hex,
            short_ref: view.short_ref,
            kind: view.kind,
            occurred_start: signed_seconds("occurred_start", view.occurred_start)?,
            occurred_end: signed_seconds("occurred_end", view.occurred_end)?,
            learned_at: signed_seconds("learned_at", view.learned_at)?,
            body: Lift::lift(view.body)?,
        })
    }
}

impl Lift<engine::LexicalHit> for LexicalHit {
    fn lift(hit: engine::LexicalHit) -> Result<Self, OneironError> {
        Ok(Self {
            short_id: hit.short_id,
            kind: hit.kind,
            score: hit.score,
            snippet: hit.snippet,
        })
    }
}

impl Lift<engine::NeighborHit> for NeighborHit {
    fn lift(hit: engine::NeighborHit) -> Result<Self, OneironError> {
        Ok(Self {
            short_id: hit.short_id,
            kind: hit.kind,
            edge_kind: hit.edge_kind,
            weight: hit.weight,
            direction: hit.direction,
        })
    }
}

impl Lift<ScopedReadResult<Vec<engine::ClaimView>>> for ClaimViews {
    fn lift(read: ScopedReadResult<Vec<engine::ClaimView>>) -> Result<Self, OneironError> {
        Ok(Self {
            value: Lift::lift(read.value)?,
            narrowing: ReadReceipt::lift(read.receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<Vec<engine::EntityView>>> for EntityViews {
    fn lift(read: ScopedReadResult<Vec<engine::EntityView>>) -> Result<Self, OneironError> {
        Ok(Self {
            value: Lift::lift(read.value)?,
            narrowing: ReadReceipt::lift(read.receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<Option<engine::EntityView>>> for EntityRead {
    fn lift(read: ScopedReadResult<Option<engine::EntityView>>) -> Result<Self, OneironError> {
        Ok(Self {
            value: Lift::lift(read.value)?,
            narrowing: ReadReceipt::lift(read.receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<Vec<engine::LexicalHit>>> for LexicalHits {
    fn lift(read: ScopedReadResult<Vec<engine::LexicalHit>>) -> Result<Self, OneironError> {
        Ok(Self {
            value: Lift::lift(read.value)?,
            narrowing: ReadReceipt::lift(read.receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<Vec<engine::NeighborHit>>> for NeighborHits {
    fn lift(read: ScopedReadResult<Vec<engine::NeighborHit>>) -> Result<Self, OneironError> {
        Ok(Self {
            value: Lift::lift(read.value)?,
            narrowing: ReadReceipt::lift(read.receipt)?,
        })
    }
}

// ── structural writes and specialized inputs ────────────────────────────

impl Lower<engine::StructuralPutInput> for StructuralPutInput {
    fn lower(self) -> Result<engine::StructuralPutInput, OneironError> {
        Ok(engine::StructuralPutInput {
            id: self.id,
            kind: self.kind,
            body: self.body.lower()?,
            text_fields: self.text_fields.map(|fields| {
                fields
                    .into_iter()
                    .map(|field| engine::TextIndexField {
                        field: field.field,
                        value: field.value,
                    })
                    .collect()
            }),
            edges: self.edges.map(|edges| {
                edges
                    .into_iter()
                    .map(|edge| engine::StructuralEdgeSpec {
                        edge_kind: edge.edge_kind,
                        target_ref: edge.target_ref,
                        weight: edge.weight,
                    })
                    .collect()
            }),
            occurred_at: stamped_seconds("occurred_at", self.occurred_at)?,
            learned_at: optional_seconds("learned_at", self.learned_at)?,
        })
    }
}

impl Lower<engine::HabitCheckinInput> for HabitCheckinInput {
    fn lower(self) -> Result<engine::HabitCheckinInput, OneironError> {
        Ok(engine::HabitCheckinInput {
            habit_ref: self.habit_ref,
            id: self.id,
            data: self.data.lower()?,
            occurred_at: stamped_seconds("occurred_at", self.occurred_at)?,
            learned_at: optional_seconds("learned_at", self.learned_at)?,
        })
    }
}

impl Lower<engine::AdmitImportedClaimInput> for AdmitImportedClaimInput {
    fn lower(self) -> Result<engine::AdmitImportedClaimInput, OneironError> {
        Ok(engine::AdmitImportedClaimInput {
            source_id: self.source_id,
            source_record_id: self.source_record_id,
            id: self.id,
            subject_ref: self.subject_ref,
            predicate: self.predicate,
            value: self.value.lower()?,
            occurred_at: stamped_seconds("occurred_at", self.occurred_at)?,
            learned_at: optional_seconds("learned_at", self.learned_at)?,
        })
    }
}

impl Lift<engine::EntityRefReceipt> for EntityRefReceipt {
    fn lift(value: engine::EntityRefReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            entity_ref: value.entity_ref,
            id_hex: value.id_hex,
            receipt_ref: value.receipt_ref,
        })
    }
}

// ── blob bytes ──────────────────────────────────────────────────────────

impl Lower<engine::BlobArtifactInput> for BlobArtifactInput {
    fn lower(self) -> Result<engine::BlobArtifactInput, OneironError> {
        Ok(engine::BlobArtifactInput {
            id: self.id,
            name: self.name,
            media_type: self.media_type,
            occurred_at: stamped_seconds("occurred_at", self.occurred_at)?,
            learned_at: optional_seconds("learned_at", self.learned_at)?,
        })
    }
}

/// `vault.artifacts.append`'s arguments: the raw bytes are measured against
/// the engine blob ceiling before they are base64-encoded for the request.
impl Lower<sdk::AppendBlobVersionRequest>
    for (String, Vec<u8>, Option<String>, Option<i64>, Option<i64>)
{
    fn lower(self) -> Result<sdk::AppendBlobVersionRequest, OneironError> {
        let (artifact_ref, content, run_ref, occurred_at, learned_at) = self;
        engine::caps::check_blob_bytes(content.len())?;
        Ok(sdk::AppendBlobVersionRequest {
            artifact_ref,
            content_base64: base64::engine::general_purpose::STANDARD.encode(&content),
            run_ref,
            occurred_at: stamped_seconds("occurred_at", occurred_at)?,
            learned_at: optional_seconds("learned_at", learned_at)?,
        })
    }
}

impl Lower<sdk::ReadBlobVersionRequest> for (String, u64) {
    fn lower(self) -> Result<sdk::ReadBlobVersionRequest, OneironError> {
        let (artifact_ref, version) = self;
        Ok(sdk::ReadBlobVersionRequest {
            artifact_ref,
            version,
        })
    }
}

impl Lift<engine::BlobVersionView> for BlobVersionView {
    fn lift(value: engine::BlobVersionView) -> Result<Self, OneironError> {
        Ok(Self {
            artifact_ref: value.artifact_ref,
            version: value.version,
            content_hash_hex: value.content_hash_hex,
            claim_ref: value.claim_ref,
            created_at: signed_seconds("created_at", value.created_at)?,
        })
    }
}

impl Lift<sdk::BlobContent> for Vec<u8> {
    fn lift(value: sdk::BlobContent) -> Result<Self, OneironError> {
        base64::engine::general_purpose::STANDARD
            .decode(&value.content_base64)
            .map_err(|error| internal(format!("the blob content is not base64: {error}")))
    }
}

// ── consolidation jobs ──────────────────────────────────────────────────

impl Lower<sdk::ConsolidationEnqueueRequest> for ConsolidationJobInput {
    fn lower(self) -> Result<sdk::ConsolidationEnqueueRequest, OneironError> {
        Ok(sdk::ConsolidationEnqueueRequest {
            scope: self.scope,
            input: self.input.lower()?,
            run_id: self.run_id,
            dedupe_key: self.dedupe_key,
            now: optional_seconds("now", self.now)?,
        })
    }
}

impl Lower<sdk::ConsolidationStatusRequest> for String {
    fn lower(self) -> Result<sdk::ConsolidationStatusRequest, OneironError> {
        Ok(sdk::ConsolidationStatusRequest { job_ref: self })
    }
}

impl Lift<engine::DreamerAttemptRef> for DreamerJobRef {
    fn lift(job: engine::DreamerAttemptRef) -> Result<Self, OneironError> {
        Ok(Self {
            job_ref: job.job_ref,
            state: job.state,
            existing: job.existing,
        })
    }
}

impl Lift<engine::DreamerAttemptView> for DreamerJobView {
    fn lift(job: engine::DreamerAttemptView) -> Result<Self, OneironError> {
        Ok(Self {
            job_ref: job.job_ref,
            state: job.state,
            kind: job.kind,
            lease_owner: job.lease_owner,
            attempt_count: job.attempt_count,
            run_id: job.run_id,
            last_error: job.last_error,
            created_at: signed_seconds("created_at", job.created_at)?,
            updated_at: signed_seconds("updated_at", job.updated_at)?,
        })
    }
}

// ── outbound (scheduling only) ──────────────────────────────────────────

impl Lower<sdk::OutboundScheduleRequest> for OutboundDraftInput {
    fn lower(self) -> Result<sdk::OutboundScheduleRequest, OneironError> {
        Ok(sdk::OutboundScheduleRequest {
            verb: self.verb,
            channel: self.channel,
            target: self.target,
            on_behalf_of: self.on_behalf_of,
            content_ref: self.content_ref,
            idempotency_key: self.idempotency_key,
            dedupe_key: self.dedupe_key,
            trigger: self.trigger,
            trigger_ref: self.trigger_ref,
            job_ref: self.job_ref,
            occurred_at: optional_seconds("occurred_at", self.occurred_at)?,
            mention: self.mention.lower()?,
        })
    }
}

impl Lower<identity::MentionProvenance> for MentionProvenance {
    fn lower(self) -> Result<identity::MentionProvenance, OneironError> {
        Ok(identity::MentionProvenance {
            turn: self.turn,
            message: self.message,
            start: self.start,
            end: self.end,
        })
    }
}

impl Lift<engine::OutboundIntentReceipt> for OutboundIntentReceipt {
    fn lift(value: engine::OutboundIntentReceipt) -> Result<Self, OneironError> {
        Ok(Self {
            intent_ref: value.intent_ref,
            outcome: value.outcome,
            gate_outcome: value.gate_outcome,
            gate_decision_ref: value.gate_decision_ref,
            gate_reason_codes: value.gate_reason_codes,
            deduped: value.deduped,
        })
    }
}

// ── recall ──────────────────────────────────────────────────────────────

impl Lower<engine::RecallEffort> for Effort {
    fn lower(self) -> Result<engine::RecallEffort, OneironError> {
        Ok(match self {
            Self::Light => engine::RecallEffort::Light,
            Self::Medium => engine::RecallEffort::Medium,
            Self::High => engine::RecallEffort::High,
            Self::Xhigh => engine::RecallEffort::Xhigh,
            Self::Max => engine::RecallEffort::Max,
            Self::Call => engine::RecallEffort::Call,
        })
    }
}

/// A recall's media query crosses as the engine's wire type, kind for kind.
impl Lower<oneiron::code_run::vault_read::ContextPackMediaQuery> for RecallMedia {
    fn lower(self) -> Result<oneiron::code_run::vault_read::ContextPackMediaQuery, OneironError> {
        use oneiron::code_run::vault_read::MediaQueryKind;
        Ok(oneiron::code_run::vault_read::ContextPackMediaQuery {
            space: self.space,
            mime: self.mime,
            bytes_b64: self.bytes_b64,
            kinds: self
                .kinds
                .into_iter()
                .map(|kind| match kind {
                    crate::InputKind::Text => MediaQueryKind::Text,
                    crate::InputKind::Image => MediaQueryKind::Image,
                    crate::InputKind::Audio => MediaQueryKind::Audio,
                })
                .collect(),
        })
    }
}

/// An omitted scope is the vault floor, the engine's default scope.
impl Lower<engine::RecallScope> for Option<RecallScope> {
    fn lower(self) -> Result<engine::RecallScope, OneironError> {
        Ok(
            self.map_or_else(engine::RecallScope::default, |scope| engine::RecallScope {
                world_ref: scope.world_ref,
                facet: scope.facet,
                kinds: scope.kinds,
            }),
        )
    }
}

impl Lift<engine::MemoryItem> for MemoryItem {
    fn lift(item: engine::MemoryItem) -> Result<Self, OneironError> {
        Ok(Self {
            short_id: item.short_id,
            source_revision_ref: item.source_revision_ref,
            kind: item.kind,
            predicate: item.predicate,
            value_text: item.value_text,
            confidence: item.confidence,
            hedge_bucket: item.hedge_bucket,
            provenance: MemoryProvenance {
                source: item.provenance.source,
                source_revision_ids: item.provenance.source_revision_ids,
                evidence_turn_ids: item.provenance.evidence_turn_ids,
            },
            world: item.world,
            facet: item.facet,
            salience: item.salience,
            reactions: item.reactions,
            cited_messages: item
                .cited_messages
                .into_iter()
                .map(|cited| CitedMessage {
                    short_id: cited.short_id,
                    value_text: cited.value_text,
                })
                .collect(),
            conversation_id: item.conversation_id,
        })
    }
}

fn rerank_report(report: engine::RerankReport) -> Result<RerankReport, OneironError> {
    Ok(match report {
        engine::RerankReport::Applied {
            model,
            served_model,
            candidates,
            calls,
        } => RerankReport::Applied {
            model,
            served_model,
            candidates: count("rerank candidates", candidates)?,
            calls,
        },
        engine::RerankReport::Skipped { reason } => RerankReport::Skipped {
            reason: match reason {
                engine::RerankSkip::NoReranker => RerankSkip::NoReranker,
                engine::RerankSkip::NoCandidates => RerankSkip::NoCandidates,
                engine::RerankSkip::Deadline => RerankSkip::Deadline,
                engine::RerankSkip::DeviceOnly => RerankSkip::DeviceOnly,
            },
        },
    })
}

impl Lift<engine::RetrievalMeta> for RetrievalMeta {
    fn lift(meta: engine::RetrievalMeta) -> Result<Self, OneironError> {
        // The adjustment is fixed-point; its JSON number is the exact f64
        // every other surface reports.
        let confidence_adjustment = serde_json::to_value(meta.confidence_adjustment)
            .ok()
            .as_ref()
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| internal("the confidence adjustment is not a number".to_owned()))?;
        Ok(Self {
            quality: match meta.quality {
                quality::RetrievalQuality::Full => RetrievalQuality::Full,
                quality::RetrievalQuality::Degraded => RetrievalQuality::Degraded,
                quality::RetrievalQuality::Passthrough => RetrievalQuality::Passthrough,
            },
            degradation: meta
                .degradation
                .into_iter()
                .map(|reason| match reason {
                    quality::RetrievalDegradation::PprCacheMiss => {
                        RetrievalDegradation::PprCacheMiss
                    }
                    quality::RetrievalDegradation::EmbeddingTimeout => {
                        RetrievalDegradation::EmbeddingTimeout
                    }
                    quality::RetrievalDegradation::Bm25Stale => RetrievalDegradation::Bm25Stale,
                    quality::RetrievalDegradation::TemporalSignalSkipped => {
                        RetrievalDegradation::TemporalSignalSkipped
                    }
                })
                .collect(),
            confidence_adjustment,
            rerank: meta.rerank.map(rerank_report).transpose()?,
            sparse: meta.sparse,
            total_candidates: meta.total_candidates,
            claims_returned: meta.claims_returned,
            deep_pending: meta.deep_pending,
            partial: meta.partial,
            temporal_hints: meta
                .temporal_hints
                .into_iter()
                .map(|hint| TemporalHint {
                    phrase: hint.phrase,
                    status: hint.status.as_str().to_owned(),
                    start: hint.start,
                    end: hint.end,
                })
                .collect(),
            limit_clamped: meta.limit_clamped,
        })
    }
}

impl Lift<engine::MemoryPack> for MemoryPack {
    fn lift(pack: engine::MemoryPack) -> Result<Self, OneironError> {
        Ok(Self {
            items: Lift::lift(pack.items)?,
            scope_honesty: ScopeHonesty {
                out_of_scope_worlds: pack.scope_honesty.out_of_scope_worlds,
                census_capped: pack.scope_honesty.census_capped,
            },
            retrieval_meta: RetrievalMeta::lift(pack.retrieval_meta)?,
            pack_version: pack.pack_version,
            rendered: pack.rendered,
            narrowing: ReadReceipt::lift(*pack.narrowing)?,
        })
    }
}
