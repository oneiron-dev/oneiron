//! BRIDGE-01 (ONE-1454): napi lift of the engine memory facade.
//!
//! `VaultBridge.open(path)` → `asActor("<actor_class>:<entity_ref>")` →
//! `ActorScopedVault` carrying every facade verb (W3 ABI). All methods are
//! sync `&self` (W2 — no async FFI, no `&mut`). Facade vocabulary only:
//! short-id refs, registry kind strings, typed DTOs (S1). The ONLY `Buffer`
//! on this surface is blob-version content bytes (B8 blob door) — binary
//! audio payloads have no JSON-shaped representation.
//!
//! Errors cross the boundary as `napi::Error` whose reason is the
//! JSON-serialized engine `FacadeError` (`{code, message, suggestions}`),
//! so the TS wrapper (deferred this wave) can rehydrate typed errors.

use std::sync::Arc;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use oneiron::{
    AdmitImportedClaimInput, BlobArtifactInput, ClaimInput, ClaimListFilter, CompanionRecordInput,
    EntityId, FacadeError, HabitCheckinInput, MemoryFacade, SafeDeleteReason, StructuralEdgeSpec,
    StructuralPutInput, TextIndexField, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn, parse_actor_key,
};

type BoundaryResult<T> = std::result::Result<T, String>;

fn facade_error(err: &FacadeError) -> napi::Error {
    napi::Error::from_reason(
        serde_json::to_string(err).unwrap_or_else(|_| err.to_string()),
    )
}

fn boundary_error(reason: String) -> napi::Error {
    napi::Error::from_reason(reason)
}

fn ts_to_engine(value: i64, field: &str) -> BoundaryResult<u64> {
    u64::try_from(value).map_err(|_| format!("{field} must be a non-negative Unix timestamp"))
}

fn ts_opt_to_engine(value: Option<i64>, field: &str) -> BoundaryResult<Option<u64>> {
    value.map(|v| ts_to_engine(v, field)).transpose()
}

fn ts_from_engine(value: u64, field: &str) -> BoundaryResult<i64> {
    i64::try_from(value).map_err(|_| format!("{field} does not fit a signed 64-bit integer"))
}

// ── DTOs (napi objects mirroring the engine facade DTOs) ────────────────

/// One message inside a witnessed turn.
#[napi(object)]
pub struct NapiWitnessMessage {
    /// Deterministic 32-hex entity id; omitted ⇒ generated.
    pub id: Option<String>,
    /// `user` | `companion` | `system` (system rows get no AuthoredBy edge).
    pub author: String,
    /// Message type string.
    pub message_type: String,
    /// Text content (BM25-indexed when non-empty).
    pub content: String,
    /// Opaque metadata.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag; omitted ⇒ true.
    pub is_visible: Option<bool>,
    /// Position within the turn.
    pub order: u32,
}

/// One turn to witness.
#[napi(object)]
pub struct NapiWitnessTurn {
    /// CONVERSATION ref (32-hex create-or-get, or existing short ref).
    pub conversation_ref: String,
    /// TURN ref (create-or-get); omitted ⇒ a fresh TURN.
    pub turn_ref: Option<String>,
    /// Messages, attributed to the bound actor unless `system`.
    pub messages: Vec<NapiWitnessMessage>,
    /// Unix seconds (occurred + learned_at).
    pub occurred_at: i64,
}

/// Receipt for one witnessed turn.
#[napi(object)]
pub struct NapiWitnessReceipt {
    /// TURN short ref.
    pub turn_short_id: String,
    /// MESSAGE short refs, input order.
    pub message_short_ids: Vec<String>,
    /// Facade write marker (`witness:<hex>`).
    pub receipt_ref: String,
}

/// One claim to commit (`approval` is not settable by callers).
#[napi(object)]
pub struct NapiClaimInput {
    /// Deterministic 32-hex claim id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Dotted predicate.
    pub predicate: String,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Claim value.
    pub value: serde_json::Value,
    /// Confidence in [0, 1].
    pub confidence: f64,
    /// Claim source string.
    pub source: String,
    /// Optional WORLD ref.
    pub world_ref: Option<String>,
    /// Optional scope map.
    pub scope: Option<serde_json::Value>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<i64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub occurred_at: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub learned_at: Option<i64>,
    /// Optional salience in [0, 1].
    pub salience: Option<f64>,
}

/// Receipt for one committed (or rejected) claim.
#[napi(object)]
pub struct NapiCommitReceipt {
    /// Short ref of the written claim (hash suffix tracks body revisions).
    pub claim_short_id: String,
    /// `auto` | `proposed` | `rejected`.
    pub approval: String,
    /// Short ref of the superseded prior claim, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref (`gate:<hex>`) resolvable via `receipts()`.
    pub receipt_ref: String,
}

/// Receipt for one safe delete.
#[napi(object)]
pub struct NapiDeleteReceipt {
    /// Whether the entity existed.
    pub existed: bool,
    /// The named reason used.
    pub reason: String,
    /// Redaction audit ref; absent for `user_delete`.
    pub receipt_ref: Option<String>,
}

/// One gated write parked for consent.
#[napi(object)]
pub struct NapiPendingWrite {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Gate decision ref.
    pub decision_ref: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Dreamer run lane, if any.
    pub dreamer_run_id: Option<String>,
}

/// One gate decision receipt.
#[napi(object)]
pub struct NapiGateReceipt {
    /// `gate:<hex>`.
    pub receipt_ref: String,
    /// `allow` | `pending` | `deny`.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Actor class string.
    pub actor_class: String,
    /// Actor entity hex, if enveloped.
    pub actor_ref: Option<String>,
    /// Gate content kind.
    pub content_kind: String,
    /// 32-hex claim id, if any.
    pub claim_ref: Option<String>,
}

/// Typed entity view.
#[napi(object)]
pub struct NapiEntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short ref, when assigned.
    pub short_ref: Option<String>,
    /// Registry kind string.
    pub kind: String,
    /// Unix seconds.
    pub occurred_start: i64,
    /// Unix seconds.
    pub occurred_end: i64,
    /// Unix seconds.
    pub learned_at: i64,
    /// Body as JSON, when decodable.
    pub body: Option<serde_json::Value>,
}

/// Typed claim view.
#[napi(object)]
pub struct NapiClaimView {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Short ref, when assigned.
    pub short_ref: Option<String>,
    /// Predicate.
    pub predicate: String,
    /// Subject ref.
    pub subject_ref: String,
    /// Value as JSON.
    pub value: serde_json::Value,
    /// Confidence.
    pub confidence: f64,
    /// Approval string.
    pub approval: String,
    /// Lifecycle string.
    pub lifecycle: String,
    /// Source string.
    pub source: Option<String>,
    /// World hex.
    pub world_ref: Option<String>,
    /// Scope as JSON.
    pub scope: Option<serde_json::Value>,
    /// Validity window start.
    pub valid_from: Option<i64>,
    /// Validity window end.
    pub valid_to: Option<i64>,
    /// Salience.
    pub salience: Option<f64>,
    /// Stale marker.
    pub stale: bool,
}

/// Filter for `claimList`.
#[napi(object)]
pub struct NapiClaimListFilter {
    /// Restrict to this subject.
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle.
    pub lifecycle: Option<String>,
    /// Maximum results (required).
    pub limit: u32,
}

/// One BM25 field for a structural put.
#[napi(object)]
pub struct NapiTextIndexField {
    /// Analyzer field name.
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[napi(object)]
pub struct NapiStructuralEdgeSpec {
    /// snake_case EdgeKind name.
    pub edge_kind: String,
    /// Target entity ref.
    pub target_ref: String,
    /// Weight in [0, 1]; omitted ⇒ kind default.
    pub weight: Option<f64>,
}

/// Structural put input (B2 migrator group).
#[napi(object)]
pub struct NapiStructuralPutInput {
    /// Deterministic 32-hex id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (CLAIM rejected — use commit).
    pub kind: String,
    /// Entity body (JSON object).
    pub body: serde_json::Value,
    /// BM25 fields.
    pub text_fields: Option<Vec<NapiTextIndexField>>,
    /// Outgoing edges.
    pub edges: Option<Vec<NapiStructuralEdgeSpec>>,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// Receipt for a structural write.
#[napi(object)]
pub struct NapiEntityRefReceipt {
    /// Short ref (hex fallback).
    pub entity_ref: String,
    /// 32-hex id.
    pub id_hex: String,
    /// Facade write marker.
    pub receipt_ref: String,
}

/// One habit check-in append.
#[napi(object)]
pub struct NapiHabitCheckinInput {
    /// Habit-role TASK ref.
    pub habit_ref: String,
    /// Deterministic 32-hex checkin id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Extra body fields (JSON object, no `role` key).
    pub data: Option<serde_json::Value>,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// One companion persona registration.
#[napi(object)]
pub struct NapiCompanionRecordInput {
    /// Deterministic 32-hex record id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Owner PERSON ref (personal scope).
    pub owner_ref: String,
    /// Companion persona PERSON ref.
    pub persona_ref: String,
    /// Opaque record value.
    pub value: serde_json::Value,
    /// Provenance source; omitted ⇒ user_stated.
    pub source: Option<String>,
    /// Retire the record at this time after creation.
    pub retired_at: Option<i64>,
    /// Creation time (Unix seconds).
    pub learned_at: i64,
}

/// One imported-evidence claim admission (B1a).
#[napi(object)]
pub struct NapiAdmitImportedClaimInput {
    /// Registered ingest source id (fail-closed for unknown sources).
    pub source_id: String,
    /// Stable source record id.
    pub source_record_id: String,
    /// Deterministic 32-hex claim id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value.
    pub value: serde_json::Value,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// One blob artifact registration (B8 blob door).
#[napi(object)]
pub struct NapiBlobArtifactInput {
    /// Deterministic 32-hex artifact id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Display name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// View of one appended blob version.
#[napi(object)]
pub struct NapiBlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// 1-based version number.
    pub version: i64,
    /// blake3 content hash (lowercase hex).
    pub content_hash_hex: String,
    /// 32-hex id of the blob.version LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: i64,
}

/// Selector for `forget`: a claim short ref, or `{subjectRef, predicate}`.
#[napi(object)]
pub struct NapiForgetSelector {
    /// Claim short ref (or 32-hex id).
    pub short_ref: Option<String>,
    /// Subject ref (used with `predicate`).
    pub subject_ref: Option<String>,
    /// Predicate (used with `subject_ref`).
    pub predicate: Option<String>,
}

// ── conversions ─────────────────────────────────────────────────────────

fn witness_turn_to_engine(turn: &NapiWitnessTurn) -> BoundaryResult<WitnessTurn> {
    let mut messages = Vec::with_capacity(turn.messages.len());
    for message in &turn.messages {
        let author = WitnessAuthor::parse(&message.author).ok_or_else(|| {
            format!(
                "author must be one of user, companion, system; got {:?}",
                message.author
            )
        })?;
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

#[expect(clippy::cast_possible_truncation, reason = "f64→f32 confidence/salience narrowing at the N-API boundary is intentional")]
fn claim_input_to_engine(input: &NapiClaimInput) -> BoundaryResult<ClaimInput> {
    Ok(ClaimInput {
        id: input.id.clone(),
        predicate: input.predicate.clone(),
        subject_ref: input.subject_ref.clone(),
        value: input.value.clone(),
        confidence: input.confidence as f32,
        source: input.source.clone(),
        world_ref: input.world_ref.clone(),
        scope: input.scope.clone(),
        valid_from: ts_opt_to_engine(input.valid_from, "valid_from")?,
        valid_to: ts_opt_to_engine(input.valid_to, "valid_to")?,
        occurred_at: ts_opt_to_engine(input.occurred_at, "occurred_at")?,
        learned_at: ts_opt_to_engine(input.learned_at, "learned_at")?,
        salience: input.salience.map(|s| s as f32),
    })
}

fn commit_receipt_from_engine(receipt: oneiron::CommitReceipt) -> NapiCommitReceipt {
    NapiCommitReceipt {
        claim_short_id: receipt.claim_short_id,
        approval: receipt.approval,
        superseded_short_id: receipt.superseded_short_id,
        receipt_ref: receipt.receipt_ref,
    }
}

fn entity_view_from_engine(view: oneiron::EntityView) -> BoundaryResult<NapiEntityView> {
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

fn claim_view_from_engine(view: oneiron::ClaimView) -> BoundaryResult<NapiClaimView> {
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
        valid_from: view.valid_from.map(|v| ts_from_engine(v, "valid_from")).transpose()?,
        valid_to: view.valid_to.map(|v| ts_from_engine(v, "valid_to")).transpose()?,
        salience: view.salience.map(f64::from),
        stale: view.stale,
    })
}

fn entity_ref_receipt_from_engine(receipt: oneiron::EntityRefReceipt) -> NapiEntityRefReceipt {
    NapiEntityRefReceipt {
        entity_ref: receipt.entity_ref,
        id_hex: receipt.id_hex,
        receipt_ref: receipt.receipt_ref,
    }
}

#[expect(clippy::cast_possible_truncation, reason = "f64→f32 edge-weight narrowing at the N-API boundary is intentional")]
fn structural_put_to_engine(input: &NapiStructuralPutInput) -> BoundaryResult<StructuralPutInput> {
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

// ── classes ─────────────────────────────────────────────────────────────

/// The vault bridge root: opens a vault and mints actor-scoped handles.
/// Carries NO write verbs itself (W3: construction is not authority).
#[napi]
pub struct VaultBridge {
    vault: Arc<Vault>,
}

#[napi]
impl VaultBridge {
    /// Opens (or creates) a vault at `path` with the device preset.
    #[napi(factory)]
    pub fn open(path: String, dimensions: Option<u32>) -> napi::Result<Self> {
        let mut config = VaultConfig::device();
        if let Some(dimensions) = dimensions {
            config.dimensions = dimensions as usize;
        }
        let vault = Vault::open(&path, config)
            .map_err(|e| boundary_error(format!("failed to open vault: {e}")))?;
        Ok(Self {
            vault: Arc::new(vault),
        })
    }

    /// Binds an actor scope from the pinned key grammar
    /// `"<actor_class>:<entity_ref>"` (`human|agent|system`). Malformed
    /// keys are typed errors — never a defaulted class.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<ActorScopedVault> {
        let (actor, actor_class) =
            parse_actor_key(&self.vault, &actor_key).map_err(|e| facade_error(&e))?;
        Ok(ActorScopedVault {
            vault: Arc::clone(&self.vault),
            actor_hex: actor.to_hex(),
            actor_class: actor_class as u8,
        })
    }
}

/// Actor-scoped facade handle: every memory verb lives here.
#[napi]
pub struct ActorScopedVault {
    vault: Arc<Vault>,
    actor_hex: String,
    actor_class: u8,
}

impl ActorScopedVault {
    fn facade(&self) -> napi::Result<MemoryFacade<'_>> {
        let actor = EntityId::from_hex(&self.actor_hex)
            .map_err(|e| boundary_error(format!("invalid bound actor id: {e}")))?;
        let actor_class = match self.actor_class {
            0 => oneiron::EdgeActorClass::Human,
            1 => oneiron::EdgeActorClass::Agent,
            2 => oneiron::EdgeActorClass::System,
            other => {
                return Err(boundary_error(format!("invalid bound actor class {other}")));
            }
        };
        Ok(self.vault.memory_facade(actor, actor_class))
    }
}

#[napi]
impl ActorScopedVault {
    /// Witnesses one turn (create-or-get CONVERSATION/TURN + gated MESSAGE
    /// puts + edges + BM25 indexing, one atomic batch).
    #[napi]
    pub fn witness(&self, turn: NapiWitnessTurn) -> napi::Result<NapiWitnessReceipt> {
        let engine_turn = witness_turn_to_engine(&turn).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .witness(&engine_turn)
            .map_err(|e| facade_error(&e))?;
        Ok(NapiWitnessReceipt {
            turn_short_id: receipt.turn_short_id,
            message_short_ids: receipt.message_short_ids,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Commits claims, one individually gated write per element; rejected
    /// elements come back with approval `rejected` and persist nothing.
    #[napi]
    pub fn commit(&self, claims: Vec<NapiClaimInput>) -> napi::Result<Vec<NapiCommitReceipt>> {
        let mut engine_claims = Vec::with_capacity(claims.len());
        for claim in &claims {
            engine_claims.push(claim_input_to_engine(claim).map_err(boundary_error)?);
        }
        let receipts = self
            .facade()?
            .commit(&engine_claims)
            .map_err(|e| facade_error(&e))?;
        Ok(receipts.into_iter().map(commit_receipt_from_engine).collect())
    }

    /// Commits one claim with single-cardinality auto-supersede.
    #[napi]
    pub fn claim_upsert(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        let engine_claim = claim_input_to_engine(&claim).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .claim_upsert(&engine_claim)
            .map_err(|e| facade_error(&e))?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: `remember` = claimUpsert with auto-supersede.
    /// NO natural-language parsing on this surface (EF-126 out of chain).
    #[napi]
    pub fn remember(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        self.claim_upsert(claim)
    }

    /// Retracts an active claim by ref.
    #[napi]
    pub fn claim_retract(&self, claim_ref: String) -> napi::Result<NapiCommitReceipt> {
        let receipt = self
            .facade()?
            .claim_retract(&claim_ref)
            .map_err(|e| facade_error(&e))?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: retract-with-receipt by short ref or
    /// `{subjectRef, predicate}` selector (all active matches retract).
    #[napi]
    pub fn forget(&self, selector: NapiForgetSelector) -> napi::Result<Vec<NapiCommitReceipt>> {
        let facade = self.facade()?;
        if let Some(short_ref) = &selector.short_ref {
            let receipt = facade
                .claim_retract(short_ref)
                .map_err(|e| facade_error(&e))?;
            return Ok(vec![commit_receipt_from_engine(receipt)]);
        }
        let (Some(subject_ref), Some(predicate)) = (&selector.subject_ref, &selector.predicate)
        else {
            return Err(boundary_error(
                "forget selector needs shortRef, or subjectRef + predicate".to_owned(),
            ));
        };
        let matches = facade
            .claim_list(&ClaimListFilter {
                subject_ref: Some(subject_ref.clone()),
                predicate: Some(predicate.clone()),
                lifecycle: Some("active".to_owned()),
                limit: 64,
            })
            .map_err(|e| facade_error(&e))?;
        let mut receipts = Vec::with_capacity(matches.len());
        for claim in matches {
            let receipt = facade
                .claim_retract(&claim.claim_ref)
                .map_err(|e| facade_error(&e))?;
            receipts.push(commit_receipt_from_engine(receipt));
        }
        Ok(receipts)
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by `limit`.
    #[napi]
    pub fn claim_list(&self, filter: NapiClaimListFilter) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_list(&ClaimListFilter {
                subject_ref: filter.subject_ref,
                predicate: filter.predicate,
                lifecycle: filter.lifecycle,
                limit: filter.limit as usize,
            })
            .map_err(|e| facade_error(&e))?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Supersession timeline for one claim, oldest first.
    #[napi]
    pub fn claim_history(&self, claim_ref: String) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_history(&claim_ref)
            .map_err(|e| facade_error(&e))?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Deletes an entity under a NAMED reason (`user_delete` |
    /// `user_hard_delete` | `gdpr_delete` | `policy_delete`). There is no
    /// bool-delete on this surface.
    #[napi]
    pub fn safe_delete(&self, entity_ref: String, reason: String) -> napi::Result<NapiDeleteReceipt> {
        let reason = SafeDeleteReason::parse(&reason).ok_or_else(|| {
            boundary_error(format!(
                "unknown delete reason {reason:?}; use user_delete, user_hard_delete, gdpr_delete, or policy_delete"
            ))
        })?;
        let receipt = self
            .facade()?
            .safe_delete(&entity_ref, reason)
            .map_err(|e| facade_error(&e))?;
        Ok(NapiDeleteReceipt {
            existed: receipt.existed,
            reason: receipt.reason,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Gated writes parked for consent.
    #[napi]
    pub fn pending_writes(&self, limit: u32) -> napi::Result<Vec<NapiPendingWrite>> {
        let records = self
            .facade()?
            .pending_writes(limit as usize)
            .map_err(|e| facade_error(&e))?;
        records
            .into_iter()
            .map(|record| {
                Ok(NapiPendingWrite {
                    claim_ref: record.claim_ref,
                    decision_ref: record.decision_ref,
                    created_at: ts_from_engine(record.created_at, "created_at")
                        .map_err(boundary_error)?,
                    reason_codes: record.reason_codes,
                    dreamer_run_id: record.dreamer_run_id,
                })
            })
            .collect()
    }

    /// Gate decision receipts.
    #[napi]
    pub fn receipts(&self, limit: u32) -> napi::Result<Vec<NapiGateReceipt>> {
        let records = self
            .facade()?
            .receipts(limit as usize)
            .map_err(|e| facade_error(&e))?;
        records
            .into_iter()
            .map(|record| {
                Ok(NapiGateReceipt {
                    receipt_ref: record.receipt_ref,
                    outcome: record.outcome,
                    created_at: ts_from_engine(record.created_at, "created_at")
                        .map_err(boundary_error)?,
                    reason_codes: record.reason_codes,
                    actor_class: record.actor_class,
                    actor_ref: record.actor_ref,
                    content_kind: record.content_kind,
                    claim_ref: record.claim_ref,
                })
            })
            .collect()
    }

    /// Hydrates short refs (or hex ids) to full entity views.
    #[napi]
    pub fn hydrate(&self, refs: Vec<String>) -> napi::Result<Vec<NapiEntityView>> {
        let views = self.facade()?.hydrate(&refs).map_err(|e| facade_error(&e))?;
        views
            .into_iter()
            .map(|view| entity_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Reads one entity; `null` when absent.
    #[napi]
    pub fn get_entity(&self, entity_ref: String) -> napi::Result<Option<NapiEntityView>> {
        let view = self
            .facade()?
            .get_entity(&entity_ref)
            .map_err(|e| facade_error(&e))?;
        view.map(|v| entity_view_from_engine(v).map_err(boundary_error))
            .transpose()
    }

    /// Structural put carrying text-index fields and edges (B2).
    #[napi]
    pub fn put_structural(
        &self,
        input: NapiStructuralPutInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = structural_put_to_engine(&input).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .put_structural(&engine_input)
            .map_err(|e| facade_error(&e))?;
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
            .map_err(|e| facade_error(&e))?;
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
            .map_err(|e| facade_error(&e))?;
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
            .map_err(|e| facade_error(&e))?;
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
            .map_err(|e| facade_error(&e))?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Appends one content-addressed blob version. `bytes` is the ONE
    /// deliberate `Buffer` on this surface (binary content, B8).
    #[napi]
    pub fn append_blob_version(
        &self,
        artifact_ref: String,
        bytes: Buffer,
        run_ref: Option<String>,
        occurred_at: i64,
        learned_at: Option<i64>,
    ) -> napi::Result<NapiBlobVersionView> {
        let view = self
            .facade()?
            .append_blob_version(
                &artifact_ref,
                bytes.as_ref(),
                run_ref.as_deref(),
                ts_to_engine(occurred_at, "occurred_at").map_err(boundary_error)?,
                ts_opt_to_engine(learned_at, "learned_at").map_err(boundary_error)?,
            )
            .map_err(|e| facade_error(&e))?;
        Ok(NapiBlobVersionView {
            artifact_ref: view.artifact_ref,
            version: ts_from_engine(view.version, "version").map_err(boundary_error)?,
            content_hash_hex: view.content_hash_hex,
            claim_ref: view.claim_ref,
            created_at: ts_from_engine(view.created_at, "created_at").map_err(boundary_error)?,
        })
    }

    /// Reads one blob version's bytes (hash-verified engine-side).
    #[napi]
    pub fn read_blob_version(
        &self,
        artifact_ref: String,
        version: i64,
    ) -> napi::Result<Option<Buffer>> {
        let bytes = self
            .facade()?
            .read_blob_version(
                &artifact_ref,
                ts_to_engine(version, "version").map_err(boundary_error)?,
            )
            .map_err(|e| facade_error(&e))?;
        Ok(bytes.map(Buffer::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason<T: std::fmt::Debug>(result: BoundaryResult<T>) -> String {
        result.expect_err("expected N-API boundary error")
    }

    /// C3 fitness (ONE-1454 pin 8): no napi surface source references the
    /// replicated-write bypass. The needle is split so this test never
    /// matches itself.
    #[test]
    fn napi_surface_never_references_replicated_write_bypass() {
        let needle = concat!("put_", "replicated");
        for (name, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("types.rs", include_str!("types.rs")),
            ("facade.rs", include_str!("facade.rs")),
        ] {
            assert!(
                !source.contains(needle),
                "{name} must not reference {needle}"
            );
        }
    }

    #[test]
    fn boundary_rejects_negative_timestamps() {
        assert_eq!(ts_to_engine(0, "t").unwrap(), 0);
        assert_eq!(ts_to_engine(i64::MAX, "t").unwrap(), i64::MAX as u64);
        assert_eq!(
            reason(ts_to_engine(-1, "occurred_at")),
            "occurred_at must be a non-negative Unix timestamp"
        );
        assert_eq!(ts_opt_to_engine(None, "t").unwrap(), None);
    }

    #[test]
    fn boundary_rejects_unknown_witness_author() {
        let turn = NapiWitnessTurn {
            conversation_ref: "00".repeat(16),
            turn_ref: None,
            messages: vec![NapiWitnessMessage {
                id: None,
                author: "assistant".to_owned(),
                message_type: "dialogue".to_owned(),
                content: "hi".to_owned(),
                metadata: None,
                is_visible: None,
                order: 0,
            }],
            occurred_at: 100,
        };
        let err = reason(witness_turn_to_engine(&turn));
        assert!(err.contains("user, companion, system"), "got: {err}");
    }
}
