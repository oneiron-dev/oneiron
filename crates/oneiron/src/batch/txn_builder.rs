use super::*;

use std::str;

use heed::RwTxn;
use rmpv::Value;

use crate::Vault;
use crate::affect::Vad;
use crate::affect::{AffectTriggerValue, affect_trigger_claim_candidate};
use crate::claim::{ClaimApprovalStatus, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::AutoChecker;
use crate::off_record::PromoteReplayGrant;
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

/// Builder for batch writes into an externally-owned LMDB write transaction.
///
/// Created by [`Vault::batch_in`]. Writes are applied via [`apply()`](TxnBatchBuilder::apply)
/// without committing — the caller controls transaction commit via `with_write_txn`.
#[must_use = "TxnBatchBuilder performs no writes until `.apply()` is called"]
pub struct TxnBatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
    origin: BaseWriteOrigin<'a>,
}

impl<'a> TxnBatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
            validation_error: None,
            origin: BaseWriteOrigin::Ordinary,
        }
    }

    /// The off-record promotion entry (ARCH-0052 D4, ONE-1730).
    ///
    /// Takes an already-built replay program rather than growing verb methods:
    /// the ops come from the typed journal verbatim (only their edge arm is
    /// re-shaped to carry the journaled `created_at`), so re-deriving them
    /// through builder verbs would be a chance to drift from what the room
    /// actually staged.
    ///
    /// This is the ONLY constructor that carries a non-`Ordinary` origin, and
    /// it demands the capability itself: a [`PromoteReplayGrant`] can only be
    /// minted inside `off_record::promote`, out of the closure that promote
    /// transaction is replaying. Crate code without a grant cannot reach this
    /// constructor at all, and a grant cannot answer for any other session's
    /// overlay ids.
    pub(crate) fn promotion_replay(
        vault: &'a Vault,
        ops: Vec<BatchOp>,
        grant: &'a PromoteReplayGrant,
    ) -> Self {
        Self {
            vault,
            ops,
            validation_error: None,
            origin: BaseWriteOrigin::PromoteReplay(grant),
        }
    }

    /// Adds an entity put operation.
    ///
    /// This is a PUBLIC door and is held to the public checks, the same ones
    /// [`BatchBuilder::put`] applies. It used to pass the INTERNAL door, which
    /// meant the one check that door gates — the born-expired TASK deadline —
    /// was skipped, and a body `Vault::batch()` refuses persisted through
    /// `Vault::batch_in()`. Two public doors at the same API tier disagreeing
    /// about the same body is not a seam, it is a hole.
    ///
    /// Crate callers that legitimately write a TASK whose deadline has already
    /// passed — settling an expired task is the whole example — say so by name
    /// through the crate-private internal put instead.
    pub fn put(
        self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.put_through(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            RawPutDoor::Public,
        )
    }

    /// [`Self::put`] through the INTERNAL door: everything the public door
    /// checks except the born-expired TASK deadline.
    ///
    /// The expiry lane's whole job is to write to a task whose deadline has
    /// passed. Refusing that would make settling an expired task impossible,
    /// so the lane names its exemption here rather than the door quietly
    /// granting it to every caller.
    pub(crate) fn put_internal(
        self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.put_through(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            RawPutDoor::Internal,
        )
    }

    /// The ONE-1686 witness MESSAGE put: the only door that stages an
    /// `ENTITY_TYPE_MESSAGE` row.
    ///
    /// It takes the ceiling door's own [`WitnessMessageAuthorization`] and
    /// writes the bytes THAT value carries — never a separately supplied body —
    /// so the axes the door authorized and the bytes that land cannot diverge,
    /// and nothing between the check and the put can substitute an envelope.
    /// Holding the authorization is the permission: its only constructor is
    /// [`crate::gate::check_witness_message_ceiling`], which runs inside this
    /// same write transaction against the same policy snapshot.
    pub(crate) fn put_witness_message(
        self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        authorization: &crate::gate::WitnessMessageAuthorization<'_>,
    ) -> Self {
        let body = authorization.body();
        self.put_through(
            id,
            crate::registry::ENTITY_TYPE_MESSAGE,
            occurred,
            learned_at,
            body,
            RawPutDoor::WitnessMessage,
        )
    }

    fn put_through(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
        door: RawPutDoor,
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = validate_public_raw_put(entity_type, data, learned_at, door)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        self
    }

    /// Transactional variant of [`BatchBuilder::put_habit_checkin`].
    pub fn put_habit_checkin(
        self,
        habit_id: &EntityId,
        checkin_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        let mut builder = self.put(checkin_id, ENTITY_TYPE_TASK, occurred, learned_at, data);
        if builder.validation_error.is_none()
            && let Err(e) = validate_habit_checkin_body(data)
        {
            builder.validation_error = Some(e);
        }
        builder.edge(checkin_id, EdgeKind::ChildOf, habit_id, 1.0)
    }

    /// Adds a claim candidate write stamped by a [`WriteEnvelope`].
    pub fn claim_candidate(
        mut self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = reject_family_owned_candidate(&candidate)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::ClaimCandidate {
            id: *id,
            candidate: Box::new(candidate),
            envelope: envelope.clone(),
            occurred,
            learned_at,
            internal_lexical_query_hint: false,
        });
        self.ops.push(BatchOp::ReconcileLexicalQueryHints {
            source: *id,
            keep: Vec::new(),
        });
        self
    }

    /// Adds a claim candidate and capped prospective-query lexical hints.
    pub fn claim_candidate_with_lexical_hints(
        mut self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        hints: &[&str],
    ) -> Self {
        push_claim_candidate_with_lexical_hints(
            &mut self.ops,
            &mut self.validation_error,
            id,
            candidate,
            envelope,
            occurred,
            learned_at,
            hints,
        );
        self
    }

    /// Adds an `affect.trigger` claim candidate.
    pub fn affect_trigger_claim(
        self,
        id: &EntityId,
        value: AffectTriggerValue,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            affect_trigger_claim_candidate(value),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Adds a `conflict.open` claim candidate.
    #[expect(
        clippy::too_many_arguments,
        reason = "conflict helper mirrors claim_candidate writer context"
    )]
    pub fn conflict_open_claim(
        self,
        id: &EntityId,
        subject: EntityId,
        value: Value,
        confidence: f32,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            conflict_claim_candidate(PREDICATE_CONFLICT_OPEN, subject, value, confidence),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Adds a `conflict.resolved` claim candidate.
    #[expect(
        clippy::too_many_arguments,
        reason = "conflict helper mirrors claim_candidate writer context"
    )]
    pub fn conflict_resolved_claim(
        self,
        id: &EntityId,
        subject: EntityId,
        value: Value,
        confidence: f32,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            conflict_claim_candidate(PREDICATE_CONFLICT_RESOLVED, subject, value, confidence),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for Observer B's CRDT→LMDB rematerialization. It
    /// admits BOTH engine-authored bands that the public [`put`](Self::put)
    /// gate rejects:
    ///
    /// * the engine-authored system zone (e.g. REDACTION_AUDIT), validated
    ///   via the registry-only entity-type gate in `apply_ops`
    ///   so GDPR receipts survive sync — public writes still fail with
    ///   `MaintenanceKindNotWritable`, genuinely unknown bytes still fail
    ///   with `InvalidEntityType`;
    /// * the reserved `edge.*` predicate namespace (D17) on type-0 CLAIM
    ///   bodies, so `edge.provenance` truth-Claims authored on a remote node
    ///   rematerialize — public writes still fail with `ReservedPredicate`.
    ///
    /// The door bypasses nothing except those two band rejections: `apply_put`
    /// still runs the full D18 structural validation on every type-0 body, so
    /// ungrammatical predicates and malformed bodies fail typed even here.
    /// Used ONLY by `bridge::materialize_entity_blob_in_txn`.
    #[cfg(feature = "sync")]
    pub(crate) fn put_replicated(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(replicated_put_op(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
        ));
        self
    }

    /// Adds a type-0 (CLAIM) put whose predicate may live in the reserved
    /// `edge.*` namespace (D17 reserved-namespace door).
    ///
    /// This is the ONLY path that may write `edge.*` predicates; it exists
    /// for the engine's provenance unit (`edge.provenance` Claims). Full
    /// structural body validation (D18) still applies at apply time — the
    /// door bypasses nothing except the reserved-namespace rejection.
    pub(crate) fn put_reserved_claim(
        mut self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        });
        self
    }

    /// Adds the actor-attributed NOTE put behind
    /// [`Memory::author_take`](crate::memory::Memory::author_take)
    /// — the only door that may write `ENTITY_TYPE_NOTE`, since the raw put
    /// rejects the type outright.
    ///
    /// The typed door earns that bypass rather than inheriting it: it decodes
    /// the body under the pinned NOTE ABI and requires the stored
    /// `author_ref` to be `author`, the actor the caller has already verified
    /// against the store in this transaction. What the raw door cannot do is
    /// name that actor; this one is handed it.
    pub(crate) fn put_authored_note(
        mut self,
        id: &EntityId,
        author: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = validate_authored_note_body(author, data)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_NOTE,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        self
    }

    fn capture_reserved_edge_kind(&mut self, kind: EdgeKind) {
        self.capture_edge_kind_gate(crate::edge::validate_public_edge_kind(kind));
    }

    /// The CREATION-side gate (ONE-1414), mirroring
    /// [`BatchBuilder::capture_owned_door_edge_kind`].
    fn capture_owned_door_edge_kind(&mut self, kind: EdgeKind) {
        self.capture_edge_kind_gate(crate::edge::validate_public_edge_creation_kind(kind));
    }

    fn capture_edge_kind_gate(&mut self, gate: Result<()>) {
        if self.validation_error.is_none()
            && let Err(e) = gate
        {
            self.validation_error = Some(e);
        }
    }

    /// Adds a graph edge write operation.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.capture_owned_door_edge_kind(kind);
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a public graph edge write with an explicit `created_at` timestamp.
    pub fn edge_with_created_at(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
    ) -> Self {
        self.capture_owned_door_edge_kind(kind);
        self.ops.push(BatchOp::PublicEdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a public graph edge write with explicit `created_at` and VAD scores.
    pub fn edge_with_created_at_and_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    ) -> Self {
        self.capture_owned_door_edge_kind(kind);
        self.ops.push(BatchOp::PublicEdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad,
        });
        self
    }

    /// Internal edge upsert carrying every value field, mirroring
    /// [`BatchBuilder::edge_with_value_fields`] for callers composing writes in
    /// an externally-owned transaction (the ARCH-0055 forward-remat shell-edge
    /// healing write shares the mandate-check txn). Pushes the INTERNAL
    /// [`BatchOp::EdgeWithCreatedAt`] — no reserved-kind gate, because the sole
    /// caller has already proven the ledger mandates this exact shell edge.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn edge_with_value_fields(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        value: EdgeValueFields,
    ) -> Self {
        self.ops.push(BatchOp::EdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight: value.weight,
            created_at: value.created_at,
            vad: value.vad,
            provenance: value.provenance,
        });
        self
    }

    /// Adds an operational VAD rewrite for an EXISTING semantic edge.
    ///
    /// Mirrors [`BatchBuilder::set_edge_vad`] for callers composing writes in
    /// an externally-owned transaction, including its reserved-kind
    /// rejection ([`crate::Error::ReservedEdgeKind`], ARCH-0055).
    pub fn set_edge_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        vad: Vad,
    ) -> Self {
        self.capture_reserved_edge_kind(kind);
        self.ops.push(BatchOp::SetEdgeVad {
            src: *src,
            kind,
            tgt: *tgt,
            vad,
        });
        self
    }

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
        self.capture_reserved_edge_kind(kind);
        self.ops.push(BatchOp::DeleteEdge {
            src: *src,
            kind,
            tgt: *tgt,
        });
        self
    }

    /// Applies all queued operations to the given write transaction without committing.
    ///
    /// Note: operations are staged eagerly into `wtxn`. If this returns an
    /// error, earlier writes may already be present in the transaction, so
    /// callers must abort the transaction (drop without committing) to discard
    /// it.
    pub fn apply(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(false, true))
    }

    /// Applies queued promotion operations while recording their gate decisions
    /// in the caller's transaction.
    pub(crate) fn apply_recording_gate_decisions(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        self.apply_recording_gate_decisions_inner(wtxn, None)
    }

    /// [`Self::apply_recording_gate_decisions`] with the host's auto checker
    /// injected for this batch's claim candidates (ONE-1296).
    ///
    /// `None` is byte-identical to the method above — same single apply pass,
    /// same receipts, same metrics — so this terminal costs a caller that has
    /// no checker exactly nothing.
    pub(crate) fn apply_recording_gate_decisions_with_checker(
        self,
        wtxn: &mut RwTxn<'_>,
        checker: Option<&dyn AutoChecker>,
    ) -> Result<()> {
        self.apply_recording_gate_decisions_inner(wtxn, checker)
    }

    fn apply_recording_gate_decisions_inner(
        self,
        wtxn: &mut RwTxn<'_>,
        checker: Option<&dyn AutoChecker>,
    ) -> Result<()> {
        // A batch that already failed builder validation never reaches a host
        // checker: the builder's own refusal is the answer, and asking anyway
        // would spend a host call on a write that cannot happen.
        if let Some(checker) = checker
            && self.validation_error.is_none()
        {
            consult_auto_checker_for_claim_candidates(self.vault, &self.ops, wtxn, checker)?;
        }
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(true, true))
    }

    fn apply_with_gate_mode(self, wtxn: &mut RwTxn<'_>, gate_mode: ApplyOpsGateMode) -> Result<()> {
        if let Some(err) = self.validation_error {
            return Err(err);
        }
        let text_index_trusted = if contains_text_op(&self.ops) {
            self.vault.ensure_text_index_trusted()?;
            true
        } else {
            self.vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire)
        };
        apply_ops_with_origin(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            wtxn,
            self.ops,
            text_index_trusted,
            gate_mode,
            self.origin,
        )
    }
}

/// Runs the claim write door over this batch's candidate ops with the host's
/// auto checker injected, BEFORE the ordinary apply pass runs the same door
/// without one.
///
/// The consult pass records nothing and persists nothing: its only job is to
/// let the checker narrow an otherwise-Auto verdict, and a narrowed verdict
/// surfaces as the door's ordinary typed refusal — which aborts the caller's
/// transaction before any claim-side write lands. Splitting the consult out
/// this way is what keeps the checker to EXACTLY ONE call per candidate: the
/// apply pass below re-evaluates the ordinary decision with no checker
/// injected, so it cannot ask a second time.
///
/// A manifest that names no checker returns before the door is opened at all,
/// so an unset knob adds no work and no receipts to this path.
fn consult_auto_checker_for_claim_candidates(
    vault: &Vault,
    ops: &[BatchOp],
    wtxn: &mut RwTxn<'_>,
    checker: &dyn AutoChecker,
) -> Result<()> {
    let mut candidates = ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint: false,
                ..
            } => Some((id, candidate, envelope)),
            _ => None,
        })
        .peekable();
    if candidates.peek().is_none() {
        return Ok(());
    }

    let policy = crate::gate::resolve_policy_manifest(&vault.store, &*wtxn)?;
    if policy.auto_checker().is_none() {
        return Ok(());
    }

    for (id, candidate, envelope) in candidates {
        let body = (**candidate).clone().into_claim_body(envelope);
        // Only a candidate REQUESTING Auto is the checker's business. One
        // already asking for Proposed is not asking to self-approve, so there
        // is nothing for a hold to narrow here — and asking anyway would spend
        // a host call on an answer this pass could not act on.
        if body.approval != ClaimApprovalStatus::Auto {
            continue;
        }
        let mut recorded_decision = None;
        crate::gate::check_claim_policy_for_write_with_record(
            &vault.store,
            wtxn,
            id,
            crate::gate::ClaimGateWrite {
                body: &body,
                envelope: Some(envelope),
                auto_checker: Some(checker),
                defer_metrics_until_commit: true,
            },
            &policy,
            crate::gate::GateWriteMode {
                record_decision: false,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
            &mut recorded_decision,
        )?;
    }
    Ok(())
}
