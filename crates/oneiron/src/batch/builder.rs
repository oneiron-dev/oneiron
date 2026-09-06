use super::*;

use std::collections::{HashMap, VecDeque};
use std::str;

use heed::RwTxn;
use rmpv::Value;

use crate::Vault;
use crate::affect::Vad;
use crate::affect::{AffectTriggerValue, affect_trigger_claim_candidate};
use crate::claim::{PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::edge::{EdgeKind, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

/// Builder for atomic multi-database write batches.
#[must_use = "BatchBuilder performs no writes until `.commit()` is called"]
pub struct BatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
}

#[derive(Clone)]
pub(crate) enum BatchOp {
    Put {
        id: EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        /// When `true`, `apply_put` validates the type byte through the
        /// registry-only entity-type gate (which permits the
        /// engine-authored system zone, e.g. REDACTION_AUDIT)
        /// instead of the public entity-type gate. Only
        /// the engine-internal sync rematerialization path sets this so GDPR
        /// receipts survive cross-node sync / replay; every public write keeps
        /// it `false` and stays subject to the maintenance-kind rejection.
        allow_maintenance: bool,
        /// D17 reserved-namespace gate for type-0 (CLAIM) bodies. `false` on
        /// every public path; crate-private owner doors (including
        /// [`TxnBatchBuilder::put_reserved_claim`] and the Vault skill-claim
        /// door) plus sync replay set it.
        allow_reserved_predicate: bool,
        /// Narrow ONE-1736 inlet for an imported SKILL body accepted by the
        /// hub-sync policy door. This changes only the SKILL update validator;
        /// all materialization and index maintenance still run through the
        /// normal Put chokepoint.
        hub_sync_imported: bool,
    },
    ClaimCandidate {
        id: EntityId,
        candidate: Box<ClaimCandidate>,
        envelope: WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        internal_lexical_query_hint: bool,
    },
    ReconcileLexicalQueryHints {
        source: EntityId,
        keep: Vec<EntityId>,
    },
    Vector {
        id: EntityId,
        vector: Vec<f32>,
        pending_embedding_token: Option<Vec<u8>>,
    },
    Edge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
        vad: Vad,
    },
    PublicEdgeWithCreatedAt {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    },
    EdgeWithCreatedAt {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
        provenance: Option<EdgeProvenanceFlags>,
    },
    /// ONE-1113 operational setter: rewrite ONLY the weight bytes (offset
    /// 0..4) of an EXISTING edge value, preserving every other byte —
    /// `created_at`, VAD, and the two provenance hot-flag bytes when the
    /// value is the 26-byte provenanced layout. Exempt from the
    /// reject-and-route gate by construction: "the provenance Claim asserts
    /// the relation, never the weight" (ARCH-0034 #write-protection).
    SetEdgeWeight {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
    },
    /// ONE-1113 operational setter: rewrite ONLY the VAD bytes (offset
    /// 12..24) of an EXISTING semantic edge value, preserving weight,
    /// `created_at`, and the provenance hot-flag bytes when present.
    /// Structural 12-byte edges carry no VAD and are rejected typed.
    SetEdgeVad {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        vad: Vad,
    },
    Text {
        id: EntityId,
        fields: Vec<(String, String)>,
    },
    Phonetic {
        id: EntityId,
        codes: Vec<String>,
    },
    Delete {
        id: EntityId,
    },
    DeleteEdge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
    },
    /// CMT-4 (ONE-1541): the gap-decay lapse of a SET of overdue commitment
    /// instances, as one all-or-nothing local CLAIM write.
    ///
    /// Crate-private and constructed only by
    /// [`BatchBuilder::commitment_gap_decay`]. It is an op rather than a loop
    /// of status verbs because a sweep that lapsed half its selection would
    /// leave the other half owed with its due row already consumed; the
    /// caller-owned transaction is what makes the set atomic.
    CommitmentGapDecay {
        ids: Vec<EntityId>,
        envelope: WriteEnvelope,
        learned_at: u64,
    },
}

/// Builds the sync-replay put op — the SINGLE place where the replicated
/// door's two admit flags are set (`allow_maintenance` AND
/// `allow_reserved_predicate`). Both `put_replicated` flavors
/// ([`BatchBuilder::put_replicated`] / [`TxnBatchBuilder::put_replicated`])
/// delegate here; no other constructor may open both bands at once.
///
/// A trusted door still validates structure: the flags only skip the
/// public-band rejections (`MaintenanceKindNotWritable` /
/// `ReservedPredicate`). `apply_put` still runs the registry type-byte gate,
/// the full D17/D18 CLAIM body validation, and registered maintenance body
/// validation on every typed maintenance kind that defines one. Policy
/// manifests and AccessGrants are authority-bearing control-plane inputs and
/// are not admitted through this unverified replicated door.
///
/// Compiled for sync production replay (`TxnBatchBuilder::put_replicated`) and
/// for the test fixture door (`BatchBuilder::put_replicated`), which is the
/// only reason this constructor exists in a featureless test build.
#[cfg(any(feature = "sync", test))]
pub(super) fn replicated_put_op(
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> BatchOp {
    BatchOp::Put {
        id: *id,
        entity_type,
        occurred,
        learned_at,
        data: data.to_vec(),
        allow_maintenance: true,
        allow_reserved_predicate: true,
        hub_sync_imported: false,
    }
}

pub(super) fn capture_invalid_vector_component(
    validation_error: &mut Option<Error>,
    vector: &[f32],
) {
    if validation_error.is_none()
        && let Some(error) = Error::invalid_vector_component(vector)
    {
        *validation_error = Some(error);
    }
}

impl<'a> BatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
            validation_error: None,
        }
    }

    /// Adds an entity put operation to the batch.
    ///
    /// Validates `entity_type` eagerly via the entity type registry. If validation
    /// fails, the error is stored and surfaced on [`commit()`](Self::commit).
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = self.vault.store.validate_public_entity_type(entity_type)
        {
            self.validation_error = Some(e);
        }
        if self.validation_error.is_none()
            && let Err(e) =
                validate_public_raw_put(entity_type, data, learned_at, RawPutDoor::Public)
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

    /// TEST-ONLY MESSAGE seeding (ONE-1686).
    ///
    /// Unrelated fixtures across the crate need one MESSAGE row to exist —
    /// a VAD annotation target, a conversion source, a citation — without the
    /// conversation, turn, actor and edges a real witness call mints, because
    /// those extra entities are exactly what those fixtures are counting.
    /// Routing them through the witness door would change what they measure;
    /// leaving them on the public raw door would mean the door was never
    /// closed.
    ///
    /// This is NOT a bypass of the envelope law: the op still lands in
    /// `apply_put`, which proves the bytes are the canonical six-axis envelope
    /// on every road, so a fixture can only seed a row a real witness could
    /// also have written. What it skips is the ACTOR-bound ceiling, which a
    /// fixture with no actor has nothing to present to — and it exists only
    /// under `cfg(test)`, so no production caller can reach it at all.
    #[cfg(test)]
    pub(crate) fn put_canonical_message_for_test(
        mut self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_MESSAGE,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        self
    }

    /// Appends an immutable TASK/HabitCheckin child under an existing Habit TASK.
    ///
    /// The check-in is stored as its own TASK entity and linked with a
    /// `ChildOf` edge (`checkin -> habit`). The shared apply path rejects
    /// divergent same-id re-put of check-ins and rejects attachments whose
    /// parent is not a Habit-role TASK.
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
        builder.edge_checked(checkin_id, habit_id, 1.0)
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
    /// engine-internal put for CRDT→LMDB rematerialization. It admits BOTH
    /// engine-authored bands that the public [`put`](Self::put) gate rejects:
    ///
    /// * the engine-authored system zone (e.g. REDACTION_AUDIT), validated
    ///   via the registry-only entity-type gate so GDPR receipts
    ///   survive cross-node sync / replay — public writes still fail with
    ///   `MaintenanceKindNotWritable`, and genuinely unknown bytes still
    ///   fail here with `InvalidEntityType`;
    /// * the reserved `edge.*` predicate namespace (D17) on type-0 CLAIM
    ///   bodies, so `edge.provenance` truth-Claims authored on a remote node
    ///   rematerialize — public writes still fail with `ReservedPredicate`.
    ///
    /// The door bypasses nothing except those two band rejections: `apply_put`
    /// still runs the full D18 structural validation on every type-0 body, so
    /// ungrammatical predicates and malformed bodies fail typed even here.
    ///
    /// FIXTURE DOOR: this non-transactional flavor has NO production caller.
    /// Production replay runs through `TxnBatchBuilder::put_replicated`, which
    /// stays `sync`-gated (`window::forward_rematerialize` and the other sync
    /// doors call THAT flavor). The gate below is exactly its consumer set:
    ///
    /// * `test` — in-crate fixtures seeding replicated-shape rows without a
    ///   live sync stack, including featureless builds, where the op-level
    ///   admit flags it sets are ordinary base machinery;
    /// * `sync` + `test-hooks` — `sync::selector::put_selector_test_federation_grant`,
    ///   the cross-crate test-only seam, which is compiled into the non-test
    ///   library whenever both features are on.
    ///
    /// Keeping the gate this tight is load-bearing: under plain `--features
    /// sync` the method would otherwise be dead code under `-D warnings`.
    #[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
    pub(crate) fn put_replicated(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = self.vault.store.validate_entity_type(entity_type)
        {
            self.validation_error = Some(e);
        }
        if self.validation_error.is_none() && occurred.start > occurred.end {
            self.validation_error = Some(Error::InvalidTimeRange {
                start: occurred.start,
                end: occurred.end,
            });
        }
        self.ops.push(replicated_put_op(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
        ));
        self
    }

    /// Adds a vector write operation to the batch.
    pub fn vector(mut self, id: &EntityId, vector: &[f32]) -> Self {
        capture_invalid_vector_component(&mut self.validation_error, vector);
        self.ops.push(BatchOp::Vector {
            id: *id,
            vector: vector.to_vec(),
            pending_embedding_token: None,
        });
        self
    }

    /// Adds a vector fill for a pending CLAIM embedding marker.
    ///
    /// The vector row is written only if `pending_embedding_token` still
    /// matches the current marker for `id`; stale async fills become no-ops.
    pub fn vector_for_pending_embedding(
        mut self,
        id: &EntityId,
        vector: &[f32],
        pending_embedding_token: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Vector {
            id: *id,
            vector: vector.to_vec(),
            pending_embedding_token: Some(pending_embedding_token.to_vec()),
        });
        self
    }

    fn capture_reserved_edge_kind(&mut self, kind: EdgeKind) {
        self.capture_edge_kind_gate(crate::edge::validate_public_edge_kind(kind));
    }

    /// The CREATION-side gate (ONE-1414): also refuses kinds whose links belong
    /// to an owning engine door. Applied by the edge-minting builders only —
    /// deletes and operational rewrites cannot mint a row, and no door owns
    /// their removal.
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

    /// Adds a graph edge write operation to the batch.
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

    /// Adds a ChildOf edge write operation.
    ///
    /// All `ChildOf` writes are validated atomically during commit/apply to
    /// enforce single-parent tree semantics and reject cycles.
    pub fn edge_checked(self, src: &EntityId, tgt: &EntityId, weight: f32) -> Self {
        self.edge(src, EdgeKind::ChildOf, tgt, weight)
    }

    /// Adds a graph edge with explicit VAD scores to the batch.
    pub fn edge_with_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        vad: Vad,
    ) -> Self {
        self.capture_owned_door_edge_kind(kind);
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            vad,
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

    /// Internal edge upsert carrying every value field.
    ///
    /// Pushes the INTERNAL [`BatchOp::EdgeWithCreatedAt`] — no reserved-kind
    /// gate — so a crate-private door that has already proven what a raw
    /// builder cannot may write a reserved kind. Its callers are
    /// `commitment_lifecycle::link_brief_fulfillment` (CMT-4, ONE-1541: both
    /// ruled `fulfills`/`discharged_by` directions in one transaction, after
    /// proving both endpoint classes) and `ppr/tests.rs`; the sync
    /// forward-remat healing write uses the `TxnBatchBuilder` twin below to
    /// share its mandate-check txn (ARCH-0055).
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

    /// Adds an operational weight rewrite for an EXISTING edge (ONE-1113).
    ///
    /// The batch form of [`crate::Vault::set_edge_weight`] for decay /
    /// retrieval-feedback loops: rewrites ONLY the weight bytes (offset
    /// 0..4) in BOTH directions, preserving `created_at`, VAD, and the
    /// provenance hot-flag bytes verbatim. Never touches provenance Claims —
    /// exempt from the provenanced-edge reject gate by construction. Fails
    /// typed at apply time: [`crate::Error::EdgeNotFound`] when the edge
    /// does not exist (the setter never upserts),
    /// [`crate::Error::InvalidEdgeWeight`] outside the contract \[0, 1\].
    ///
    /// Reserved redirect-shell kinds (`merged_into` / `split_into`) reject
    /// typed at the API boundary ([`crate::Error::ReservedEdgeKind`]): a
    /// weight rewrite IS a topology-effect mutation — PPR drops a
    /// zero-weight shell edge, severing the shell's mass from its
    /// canonical head with no type-76 ledger event — so shell edges stay
    /// writable only through the identity-topology door (ARCH-0055).
    pub fn set_edge_weight(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Self {
        self.capture_reserved_edge_kind(kind);
        self.ops.push(BatchOp::SetEdgeWeight {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
        });
        self
    }

    /// Adds an operational VAD rewrite for an EXISTING semantic edge
    /// (ONE-1113).
    ///
    /// The batch form of [`crate::Vault::set_edge_vad`]: rewrites ONLY the
    /// VAD bytes (offset 12..24) in BOTH directions, preserving weight,
    /// `created_at`, the value length, and the provenance hot-flag bytes
    /// verbatim. Never touches provenance Claims — exempt from the
    /// provenanced-edge reject gate by construction. Fails typed at apply
    /// time: [`crate::Error::EdgeNotFound`] when the edge does not exist,
    /// [`crate::Error::InvalidVad`] on non-finite/out-of-range components,
    /// and a typed rejection on structural 12-byte edges (they carry no
    /// VAD). Reserved redirect-shell kinds (`merged_into` / `split_into`)
    /// reject typed at the API boundary
    /// ([`crate::Error::ReservedEdgeKind`]), same as every other public
    /// edge write (ARCH-0055).
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

    /// Adds a text indexing operation to the batch.
    pub fn text(mut self, id: &EntityId, fields: &[(&str, &str)]) -> Self {
        self.ops.push(BatchOp::Text {
            id: *id,
            fields: fields
                .iter()
                .map(|(f, v)| ((*f).to_owned(), (*v).to_owned()))
                .collect(),
        });
        self
    }

    /// Adds a phonetic indexing operation to the batch.
    pub fn phonetic(mut self, id: &EntityId, codes: &[&str]) -> Self {
        self.ops.push(BatchOp::Phonetic {
            id: *id,
            codes: codes.iter().map(|c| (*c).to_owned()).collect(),
        });
        self
    }

    /// Adds a full entity delete/deindex operation to the batch.
    pub fn delete(mut self, id: &EntityId) -> Self {
        self.ops.push(BatchOp::Delete { id: *id });
        self
    }

    /// Queues the all-or-nothing Open→Lapsed transition of `ids` (CMT-4,
    /// ONE-1541).
    ///
    /// Crate-private: the ONLY caller is
    /// `commitment_lifecycle::lapse_overdue_commitments`, which has already
    /// classified the status-unfiltered overdue candidates and is passing the
    /// Open ones. `learned_at` is the sweep instant, which is the ONE place a
    /// lifecycle time comes from the sweep rather than from a terminal claim
    /// header: this write IS the transition.
    ///
    /// Duplicate ids are collapsed in input order so the gate preflight and
    /// the apply arm agree on exactly one decision per instance.
    pub(crate) fn commitment_gap_decay(
        mut self,
        ids: &[EntityId],
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Self {
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        let ids: Vec<EntityId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
        self.ops.push(BatchOp::CommitmentGapDecay {
            ids,
            envelope: envelope.clone(),
            learned_at,
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

    /// Commits all queued operations atomically in a single LMDB write transaction.
    ///
    /// Gate decisions for local claim writes are appended by the same
    /// transaction, so a later validation failure cannot leave an orphan
    /// receipt behind.
    ///
    /// Returns any validation error captured during builder calls before
    /// opening the LMDB write transaction, avoiding unnecessary I/O on bad
    /// input.
    pub fn commit(self) -> Result<()> {
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
        let mut wtxn = self.vault.store.env.write_txn()?;
        let mut staged_gate_decisions = Vec::new();
        let mut preflight_gate_decision_ids = HashMap::new();
        if let Err(err) = preflight_gate_decisions_in_txn(
            &self.vault.store,
            &self.ops,
            &mut wtxn,
            &mut staged_gate_decisions,
            &mut preflight_gate_decision_ids,
        ) {
            // A gate rejection is itself an intentional ledger event. Keep
            // that denial receipt, matching the historical gate semantics;
            // later phase-2 failures drop this transaction and its receipt.
            wtxn.commit()?;
            for decision in staged_gate_decisions {
                decision.record_metrics();
            }
            return Err(err);
        }

        // ONE-1741: batch deletes no longer pre-scan for scan-verdict
        // relocation. The content-hash index row is maintained by
        // `deindex_entity` inside `apply_ops`, and verdicts anchor to the
        // content bytes rather than to any departing holder.
        apply_ops_with_gate_mode(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            &mut wtxn,
            self.ops,
            text_index_trusted,
            ApplyOpsGateMode::new(false, true)
                .with_preflight_gate_decision_ids(preflight_gate_decision_ids),
        )?;
        wtxn.commit()?;
        for decision in staged_gate_decisions {
            decision.record_metrics();
        }
        Ok(())
    }
}

/// Evaluates local claim gates and appends their decisions to `wtxn`.
///
/// The caller owns committing or aborting the transaction.
pub(super) fn preflight_gate_decisions_in_txn(
    store: &Store,
    ops: &[BatchOp],
    wtxn: &mut RwTxn<'_>,
    staged_decisions: &mut Vec<crate::gate::RecordedClaimGateDecision>,
    preflight_gate_decision_ids: &mut HashMap<
        EntityId,
        VecDeque<Option<crate::store::GateDecisionId>>,
    >,
) -> Result<()> {
    if !contains_local_claim_put(ops) {
        return Ok(());
    }

    // #493 now owns this caller-provided transaction: gate receipts remain
    // atomic with phase-2 apply and metrics are emitted only after commit.
    // Run the entity write door's verdict in that SAME transaction before any
    // gate receipt is appended, so a write `apply_put` will reject cannot leave
    // a decision behind for a turn that never materializes.
    // CMT-4 (ONE-1541): the lapse op's post-transition bodies are derived HERE,
    // before any gate receipt is appended, for the same reason the overlay door
    // below runs first — a set the apply arm will refuse outright must not
    // leave a decision behind for a transition that never materializes. One
    // queue entry per op, consumed in order by the gating loop.
    let mut gap_decay_lapses = VecDeque::new();
    for op in ops {
        match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => {
                // Gate preflight is an ordinary-write path; a promotion replay
                // carries no claim put and never reaches it.
                reject_overlay_member_base_write(store, id, BaseWriteOrigin::Ordinary)?;
            }
            BatchOp::CommitmentGapDecay { ids, .. } => {
                for id in ids {
                    reject_overlay_member_base_write(store, id, BaseWriteOrigin::Ordinary)?;
                }
                gap_decay_lapses.push_back(crate::commitment::pending_commitment_lapses_in_txn(
                    store, &*wtxn, ids,
                )?);
            }
            _ => continue,
        }
    }
    let policy = crate::gate::resolve_policy_manifest(store, &*wtxn)?;
    for op in ops {
        // The gap-decay op gates ONE decision per selected instance rather
        // than one per op, so it runs its own loop and never collapses the
        // selected set into a single receipt.
        if let BatchOp::CommitmentGapDecay { envelope, .. } = op {
            let lapses = gap_decay_lapses
                .pop_front()
                .ok_or(Error::InvariantViolation(
                    "commitment gap decay preflight lost its derived bodies",
                ))?;
            for lapse in lapses {
                let mut recorded_decision = None;
                let lapse_id = lapse.id;
                let body = lapse.candidate.into_claim_body(envelope);
                let result = crate::gate::check_claim_policy_for_write_with_record(
                    store,
                    wtxn,
                    &lapse_id,
                    crate::gate::ClaimGateWrite {
                        body: &body,
                        envelope: Some(envelope),
                        // Ordinary batch preflight: no checker is injected on
                        // this door, so an Auto verdict here is the engine's
                        // own and nothing consults a host.
                        auto_checker: None,
                        defer_metrics_until_commit: true,
                    },
                    &policy,
                    crate::gate::GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: false,
                        can_resolve_pending_consent: true,
                        include_source_in_gate_input: false,
                    },
                    &mut recorded_decision,
                );
                stage_preflight_decision(
                    store,
                    wtxn,
                    &lapse_id,
                    recorded_decision,
                    result,
                    staged_decisions,
                    preflight_gate_decision_ids,
                )?;
            }
            continue;
        }
        let mut recorded_decision = None;
        let eligible = match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && !*allow_reserved_predicate =>
            {
                let result =
                    crate::claim::validate_claim_body_and_decode(data, false).and_then(|body| {
                        crate::gate::check_claim_policy_for_write_with_record(
                            store,
                            wtxn,
                            id,
                            crate::gate::ClaimGateWrite {
                                body: &body,
                                envelope: None,
                                // Envelope-less local claim put: no Dreamer
                                // authorship to consult about.
                                auto_checker: None,
                                defer_metrics_until_commit: true,
                            },
                            &policy,
                            crate::gate::GateWriteMode {
                                record_decision: true,
                                persist_pending_consent: false,
                                resolve_pending: false,
                                can_resolve_pending_consent: true,
                                include_source_in_gate_input: false,
                            },
                            &mut recorded_decision,
                        )
                    });
                Some((id, result))
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint,
                ..
            } if !*internal_lexical_query_hint => {
                let body = (**candidate).clone().into_claim_body(envelope);
                let result = crate::gate::check_claim_policy_for_write_with_record(
                    store,
                    wtxn,
                    id,
                    crate::gate::ClaimGateWrite {
                        body: &body,
                        envelope: Some(envelope),
                        // Ordinary batch preflight: no checker is injected on
                        // this door, so an Auto verdict here is the engine's
                        // own and nothing consults a host.
                        auto_checker: None,
                        defer_metrics_until_commit: true,
                    },
                    &policy,
                    crate::gate::GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: false,
                        can_resolve_pending_consent: true,
                        include_source_in_gate_input: false,
                    },
                    &mut recorded_decision,
                );
                Some((id, result))
            }
            _ => None,
        };
        let Some((eligible_id, result)) = eligible else {
            continue;
        };
        stage_preflight_decision(
            store,
            wtxn,
            eligible_id,
            recorded_decision,
            result,
            staged_decisions,
            preflight_gate_decision_ids,
        )?;
    }

    Ok(())
}

/// Books ONE preflight-eligible write's gate decision and, on a refusal,
/// preserves exactly its denial receipt while discarding the transaction's
/// earlier allow receipts.
///
/// Shared by both preflight shapes — one decision per Put/ClaimCandidate op,
/// and one per instance inside a `CommitmentGapDecay` op — so a lapse denial
/// survives rollback through the same path every other local CLAIM write uses.
fn stage_preflight_decision(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    eligible_id: &EntityId,
    recorded_decision: Option<crate::gate::RecordedClaimGateDecision>,
    result: Result<()>,
    staged_decisions: &mut Vec<crate::gate::RecordedClaimGateDecision>,
    preflight_gate_decision_ids: &mut HashMap<
        EntityId,
        VecDeque<Option<crate::store::GateDecisionId>>,
    >,
) -> Result<()> {
    let decision_id = recorded_decision
        .as_ref()
        .map(crate::gate::RecordedClaimGateDecision::decision_id);
    if let Some(decision) = recorded_decision {
        staged_decisions.push(decision);
    }
    // Keep one FIFO slot for every preflight-eligible operation. A None
    // slot prevents an earlier non-receipt claim sharing this id from
    // consuming a later claim's receipt identity.
    preflight_gate_decision_ids
        .entry(*eligible_id)
        .or_default()
        .push_back(decision_id);
    if let Err(err) = result {
        let preserved_denial_id = staged_decisions
            .last()
            .filter(|decision| decision.outcome() != "allow")
            .map(crate::gate::RecordedClaimGateDecision::decision_id);
        for decision in staged_decisions.iter() {
            if Some(decision.decision_id()) != preserved_denial_id {
                store.delete_gate_decision_in_txn(wtxn, decision.decision_id())?;
            }
        }
        staged_decisions.retain(|decision| Some(decision.decision_id()) == preserved_denial_id);
        return Err(err);
    }
    Ok(())
}
