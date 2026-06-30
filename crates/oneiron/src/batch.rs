use std::collections::{HashMap, HashSet, VecDeque};
use std::str;

#[path = "export.rs"]
pub mod export;
#[path = "secret_scan.rs"]
pub(crate) mod secret_scan;

use heed::RwTxn;
use xxhash_rust::{xxh3::xxh3_128, xxh32::xxh32};

use crate::Vault;
use crate::claim::ClaimSubject;
use crate::error::{Error, Result};
use crate::limits::{ERR_CHILD_OF_CYCLE_CHECK, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    ClaimCandidate, DecodedEdgeValue, EDGE_KEY_LEN, EDGE_VALUE_SEMANTIC_LEN,
    EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN, ENTITY_ID_LEN, EdgeKind,
    EdgeProvenanceFlags, EntityId, TimeRange, Vad, WriteEnvelope, decode_edge_value_for_kind,
    encode_edge_value, validate_edge_weight,
};

pub(crate) const ENTITY_TYPE_OFFSET: usize = 0;
pub(crate) const ENTITY_OCCURRED_START_OFFSET: usize = 1;
pub(crate) const ENTITY_OCCURRED_END_OFFSET: usize = 9;
pub(crate) const ENTITY_LEARNED_AT_OFFSET: usize = 17;
pub(crate) const ENTITY_BODY_OFFSET: usize = 25;
pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;
pub(crate) const SHORT_ID_COUNTER_LEN: usize = 8;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;
const ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE: &str = "raw claim put requires WriteEnvelope";

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) struct EdgeValueFields {
    pub(crate) weight: f32,
    pub(crate) created_at: u64,
    pub(crate) vad: Vad,
    pub(crate) provenance: Option<EdgeProvenanceFlags>,
}

impl EdgeValueFields {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn from_decoded(decoded: DecodedEdgeValue) -> Self {
        Self {
            weight: decoded.weight,
            created_at: decoded.created_at,
            vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
            provenance: decoded.provenance,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EntityMetadataHeader {
    pub(crate) entity_type: u8,
    pub(crate) occurred_start: u64,
    pub(crate) occurred_end: u64,
    pub(crate) learned_at: u64,
}

impl EntityMetadataHeader {
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return None;
        }

        let entity_type = raw[ENTITY_TYPE_OFFSET];
        let occurred_start = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_START_OFFSET..ENTITY_OCCURRED_END_OFFSET]
                .try_into()
                .ok()?,
        );
        let occurred_end = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_END_OFFSET..ENTITY_LEARNED_AT_OFFSET]
                .try_into()
                .ok()?,
        );
        let learned_at = u64::from_be_bytes(
            raw[ENTITY_LEARNED_AT_OFFSET..ENTITY_BODY_OFFSET]
                .try_into()
                .ok()?,
        );

        Some(Self {
            entity_type,
            occurred_start,
            occurred_end,
            learned_at,
        })
    }
}

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
        /// engine-authored maintenance band, e.g. REDACTION_AUDIT = 120)
        /// instead of the public entity-type gate. Only
        /// the engine-internal sync rematerialization path sets this so GDPR
        /// receipts survive cross-node sync / replay; every public write keeps
        /// it `false` and stays subject to the maintenance-kind rejection.
        allow_maintenance: bool,
        /// D17 reserved-namespace gate for type-0 (CLAIM) bodies. `false` on
        /// every public path; only the `pub(crate)` provenance door
        /// ([`TxnBatchBuilder::put_reserved_claim`]) and the sync-replay door
        /// (`put_replicated` on both builders, via `replicated_put_op`) set
        /// it.
        allow_reserved_predicate: bool,
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
/// manifests are owner-policy inputs and are not admitted through this
/// unverified replicated door.
#[cfg(feature = "sync")]
fn replicated_put_op(
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
            && let Err(e) = validate_public_raw_put(entity_type, data)
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
        });
        self
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

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for CRDT→LMDB rematerialization. It admits BOTH
    /// engine-authored bands that the public [`put`](Self::put) gate rejects:
    ///
    /// * the maintenance type-byte band (REDACTION_AUDIT = 120), validated
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
    /// Used ONLY by `window::forward_rematerialize`.
    #[cfg(feature = "sync")]
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

    /// Adds a graph edge write operation to the batch.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
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
    pub fn set_edge_weight(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Self {
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
    /// VAD).
    pub fn set_edge_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        vad: Vad,
    ) -> Self {
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

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
        self.ops.push(BatchOp::DeleteEdge {
            src: *src,
            kind,
            tgt: *tgt,
        });
        self
    }

    /// Commits all queued operations atomically in a single LMDB write transaction.
    ///
    /// Returns any validation error captured during `put()` before opening
    /// the LMDB write transaction, avoiding unnecessary I/O on bad input.
    pub fn commit(self) -> Result<()> {
        if let Some(err) = self.validation_error {
            return Err(err);
        }
        if contains_text_op(&self.ops) {
            self.vault.ensure_text_index_trusted()?;
        }
        let mut wtxn = self.vault.store.env.write_txn()?;

        apply_ops(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            &mut wtxn,
            self.ops,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}

/// Builder for batch writes into an externally-owned LMDB write transaction.
///
/// Created by [`Vault::batch_in`]. Writes are applied via [`apply()`](TxnBatchBuilder::apply)
/// without committing — the caller controls transaction commit via `with_write_txn`.
#[must_use = "TxnBatchBuilder performs no writes until `.apply()` is called"]
pub struct TxnBatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
}

impl<'a> TxnBatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
            validation_error: None,
        }
    }

    /// Adds an entity put operation.
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = validate_public_raw_put(entity_type, data)
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
        });
        self
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

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for Observer B's CRDT→LMDB rematerialization. It
    /// admits BOTH engine-authored bands that the public [`put`](Self::put)
    /// gate rejects:
    ///
    /// * the maintenance type-byte band (REDACTION_AUDIT = 120), validated
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
            entity_type: crate::types::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: true,
        });
        self
    }

    /// Adds a graph edge write operation.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
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

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
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
        if let Some(err) = self.validation_error {
            return Err(err);
        }
        if contains_text_op(&self.ops) {
            self.vault.ensure_text_index_trusted()?;
        }
        apply_ops(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            wtxn,
            self.ops,
        )
    }
}

fn validate_public_raw_put(entity_type: u8, data: &[u8]) -> Result<()> {
    if entity_type != crate::types::ENTITY_TYPE_CLAIM {
        return Ok(());
    }

    let body = crate::claim::validate_claim_body_and_decode(data, false)?;
    if body.source.is_some() && !is_legacy_raw_claim_compatibility_body(&body) {
        return Err(Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE));
    }
    Ok(())
}

fn is_legacy_raw_claim_compatibility_body(body: &crate::claim::ClaimBody) -> bool {
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
fn push_claim_candidate_with_lexical_hints(
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

fn lexical_query_hint_claim_id(source_claim_id: &EntityId, hint: &str) -> Result<EntityId> {
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

fn lexical_query_hint_for_replayed_put(
    id: &EntityId,
    entity_type: u8,
    replicated: bool,
    data: &[u8],
) -> Result<Option<(EntityId, String)>> {
    if !replicated
        || entity_type != crate::types::ENTITY_TYPE_CLAIM
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

fn lexical_query_hint_target_is_ready(
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

fn materialize_lexical_query_hint_text_if_target_ready(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    hint_id: EntityId,
    target: &EntityId,
    query_hint: String,
    text_manifest_checked: &mut bool,
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
        if !*text_manifest_checked {
            crate::vault::ensure_text_index_manifest_matches_wtxn(store, wtxn, analyzer)?;
            *text_manifest_checked = true;
        }
        crate::bm25::index_text(
            store,
            wtxn,
            analyzer,
            &hint_id,
            &[("query_hint".to_owned(), query_hint)],
        )?;
    }
    Ok(true)
}

fn materialize_lexical_query_hints_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    target: &EntityId,
    text_manifest_checked: &mut bool,
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
            analyzer,
            hint_id,
            target,
            hint.query,
            text_manifest_checked,
        )? {
            had_graph_mutation = true;
        }
    }
    Ok(had_graph_mutation)
}

/// Applies a list of batch operations to an LMDB write transaction.
pub(crate) fn apply_ops(
    store: &Store,
    config: &crate::types::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<()> {
    secret_scan::scan_batch_ops(&ops)?;
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;
    let mut text_manifest_checked = false;
    let later_text_coverage_by_op = text_coverage_after_op(&ops);
    let write_policy = if contains_local_claim_put(&ops) {
        Some(crate::gate::resolve_policy_manifest(store, &*wtxn)?)
    } else {
        None
    };
    // Legacy (pre-symmetric-migration) graphs answer a vector refresh with a
    // full snapshot rebuild. Batched vector updates coalesce that into at
    // most ONE rebuild per transaction: once pending, per-op graph mutations
    // are skipped (the end-of-batch rebuild re-derives the graph from the
    // `vectors` DB) and the rebuild runs after the op loop (ONE-324 AC11).
    let mut pending_hnsw_rebuild = false;
    let mut pending_embedding_tokens_written = HashMap::<EntityId, Vec<u8>>::new();

    for (op_index, op) in ops.into_iter().enumerate() {
        match op {
            BatchOp::Put {
                id,
                entity_type,
                occurred,
                learned_at,
                data,
                allow_maintenance,
                allow_reserved_predicate,
            } => {
                // Public writes reject the engine-authored maintenance band via
                // the public entity-type gate; the sync rematerialization path
                // sets `allow_maintenance` so REDACTION_AUDIT (120) receipts
                // survive CRDT→LMDB replay (registry-only entity-type validation
                // still rejects genuinely unknown type bytes).
                if allow_maintenance
                    && allow_reserved_predicate
                    && entity_type == crate::types::ENTITY_TYPE_POLICY_MANIFEST
                {
                    return Err(Error::MaintenanceKindNotWritable(entity_type));
                }
                if allow_maintenance {
                    store.validate_entity_type(entity_type)?;
                } else {
                    store.validate_public_entity_type(entity_type)?;
                }
                let applied = apply_put(
                    store,
                    wtxn,
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    &data,
                    allow_reserved_predicate,
                    // ONE-1141: `replicated_put_op` is the SINGLE constructor
                    // that opens BOTH admit bands at once (see its doc), so
                    // both-flags-set identifies the sync replay doors
                    // (`put_replicated` → here). The replicated arm of
                    // `apply_put` deindexes the loser's BM25F postings on a
                    // body-changing overwrite, same-txn (ARCH-0031 amendment).
                    allow_maintenance && allow_reserved_predicate,
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    None,
                    false,
                )?;
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                }
                had_vector_mutation |= applied.had_vector_mutation;
                if let Some((target, query_hint)) = lexical_query_hint_for_replayed_put(
                    &id,
                    entity_type,
                    allow_maintenance && allow_reserved_predicate,
                    &data,
                )? {
                    let materialized = materialize_lexical_query_hint_text_if_target_ready(
                        store,
                        wtxn,
                        analyzer,
                        id,
                        &target,
                        query_hint,
                        &mut text_manifest_checked,
                    )?;
                    had_graph_mutation |= materialized;
                }
                if entity_type == crate::types::ENTITY_TYPE_CLAIM {
                    let materialized = materialize_lexical_query_hints_for_target(
                        store,
                        wtxn,
                        analyzer,
                        &id,
                        &mut text_manifest_checked,
                    )?;
                    had_graph_mutation |= materialized;
                }
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                occurred,
                learned_at,
                internal_lexical_query_hint,
            } => {
                let applied = apply_claim_candidate(
                    store,
                    wtxn,
                    id,
                    *candidate,
                    &envelope,
                    occurred,
                    learned_at,
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    internal_lexical_query_hint,
                )?;
                if applied.had_graph_mutation {
                    had_graph_mutation = true;
                }
                if applied.had_vector_mutation {
                    had_vector_mutation = true;
                }
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                }
            }
            BatchOp::ReconcileLexicalQueryHints { source, keep } => {
                let keep: HashSet<EntityId> = keep.into_iter().collect();
                let deleted =
                    delete_lexical_query_hint_claims_for_target(store, wtxn, &source, &keep)?;
                for (deleted_id, neighbors) in &deleted.deleted {
                    pending_embedding_tokens_written.remove(deleted_id);
                    ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
                }
                had_graph_mutation |= deleted.had_graph_mutation;
                had_vector_mutation |= deleted.had_vector;
            }
            BatchOp::Vector {
                id,
                vector,
                pending_embedding_token,
            } => {
                let same_batch_token = pending_embedding_token
                    .as_deref()
                    .or_else(|| pending_embedding_tokens_written.get(&id).map(Vec::as_slice));
                let applied = apply_vector(store, config, wtxn, id, &vector, same_batch_token)?;
                if applied.wrote_vector {
                    crate::hnsw::hnsw_insert_batched(
                        store,
                        config,
                        wtxn,
                        &id,
                        &vector,
                        &mut pending_hnsw_rebuild,
                    )?;
                    had_vector_mutation = true;
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                }
            }
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                apply_edge(store, wtxn, src, kind, tgt, weight, vad)?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight,
                created_at,
                vad,
            } => {
                apply_public_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad,
                )?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            // UNGATED by design — this is the replicated/replay shape. A
            // bare-over-provenanced LWW edge is a legitimate remote winner;
            // gating here would turn a legitimate remote merge into a
            // permanent local sync-wedging abort (H2). The public timestamped
            // builders route through the gated `PublicEdgeWithCreatedAt` arm
            // instead.
            BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight,
                created_at,
                vad,
                provenance,
            } => {
                apply_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad, provenance,
                )?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::SetEdgeWeight {
                src,
                kind,
                tgt,
                weight,
            } => {
                apply_set_edge_weight(store, wtxn, src, kind, tgt, weight)?;
                // The weight at offset 0 is the PPR edge weight — invalidate
                // and bump exactly like the plain edge-write arms.
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::SetEdgeVad {
                src,
                kind,
                tgt,
                vad,
            } => {
                apply_set_edge_vad(store, wtxn, src, kind, tgt, vad)?;
                // Mirror the existing edge-write behavior: every edge value
                // rewrite invalidates the endpoint PPR caches.
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::Text { id, fields } => {
                if !text_manifest_checked {
                    crate::vault::ensure_text_index_manifest_matches_wtxn(store, wtxn, analyzer)?;
                    text_manifest_checked = true;
                }
                crate::bm25::index_text(store, wtxn, analyzer, &id, &fields)?;
            }
            BatchOp::Phonetic { id, codes } => {
                apply_phonetic(store, wtxn, id, &codes)?;
            }
            BatchOp::Delete { id } => {
                let (_existed, had_vector, deleted_graph_state, neighbors) =
                    deindex_entity(store, wtxn, &id)?;
                pending_embedding_tokens_written.remove(&id);
                ppr::invalidate_ppr_for_delete(store, wtxn, &id, &neighbors)?;
                had_graph_mutation |= deleted_graph_state;
                had_vector_mutation |= had_vector;
            }
            BatchOp::DeleteEdge { src, kind, tgt } => {
                if apply_delete_edge(store, wtxn, src, kind, tgt)? {
                    ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                    had_graph_mutation = true;
                }
            }
        }
    }

    crate::hnsw::run_pending_legacy_rebuild(store, config, wtxn, pending_hnsw_rebuild)?;

    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector_mutation {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }

    Ok(())
}

fn contains_text_op(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| match op {
        BatchOp::Text { .. } => true,
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_maintenance,
            allow_reserved_predicate,
            ..
        } => {
            *entity_type == crate::types::ENTITY_TYPE_CLAIM
                && *allow_maintenance
                && *allow_reserved_predicate
                && id
                    .as_bytes()
                    .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
                && crate::claim::decode_claim_body(data, true)
                    .ok()
                    .is_some_and(|body| {
                        body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT
                    })
        }
        _ => false,
    })
}

fn contains_local_claim_put(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(op, BatchOp::ClaimCandidate { .. })
            || matches!(
                op,
                BatchOp::Put {
                    entity_type,
                    allow_maintenance,
                    allow_reserved_predicate,
                    ..
                } if *entity_type == crate::types::ENTITY_TYPE_CLAIM
                    && !(*allow_maintenance && *allow_reserved_predicate)
            )
    })
}

fn text_coverage_after_op(ops: &[BatchOp]) -> Vec<bool> {
    let mut text_ids_after = HashSet::new();
    let mut covered = vec![false; ops.len()];

    for (index, op) in ops.iter().enumerate().rev() {
        match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => {
                covered[index] = text_ids_after.contains(id);
            }
            BatchOp::Text { id, .. } => {
                text_ids_after.insert(*id);
            }
            _ => {}
        }
    }

    covered
}

#[derive(Debug, Default)]
struct ChildOfBatchOverlay {
    entity_clears: HashMap<EntityId, usize>,
    edge_ops: HashMap<(EntityId, EntityId), (usize, bool)>,
    edge_candidates: HashMap<EntityId, HashSet<EntityId>>,
}

impl ChildOfBatchOverlay {
    fn from_ops(ops: &[BatchOp]) -> Self {
        let mut overlay = Self::default();

        for (index, op) in ops.iter().enumerate() {
            match op {
                BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                    if *kind == EdgeKind::ChildOf =>
                {
                    overlay.edge_ops.insert((*src, *tgt), (index, true));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                    overlay.edge_ops.insert((*src, *tgt), (index, false));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::Delete { id } => {
                    overlay.entity_clears.insert(*id, index);
                }
                _ => {}
            }
        }

        overlay
    }

    fn final_edge_override(&self, child: &EntityId, parent: &EntityId) -> Option<bool> {
        let clear_seq = self
            .entity_clears
            .get(child)
            .copied()
            .into_iter()
            .chain(self.entity_clears.get(parent).copied())
            .max();
        let edge_seq = self.edge_ops.get(&(*child, *parent)).copied();

        match (clear_seq, edge_seq) {
            (Some(clear_seq), Some((op_seq, present))) if op_seq > clear_seq => Some(present),
            (Some(_), _) => Some(false),
            (None, Some((_, present))) => Some(present),
            (None, None) => None,
        }
    }

    fn effective_parents(
        &self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        child: &EntityId,
    ) -> Result<HashSet<EntityId>> {
        let mut parents = HashSet::new();
        let prefix = child_of_prefix(child);

        for entry in store.edges_out.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            validate_edge_record(key, value)?;
            let parent = EntityId::from_bytes(
                key[17..33]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("edge record"))?,
            )
            .map_err(|_| Error::CorruptedIndex("edge record"))?;

            if self.final_edge_override(child, &parent).unwrap_or(true) {
                parents.insert(parent);
            }
        }

        if let Some(candidates) = self.edge_candidates.get(child) {
            for parent in candidates {
                if self.final_edge_override(child, parent) == Some(true) {
                    parents.insert(*parent);
                }
            }
        }

        Ok(parents)
    }

    fn affected_children(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.edge_candidates.keys().copied()
    }
}

pub(crate) fn deindex_entity(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, bool, Vec<EntityId>)> {
    let (mut had_vector, mut had_graph_mutation, mut neighbors) =
        deindex_lexical_query_hints_for_target(store, wtxn, id)?;

    let (existed, entity_had_vector, entity_had_graph_mutation, mut entity_neighbors) =
        deindex_entity_without_lexical_query_hint_cascade(store, wtxn, id)?;
    had_vector |= entity_had_vector;
    had_graph_mutation |= entity_had_graph_mutation;
    neighbors.append(&mut entity_neighbors);
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((existed, had_vector, had_graph_mutation, neighbors))
}

pub(crate) fn deindex_lexical_query_hints_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, Vec<EntityId>)> {
    let deleted_hints =
        delete_lexical_query_hint_claims_for_target(store, wtxn, id, &HashSet::new())?;
    let mut neighbors = Vec::new();
    for (hint_id, hint_neighbors) in &deleted_hints.deleted {
        ppr::invalidate_ppr_for_delete(store, wtxn, hint_id, hint_neighbors)?;
        neighbors.push(*hint_id);
        neighbors.extend(
            hint_neighbors
                .iter()
                .copied()
                .filter(|neighbor| neighbor != id),
        );
    }
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((
        deleted_hints.had_vector,
        deleted_hints.had_graph_mutation,
        neighbors,
    ))
}

fn deindex_entity_without_lexical_query_hint_cascade(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, bool, Vec<EntityId>)> {
    let mut had_vector = false;
    let mut had_graph_mutation = false;
    let mut neighbors = Vec::new();

    // Clean secondary indexes unconditionally — they may exist even without an
    // entity record (e.g. text indexed via batch().text() without a preceding put()).
    crate::bm25::deindex_text(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    crate::code_revision::delete_code_revision_lifecycle_in_txn(store, wtxn, id)?;
    crate::codebase::delete_codebase_snapshot_in_txn(store, wtxn, id)?;
    store.clear_pending_embedding(wtxn, id)?;
    had_vector |= store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    let related_neighbors = delete_related_edges(store, wtxn, id)?;
    had_graph_mutation |= !related_neighbors.is_empty();
    neighbors.extend(related_neighbors);

    delete_short_id_rows_for_id(store, wtxn, id)?;

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        let cleanup = crate::vault::delete_vad_annotation_metadata_in_txn(store, wtxn, id)?;
        had_vector |= cleanup.had_vector;
        had_graph_mutation |= cleanup.had_graph_mutation;
        neighbors.extend(cleanup.neighbors);
        neighbors.sort_unstable();
        neighbors.dedup();
        return Ok((false, had_vector, had_graph_mutation, neighbors));
    };
    had_graph_mutation = true;

    let (entity_type, occurred, learned_at) = parse_entity_metadata(entity_record)?;
    let mut cleanup = crate::vault::VadAnnotationCleanup::default();
    crate::vault::delete_vad_annotation_metadata_for_type_in_txn(
        store,
        wtxn,
        id,
        entity_type,
        &mut cleanup,
    )?;
    had_vector |= cleanup.had_vector;
    had_graph_mutation |= cleanup.had_graph_mutation;
    neighbors.extend(cleanup.neighbors);
    neighbors.sort_unstable();
    neighbors.dedup();

    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index.delete(wtxn, &type_key)?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start
        .delete(wtxn, &occurred_start_key)?;
    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end
            .delete(wtxn, &occurred_end_key)?;
    }
    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_long_intervals
            .delete(wtxn, &long_interval_key)?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned.delete(wtxn, &learned_key)?;

    store.entities.delete(wtxn, id.as_bytes())?;
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((true, had_vector, had_graph_mutation, neighbors))
}

struct AppliedClaimCandidate {
    had_graph_mutation: bool,
    had_vector_mutation: bool,
    cleared_pending_embedding: bool,
    pending_embedding_token: Option<Vec<u8>>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "candidate writes thread existing apply_put context"
)]
fn apply_claim_candidate(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
    has_later_covering_text_op: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    internal_lexical_query_hint: bool,
) -> Result<AppliedClaimCandidate> {
    crate::gate::validate_write_envelope(envelope)?;

    let actor = envelope.actor();
    let actor_raw = store
        .entities
        .get(wtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let actor_header =
        EntityMetadataHeader::parse(actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())?;

    let subject = candidate.subject();
    if let crate::claim::ClaimSubject::Entity(subject_id) = subject
        && store.entities.get(wtxn, subject_id.as_bytes())?.is_none()
    {
        return Err(Error::EntityNotFound);
    }

    let body = candidate.into_claim_body(envelope);
    let data = crate::claim::encode_claim_body(&body)?;
    let applied_put = apply_put(
        store,
        wtxn,
        id,
        crate::types::ENTITY_TYPE_CLAIM,
        occurred,
        learned_at,
        &data,
        false,
        false,
        has_later_covering_text_op,
        write_policy,
        Some(envelope),
        internal_lexical_query_hint,
    )?;

    let subject_id = match subject {
        crate::claim::ClaimSubject::Entity(subject_id) => Some(subject_id),
        crate::claim::ClaimSubject::Edge { .. } => None,
    };
    let removed_claim_of = reconcile_claim_of_edges(store, wtxn, &id, subject_id)?;
    let mut had_graph_mutation = !removed_claim_of.is_empty();
    for removed_subject in &removed_claim_of {
        ppr::invalidate_ppr_for_edge(store, wtxn, &id, removed_subject)?;
    }

    let Some(subject_id) = subject_id else {
        return Ok(AppliedClaimCandidate {
            had_graph_mutation,
            had_vector_mutation: applied_put.had_vector_mutation,
            cleared_pending_embedding: applied_put.cleared_pending_embedding,
            pending_embedding_token: applied_put.pending_embedding_token,
        });
    };

    let weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_edge(
        store,
        wtxn,
        id,
        EdgeKind::ClaimOf,
        subject_id,
        weight,
        Vad::NEUTRAL,
    )?;
    ppr::invalidate_ppr_for_edge(store, wtxn, &id, &subject_id)?;
    had_graph_mutation = true;
    Ok(AppliedClaimCandidate {
        had_graph_mutation,
        had_vector_mutation: applied_put.had_vector_mutation,
        cleared_pending_embedding: applied_put.cleared_pending_embedding,
        pending_embedding_token: applied_put.pending_embedding_token,
    })
}

fn reconcile_claim_of_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    claim_id: &EntityId,
    new_subject: Option<EntityId>,
) -> Result<Vec<EntityId>> {
    let prefix = edge_kind_prefix(claim_id, EdgeKind::ClaimOf);
    let mut stale_subjects = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, &prefix)? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let subject = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        if Some(subject) != new_subject {
            stale_subjects.push(subject);
        }
    }

    for subject in &stale_subjects {
        apply_delete_edge(store, wtxn, *claim_id, EdgeKind::ClaimOf, *subject)?;
    }
    Ok(stale_subjects)
}

struct AppliedPut {
    pending_embedding_token: Option<Vec<u8>>,
    cleared_pending_embedding: bool,
    had_vector_mutation: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
fn apply_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
    allow_reserved_predicate: bool,
    replicated: bool,
    has_later_covering_text_op: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    write_envelope: Option<&WriteEnvelope>,
    internal_lexical_query_hint: bool,
) -> Result<AppliedPut> {
    // Type-byte validation runs in `apply_ops` (the public-vs-maintenance gate:
    // public writes reject the engine-authored maintenance band, the sync
    // rematerialization path admits it via `allow_maintenance`). apply_put is
    // reached only after that gate, so it does not re-validate the type byte.
    //
    // D18: every type-0 (CLAIM) write — put_entity, both batch builders, and
    // sync replay — is structurally validated before any byte is staged.
    // Registered maintenance kinds with pinned body schemas get the same
    // fail-closed treatment on every path that can admit their type byte.
    // Bodies of all other type bytes stay opaque at the storage layer.
    let mut is_lexical_query_hint_claim = false;
    if entity_type == crate::types::ENTITY_TYPE_CLAIM {
        let body = crate::claim::validate_claim_body_and_decode(data, allow_reserved_predicate)?;
        is_lexical_query_hint_claim = body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT;
        if is_lexical_query_hint_claim {
            if !id
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
            {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claim id must use LH prefix",
                ));
            }
            let hint_value = crate::claim::decode_lexical_query_hint_value(&body.value)?;
            let target = hint_value.target;
            let expected_id = lexical_query_hint_claim_id(&target, &hint_value.query)?;
            if expected_id != id {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claim id must match target and query",
                ));
            }
            if !body.stale {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claims must be stale",
                ));
            }
            if body.lifecycle != crate::claim::ClaimLifecycleStatus::Active {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claims must be active",
                ));
            }
            if target == id {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint target must not be self",
                ));
            }
            if let Some(target_raw) = store.entities.get(wtxn, target.as_bytes())? {
                let Some(target_header) = EntityMetadataHeader::parse(target_raw) else {
                    return Err(Error::CorruptedIndex("entity header"));
                };
                if target_header.entity_type != crate::types::ENTITY_TYPE_CLAIM {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be claim",
                    ));
                }
                let Ok(target_body) = crate::claim::decode_claim_body(
                    &target_raw[ENTITY_METADATA_HEADER_LEN..],
                    true,
                ) else {
                    if replicated {
                        return Err(Error::InvalidClaimBody(
                            "lexical query hint target must be claim",
                        ));
                    }
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be claim",
                    ));
                };
                if target_body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must not be synthetic hint",
                    ));
                }
            } else if !replicated {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint target must be claim",
                ));
            }
        }
        if !(replicated || is_lexical_query_hint_claim && internal_lexical_query_hint) {
            let policy = write_policy.ok_or(Error::InvariantViolation(
                "local claim write policy snapshot missing",
            ))?;
            if allow_reserved_predicate {
                crate::gate::check_reserved_claim_policy(&body, policy)?;
            } else if let Some(write_envelope) = write_envelope {
                crate::gate::check_claim_policy_with_write_envelope(&body, write_envelope, policy)?;
            } else {
                crate::gate::check_claim_policy(&body, policy)?;
            }
        }
    } else if entity_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT {
        crate::code_artifact::validate_code_artifact_body_bytes(data)?;
    } else if entity_type == crate::types::ENTITY_TYPE_FEDERATION_GRANT {
        crate::federation::validate_federation_grant_body_bytes(data)?;
    }
    if occurred.start > occurred.end {
        return Err(Error::InvalidTimeRange {
            start: occurred.start,
            end: occurred.end,
        });
    }
    // Maintenance-band kinds (REDACTION_AUDIT = 120) carry no short ID (static
    // registry `short_id_prefix: None`), matching the engine's direct receipt writer.
    // Only the internal sync path reaches here with such a kind (public puts are
    // rejected in `apply_ops`); skip short-id planning, which would otherwise
    // fail with `InvalidEntityType` on the missing prefix.
    let short_id_prefix = if is_lexical_query_hint_claim {
        None
    } else {
        store.short_id_prefix(entity_type).ok()
    };
    let short_id_plan = if let Some(short_id_prefix) = short_id_prefix {
        Some(plan_short_id_update(
            store,
            &*wtxn,
            &id,
            entity_type,
            &short_id_prefix,
            data,
        )?)
    } else {
        None
    };

    let mut body_changed = true;
    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(old_record)?;
        // ONE-1141 + ONE-1168 (ARCH-0031 amendment): body-changing overwrites
        // must not leave stale BM25F postings live. Replicated/LWW overwrites
        // always deindex the loser because sync carries no `BatchOp::Text`.
        // Local overwrites do the same unless this batch has a later same-id
        // Text op; a Text that already ran may describe an earlier body and
        // must not cover this overwrite. If a later Text is present,
        // `index_text` remains the self-deindex authority. Token source: the
        // body-independent `text_forward` row — `deindex_text` reads only it
        // and is a no-op for never-indexed entities. Byte-compare guard:
        // same-bytes replay must NOT touch the index, and metadata-only
        // (occurred/learned) changes are not body changes.
        body_changed = old_record[ENTITY_METADATA_HEADER_LEN..] != *data;
        let should_deindex_stale_text = body_changed && (replicated || !has_later_covering_text_op);
        let old_code_artifact_body =
            if old_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
                Some(old_record[ENTITY_METADATA_HEADER_LEN..].to_vec())
            } else {
                None
            };
        if old_type != entity_type {
            return Err(Error::EntityTypeImmutable {
                id,
                existing: old_type,
                attempted: entity_type,
            });
        }
        if old_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT
            && body_changed
            && crate::code_revision::has_finalized_code_revision_in_txn(store, wtxn, &id)?
        {
            return Err(Error::InvalidCodeArtifactBody(
                "finalized code revision artifacts are immutable",
            ));
        }
        if let Some(old_code_artifact_body) = old_code_artifact_body {
            crate::codebase::reconcile_codebase_snapshot_after_code_artifact_put(
                store,
                wtxn,
                &id,
                &old_code_artifact_body,
                data,
            )?;
        }
        if should_deindex_stale_text {
            crate::bm25::deindex_text(store, wtxn, &id)?;
        }

        if old_occurred.end.saturating_sub(old_occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
            let old_long_interval_key = Store::encode_temporal_key(old_occurred.end, &id);
            store
                .temporal_long_intervals
                .delete(wtxn, &old_long_interval_key)?;
        }

        if old_occurred.start != occurred.start {
            let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
            store.temporal_occurred_start.delete(wtxn, &old_start_key)?;
        }

        let old_is_range = old_occurred.start != old_occurred.end;
        let new_is_range = occurred.start != occurred.end;
        if old_is_range && (!new_is_range || old_occurred.end != occurred.end) {
            let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
            store.temporal_occurred_end.delete(wtxn, &old_end_key)?;
        }

        if old_learned != learned_at {
            let old_learned_key = Store::encode_temporal_key(old_learned, &id);
            store.temporal_learned.delete(wtxn, &old_learned_key)?;
        }
    }

    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);

    store.entities.put(wtxn, id.as_bytes(), &payload)?;

    let type_key = Store::encode_type_key(entity_type, &id);
    store.type_index.put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, &id);
    store
        .temporal_occurred_start
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, &id);
        store
            .temporal_occurred_end
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, &id);
    store.temporal_learned.put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, &id);
        let occurred_start_value = occurred.start.to_be_bytes();
        store
            .temporal_long_intervals
            .put(wtxn, &long_interval_key, &occurred_start_value)?;
    }

    if let Some(plan) = short_id_plan {
        apply_short_id_plan(store, wtxn, &id, plan)?;
    } else if is_lexical_query_hint_claim {
        delete_short_id_rows_for_id(store, wtxn, &id)?;
    }
    let mut cleared_pending_embedding = false;
    let mut had_vector_mutation = false;
    if is_lexical_query_hint_claim {
        cleared_pending_embedding = store.clear_pending_embedding(wtxn, &id)?;
        let had_hnsw = store.hnsw_neighbors.get(wtxn, id.as_bytes())?.is_some();
        had_vector_mutation = store.vectors.delete(wtxn, id.as_bytes())? || had_hnsw;
        crate::hnsw::hnsw_deindex(store, wtxn, &id)?;
    }
    let pending_embedding_token =
        if entity_type == crate::types::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {
            let has_current_pending = store.has_current_pending_embedding_in_txn(wtxn, &id)?;
            let has_vector = store.vectors.get(wtxn, id.as_bytes())?.is_some();
            if !body_changed && has_vector && !has_current_pending {
                None
            } else {
                Some(store.mark_pending_embedding(wtxn, &id, data)?)
            }
        } else {
            None
        };
    Ok(AppliedPut {
        pending_embedding_token,
        cleared_pending_embedding,
        had_vector_mutation,
    })
}

struct AppliedVector {
    wrote_vector: bool,
    cleared_pending_embedding: bool,
}

fn apply_vector(
    store: &Store,
    config: &crate::types::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    vector: &[f32],
    pending_embedding_token: Option<&[u8]>,
) -> Result<AppliedVector> {
    if stored_entity_is_lexical_query_hint_claim(store, wtxn, &id)? {
        return Err(Error::InvalidClaimBody(
            "lexical query hint ids are not vector-indexable",
        ));
    }
    if let Some(token) = pending_embedding_token
        && !store.pending_embedding_matches_in_txn(wtxn, &id, token)?
    {
        return Ok(AppliedVector {
            wrote_vector: false,
            cleared_pending_embedding: false,
        });
    }
    crate::store::ensure_model_id_for_vector_write(store, wtxn, config.embedding_model.as_deref())?;
    if vector.len() != config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(vector) {
        return Err(error);
    }

    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for v in vector {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
    let cleared_pending_embedding = match pending_embedding_token {
        Some(token) => store.clear_pending_embedding_if_token_matches(wtxn, &id, token)?,
        None => false,
    };
    Ok(AppliedVector {
        wrote_vector: true,
        cleared_pending_embedding,
    })
}

/// Applies one PUBLIC plain edge put (`BatchOp::Edge` — the op behind
/// `Vault::put_edge`, `Vault::put_edge_with_vad`, and the `edge` /
/// `edge_checked` / `edge_with_vad` batch builders).
///
/// ONE-1113 reject-and-route gate (ARCH-0034 #write-protection, ratified
/// 2026-06-13): a plain put carries no provenance, so re-encoding an edge
/// whose stored value is the 26-byte provenanced layout would silently drop
/// the two hot-flag bytes to 24 bytes in BOTH directions while the truth
/// `edge.provenance` Claim stays live. "An unattributed write can never
/// displace attributed truth as current state" — the put is rejected with
/// the typed [`Error::EdgeIsProvenanced`], whose message routes the caller
/// to the provenance path (`put_edge_provenance` / the `as_actor`-bound
/// surface) and the operational setters (`set_edge_weight` /
/// `set_edge_vad`). Layout dispatch is VALUE LENGTH (no tag byte; the
/// read-back mirrors `restamp_edge_flags`). A plain put on a bare or absent
/// edge is unchanged: absence of provenance is itself the anonymous
/// representation.
fn apply_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    vad: Vad,
) -> Result<()> {
    reject_if_existing_edge_is_provenanced(store, wtxn, src, kind, tgt)?;
    apply_edge_with_created_at(
        store,
        wtxn,
        src,
        kind,
        tgt,
        weight,
        crate::unix_seconds_now(),
        vad,
        None,
    )
}

fn reject_if_existing_edge_is_provenanced(
    store: &Store,
    wtxn: &RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    debug_assert_eq!(
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        EDGE_VALUE_SEMANTIC_LEN + 2,
        "provenanced-edge detection is layout-length based; update the reject gate if the hot-flag layout changes"
    );
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    if let Some(existing) = store.edges_out.get(wtxn, &key_out)?
        && existing.len() == EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    {
        return Err(Error::EdgeIsProvenanced { kind: kind as u8 });
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
fn apply_public_edge_with_created_at(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
) -> Result<()> {
    reject_if_existing_edge_is_provenanced(store, wtxn, src, kind, tgt)?;
    apply_edge_with_created_at(store, wtxn, src, kind, tgt, weight, created_at, vad, None)
}

/// Reads the existing edge value for an operational setter (ONE-1113):
/// the setters rewrite bytes of an EXISTING value and never upsert —
/// a missing edge is the typed [`Error::EdgeNotFound`]. The value length
/// must be one of the three contract layouts (12/24/26 B); anything else is
/// [`Error::CorruptedIndex`], mirroring `restamp_edge_flags`.
fn read_edge_value_for_setter(
    store: &Store,
    wtxn: &RwTxn<'_>,
    key_out: &[u8; EDGE_KEY_LEN],
) -> Result<Vec<u8>> {
    let existing = store
        .edges_out
        .get(wtxn, key_out)?
        .map(<[u8]>::to_vec)
        .ok_or(Error::EdgeNotFound)?;
    match existing.len() {
        EDGE_VALUE_STRUCTURAL_LEN
        | EDGE_VALUE_SEMANTIC_LEN
        | EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => Ok(existing),
        _ => Err(Error::CorruptedIndex("edge value")),
    }
}

/// ONE-1113 operational weight setter: rewrites ONLY the weight bytes
/// (f32 LE at offset 0..4 — present on ALL three layouts) of an existing
/// edge value and writes IDENTICAL bytes to both `edges_out` and `edges_in`.
/// Every other byte — `created_at`, VAD, and the provenance hot flags at
/// offsets 24/25 when the value is 26 B — is preserved verbatim, so the
/// setter can never displace attributed truth (exempt from the
/// reject-and-route gate by construction; M3 weight pin: weight is a LOCAL
/// operational field).
fn apply_set_edge_weight(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
) -> Result<()> {
    validate_edge_weight(weight)?;
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut value = read_edge_value_for_setter(store, wtxn, &key_out)?;
    value[0..4].copy_from_slice(&weight.to_le_bytes());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

/// ONE-1113 operational VAD setter: rewrites ONLY the VAD bytes (three
/// f32 LE at offset 12..24) of an existing SEMANTIC edge value and writes
/// IDENTICAL bytes to both `edges_out` and `edges_in`. Weight, `created_at`,
/// the value LENGTH (24 B stays 24 B, 26 B stays 26 B), and the provenance
/// hot flags at offsets 24/25 are preserved verbatim. Structural 12-byte
/// edges carry no VAD (contract layout table) and fail typed — never a
/// silent widen.
fn apply_set_edge_vad(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    vad: Vad,
) -> Result<()> {
    if let Some((component, value)) = vad.invalid_component() {
        return Err(Error::InvalidVad { component, value });
    }
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut value = read_edge_value_for_setter(store, wtxn, &key_out)?;
    if value.len() == EDGE_VALUE_STRUCTURAL_LEN {
        return Err(Error::InvariantViolation(
            "structural edges do not carry VAD",
        ));
    }
    value[12..16].copy_from_slice(&vad.valence.to_le_bytes());
    value[16..20].copy_from_slice(&vad.arousal.to_le_bytes());
    value[20..24].copy_from_slice(&vad.dominance.to_le_bytes());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
// UNGATED by design — this is the replicated/replay shape. A
// bare-over-provenanced LWW edge is a legitimate remote winner; gating here
// would turn a legitimate remote merge into a permanent local sync-wedging
// abort (H2). The public timestamped builders route through the gated
// `PublicEdgeWithCreatedAt` arm instead.
fn apply_edge_with_created_at(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
    provenance: Option<EdgeProvenanceFlags>,
) -> Result<()> {
    validate_edge_weight(weight)?;
    if let Some((component, value)) = vad.invalid_component() {
        return Err(Error::InvalidVad { component, value });
    }

    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let value = encode_edge_value(kind, weight, created_at, vad, provenance)?;
    // Paired-write invariant: edge value bytes are identical in `edges_out`
    // and `edges_in`; callers that alter edge payload layout must keep both
    // directions in lock-step.
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

fn validate_child_of_batch(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
) -> Result<()> {
    for child in child_of_overlay.affected_children() {
        let parents = child_of_overlay.effective_parents(store, rtxn, &child)?;
        if parents.len() > 1 {
            // Typed (not InvariantViolation) so the sync replay classifier
            // can treat a remote ChildOf cardinality violation as a
            // quarantine-and-continue rejection instead of aborting the
            // whole materialization batch (ONE-1124).
            return Err(Error::ChildOfCardinality);
        }
        let Some(parent) = parents.iter().next() else {
            continue;
        };
        if child == *parent {
            return Err(Error::CycleDetected);
        }
        if would_create_child_of_cycle(store, rtxn, child_of_overlay, &child, parent)? {
            return Err(Error::CycleDetected);
        }
    }

    Ok(())
}

fn would_create_child_of_cycle(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
    child: &EntityId,
    proposed_parent: &EntityId,
) -> Result<bool> {
    let mut frontier = VecDeque::new();
    frontier.push_back(*proposed_parent);
    let mut visited = HashSet::new();
    visited.insert(*proposed_parent);
    let mut traversed_steps = 0usize;

    while let Some(node) = frontier.pop_front() {
        for parent in child_of_overlay.effective_parents(store, rtxn, &node)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if parent == *child {
                return Ok(true);
            }
            if visited.insert(parent) {
                frontier.push_back(parent);
            }
        }
    }

    Ok(false)
}

fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; 17] {
    let mut prefix = [0u8; 17];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

fn child_of_prefix(id: &EntityId) -> [u8; 17] {
    edge_kind_prefix(id, EdgeKind::ChildOf)
}

#[derive(Default)]
struct DeletedLexicalQueryHints {
    had_vector: bool,
    had_graph_mutation: bool,
    deleted: Vec<(EntityId, Vec<EntityId>)>,
}

fn delete_lexical_query_hint_claims_for_target(
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

fn lexical_query_hint_claim_ids_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut hint_ids = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, target.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        if kind != EdgeKind::ClaimOf {
            continue;
        }
        let source = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        let Some(raw) = store.entities.get(wtxn, source.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {
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

fn legacy_lexical_query_hint_claim_ids_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut candidates = Vec::new();
    let mut prefix = Vec::with_capacity(1 + crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX.len());
    prefix.push(crate::types::ENTITY_TYPE_CLAIM);
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

fn stored_entity_is_lexical_query_hint_claim(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(body) = stored_claim_body(store, wtxn, id)? else {
        return Ok(false);
    };
    Ok(body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT)
}

fn stored_entity_is_claim_type(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    Ok(header.entity_type == crate::types::ENTITY_TYPE_CLAIM)
}

fn stored_claim_body(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<crate::claim::ClaimBody>> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(None);
    };
    Ok(Some(body))
}

fn apply_delete_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<bool> {
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let deleted_out = store.edges_out.delete(wtxn, &key_out)?;
    let _deleted_in = store.edges_in.delete(wtxn, &key_in)?;
    Ok(deleted_out)
}

fn apply_phonetic(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: &[String],
) -> Result<()> {
    let mut forward_codes = match store.phonetic_forward.get(wtxn, id.as_bytes())? {
        Some(raw) => match decode_phonetic_forward_codes(raw) {
            Ok(codes) => codes,
            Err(Error::CorruptedIndex(_)) => Vec::new(),
            Err(err) => return Err(err),
        },
        None => Vec::new(),
    };
    let mut forward_changed = false;

    let mut seen_codes = HashSet::with_capacity(codes.len());
    for code in codes {
        validate_phonetic_code(code)?;
        if !seen_codes.insert(code.as_str()) {
            continue;
        }

        let existing = store.phonetic_index.get(wtxn, code.as_bytes())?;
        let mut posting =
            existing.map_or_else(|| Vec::with_capacity(ENTITY_ID_LEN), |bytes| bytes.to_vec());
        if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(Error::CorruptedIndex("phonetic posting"));
        }

        if posting
            .chunks_exact(ENTITY_ID_LEN)
            .any(|chunk| chunk == id.as_bytes())
        {
            if !forward_codes.iter().any(|known| known == code) {
                forward_codes.push(code.clone());
                forward_changed = true;
            }
            continue;
        }

        posting.extend_from_slice(id.as_bytes());
        store.phonetic_index.put(wtxn, code.as_bytes(), &posting)?;

        if !forward_codes.iter().any(|known| known == code) {
            forward_codes.push(code.clone());
            forward_changed = true;
        }
    }

    if forward_changed {
        forward_codes.sort();
        forward_codes.dedup();
        let encoded = encode_phonetic_forward_codes(&forward_codes);
        store.phonetic_forward.put(wtxn, id.as_bytes(), &encoded)?;
    }

    Ok(())
}

enum ShortIdPlan {
    UpdateExisting {
        short_id: String,
        old_content_hash: u8,
        content_hash: u8,
    },
    InsertNew {
        counter_key: [u8; crate::store::SHORT_ID_COUNTER_KEY_LEN],
        next_counter: u64,
        short_id: String,
        content_hash: u8,
    },
}

fn plan_short_id_update(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    short_id_prefix: &str,
    data: &[u8],
) -> Result<ShortIdPlan> {
    let content_hash = (xxh32(data, 0) % 256) as u8;

    if let Some(existing) = store.short_ids_reverse.get(txn, id.as_bytes())? {
        let (short_id, old_content_hash) = parse_short_id_value(existing)?;
        return Ok(ShortIdPlan::UpdateExisting {
            short_id: short_id.to_owned(),
            old_content_hash,
            content_hash,
        });
    }

    // Per-type counters live in `vault_meta` under the documented
    // `b"sid_counter:" ‖ type_byte` key scheme (store.rs), NOT as sentinel
    // rows inside `short_ids` — that table holds only the ARCH-0019 row n3
    // mapping `(short_id, content_hash)` -> `entity_id`.
    let counter_key = crate::store::short_id_counter_key(entity_type);
    let current = match store.vault_meta.get(txn, &counter_key)? {
        Some(raw) => {
            let buf: [u8; SHORT_ID_COUNTER_LEN] = raw
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id counter"))?;
            u64::from_le_bytes(buf)
        }
        None => 0,
    };

    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("short id counter"))?;
    let short_id = format!("{short_id_prefix}{next}");
    Ok(ShortIdPlan::InsertNew {
        counter_key,
        next_counter: next,
        short_id,
        content_hash,
    })
}

fn apply_short_id_plan(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    plan: ShortIdPlan,
) -> Result<()> {
    match plan {
        ShortIdPlan::UpdateExisting {
            short_id,
            old_content_hash,
            content_hash,
        } => {
            if old_content_hash != content_hash {
                // The content hash is part of the forward KEY, so a content
                // update must remove the stale forward row before rewriting.
                let old_forward_key = encode_short_id_forward_key(&short_id, old_content_hash);
                store.short_ids.delete(wtxn, &old_forward_key)?;
            }
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
        ShortIdPlan::InsertNew {
            counter_key,
            next_counter,
            short_id,
            content_hash,
        } => {
            store
                .vault_meta
                .put(wtxn, &counter_key, &next_counter.to_le_bytes())?;
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
    }

    Ok(())
}

fn delete_short_id_rows_for_id(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let forward_key = store
        .short_ids_reverse
        .get(wtxn, id.as_bytes())?
        .map(parse_short_id_value)
        .transpose()?
        .map(|(short_id, content_hash)| encode_short_id_forward_key(short_id, content_hash));
    if let Some(forward_key) = forward_key {
        store.short_ids.delete(wtxn, &forward_key)?;
        store.short_ids_reverse.delete(wtxn, id.as_bytes())?;
    }
    Ok(())
}

/// Writes both pinned ARCH-0019 short-id rows for one entity:
/// row n3 `short_ids`: key `(short_id bytes ‖ content_hash u8)` -> 16-byte
/// entity id; row n4 `short_ids_reverse`: key entity id -> value
/// `(short_id bytes ‖ content_hash u8)` (same bytes as the forward key).
fn write_short_id_rows(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    short_id: &str,
    content_hash: u8,
) -> Result<()> {
    let forward_key = encode_short_id_forward_key(short_id, content_hash);
    store.short_ids.put(wtxn, &forward_key, id.as_bytes())?;
    store
        .short_ids_reverse
        .put(wtxn, id.as_bytes(), &forward_key)?;
    Ok(())
}

/// Encodes the `short_ids` forward key `(short_id bytes ‖ content_hash u8)`
/// pinned by ARCH-0019 manifest row n3. The same byte shape is stored as the
/// `short_ids_reverse` VALUE (row n4) and is parsed back by
/// [`parse_short_id_value`].
pub(crate) fn encode_short_id_forward_key(short_id: &str, content_hash: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(short_id.len() + 1);
    key.extend_from_slice(short_id.as_bytes());
    key.push(content_hash);
    key
}

pub(crate) fn parse_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    if value.len() < 2 {
        return Err(Error::CorruptedIndex("short id value"));
    }

    let Some((&hash, short_id_bytes)) = value.split_last() else {
        return Err(Error::CorruptedIndex("short id value"));
    };
    let short_id =
        str::from_utf8(short_id_bytes).map_err(|_| Error::CorruptedIndex("short id value"))?;
    Ok((short_id, hash))
}

fn parse_entity_metadata(record: &[u8]) -> Result<(u8, TimeRange, u64)> {
    let header =
        EntityMetadataHeader::parse(record).ok_or(Error::CorruptedIndex("entity metadata"))?;

    Ok((
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    ))
}

fn delete_related_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut outbound = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        let target = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        outbound.push((kind, target));
    }

    for (kind, target) in &outbound {
        let out_key = Store::encode_edge_key(id, *kind, target);
        let in_key = Store::encode_edge_key(target, *kind, id);
        store.edges_out.delete(wtxn, &out_key)?;
        store.edges_in.delete(wtxn, &in_key)?;
    }

    let mut inbound = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        let source = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        inbound.push((kind, source));
    }

    for (kind, source) in &inbound {
        let in_key = Store::encode_edge_key(id, *kind, source);
        let out_key = Store::encode_edge_key(source, *kind, id);
        store.edges_in.delete(wtxn, &in_key)?;
        store.edges_out.delete(wtxn, &out_key)?;
    }

    let mut neighbors: Vec<EntityId> = outbound
        .into_iter()
        .map(|(_, id)| id)
        .chain(inbound.into_iter().map(|(_, id)| id))
        .collect();
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok(neighbors)
}

pub(crate) fn delete_from_phonetic_postings(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if let Some(raw) = store.phonetic_forward.get(wtxn, id.as_bytes())? {
        match decode_phonetic_forward_codes(raw) {
            Ok(codes) => match delete_from_known_phonetic_codes(store, wtxn, id, &codes) {
                Ok(()) => {
                    if reconcile_phonetic_postings(store, wtxn, id)? {
                        log_phonetic_forward_fallback(id, "stale_forward_row");
                    }
                    store.phonetic_forward.delete(wtxn, id.as_bytes())?;
                    return Ok(());
                }
                Err(Error::MissingPostingEntry) => {
                    log_phonetic_forward_fallback(id, "missing_posting_entry");
                }
                Err(err) => return Err(err),
            },
            Err(Error::CorruptedIndex(_)) => {
                log_phonetic_forward_fallback(id, "corrupted_forward_row");
            }
            Err(err) => return Err(err),
        }
    }

    scan_and_strip_phonetic_postings(store, wtxn, id)?;
    store.phonetic_forward.delete(wtxn, id.as_bytes())?;
    Ok(())
}

/// Scan the entire phonetic posting index, drop `id` from every row that
/// contains it, persist the updates, and report whether any row changed.
/// Shared by the full-scan fallback in `delete_from_phonetic_postings` and
/// the reconcile pass that runs after a forward-row-driven delete to catch
/// stale references.
fn scan_and_strip_phonetic_postings(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let mut repaired = false;
    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for entry in store.phonetic_index.iter(wtxn)? {
        let (code, posting) = entry?;
        let Some(updated) = posting_without_entity(posting, id)? else {
            continue;
        };

        repaired = true;
        if updated.is_empty() {
            deletes.push(code.to_vec());
        } else {
            updates.push((code.to_vec(), updated));
        }
    }

    for code in deletes {
        store.phonetic_index.delete(wtxn, &code)?;
    }

    for (code, posting) in updates {
        store.phonetic_index.put(wtxn, &code, &posting)?;
    }

    Ok(repaired)
}

fn log_phonetic_forward_fallback(id: &EntityId, reason: &'static str) {
    tracing::warn!(
        entity = %id.to_hex(),
        reason,
        "phonetic_forward unavailable during delete; falling back to full scan"
    );
}

fn delete_from_known_phonetic_codes(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    codes: &[String],
) -> Result<()> {
    for code in codes {
        let posting = store
            .phonetic_index
            .get(wtxn, code.as_bytes())?
            .ok_or(Error::MissingPostingEntry)?;
        let updated = posting_without_entity(posting, id)?.ok_or(Error::MissingPostingEntry)?;

        if updated.is_empty() {
            store.phonetic_index.delete(wtxn, code.as_bytes())?;
        } else {
            store.phonetic_index.put(wtxn, code.as_bytes(), &updated)?;
        }
    }

    Ok(())
}

fn validate_phonetic_code(code: &str) -> Result<()> {
    if code.is_empty() || code.as_bytes().contains(&0) {
        return Err(Error::InvalidKey);
    }

    Ok(())
}

fn posting_without_entity(posting: &[u8], id: &EntityId) -> Result<Option<Vec<u8>>> {
    if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex("phonetic posting"));
    }

    let retained: Vec<u8> = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk != id.as_bytes())
        .flat_map(|chunk| chunk.iter().copied())
        .collect();

    Ok((retained.len() != posting.len()).then_some(retained))
}

fn reconcile_phonetic_postings(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
    scan_and_strip_phonetic_postings(store, wtxn, id)
}

fn decode_phonetic_forward_codes(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Err(Error::CorruptedIndex("phonetic forward row"));
    }

    let mut codes: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(Error::CorruptedIndex("phonetic forward row"));
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| Error::CorruptedIndex("phonetic forward row"))
        })
        .collect::<Result<_>>()?;
    codes.sort();
    codes.dedup();
    Ok(codes)
}

fn encode_phonetic_forward_codes(codes: &[String]) -> Vec<u8> {
    codes.join("\0").into_bytes()
}

fn validate_edge_record(key: &[u8], value: &[u8]) -> Result<()> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }

    let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
    decode_edge_value_for_kind(kind, value).map_err(|_| Error::CorruptedIndex("edge record"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    };
    use crate::deletion::DeleteReason;
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    use crate::types::{
        ClaimCandidate, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
        ENTITY_TYPE_TASK, EdgeActorClass, HnswConfig, VaultConfig,
        WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
        WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor, WriteEnvelope, WriteProvenance,
    };
    use core::assert_matches;
    use rmpv::Value;

    struct EdgeFixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        edge: EdgeRef,
        claim_id: EntityId,
    }

    type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(test_config())
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
        let rtxn = vault.store.env.read_txn()?;
        let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
        let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
        let out = vault
            .store
            .edges_out
            .get(&rtxn, &key_out)?
            .map(<[u8]>::to_vec);
        let inn = vault
            .store
            .edges_in
            .get(&rtxn, &key_in)?
            .map(<[u8]>::to_vec);
        Ok((out, inn))
    }

    fn assert_edge_is_provenanced_reject(err: Error, expected_kind: EdgeKind, context: &str) {
        match err {
            Error::EdgeIsProvenanced { kind } => {
                assert_eq!(kind, expected_kind as u8, "{context}: kind byte");
            }
            other => panic!("{context}: expected EdgeIsProvenanced, got {other:?}"),
        }
    }

    fn assert_raw_edge_unchanged(
        vault: &Vault,
        edge: &EdgeRef,
        before: &[u8],
        context: &str,
    ) -> Result<()> {
        let (after_out, after_in) = raw_edge_values(vault, edge)?;
        assert_eq!(
            after_out.as_deref(),
            Some(before),
            "{context}: edges_out must stay byte-identical"
        );
        assert_eq!(
            after_in.as_deref(),
            Some(before),
            "{context}: edges_in must stay byte-identical"
        );
        Ok(())
    }

    const GITHUB_PAT_SECRET_FIXTURE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

    fn assert_secret_scan_rejected(err: Error) {
        match err {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "deny");
                assert_eq!(
                    reason_codes.as_slice(),
                    &["gate.secret_scan.detected", "gate.secret_scan.github_token"]
                );
            }
            other => panic!("expected secret-scan GateWriteRejected, got {other:?}"),
        }
    }

    #[test]
    fn secret_scan_rejects_known_secret_fixture_before_persistence() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let safe_id = EntityId::now();
        let secret_id = EntityId::now();
        let occurred = test_time_range(10, 10);

        let err = vault
            .batch()
            .put(
                &safe_id,
                ENTITY_TYPE_PERSON,
                occurred,
                10,
                b"ordinary memory",
            )
            .put(
                &secret_id,
                ENTITY_TYPE_PERSON,
                occurred,
                10,
                GITHUB_PAT_SECRET_FIXTURE,
            )
            .commit()
            .expect_err("known secret fixture must reject before any batch write");

        assert_secret_scan_rejected(err);
        assert!(vault.get(&safe_id)?.is_none());
        assert!(vault.get(&secret_id)?.is_none());
        Ok(())
    }

    #[test]
    fn secret_scan_allows_non_secret_write_unchanged() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        let occurred = test_time_range(20, 20);
        let data = b"ordinary memory body";

        vault
            .batch()
            .put(&id, ENTITY_TYPE_PERSON, occurred, 20, data)
            .text(&id, &[("body", "ordinary memory body")])
            .commit()?;

        assert_eq!(vault.get(&id)?.as_deref(), Some(&data[..]));
        assert_eq!(vault.search_text("ordinary", 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn secret_scan_rejects_phonetic_payload_before_persistence() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let safe_id = EntityId::now();
        let phonetic_id = EntityId::now();
        let occurred = test_time_range(25, 25);
        let secret_code =
            std::str::from_utf8(GITHUB_PAT_SECRET_FIXTURE).expect("secret fixture is UTF-8");

        let err = vault
            .batch()
            .put(
                &safe_id,
                ENTITY_TYPE_PERSON,
                occurred,
                25,
                b"ordinary memory",
            )
            .phonetic(&phonetic_id, &[secret_code])
            .commit()
            .expect_err("known secret fixture in phonetic payload must reject before batch write");

        assert_secret_scan_rejected(err);
        assert!(vault.get(&safe_id)?.is_none());

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .phonetic_index
                .get(&rtxn, secret_code.as_bytes())?
                .is_none()
        );
        assert!(
            vault
                .store
                .phonetic_forward
                .get(&rtxn, phonetic_id.as_bytes())?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn txn_batch_secret_scan_rejects_before_staging_writes() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let safe_id = EntityId::now();
        let secret_id = EntityId::now();
        let occurred = test_time_range(30, 30);
        let mut wtxn = vault.store.env.write_txn()?;

        let err = vault
            .batch_in()
            .put(
                &safe_id,
                ENTITY_TYPE_PERSON,
                occurred,
                30,
                b"ordinary memory",
            )
            .put(
                &secret_id,
                ENTITY_TYPE_PERSON,
                occurred,
                30,
                GITHUB_PAT_SECRET_FIXTURE,
            )
            .apply(&mut wtxn)
            .expect_err("txn batch secret fixture must reject before staging writes");

        assert_secret_scan_rejected(err);
        wtxn.commit()?;

        assert!(vault.get(&safe_id)?.is_none());
        assert!(vault.get(&secret_id)?.is_none());
        Ok(())
    }

    fn provenanced_edge_fixture() -> Result<EdgeFixture> {
        let (dir, vault) = open_test_vault();
        let src = EntityId::now();
        let tgt = EntityId::now();
        let actor = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

        let edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
        let claim_id = EntityId::now();
        vault.put_edge_provenance(
            &claim_id,
            &edge,
            &EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            1_000,
        )?;

        Ok(EdgeFixture {
            _dir: dir,
            vault,
            edge,
            claim_id,
        })
    }

    fn evidence_entry<'a>(evidence: &'a Value, key: &str) -> &'a Value {
        let Value::Map(entries) = evidence else {
            panic!("expected write envelope evidence map, got {evidence:?}");
        };
        entries
            .iter()
            .find_map(|(entry_key, entry_value)| {
                (entry_key.as_str() == Some(key)).then_some(entry_value)
            })
            .unwrap_or_else(|| panic!("missing evidence key {key:?} in {evidence:?}"))
    }

    fn has_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        Ok(vault.store.pending_embedding_token(&rtxn, id)?.is_some())
    }

    fn raw_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = vault.store.env.read_txn()?;
        let key = Store::pending_embedding_marker_key(id);
        Ok(vault
            .store
            .sync_state
            .get(&rtxn, key.as_str())?
            .map(<[u8]>::to_vec))
    }

    fn overwrite_pending_embedding_marker(
        vault: &Vault,
        id: &EntityId,
        token: &[u8],
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        let key = Store::pending_embedding_marker_key(id);
        vault.store.sync_state.put(&mut wtxn, key.as_str(), token)?;
        wtxn.commit()?;
        Ok(())
    }

    fn pending_embedding_token(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_embedding_token(&rtxn, id)?
            .ok_or(Error::InvariantViolation("pending embedding token missing"))
    }

    fn seed_raw_claim_record(vault: &Vault, id: &EntityId, body: ClaimBody) -> Result<()> {
        let data = crate::claim::encode_claim_body(&body)?;
        let occurred = test_time_range(30, 30);
        let learned_at = 31_u64;
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_CLAIM);
        payload.extend_from_slice(&occurred.start.to_be_bytes());
        payload.extend_from_slice(&occurred.end.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&data);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, id);
        vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
        let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
        vault
            .store
            .temporal_occurred_start
            .put(&mut wtxn, &occurred_start_key, &[])?;
        let learned_key = Store::encode_temporal_key(learned_at, id);
        vault
            .store
            .temporal_learned
            .put(&mut wtxn, &learned_key, &[])?;
        wtxn.commit()?;
        Ok(())
    }

    fn seed_stale_vector_state(vault: &Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for component in vector {
            bytes.extend_from_slice(&component.to_le_bytes());
        }
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, id.as_bytes(), &bytes)?;
        let mut pending_rebuild = false;
        crate::hnsw::hnsw_insert_batched(
            &vault.store,
            &vault.config,
            &mut wtxn,
            id,
            vector,
            &mut pending_rebuild,
        )?;
        crate::hnsw::run_pending_legacy_rebuild(
            &vault.store,
            &vault.config,
            &mut wtxn,
            pending_rebuild,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn seed_claim_of_edge(vault: &Vault, claim: &EntityId, subject: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        apply_edge(
            &vault.store,
            &mut wtxn,
            *claim,
            EdgeKind::ClaimOf,
            *subject,
            1.0,
            Vad::NEUTRAL,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn seed_policy_manifest_with_critical_defaults(vault: &Vault) -> Result<()> {
        let manifest = Value::Map(vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("lexical-hint-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("critical")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (
                Value::from("rules"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("prefix"), Value::from("profile.")),
                    (
                        Value::from("axes"),
                        Value::Map(vec![
                            (Value::from("criticality"), Value::from("normal")),
                            (Value::from("sensitivity"), Value::from("normal")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("human")),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest).expect("encode policy manifest fixture");

        let id = EntityId::from_bytes([0x51; ENTITY_ID_LEN])
            .map_err(|_| Error::InvariantViolation("invalid policy fixture id"))?;
        let occurred = test_time_range(32, 32);
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&occurred.start.to_be_bytes());
        payload.extend_from_slice(&occurred.end.to_be_bytes());
        payload.extend_from_slice(&33_u64.to_be_bytes());
        payload.extend_from_slice(&data);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
        wtxn.commit()?;
        Ok(())
    }

    fn lh_prefixed_id(fill: u8) -> Result<EntityId> {
        let mut raw = [fill; ENTITY_ID_LEN];
        raw[0] = b'L';
        raw[1] = b'H';
        EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid LH fixture id"))
    }

    fn test_write_envelope(actor: EntityId) -> Result<WriteEnvelope> {
        Ok(WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("fixture"))?,
            ClaimApprovalStatus::Approved,
        ))
    }

    #[test]
    fn write_envelope_validation_rejects_missing_required_axes() -> Result<()> {
        let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
        let provenance = WriteProvenance::new(Value::from("fixture"))?;

        let err = WriteEnvelope::try_new(
            None,
            Some(ClaimSource::UserStated),
            Some(provenance.clone()),
            Some(ClaimApprovalStatus::Proposed),
        )
        .expect_err("actor is required");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("write envelope missing actor")
        ));

        let err = WriteEnvelope::try_new(
            Some(actor),
            None,
            Some(provenance.clone()),
            Some(ClaimApprovalStatus::Proposed),
        )
        .expect_err("source is required");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("write envelope missing source")
        ));

        let err = WriteEnvelope::try_new(
            Some(actor),
            Some(ClaimSource::UserStated),
            None,
            Some(ClaimApprovalStatus::Proposed),
        )
        .expect_err("provenance is required");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("write envelope missing provenance")
        ));

        let err = WriteEnvelope::try_new(
            Some(actor),
            Some(ClaimSource::UserStated),
            Some(provenance),
            None,
        )
        .expect_err("approval is required");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("write envelope missing approval")
        ));

        let err = WriteProvenance::new(Value::Nil).expect_err("nil provenance must reject");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("write envelope missing provenance")
        ));
        Ok(())
    }

    #[test]
    fn claim_candidate_rejects_missing_actor_entity() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"subject",
        )?;

        let claim = EntityId::now();
        let missing_actor = EntityId::now();
        let envelope = WriteEnvelope::new(
            WriteActor::new(missing_actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("fixture"))?,
            ClaimApprovalStatus::Proposed,
        );
        let candidate = ClaimCandidate::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from("Alice"),
            0.9,
        );

        let err = vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(1, 1), 2)
            .commit()
            .expect_err("missing actor entity must reject");
        assert!(matches!(err, Error::EntityNotFound));
        assert!(vault.get_claim(&claim)?.is_none());
        Ok(())
    }

    #[test]
    fn claim_candidate_write_stamps_approved_envelope() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let provenance = Value::Map(vec![(
            Value::from("source_record_id"),
            Value::from("fixture-approved-1"),
        )]);
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(provenance.clone())?,
            ClaimApprovalStatus::Approved,
        );
        let candidate = ClaimCandidate::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from("Alice"),
            0.9,
        )
        .with_salience(0.4);

        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
        assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
        assert_eq!(stored.source, Some(ClaimSource::UserStated));
        assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(stored.salience, Some(0.4));

        let evidence = stored.evidence.as_ref().expect("envelope evidence");
        match evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
            Value::Binary(bytes) => assert_eq!(bytes.as_slice(), actor.as_bytes()),
            other => panic!("actor evidence must be binary, got {other:?}"),
        }
        assert_eq!(
            evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).as_u64(),
            Some(EdgeActorClass::Human as u64)
        );
        assert_eq!(
            evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
            &provenance
        );
        assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
        Ok(())
    }

    #[test]
    fn claim_candidate_lexical_hints_write_read_and_search_source_claim() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );

        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &[
                    "green tea preferences",
                    "  matcha order history  ",
                    "green tea preferences",
                ],
            )
            .commit()?;

        let hint_claims = vault.claims_for_subject(&claim)?;
        assert_eq!(hint_claims.len(), 2);
        let mut stored_queries = Vec::new();
        for hint_claim in &hint_claims {
            assert!(
                hint_claim
                    .as_bytes()
                    .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
            );
            assert!(
                !has_pending_embedding_marker(&vault, hint_claim)?,
                "lexical hint side claims must not be queued for embeddings"
            );
            let stored = vault
                .get_claim(hint_claim)?
                .expect("lexical hint claim stored");
            assert_eq!(stored.predicate, crate::claim::PREDICATE_LEXICAL_QUERY_HINT);
            assert!(stored.stale, "lexical hint side claims are derived data");
            assert_eq!(stored.source, Some(ClaimSource::UserStated));
            assert!(stored.evidence.is_some());
            let value = crate::claim::decode_lexical_query_hint_value(&stored.value)?;
            assert_eq!(value.target, claim);
            stored_queries.push(value.query);
        }
        stored_queries.sort();
        assert_eq!(
            stored_queries,
            vec!["green tea preferences", "matcha order history"]
        );

        let hits = vault.search_text("matcha order", 10)?;
        assert_eq!(hits.first().map(|hit| hit.id), Some(claim));
        assert!(
            !hits.iter().any(|hit| hint_claims.contains(&hit.id)),
            "lexical hint docs must collapse to the source claim"
        );
        let ppr_hits = vault.query().search_ppr(&[claim], 2).run()?;
        assert!(
            !ppr_hits.iter().any(|hit| hint_claims.contains(&hit.id)),
            "lexical hint side claims must not surface through PPR"
        );
        let rtxn = vault.store.env.read_txn()?;
        for hint in &hint_claims {
            assert!(
                vault
                    .store
                    .short_ids_reverse
                    .get(&rtxn, hint.as_bytes())?
                    .is_none(),
                "lexical hint side claims must not receive public short ids"
            );
        }
        Ok(())
    }

    #[test]
    fn claim_candidate_lexical_hints_bypass_hint_policy_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        seed_policy_manifest_with_critical_defaults(&vault)?;
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &["policy bypass lexical hint"],
            )
            .commit()?;

        assert_eq!(
            vault
                .search_text("policy bypass lexical", 10)?
                .first()
                .map(|hit| hit.id),
            Some(claim)
        );
        Ok(())
    }

    #[test]
    fn raw_lexical_hint_put_does_not_bypass_policy_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        seed_policy_manifest_with_critical_defaults(&vault)?;
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        let query = "raw policy lexical hint";
        let hint = lexical_query_hint_claim_id(&claim, query)?;
        let mut body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(claim),
            crate::claim::encode_lexical_query_hint_value(&claim, query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.stale = true;
        let data = crate::claim::encode_claim_body(&body)?;

        let err = vault
            .batch()
            .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(20, 20), 21, &data)
            .commit()
            .expect_err("raw lexical hint puts must still pass ordinary policy");
        assert_matches!(err, Error::GateWriteRejected { .. });
        assert!(vault.search_text(query, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn claim_candidate_lexical_hints_replace_and_delete_stale_side_records() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let write_hints = |hints: &[&str]| -> Result<()> {
            let candidate = ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.9,
            );
            vault
                .batch()
                .claim_candidate_with_lexical_hints(
                    &claim,
                    candidate,
                    &envelope,
                    test_time_range(10, 10),
                    11,
                    hints,
                )
                .commit()
        };

        write_hints(&["retireduniquealpha", "liveuniquebeta"])?;
        let obsolete_hint = lexical_query_hint_claim_id(&claim, "retireduniquealpha")?;
        let live_hint = lexical_query_hint_claim_id(&claim, "liveuniquebeta")?;
        assert!(vault.get_claim(&obsolete_hint)?.is_some());
        assert!(vault.get_claim(&live_hint)?.is_some());

        write_hints(&["liveuniquebeta"])?;
        assert!(vault.get_claim(&obsolete_hint)?.is_none());
        assert!(vault.get_claim(&live_hint)?.is_some());
        assert_eq!(vault.claims_for_subject(&claim)?, vec![live_hint]);
        assert!(vault.search_text("retireduniquealpha", 10)?.is_empty());
        assert_eq!(
            vault
                .search_text("liveuniquebeta", 10)?
                .first()
                .map(|hit| hit.id),
            Some(claim)
        );

        let plain_candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(
                &claim,
                plain_candidate,
                &envelope,
                test_time_range(12, 12),
                13,
            )
            .commit()?;
        assert!(vault.get_claim(&live_hint)?.is_none());
        assert!(vault.claims_for_subject(&claim)?.is_empty());
        assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());

        write_hints(&["liveuniquebeta"])?;
        assert!(vault.get_claim(&live_hint)?.is_some());

        vault.batch().delete(&claim).commit()?;
        assert!(vault.get_claim(&live_hint)?.is_none());
        assert!(vault.claims_for_subject(&claim)?.is_empty());
        assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn soft_delete_removes_lexical_hint_side_records() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &["soft delete lexical hint"],
            )
            .commit()?;
        let hint = lexical_query_hint_claim_id(&claim, "soft delete lexical hint")?;

        vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

        assert!(vault.get_claim(&hint)?.is_none());
        assert!(vault.claims_for_subject(&claim)?.is_empty());
        assert!(vault.search_text("soft delete lexical", 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn plain_overwrite_removes_orphan_lexical_hint_without_claim_of() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        let stale_query = "legacy orphan lexical hint";
        let orphan_hint = lexical_query_hint_claim_id(&claim, stale_query)?;
        let mut orphan_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(claim),
            crate::claim::encode_lexical_query_hint_value(&claim, stale_query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        orphan_body.stale = true;
        seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
        vault
            .batch()
            .text(&orphan_hint, &[("query_hint", stale_query)])
            .commit()?;
        assert!(
            vault.claims_for_subject(&claim)?.is_empty(),
            "fixture intentionally omits the legacy hint ClaimOf edge"
        );
        assert_eq!(
            vault
                .search_text(stale_query, 10)?
                .first()
                .map(|hit| hit.id),
            Some(claim)
        );

        let replacement = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("hojicha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(&claim, replacement, &envelope, test_time_range(12, 12), 13)
            .commit()?;

        assert!(vault.get_claim(&orphan_hint)?.is_none());
        assert!(vault.search_text(stale_query, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn raw_claim_put_rejects_malformed_lexical_hint_claim() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let target = EntityId::now();
        let hint = EntityId::now();
        let body = crate::claim::ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(target),
            Value::from("not a typed lexical hint value"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let data = crate::claim::encode_claim_body(&body)?;

        let err = vault
            .batch()
            .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
            .commit()
            .expect_err("malformed lexical hint values must reject at the write door");
        assert_matches!(err, Error::InvalidClaimBody(_));
        assert!(vault.get_claim(&hint)?.is_none());
        Ok(())
    }

    #[test]
    fn raw_lexical_hint_put_rejects_non_lh_prefixed_id() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let target = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"subject",
        )?;
        let target_body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        seed_raw_claim_record(&vault, &target, target_body)?;

        let mut raw = [0x44; ENTITY_ID_LEN];
        raw[ENTITY_ID_LEN - 1] &= 0x7F;
        let hint =
            EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid test id"))?;
        assert!(
            !hint
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
        );
        let mut body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(target),
            crate::claim::encode_lexical_query_hint_value(&target, "non lh id hint"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.stale = true;
        let data = crate::claim::encode_claim_body(&body)?;

        let err = vault
            .batch()
            .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
            .commit()
            .expect_err("lexical.query_hint records must live under derived LH ids");
        assert_matches!(err, Error::InvalidClaimBody(_));
        assert!(vault.get_claim(&hint)?.is_none());
        Ok(())
    }

    #[test]
    fn lexical_hint_write_door_rejects_self_and_synthetic_targets() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "self target")?;
        let mut self_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(self_hint),
            crate::claim::encode_lexical_query_hint_value(&self_hint, "self target"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        self_body.stale = true;
        let self_data = crate::claim::encode_claim_body(&self_body)?;
        let mut wtxn = vault.store.env.write_txn()?;
        let err = apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: self_hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: self_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            }],
        )
        .expect_err("self-target lexical hints must reject");
        assert_matches!(err, Error::InvalidClaimBody(_));
        drop(wtxn);
        assert!(vault.get_claim(&self_hint)?.is_none());

        let source = EntityId::now();
        let source_body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(EntityId::now()),
            Value::from("sencha"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        seed_raw_claim_record(&vault, &source, source_body)?;
        let synthetic_target = lexical_query_hint_claim_id(&source, "synthetic target")?;
        let mut synthetic_target_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(source),
            crate::claim::encode_lexical_query_hint_value(&source, "synthetic target"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        synthetic_target_body.stale = true;
        seed_raw_claim_record(&vault, &synthetic_target, synthetic_target_body)?;
        let outer_hint = lexical_query_hint_claim_id(&source, "outer target")?;
        let mut synthetic_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(synthetic_target),
            crate::claim::encode_lexical_query_hint_value(&synthetic_target, "outer target"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        synthetic_body.stale = true;
        let synthetic_data = crate::claim::encode_claim_body(&synthetic_body)?;
        let mut wtxn = vault.store.env.write_txn()?;
        let err = apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: outer_hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(22, 22),
                learned_at: 23,
                data: synthetic_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            }],
        )
        .expect_err("lexical hints targeting synthetic hints must reject");
        assert_matches!(err, Error::InvalidClaimBody(_));
        drop(wtxn);
        assert!(vault.get_claim(&outer_hint)?.is_none());
        Ok(())
    }

    #[test]
    fn lexical_hint_write_door_rejects_non_claim_targets() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let target = EntityId::now();
        vault.put_entity(
            &target,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"not a claim",
        )?;
        let hint = lexical_query_hint_claim_id(&target, "non claim target")?;
        let mut body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(target),
            crate::claim::encode_lexical_query_hint_value(&target, "non claim target"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.stale = true;
        let data = crate::claim::encode_claim_body(&body)?;

        let mut wtxn = vault.store.env.write_txn()?;
        let err = apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            }],
        )
        .expect_err("lexical hints must target claim records");
        assert_matches!(err, Error::InvalidClaimBody(_));
        drop(wtxn);
        assert!(vault.get_claim(&hint)?.is_none());
        Ok(())
    }

    #[test]
    fn legacy_cyclic_lexical_hints_delete_without_recursive_cleanup() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let hint_a = lexical_query_hint_claim_id(&EntityId::now(), "cycle a")?;
        let hint_b = lexical_query_hint_claim_id(&EntityId::now(), "cycle b")?;
        let mut body_a = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(hint_b),
            crate::claim::encode_lexical_query_hint_value(&hint_b, "cycle a"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body_a.stale = true;
        let mut body_b = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(hint_a),
            crate::claim::encode_lexical_query_hint_value(&hint_a, "cycle b"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body_b.stale = true;
        seed_raw_claim_record(&vault, &hint_a, body_a)?;
        seed_raw_claim_record(&vault, &hint_b, body_b)?;
        seed_claim_of_edge(&vault, &hint_a, &hint_b)?;
        seed_claim_of_edge(&vault, &hint_b, &hint_a)?;

        vault.batch().delete(&hint_a).commit()?;

        assert!(vault.get_claim(&hint_a)?.is_none());
        assert!(vault.get_claim(&hint_b)?.is_none());

        let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "legacy self")?;
        let mut self_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(self_hint),
            crate::claim::encode_lexical_query_hint_value(&self_hint, "legacy self"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        self_body.stale = true;
        seed_raw_claim_record(&vault, &self_hint, self_body)?;
        seed_claim_of_edge(&vault, &self_hint, &self_hint)?;

        vault.batch().delete(&self_hint).commit()?;

        assert!(vault.get_claim(&self_hint)?.is_none());
        Ok(())
    }

    #[test]
    fn replicated_lexical_hint_put_indexes_query_text_and_deletes_without_claim_of() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        let query = "replicated rematerialized hint";
        let hint = lexical_query_hint_claim_id(&claim, query)?;
        let mut body = crate::claim::ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(claim),
            crate::claim::encode_lexical_query_hint_value(&claim, query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.stale = true;
        let data = crate::claim::encode_claim_body(&body)?;
        assert!(
            vault.claims_for_subject(&claim)?.is_empty(),
            "regression fixture starts without a hint ClaimOf edge"
        );
        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            }],
        )?;
        wtxn.commit()?;

        assert!(
            !has_pending_embedding_marker(&vault, &hint)?,
            "replayed lexical hint side claims must not be queued for embeddings"
        );
        assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
        assert_eq!(
            vault.search_text(query, 10)?.first().map(|hit| hit.id),
            Some(claim)
        );

        vault.batch().delete(&claim).commit()?;

        assert!(vault.get_claim(&hint)?.is_none());
        assert!(vault.search_text(query, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn replicated_lexical_hint_put_defers_until_target_claim_materializes() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"subject",
        )?;

        let claim = EntityId::from_bytes([0x7A; ENTITY_ID_LEN])
            .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
        let query = "deferred replay lexical hint";
        let hint = lexical_query_hint_claim_id(&claim, query)?;
        let mut hint_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(claim),
            crate::claim::encode_lexical_query_hint_value(&claim, query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        hint_body.stale = true;
        let hint_data = crate::claim::encode_claim_body(&hint_body)?;

        let claim_body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let claim_data = crate::claim::encode_claim_body(&claim_body)?;

        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: hint,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: test_time_range(20, 20),
                    learned_at: 21,
                    data: hint_data,
                    allow_maintenance: true,
                    allow_reserved_predicate: true,
                },
                BatchOp::Put {
                    id: claim,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: test_time_range(10, 10),
                    learned_at: 11,
                    data: claim_data,
                    allow_maintenance: true,
                    allow_reserved_predicate: true,
                },
            ],
        )?;
        wtxn.commit()?;

        assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
        assert_eq!(
            vault.search_text(query, 10)?.first().map(|hit| hit.id),
            Some(claim)
        );
        Ok(())
    }

    #[test]
    fn bm25_drops_orphan_and_inactive_lexical_hint_postings() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let missing_hint_query = "missingrowuniquealpha";
        let missing_hint = lexical_query_hint_claim_id(&EntityId::now(), missing_hint_query)?;
        vault
            .batch()
            .text(&missing_hint, &[("query_hint", missing_hint_query)])
            .commit()?;
        assert_eq!(
            vault
                .search_text(missing_hint_query, 10)?
                .first()
                .map(|hit| hit.id),
            Some(missing_hint)
        );

        let missing_claim = EntityId::now();
        let orphan_query = "orphanrowuniquebeta";
        let orphan_hint = lexical_query_hint_claim_id(&missing_claim, orphan_query)?;
        let mut orphan_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(missing_claim),
            crate::claim::encode_lexical_query_hint_value(&missing_claim, orphan_query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        orphan_body.stale = true;
        seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
        vault
            .batch()
            .text(&orphan_hint, &[("query_hint", orphan_query)])
            .commit()?;
        assert!(vault.search_text(orphan_query, 10)?.is_empty());

        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;
        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        let inactive_query = "inactiverowuniquegamma";
        let inactive_hint = lexical_query_hint_claim_id(&claim, inactive_query)?;
        let mut inactive_body = ClaimBody::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(claim),
            crate::claim::encode_lexical_query_hint_value(&claim, inactive_query),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Superseded,
        );
        inactive_body.stale = true;
        seed_raw_claim_record(&vault, &inactive_hint, inactive_body)?;
        vault
            .batch()
            .text(&inactive_hint, &[("query_hint", inactive_query)])
            .commit()?;
        assert!(vault.search_text(inactive_query, 10)?.is_empty());

        let soft_deleted_query = "softdeletedrowuniquedelta";
        let soft_deleted_hint = lexical_query_hint_claim_id(&claim, soft_deleted_query)?;
        let header = EntityMetadataHeader {
            entity_type: ENTITY_TYPE_CLAIM,
            occurred_start: 30,
            occurred_end: 30,
            learned_at: 31,
        };
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN);
        payload.push(header.entity_type);
        payload.extend_from_slice(&header.occurred_start.to_be_bytes());
        payload.extend_from_slice(&header.occurred_end.to_be_bytes());
        payload.extend_from_slice(&header.learned_at.to_be_bytes());
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, soft_deleted_hint.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &soft_deleted_hint);
        vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
        wtxn.commit()?;
        vault
            .batch()
            .text(&soft_deleted_hint, &[("query_hint", soft_deleted_query)])
            .commit()?;
        assert!(vault.search_text(soft_deleted_query, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn retained_lexical_hint_reput_clears_stale_vector_and_embedding_state() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let write_hints = || -> Result<()> {
            let candidate = ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.9,
            );
            vault
                .batch()
                .claim_candidate_with_lexical_hints(
                    &claim,
                    candidate,
                    &envelope,
                    test_time_range(10, 10),
                    11,
                    &["retained vector cleanup hint"],
                )
                .commit()
        };

        write_hints()?;
        let hint = lexical_query_hint_claim_id(&claim, "retained vector cleanup hint")?;
        let err = vault
            .put_vector(&hint, &[1.0, 0.0, 0.0, 0.0])
            .expect_err("synthetic lexical hint vectors must reject");
        assert_matches!(err, Error::InvalidClaimBody(_));
        assert!(vault.get_vector(&hint)?.is_none());
        assert!(
            !vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
                .iter()
                .any(|hit| hit.id == hint),
            "rejected vector writes must never expose lexical hints"
        );

        seed_stale_vector_state(&vault, &hint, &[1.0, 0.0, 0.0, 0.0])?;
        overwrite_pending_embedding_marker(&vault, &hint, b"stale lexical hint marker")?;

        assert_eq!(
            vault.get_vector(&hint)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice())
        );
        assert!(raw_pending_embedding_marker(&vault, &hint)?.is_some());
        assert!(
            vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
                .iter()
                .any(|hit| hit.id == hint),
            "seeded stale vector must be reachable before the retained hint re-put"
        );

        write_hints()?;

        assert!(
            raw_pending_embedding_marker(&vault, &hint)?.is_none(),
            "retained lexical hint re-put must clear stale embedding marker state"
        );
        assert!(
            vault.get_vector(&hint)?.is_none(),
            "retained lexical hint re-put must delete stale vector rows"
        );
        assert!(
            !vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
                .iter()
                .any(|hit| hit.id == hint),
            "retained lexical hint must not remain reachable through vector search"
        );
        assert_eq!(
            vault
                .search_text("retained vector cleanup hint", 10)?
                .first()
                .map(|hit| hit.id),
            Some(claim),
            "lexical hint text must remain searchable after vector cleanup"
        );
        Ok(())
    }

    #[test]
    fn lh_prefixed_normal_ids_are_not_treated_as_synthetic_hints() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let normal_entity = lh_prefixed_id(0x11)?;
        vault.put_entity(
            &normal_entity,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"ordinary LH-prefixed entity",
        )?;
        vault
            .batch()
            .text(&normal_entity, &[("body", "ordinary LH text")])
            .commit()?;
        assert_eq!(
            vault
                .search_text("ordinary LH text", 10)?
                .first()
                .map(|hit| hit.id),
            Some(normal_entity)
        );
        vault.put_vector(&normal_entity, &[1.0, 0.0, 0.0, 0.0])?;
        assert_eq!(
            vault.get_vector(&normal_entity)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice())
        );

        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(2, 2);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 2, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 2, b"subject")?;

        let claim = lh_prefixed_id(0x22)?;
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &["normal LH source claim hint"],
            )
            .commit()?;

        assert_eq!(
            vault
                .search_text("normal LH source", 10)?
                .first()
                .map(|hit| hit.id),
            Some(claim)
        );
        Ok(())
    }

    #[test]
    fn claim_candidate_lexical_hint_ids_are_order_stable() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let write_hints = |hints: &[&str]| -> Result<()> {
            let candidate = ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.9,
            );
            vault
                .batch()
                .claim_candidate_with_lexical_hints(
                    &claim,
                    candidate,
                    &envelope,
                    test_time_range(10, 10),
                    11,
                    hints,
                )
                .commit()
        };

        write_hints(&["spring roadmap migration", "account recovery plan"])?;
        let mut first_hint_claims = vault.claims_for_subject(&claim)?;
        first_hint_claims.sort();
        assert_eq!(first_hint_claims.len(), 2);

        write_hints(&["account recovery plan", "spring roadmap migration"])?;
        let mut reordered_hint_claims = vault.claims_for_subject(&claim)?;
        reordered_hint_claims.sort();
        assert_eq!(reordered_hint_claims, first_hint_claims);
        assert!(reordered_hint_claims.iter().all(|hint_claim| {
            hint_claim
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
        }));

        let roadmap_hits = vault.search_text("spring roadmap migration", 10)?;
        assert_eq!(roadmap_hits.first().map(|hit| hit.id), Some(claim));
        assert!(
            !roadmap_hits
                .iter()
                .any(|hit| reordered_hint_claims.contains(&hit.id)),
            "reordered lexical hint docs must collapse to the source claim"
        );

        let recovery_hits = vault.search_text("account recovery plan", 10)?;
        assert_eq!(recovery_hits.first().map(|hit| hit.id), Some(claim));
        assert!(
            !recovery_hits
                .iter()
                .any(|hit| reordered_hint_claims.contains(&hit.id)),
            "reordered lexical hint docs must collapse to the source claim"
        );
        Ok(())
    }

    #[test]
    fn claim_candidate_lexical_hints_are_capped() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        let hints = [
            "hint zero",
            "hint one",
            "hint two",
            "hint three",
            "hint four",
            "hint five",
            "hint six",
            "hint seven",
            "hint eight",
            "hint nine",
        ];

        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &hints,
            )
            .commit()?;

        let hint_claims = vault.claims_for_subject(&claim)?;
        assert_eq!(
            hint_claims.len(),
            crate::claim::MAX_LEXICAL_QUERY_HINTS_PER_CLAIM
        );
        assert!(
            vault
                .search_text("seven", 10)?
                .iter()
                .any(|hit| hit.id == claim)
        );
        assert!(vault.search_text("nine", 10)?.is_empty());
        Ok(())
    }

    fn claim_candidate_fixture(
        vault: &Vault,
        value: &str,
    ) -> Result<(WriteEnvelope, ClaimCandidate)> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

        let envelope = test_write_envelope(actor)?;
        let candidate = ClaimCandidate::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from(value),
            0.9,
        );
        Ok((envelope, candidate))
    }

    fn commit_claim_candidate_with_value(
        vault: &Vault,
        claim: EntityId,
        value: &str,
    ) -> Result<()> {
        let (envelope, candidate) = claim_candidate_fixture(vault, value)?;
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()
    }

    fn commit_claim_candidate_fixture(vault: &Vault, claim: EntityId) -> Result<()> {
        commit_claim_candidate_with_value(vault, claim, "Alice")
    }

    #[test]
    fn claim_candidate_commit_writes_pending_embedding_marker_before_vector_exists() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();

        commit_claim_candidate_fixture(&vault, claim)?;

        assert!(vault.get_claim(&claim)?.is_some(), "claim must be durable");
        assert!(
            vault.get_vector(&claim)?.is_none(),
            "claim commit must not fabricate a vector row"
        );
        assert!(
            has_pending_embedding_marker(&vault, &claim)?,
            "claim commit must mark embedding as pending"
        );
        Ok(())
    }

    #[test]
    fn vector_fill_clears_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_fixture(&vault, claim)?;
        let token = pending_embedding_token(&vault, &claim)?;

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
            .commit()?;

        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice())
        );
        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "vector fill must clear the pending marker"
        );
        assert!(
            raw_pending_embedding_marker(&vault, &claim)?.is_none(),
            "token-proven vector fill must remove durable marker state"
        );
        Ok(())
    }

    #[test]
    fn duplicate_vector_fill_keeps_pending_embedding_marker_cleared() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_fixture(&vault, claim)?;
        let token = pending_embedding_token(&vault, &claim)?;

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
            .commit()?;
        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
            .commit()?;

        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "duplicate fills must be idempotent"
        );
        assert_eq!(
            vault
                .query()
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
                .run()?
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn plain_vector_fill_keeps_current_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_fixture(&vault, claim)?;
        let token = pending_embedding_token(&vault, &claim)?;

        vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice())
        );
        assert_eq!(
            pending_embedding_token(&vault, &claim)?,
            token,
            "un-tokened vector fills cannot prove they embedded the current claim body"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replicated_claim_materialization_writes_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        let body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(EntityId::now()),
            Value::from("replicated Alice"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let data = crate::claim::encode_claim_body(&body)?;

        vault
            .batch()
            .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
            .commit()?;

        assert!(
            has_pending_embedding_marker(&vault, &claim)?,
            "replicated claim materialization must request embedding"
        );
        assert!(
            !pending_embedding_token(&vault, &claim)?.is_empty(),
            "replicated marker must carry a body token"
        );
        Ok(())
    }

    #[test]
    fn stale_vector_fill_does_not_clear_or_overwrite_newer_claim_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_with_value(&vault, claim, "Alice")?;
        let old_token = pending_embedding_token(&vault, &claim)?;

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &old_token)
            .commit()?;
        commit_claim_candidate_with_value(&vault, claim, "Bob")?;
        let new_token = pending_embedding_token(&vault, &claim)?;
        assert_ne!(
            old_token, new_token,
            "claim body overwrite must mint a new token"
        );

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &old_token)
            .commit()?;

        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice()),
            "stale fill must not overwrite the current vector row"
        );
        assert_eq!(
            pending_embedding_token(&vault, &claim)?,
            new_token,
            "stale fill must leave the newer marker token pending"
        );

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &new_token)
            .commit()?;
        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "current-token fill must clear the marker"
        );
        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([0.0, 1.0, 0.0, 0.0].as_slice())
        );
        Ok(())
    }

    #[test]
    fn plain_vector_fill_does_not_clear_stale_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_with_value(&vault, claim, "Alice")?;
        let old_token = pending_embedding_token(&vault, &claim)?;

        commit_claim_candidate_with_value(&vault, claim, "Bob")?;
        let new_token = pending_embedding_token(&vault, &claim)?;
        assert_ne!(
            old_token, new_token,
            "claim body overwrite must mint a new token"
        );
        overwrite_pending_embedding_marker(&vault, &claim, &old_token)?;
        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "stale marker token must not report as current pending work"
        );

        vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice())
        );
        assert_eq!(
            raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
            Some(old_token.as_slice()),
            "plain vector fills must not clear stale markers by id alone"
        );
        Ok(())
    }

    #[test]
    fn plain_vector_fill_after_claim_overwrite_keeps_newer_pending_embedding_marker() -> Result<()>
    {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_with_value(&vault, claim, "Alice")?;
        let old_token = pending_embedding_token(&vault, &claim)?;

        commit_claim_candidate_with_value(&vault, claim, "Bob")?;
        let new_token = pending_embedding_token(&vault, &claim)?;
        assert_ne!(
            old_token, new_token,
            "claim body overwrite must mint a new token"
        );

        vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice()),
            "legacy vector path still writes the row"
        );
        assert_eq!(
            pending_embedding_token(&vault, &claim)?,
            new_token,
            "un-tokened vector fills must not clear a newer pending marker"
        );
        assert_eq!(
            raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
            Some(new_token.as_slice()),
            "the durable marker row must remain for the current claim body"
        );
        Ok(())
    }

    #[test]
    fn same_batch_claim_then_vector_clears_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
            .commit()?;

        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "same-batch vector after claim materialization proves freshness"
        );
        assert!(
            raw_pending_embedding_marker(&vault, &claim)?.is_none(),
            "same-batch vector after claim must remove durable marker state"
        );
        Ok(())
    }

    #[test]
    fn same_batch_delete_clears_pending_embedding_token_cache_before_plain_vector() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .delete(&claim)
            .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
            .commit()?;

        assert!(
            vault.get_claim(&claim)?.is_none(),
            "delete must remove the same-batch claim materialization"
        );
        assert_eq!(
            vault.get_vector(&claim)?.as_deref(),
            Some([1.0, 0.0, 0.0, 0.0].as_slice()),
            "delete must not leave a stale same-batch token that drops later vectors"
        );
        assert!(
            raw_pending_embedding_marker(&vault, &claim)?.is_none(),
            "delete must clear durable pending marker state"
        );
        Ok(())
    }

    #[test]
    fn same_batch_vector_then_claim_leaves_pending_embedding_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

        vault
            .batch()
            .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
            .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
            .commit()?;

        assert!(
            has_pending_embedding_marker(&vault, &claim)?,
            "vector before claim materialization cannot prove it embedded the claim"
        );
        Ok(())
    }

    #[test]
    fn soft_delete_removes_pending_embedding_state_for_claim_shell() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = EntityId::now();
        commit_claim_candidate_fixture(&vault, claim)?;
        assert!(has_pending_embedding_marker(&vault, &claim)?);

        let outcome = vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

        assert!(outcome.existed);
        assert!(
            !has_pending_embedding_marker(&vault, &claim)?,
            "soft-erased header-only claims must not remain pending"
        );
        assert!(
            raw_pending_embedding_marker(&vault, &claim)?.is_none(),
            "soft delete must remove the durable marker row, not only hide API-visible pending state"
        );
        Ok(())
    }

    #[test]
    fn raw_public_batch_put_rejects_claim_without_write_envelope() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let subject = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from("Alice"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::UserStated);
        let data = crate::claim::encode_claim_body(&body)?;

        let batch_claim = EntityId::now();
        let err = vault
            .batch()
            .put(
                &batch_claim,
                ENTITY_TYPE_CLAIM,
                test_time_range(1, 1),
                2,
                &data,
            )
            .commit()
            .expect_err("raw batch claim put must require WriteEnvelope");
        assert!(matches!(
            err,
            Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
        ));
        assert!(vault.get_claim(&batch_claim)?.is_none());

        let txn_claim = EntityId::now();
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put(
                        &txn_claim,
                        ENTITY_TYPE_CLAIM,
                        test_time_range(1, 1),
                        2,
                        &data,
                    )
                    .apply(wtxn)
            })
            .expect_err("raw transaction-batch claim put must require WriteEnvelope");
        assert!(matches!(
            err,
            Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
        ));
        assert!(vault.get_claim(&txn_claim)?.is_none());
        Ok(())
    }

    #[test]
    fn raw_public_put_allows_legacy_code_revision_claim_compatibility() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let subject = EntityId::now();
        let mut body = ClaimBody::new(
            "code.revision",
            ClaimSubject::Entity(subject),
            Value::from("finalized"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Generated);
        let data = crate::claim::encode_claim_body(&body)?;

        let claim = EntityId::now();
        vault.put_entity(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)?;

        let stored = vault.get_claim(&claim)?.expect("legacy claim stored");
        assert_eq!(stored.predicate, "code.revision");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        Ok(())
    }

    #[test]
    fn claim_candidate_overwrite_reconciles_claim_of_edges() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = EntityId::now();
        let subject_a = EntityId::now();
        let subject_b = EntityId::now();
        let edge_source = EntityId::now();
        let edge_target = EntityId::now();
        let occurred = test_time_range(1, 1);
        for (id, body) in [
            (actor, b"actor".as_slice()),
            (subject_a, b"subject-a".as_slice()),
            (subject_b, b"subject-b".as_slice()),
            (edge_source, b"edge-source".as_slice()),
            (edge_target, b"edge-target".as_slice()),
        ] {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred, 1, body)?;
        }

        let claim = EntityId::now();
        let envelope = test_write_envelope(actor)?;
        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    "profile.name",
                    ClaimSubject::Entity(subject_a),
                    Value::from("Alice"),
                    0.9,
                ),
                &envelope,
                test_time_range(10, 10),
                11,
            )
            .commit()?;
        assert_eq!(vault.claims_for_subject(&subject_a)?, vec![claim]);

        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    "profile.name",
                    ClaimSubject::Entity(subject_b),
                    Value::from("Bob"),
                    0.8,
                ),
                &envelope,
                test_time_range(12, 12),
                13,
            )
            .commit()?;
        assert!(vault.claims_for_subject(&subject_a)?.is_empty());
        assert_eq!(vault.claims_for_subject(&subject_b)?, vec![claim]);

        let edge_subject = ClaimSubject::Edge {
            source: edge_source,
            kind: EdgeKind::Supports,
            target: edge_target,
        };
        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    "graph.observation",
                    edge_subject,
                    Value::from("supports"),
                    0.7,
                ),
                &envelope,
                test_time_range(14, 14),
                15,
            )
            .commit()?;
        assert!(vault.claims_for_subject(&subject_b)?.is_empty());
        let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
        assert_eq!(stored.subject, edge_subject);
        assert!(
            vault
                .edges_out(&claim)?
                .iter()
                .all(|edge| edge.kind != EdgeKind::ClaimOf),
            "edge-subject overwrite must remove stale ClaimOf rows"
        );
        Ok(())
    }

    #[test]
    fn public_timestamped_builder_rejects_over_provenanced_edge() -> Result<()> {
        let fixture = provenanced_edge_fixture()?;
        let vault = &fixture.vault;
        let src = fixture.edge.source;
        let kind = fixture.edge.kind;
        let tgt = fixture.edge.target;
        let vad = Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        };

        let (before_out, before_in) = raw_edge_values(vault, &fixture.edge)?;
        let before_out = before_out.expect("provenanced edge");
        assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
        assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

        let err = vault
            .batch()
            .edge_with_created_at(&src, kind, &tgt, 0.5, 2_000)
            .commit()
            .expect_err("batch edge_with_created_at must reject");
        assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at");
        assert_raw_edge_unchanged(
            vault,
            &fixture.edge,
            &before_out,
            "batch edge_with_created_at",
        )?;

        let err = vault
            .batch()
            .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_001, vad)
            .commit()
            .expect_err("batch edge_with_created_at_and_vad must reject");
        assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at_and_vad");
        assert_raw_edge_unchanged(
            vault,
            &fixture.edge,
            &before_out,
            "batch edge_with_created_at_and_vad",
        )?;

        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .edge_with_created_at(&src, kind, &tgt, 0.5, 2_002)
                    .apply(wtxn)
            })
            .expect_err("batch_in edge_with_created_at must reject");
        assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at");
        assert_raw_edge_unchanged(
            vault,
            &fixture.edge,
            &before_out,
            "batch_in edge_with_created_at",
        )?;

        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_003, vad)
                    .apply(wtxn)
            })
            .expect_err("batch_in edge_with_created_at_and_vad must reject");
        assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at_and_vad");
        assert_raw_edge_unchanged(
            vault,
            &fixture.edge,
            &before_out,
            "batch_in edge_with_created_at_and_vad",
        )?;

        let claim = vault
            .get_claim(&fixture.claim_id)?
            .expect("provenance claim readable");
        assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
        Ok(())
    }

    #[test]
    fn public_timestamped_builder_accepts_over_bare_edge() -> Result<()> {
        let (dir, vault) = open_test_vault();
        let _dir = dir;
        let src = EntityId::now();
        let tgt = EntityId::now();
        let absent_tgt = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
        vault.put_entity(&absent_tgt, ENTITY_TYPE_PERSON, occurred, 1, b"absent")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

        let bare_edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
        vault
            .batch()
            .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.5, 2_000)
            .commit()?;
        let (bare_out, bare_in) = raw_edge_values(&vault, &bare_edge)?;
        let bare_out = bare_out.expect("bare edge");
        assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN);
        assert_eq!(bare_in.as_deref(), Some(bare_out.as_slice()));

        let absent_edge = EdgeRef::new(src, EdgeKind::About, absent_tgt);
        vault
            .batch()
            .edge_with_created_at_and_vad(
                &src,
                EdgeKind::About,
                &absent_tgt,
                0.5,
                2_001,
                Vad::NEUTRAL,
            )
            .commit()?;
        let (absent_out, absent_in) = raw_edge_values(&vault, &absent_edge)?;
        let absent_out = absent_out.expect("formerly absent edge");
        assert_eq!(absent_out.len(), EDGE_VALUE_SEMANTIC_LEN);
        assert_eq!(absent_in.as_deref(), Some(absent_out.as_slice()));
        Ok(())
    }

    #[test]
    fn public_timestamped_builder_keeps_structural_edge_layout() -> Result<()> {
        let (dir, vault) = open_test_vault();
        let _dir = dir;
        let child = EntityId::now();
        let parent = EntityId::now();
        let occurred = test_time_range(1, 1);
        vault.put_entity(&child, ENTITY_TYPE_TASK, occurred, 1, b"child")?;
        vault.put_entity(&parent, ENTITY_TYPE_TASK, occurred, 1, b"parent")?;

        vault
            .batch()
            .edge_with_created_at(&child, EdgeKind::ChildOf, &parent, 0.5, 2_000)
            .commit()?;

        let edge = EdgeRef::new(child, EdgeKind::ChildOf, parent);
        let (out, inn) = raw_edge_values(&vault, &edge)?;
        let out = out.expect("structural edge");
        assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
        assert_eq!(inn.as_deref(), Some(out.as_slice()));

        let err = vault
            .batch()
            .edge_with_created_at_and_vad(
                &child,
                EdgeKind::ChildOf,
                &parent,
                0.5,
                2_001,
                Vad {
                    valence: 0.1,
                    arousal: 0.2,
                    dominance: 0.3,
                },
            )
            .commit()
            .expect_err("structural edge must reject VAD payload");
        assert!(
            matches!(
                err,
                Error::InvariantViolation("structural edges do not carry VAD")
            ),
            "expected structural VAD rejection, got {err:?}"
        );
        assert_raw_edge_unchanged(&vault, &edge, &out, "structural VAD rejection")?;
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replay_edge_with_created_at_accepts_bare_over_provenanced() -> Result<()> {
        let fixture = provenanced_edge_fixture()?;
        let vault = &fixture.vault;
        let src = fixture.edge.source;
        let kind = fixture.edge.kind;
        let tgt = fixture.edge.target;
        let (before_out, _) = raw_edge_values(vault, &fixture.edge)?;
        assert_eq!(
            before_out.expect("provenanced edge").len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
        );

        vault.with_write_txn(|wtxn| {
            apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![BatchOp::EdgeWithCreatedAt {
                    src,
                    kind,
                    tgt,
                    weight: 0.91,
                    created_at: 3_000,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                }],
            )
        })?;

        let (after_out, after_in) = raw_edge_values(vault, &fixture.edge)?;
        let after_out = after_out.expect("replayed edge");
        assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_LEN);
        assert_eq!(after_in.as_deref(), Some(after_out.as_slice()));
        Ok(())
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; ENTITY_ID_LEN]).expect("test entity id")
    }

    fn child_of_edge(child: EntityId, parent: EntityId) -> BatchOp {
        BatchOp::Edge {
            src: child,
            kind: EdgeKind::ChildOf,
            tgt: parent,
            weight: 1.0,
            vad: Vad::NEUTRAL,
        }
    }

    #[test]
    fn child_of_overlay_orders_entity_clear_against_same_pair_edge() {
        let child = entity(0x41);
        let parent = entity(0x42);

        let edge_after_clear = ChildOfBatchOverlay::from_ops(&[
            BatchOp::Delete { id: child },
            child_of_edge(child, parent),
        ]);
        assert_eq!(
            edge_after_clear.final_edge_override(&child, &parent),
            Some(true),
            "a ChildOf edge re-added after clearing the child must win"
        );

        let clear_after_edge = ChildOfBatchOverlay::from_ops(&[
            child_of_edge(child, parent),
            BatchOp::Delete { id: child },
        ]);
        assert_eq!(
            clear_after_edge.final_edge_override(&child, &parent),
            Some(false),
            "clearing the child after touching the ChildOf pair must win"
        );
    }
}
