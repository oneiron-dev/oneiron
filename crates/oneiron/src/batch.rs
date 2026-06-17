use std::collections::{HashMap, HashSet, VecDeque};
use std::str;

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::Vault;
use crate::error::{Error, Result};
use crate::limits::{ERR_CHILD_OF_CYCLE_CHECK, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    DecodedEdgeValue, EDGE_KEY_LEN, EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
    EDGE_VALUE_STRUCTURAL_LEN, ENTITY_ID_LEN, EdgeKind, EdgeProvenanceFlags, EntityId, TimeRange,
    Vad, decode_edge_value_for_kind, encode_edge_value, short_id_prefix, validate_edge_weight,
    validate_entity_type, validate_public_entity_type,
};

pub(crate) const ENTITY_TYPE_OFFSET: usize = 0;
pub(crate) const ENTITY_OCCURRED_START_OFFSET: usize = 1;
pub(crate) const ENTITY_OCCURRED_END_OFFSET: usize = 9;
pub(crate) const ENTITY_LEARNED_AT_OFFSET: usize = 17;
pub(crate) const ENTITY_BODY_OFFSET: usize = 25;
pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;
pub(crate) const SHORT_ID_COUNTER_LEN: usize = 8;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EdgeValueFields {
    pub(crate) weight: f32,
    pub(crate) created_at: u64,
    pub(crate) vad: Vad,
    pub(crate) provenance: Option<EdgeProvenanceFlags>,
}

impl EdgeValueFields {
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
        /// registry-only [`validate_entity_type`] gate (which permits the
        /// engine-authored maintenance band, e.g. REDACTION_AUDIT = 120)
        /// instead of the public [`validate_public_entity_type`] gate. Only
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
    Vector {
        id: EntityId,
        vector: Vec<f32>,
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
/// `ReservedPredicate`). `apply_put` still runs the registry type-byte gate
/// and the full D17/D18 CLAIM body validation on every op built here.
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
            && let Err(e) = validate_public_entity_type(entity_type)
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

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for CRDT→LMDB rematerialization. It admits BOTH
    /// engine-authored bands that the public [`put`](Self::put) gate rejects:
    ///
    /// * the maintenance type-byte band (REDACTION_AUDIT = 120), validated
    ///   via the registry-only [`validate_entity_type`] gate so GDPR receipts
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
            && let Err(e) = validate_entity_type(entity_type)
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
}

impl<'a> TxnBatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
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

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for Observer B's CRDT→LMDB rematerialization. It
    /// admits BOTH engine-authored bands that the public [`put`](Self::put)
    /// gate rejects:
    ///
    /// * the maintenance type-byte band (REDACTION_AUDIT = 120), validated
    ///   via the registry-only [`validate_entity_type`] gate in `apply_ops`
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

/// Applies a list of batch operations to an LMDB write transaction.
pub(crate) fn apply_ops(
    store: &Store,
    config: &crate::types::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<()> {
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;
    let mut text_manifest_checked = false;
    // Legacy (pre-symmetric-migration) graphs answer a vector refresh with a
    // full snapshot rebuild. Batched vector updates coalesce that into at
    // most ONE rebuild per transaction: once pending, per-op graph mutations
    // are skipped (the end-of-batch rebuild re-derives the graph from the
    // `vectors` DB) and the rebuild runs after the op loop (ONE-324 AC11).
    let mut pending_hnsw_rebuild = false;

    for op in ops {
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
                // `validate_public_entity_type`; the sync rematerialization path
                // sets `allow_maintenance` so REDACTION_AUDIT (120) receipts
                // survive CRDT→LMDB replay (registry-only `validate_entity_type`
                // still rejects genuinely unknown type bytes).
                if allow_maintenance {
                    validate_entity_type(entity_type)?;
                } else {
                    validate_public_entity_type(entity_type)?;
                }
                apply_put(
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
                )?;
            }
            BatchOp::Vector { id, vector } => {
                apply_vector(store, config, wtxn, id, &vector)?;
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
    ops.iter().any(|op| matches!(op, BatchOp::Text { .. }))
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
    // Clean secondary indexes unconditionally — they may exist even without an
    // entity record (e.g. text indexed via batch().text() without a preceding put()).
    crate::bm25::deindex_text(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    let had_vector = store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    let neighbors = delete_related_edges(store, wtxn, id)?;
    let mut had_graph_mutation = !neighbors.is_empty();

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

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok((false, had_vector, had_graph_mutation, neighbors));
    };
    had_graph_mutation = true;

    let (entity_type, occurred, learned_at) = parse_entity_metadata(entity_record)?;
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
    Ok((true, had_vector, had_graph_mutation, neighbors))
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
) -> Result<()> {
    // Type-byte validation runs in `apply_ops` (the public-vs-maintenance gate:
    // public writes reject the engine-authored maintenance band, the sync
    // rematerialization path admits it via `allow_maintenance`). apply_put is
    // reached only after that gate, so it does not re-validate the type byte.
    //
    // D18: every type-0 (CLAIM) write — put_entity, both batch builders, and
    // sync replay — is structurally validated before any byte is staged.
    // Bodies of all other type bytes stay opaque at the storage layer.
    if entity_type == crate::types::ENTITY_TYPE_CLAIM {
        let body = crate::claim::validate_claim_body_and_decode(data, allow_reserved_predicate)?;
        if !replicated {
            let ceiling = crate::claim::read_source_trust_ceiling(store, &*wtxn)?;
            crate::claim::check_claim_source_trust(&body, &ceiling)?;
        }
    }
    if occurred.start > occurred.end {
        return Err(Error::InvalidTimeRange {
            start: occurred.start,
            end: occurred.end,
        });
    }
    // Maintenance-band kinds (REDACTION_AUDIT = 120) carry no short ID (registry
    // `short_id_prefix: None`), matching the engine's direct receipt writer.
    // Only the internal sync path reaches here with such a kind (public puts are
    // rejected in `apply_ops`); skip short-id planning, which would otherwise
    // fail with `InvalidEntityType` on the missing prefix.
    let short_id_plan = if short_id_prefix(entity_type).is_ok() {
        Some(plan_short_id_update(store, &*wtxn, &id, entity_type, data)?)
    } else {
        None
    };

    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(old_record)?;
        // ONE-1141 (ARCH-0031 amendment): "no replicated overwrite ever
        // leaves loser postings live" — when an LWW replicated overwrite
        // changes the stored body, the loser document's BM25F postings are
        // removed in the SAME transaction as the overwrite, BEFORE the
        // displacement block below. Text is a LOCAL `BatchOp::Text` family
        // that sync does not carry, so without this the losing node keeps
        // serving its pre-merge terms. Token source: the body-independent
        // `text_forward` row — `deindex_text` reads only it and is a no-op
        // for never-indexed entities. Byte-compare guard: a same-bytes
        // replay (idempotent re-import / reconnect echo, or the winner node
        // re-receiving its own winning value) must NOT touch the index, so
        // a converged winner's postings survive the merge; metadata-only
        // (occurred/learned) changes are not body changes. Local overwrites
        // stay out of scope: the local writer owns both the put and its
        // `BatchOp::Text` re-index (`index_text` self-deindexes stale rows).
        let replicated_body_changed =
            replicated && old_record[ENTITY_METADATA_HEADER_LEN..] != *data;
        if old_type != entity_type {
            return Err(Error::EntityTypeImmutable {
                id,
                existing: old_type,
                attempted: entity_type,
            });
        }
        if replicated_body_changed {
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
    }
    Ok(())
}

fn apply_vector(
    store: &Store,
    config: &crate::types::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    vector: &[f32],
) -> Result<()> {
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
    Ok(())
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
        if let Some(parent) = parents.iter().next() {
            if child == *parent {
                return Err(Error::CycleDetected);
            }
            if would_create_child_of_cycle(store, rtxn, child_of_overlay, &child, parent)? {
                return Err(Error::CycleDetected);
            }
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

fn child_of_prefix(id: &EntityId) -> [u8; 17] {
    let mut prefix = [0u8; 17];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::ChildOf as u8;
    prefix
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
    let short_id = format!("{}{}", short_id_prefix(entity_type)?, next);
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

    let (short_id_bytes, hash_bytes) = value.split_at(value.len() - 1);
    let short_id =
        str::from_utf8(short_id_bytes).map_err(|_| Error::CorruptedIndex("short id value"))?;
    Ok((short_id, hash_bytes[0]))
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
    use crate::claim::ClaimLifecycleStatus;
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    use crate::types::{ENTITY_TYPE_PERSON, EdgeActorClass, HnswConfig, VaultConfig};

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
}
