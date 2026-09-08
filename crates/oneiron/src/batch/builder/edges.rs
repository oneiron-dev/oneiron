//! Edge/vector/text/phonetic/delete doors plus edge-kind gate helpers.

use super::super::*;
use super::BatchBuilder;
use super::ops::capture_invalid_vector_component;

use crate::affect::Vad;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;

impl BatchBuilder<'_> {
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
}
