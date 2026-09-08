//! Batch op vocabulary and shared op constructors.

use crate::affect::Vad;
use crate::edge::{EdgeKind, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

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
        /// owner-controlled claim puts and the Vault skill-claim
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
pub(in crate::batch) fn replicated_put_op(
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
