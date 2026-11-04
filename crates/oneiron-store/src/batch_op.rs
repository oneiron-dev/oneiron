//! The batch op vocabulary: one write a batch applies, as the engine's batch
//! builder records it.

use oneiron_base::edge::{EdgeKind, EdgeProvenanceFlags};
use oneiron_contracts::affect::Vad;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

use crate::embedding_vocabulary::{EmbeddingProvenance, InputKind, TEXT_HASH_LEN};
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// One op of a batch.
#[derive(Clone)]
pub enum BatchOp {
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
        /// Who computed the vector; `None` when the caller does not say.
        provenance: Option<EmbeddingProvenance>,
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
    /// OF-370: one host-computed vector of `id` in declared embedding space `space`, of input
    /// `kind`; a text row carries the hash of the text it embeds. Only a room stages it (the
    /// session media door, `Vault::put_session_media_vector`), so an off-record media write
    /// stays in the room; promotion replays it into base, where a binding the room no longer
    /// has leaves it to the backfill.
    MediaVector {
        space: String,
        id: EntityId,
        kind: InputKind,
        text_hash: Option<[u8; TEXT_HASH_LEN]>,
        vector: Vec<f32>,
        /// The device and runtime that computed it, stored beside it outside the space
        /// identity (FIX 7796); `None` for a vector a caller supplied.
        provenance: Option<EmbeddingProvenance>,
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
    /// Constructed only by the engine's `BatchBuilder::commitment_gap_decay`.
    /// It is an op rather than a loop
    /// of status verbs because a sweep that lapsed half its selection would
    /// leave the other half owed with its due row already consumed; the
    /// caller-owned transaction is what makes the set atomic.
    CommitmentGapDecay {
        ids: Vec<EntityId>,
        envelope: WriteEnvelope,
        learned_at: u64,
    },
}
