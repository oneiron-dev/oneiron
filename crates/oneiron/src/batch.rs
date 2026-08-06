use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::str;

pub mod export;
pub(crate) mod secret_scan;

use heed::RwTxn;
use rmpv::Value;
use xxhash_rust::{xxh3::xxh3_128, xxh32::xxh32};

use crate::Vault;
use crate::affect::Vad;
use crate::affect::{AffectTriggerValue, affect_trigger_claim_candidate};
use crate::claim::{
    ClaimLifecycleStatus, ClaimSubject, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED,
};
use crate::companion::{
    CompanionExportClassification, CompanionRecord, CompanionRecordKey, CompanionSubject,
    ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::companion::{CompanionLifecycleEvent, CompanionLifecycleEventKind};
use crate::edge::{
    DecodedEdgeValue, EDGE_KEY_LEN, EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
    EDGE_VALUE_STRUCTURAL_LEN, EdgeKind, EdgeProvenanceFlags, encode_edge_value,
    parse_strict_edge_record, validate_edge_weight,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, ErrorKind, Result};
use crate::habit::TaskRole;
use crate::limits::{ERR_CHILD_OF_CYCLE_CHECK, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::ppr;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG,
    ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMM_RECORD,
    ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
};
use crate::session_overlay::{JournalEntry, RouteTarget, SessionWriteRoute};
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

pub(crate) const ENTITY_TYPE_OFFSET: usize = 0;
pub(crate) const ENTITY_OCCURRED_START_OFFSET: usize = 1;
pub(crate) const ENTITY_OCCURRED_END_OFFSET: usize = 9;
pub(crate) const ENTITY_LEARNED_AT_OFFSET: usize = 17;
pub(crate) const ENTITY_BODY_OFFSET: usize = 25;
pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;
pub(crate) const SHORT_ID_COUNTER_LEN: usize = 8;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;
const ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE: &str = "raw claim put requires WriteEnvelope";
type CompanionRetiredHistoryOverlay = HashSet<(CompanionRecordKey, Vec<CompanionLifecycleEvent>)>;

fn is_relationship_end_scrub_value(value: &Value) -> bool {
    let Value::Map(entries) = value else {
        return false;
    };
    let mut has_kind = false;
    let mut has_private_memory_marker = false;
    let mut has_ended_at = false;
    for (key, value) in entries {
        match key.as_str() {
            Some("kind") => has_kind = value.as_str() == Some("relationship_ended"),
            Some("private_memory") => has_private_memory_marker = value.as_str() == Some("removed"),
            Some("ended_at") => has_ended_at = value.as_u64().is_some(),
            _ => {}
        }
    }
    has_kind && has_private_memory_marker && has_ended_at
}

fn is_retired_relationship_end_rescrub(
    existing: &CompanionRecord,
    record: &CompanionRecord,
) -> bool {
    existing.lifecycle == ClaimLifecycleStatus::Retracted
        && record.lifecycle == ClaimLifecycleStatus::Retracted
        && matches!(&existing.subject, CompanionSubject::Relationship { .. })
        && record.key() == existing.key()
        && record.lifecycle_events == existing.lifecycle_events
        && record.export_classification == existing.export_classification
        && is_relationship_end_scrub_value(&record.value)
}

fn conflict_claim_candidate(
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    confidence: f32,
) -> ClaimCandidate {
    ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence)
}

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

fn authority_observation_secs_for_write(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    candidate_secs: u64,
) -> Result<u64> {
    let floor_key = crate::authority::authority_first_seen_clock_sync_key();
    let previous_floor = store
        .sync_state
        .get(wtxn, floor_key)?
        .and_then(|raw| crate::authority::decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    let observed_secs = crate::authority::authority_observation_secs_for_domain(
        store.authority_clock_domain,
        previous_floor,
        candidate_secs,
    );
    if observed_secs != previous_floor {
        let encoded = crate::authority::encode_authority_first_seen_secs(observed_secs);
        store.sync_state.put(wtxn, floor_key, &encoded)?;
    }
    Ok(observed_secs)
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
        hub_sync_imported: false,
    }
}

fn capture_invalid_vector_component(validation_error: &mut Option<Error>, vector: &[f32]) {
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
        if self.validation_error.is_none()
            && let Err(e) = crate::edge::validate_public_edge_kind(kind)
        {
            self.validation_error = Some(e);
        }
    }

    /// Adds a graph edge write operation to the batch.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.capture_reserved_edge_kind(kind);
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
        self.capture_reserved_edge_kind(kind);
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
        self.capture_reserved_edge_kind(kind);
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
        self.capture_reserved_edge_kind(kind);
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

    // Only ppr/tests.rs still composes an edge through the owned-batch form;
    // the sync forward-remat healing write moved to the TxnBatchBuilder twin
    // below to share its mandate-check txn (ARCH-0055), leaving this dead in
    // non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
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
        if let Err(err) = preflight_gate_decisions_in_txn(
            &self.vault.store,
            &self.ops,
            &mut wtxn,
            &mut staged_gate_decisions,
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
        apply_ops(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            &mut wtxn,
            self.ops,
            text_index_trusted,
            false,
            true,
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
fn preflight_gate_decisions_in_txn(
    store: &Store,
    ops: &[BatchOp],
    wtxn: &mut RwTxn<'_>,
    staged_decisions: &mut Vec<crate::gate::RecordedClaimGateDecision>,
) -> Result<()> {
    if !contains_local_claim_put(ops) {
        return Ok(());
    }

    // #493 now owns this caller-provided transaction: gate receipts remain
    // atomic with phase-2 apply and metrics are emitted only after commit.
    // Run #498's entity write door in that SAME transaction before any gate
    // receipt is appended, so a closed off-record fence cannot leave a
    // decision behind when the later materialization is rejected.
    for op in ops {
        let id = match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => id,
            _ => continue,
        };
        crate::off_record::guard_off_record_entity_put(store, &*wtxn, id, false)?;
    }
    let policy = crate::gate::resolve_policy_manifest(store, &*wtxn)?;
    for op in ops {
        let mut recorded_decision = None;
        let result = match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && !*allow_reserved_predicate =>
            {
                crate::claim::validate_claim_body_and_decode(data, false).and_then(|body| {
                    crate::gate::check_claim_policy_for_write_with_record(
                        store,
                        wtxn,
                        id,
                        crate::gate::ClaimGateWrite {
                            body: &body,
                            envelope: None,
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
                })
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint,
                ..
            } if !*internal_lexical_query_hint => {
                let body = (**candidate).clone().into_claim_body(envelope);
                crate::gate::check_claim_policy_for_write_with_record(
                    store,
                    wtxn,
                    id,
                    crate::gate::ClaimGateWrite {
                        body: &body,
                        envelope: Some(envelope),
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
            }
            _ => Ok(()),
        };

        if let Some(decision) = recorded_decision {
            staged_decisions.push(decision);
        }
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
    }

    Ok(())
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

    fn capture_reserved_edge_kind(&mut self, kind: EdgeKind) {
        if self.validation_error.is_none()
            && let Err(e) = crate::edge::validate_public_edge_kind(kind)
        {
            self.validation_error = Some(e);
        }
    }

    /// Adds a graph edge write operation.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.capture_reserved_edge_kind(kind);
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
        self.capture_reserved_edge_kind(kind);
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
        self.capture_reserved_edge_kind(kind);
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
        apply_ops_with_gate_mode(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            wtxn,
            self.ops,
            text_index_trusted,
            gate_mode,
        )
    }
}

fn validate_public_raw_put(entity_type: u8, data: &[u8]) -> Result<()> {
    match entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            let body = crate::claim::validate_claim_body_and_decode(data, false)?;
            if body.source.is_some() && !is_legacy_raw_claim_compatibility_body(&body) {
                return Err(Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE));
            }
        }
        ENTITY_TYPE_SKILL => crate::skill::validate_skill_record_bytes(data)?,
        ENTITY_TYPE_AGENT_DEF => crate::agent_def::validate_agent_definition_bytes(data)?,
        _ => {}
    }
    Ok(())
}

fn validate_habit_checkin_body(data: &[u8]) -> Result<()> {
    match crate::habit::task_role_from_body_bytes(data)? {
        TaskRole::HabitCheckin => Ok(()),
        _ => Err(Error::InvalidTaskBody(
            "habit check-in writes require HabitCheckin role",
        )),
    }
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
        || entity_type != crate::registry::ENTITY_TYPE_CLAIM
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

struct LexicalHintTextIndexing<'a> {
    analyzer: &'a crate::analyzer::MultilingualAnalyzer,
    manifest_checked: &'a mut bool,
    trusted: bool,
}

fn materialize_lexical_query_hint_text_if_target_ready(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text_indexing: &mut LexicalHintTextIndexing<'_>,
    hint_id: EntityId,
    target: &EntityId,
    query_hint: String,
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
        if !text_indexing.trusted {
            return Err(Error::CorruptedIndex(
                "text index handshake bypassed on populated index",
            ));
        }
        if !*text_indexing.manifest_checked {
            crate::vault::ensure_text_index_manifest_matches_wtxn(
                store,
                wtxn,
                text_indexing.analyzer,
            )?;
            *text_indexing.manifest_checked = true;
        }
        crate::bm25::index_text(
            store,
            wtxn,
            text_indexing.analyzer,
            &hint_id,
            &[("query_hint".to_owned(), query_hint)],
        )?;
    }
    Ok(true)
}

fn materialize_lexical_query_hints_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text_indexing: &mut LexicalHintTextIndexing<'_>,
    target: &EntityId,
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
            text_indexing,
            hint_id,
            target,
            hint.query,
        )? {
            had_graph_mutation = true;
        }
    }
    Ok(had_graph_mutation)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApplyOpsGateMode {
    record_decisions: bool,
    persist_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
}

impl ApplyOpsGateMode {
    pub(crate) const fn new(record_decisions: bool, persist_pending_consent: bool) -> Self {
        Self {
            record_decisions,
            persist_pending_consent,
            include_source_in_gate_input: false,
            claim_gate_prechecked: false,
        }
    }

    pub(crate) const fn with_source_in_gate_input(mut self) -> Self {
        self.include_source_in_gate_input = true;
        self
    }

    /// Marks local CLAIM puts as already authorized in this transaction.
    /// Structural validation and materialization still run; only the duplicate
    /// gate evaluation in `apply_put` is skipped.
    const fn with_prechecked_claim_gate(mut self) -> Self {
        self.claim_gate_prechecked = true;
        self
    }
}

/// Materializes the already-authorized CLAIM puts from a session-bundle merge.
///
/// The narrow operation-shape check prevents the prechecked mode from being
/// reused as a general batch gate bypass. The caller must have evaluated every
/// body with `check_claim_policy_for_write_with_record` in this same `wtxn`.
pub(crate) fn apply_session_bundle_claim_puts(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
) -> Result<()> {
    if ops.iter().any(|op| {
        !matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                ..
            }
        )
    }) {
        return Err(Error::InvariantViolation(
            "session bundle claim batch contains a non-claim put",
        ));
    }
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        ApplyOpsGateMode::new(false, false).with_prechecked_claim_gate(),
    )
}

/// Applies a list of batch operations to an LMDB write transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "batch write plumbing keeps gate persistence modes explicit at call sites"
)]
pub(crate) fn apply_ops(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
) -> Result<()> {
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        ApplyOpsGateMode::new(record_gate_decisions, persist_gate_pending_consent),
    )
}

/// Why a base write transaction is allowed to touch the ids it touches
/// (ARCH-0052 D2, ONE-1728 K4). Exactly two arms: there is no grant type and
/// no test-mintable capability anywhere in this design.
///
/// * [`Self::Ordinary`] — every ordinary base write. An op referencing a live
///   session overlay's member is rejected at the decode point.
/// * [`Self::PromoteReplay`] — the promote transaction replaying one session's
///   own closure into base (ONE-1730). It exempts ONLY the ids of the session
///   whose promote this transaction is; every other live session's ids still
///   reject.
///
/// The exemption set is not carried on this type. It rides beside the origin
/// as the per-call `promote_member_of` channel on [`apply_ops_with_origin`],
/// whose closed form is supplied by the promote call site out of the session
/// identity already present in its own parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaseWriteOrigin {
    Ordinary,
    #[allow(
        dead_code,
        reason = "ONE-1730's promote transaction is the only legal constructor; \
                  the P4a guard defines its semantics and the oracle covers them"
    )]
    PromoteReplay,
}

/// Session-membership exemption channel carried beside a [`BaseWriteOrigin`].
///
/// Option contract (pinned by ONE-1728, bound by ONE-1730): `None` iff the
/// origin is [`BaseWriteOrigin::Ordinary`]; `Some` iff it is
/// [`BaseWriteOrigin::PromoteReplay`], in which case the predicate answers
/// "is this id a member of the session whose promote this transaction is".
/// Because the `Ordinary` wrapper passes `None` by construction, no state
/// inside the transaction can exempt another session's ids.
pub(crate) type PromoteMemberOf<'a> = Option<&'a dyn Fn(&EntityId) -> bool>;

/// The K4 taint guard, run at the decode point of ONE op inside the applying
/// write transaction (ARCH-0052 D2, ONE-1728).
///
/// **Enumeration IS the decode point.** The overlay-id-bearing op list is not a
/// separate table that could drift: it is this function's own exhaustive match
/// over [`BatchOp`], so a new id-bearing variant fails to compile until it names
/// its refs here. Raw base CLAIM puts hide their subject/world refs inside an
/// opaque body, so they decode through the same landed decoder their apply path
/// uses ([`crate::claim::validate_claim_body_and_decode`]) and an undecodable
/// body fails closed.
///
/// Membership is read from live registry state INSIDE the transaction, at the
/// moment the op is decoded — there is no preflight pass and no membership-epoch
/// publication protocol to keep in sync. The state read here is the state this
/// transaction applies against, which removes the TOCTOU class rather than
/// racing it.
fn check_decode_point_taint_guard(
    store: &Store,
    op: &BatchOp,
    origin: BaseWriteOrigin,
    promote_member_of: PromoteMemberOf<'_>,
) -> Result<()> {
    // Decode-point membership probe. With zero live overlay entities no id in
    // this op can be a member, so the guard is a no-op and a raw CLAIM body is
    // never decoded twice on the canonical path. This is the same live read the
    // per-id checks below make — read here, inside the applying transaction, at
    // the decode point — not a hoisted preflight: it answers "could any id be
    // tainted right now", and the transaction applies against exactly this
    // state.
    if !store.off_record_sessions.has_overlay_entities()? {
        return Ok(());
    }
    let tainted = |id: &EntityId| Error::OffRecordTaintedBaseWrite {
        entity_ref: id.to_hex(),
    };
    let check = |id: &EntityId| -> Result<()> {
        if !store.off_record_sessions.contains_entity(id)? {
            return Ok(());
        }
        // `PromoteReplay` exempts ONLY the session whose promote this
        // transaction is. The predicate is minted by the promote call site out
        // of the session identity in its own parameters, so it has no way to
        // answer `true` for another live session's ids — and `Ordinary` carries
        // no predicate at all.
        if promote_member_of.is_some_and(|member_of| member_of(id)) {
            debug_assert_eq!(origin, BaseWriteOrigin::PromoteReplay);
            return Ok(());
        }
        Err(tainted(id))
    };

    match op {
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_reserved_predicate,
            ..
        } => {
            // The MATERIALIZED id is deliberately not judged here: it reaches
            // `off_record::guard_off_record_entity_put` inside `apply_put`, the
            // landed entity-materialization chokepoint, which rejects the same
            // condition (live-overlay membership) with the settled typed
            // `OffRecordFencedTurnWriteRejected` — and covers durable fence
            // state K4 knows nothing about, so it is strictly stronger on this
            // ref. Minting a second error identity for one condition would be a
            // regression, not a hardening: `sync/window.rs` and
            // `sync/quarantine.rs` classify on that typed identity to
            // quarantine-and-continue a replicated window, and an unrecognized
            // reason there fails the window closed. K4 owns the refs the entity
            // door structurally cannot see — the ones below, which materialize
            // nothing and so never reach it.
            if *entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                let Ok(body) =
                    crate::claim::validate_claim_body_and_decode(data, *allow_reserved_predicate)
                else {
                    // Undecodable body: its refs cannot be enumerated, so
                    // membership cannot be disproved. FAIL CLOSED with the
                    // taint error rather than letting an opaque body through to
                    // be judged later. (`apply_put` would reject it too, with
                    // `InvalidClaimBody`; reaching that verdict would mean
                    // deciding an undecodable body is untainted, which is the
                    // open-by-default shape the guard exists to forbid.)
                    return Err(tainted(id));
                };
                check_claim_body_refs(&body, &check)?;
            }
        }
        BatchOp::ClaimCandidate {
            candidate,
            envelope,
            ..
        } => {
            // The candidate's own `id` materializes through `apply_put` and is
            // judged by the entity door there, for the reason above. Its
            // world/subject/actor refs do not materialize, so they are K4's.
            if let Some(world) = candidate.world() {
                check(&world)?;
            }
            check_claim_subject_refs(candidate.subject(), &check)?;
            check(&envelope.actor().entity_ref())?;
        }
        BatchOp::ReconcileLexicalQueryHints { source, keep } => {
            check(source)?;
            for id in keep {
                check(id)?;
            }
        }
        BatchOp::Vector { id, .. }
        | BatchOp::Text { id, .. }
        | BatchOp::Phonetic { id, .. }
        | BatchOp::Delete { id } => check(id)?,
        BatchOp::Edge { src, tgt, .. }
        | BatchOp::PublicEdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::EdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::SetEdgeWeight { src, tgt, .. }
        | BatchOp::SetEdgeVad { src, tgt, .. }
        | BatchOp::DeleteEdge { src, tgt, .. } => {
            check(src)?;
            check(tgt)?;
        }
    }
    Ok(())
}

/// Entity refs a decoded CLAIM body carries: its subject and its world scope.
fn check_claim_body_refs(
    body: &crate::claim::ClaimBody,
    check: &impl Fn(&EntityId) -> Result<()>,
) -> Result<()> {
    check_claim_subject_refs(body.subject, check)?;
    if let Some(world) = body.world {
        check(&world)?;
    }
    Ok(())
}

/// Entity refs a [`crate::claim::ClaimSubject`] carries: the entity itself, or
/// BOTH endpoints of an edge subject.
fn check_claim_subject_refs(
    subject: crate::claim::ClaimSubject,
    check: &impl Fn(&EntityId) -> Result<()>,
) -> Result<()> {
    match subject {
        crate::claim::ClaimSubject::Entity(id) => check(&id),
        crate::claim::ClaimSubject::Edge { source, target, .. } => {
            check(&source)?;
            check(&target)
        }
    }
}

/// Applies a batch under [`BaseWriteOrigin::Ordinary`] — the shape every
/// existing caller uses, unchanged.
pub(crate) fn apply_ops_with_gate_mode(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
) -> Result<()> {
    apply_ops_with_origin(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        gate_mode,
        BaseWriteOrigin::Ordinary,
        None,
    )
}

/// Applies a batch under an explicit [`BaseWriteOrigin`].
///
/// The K4 taint guard runs INSIDE this transaction, at the point where each op
/// is decoded — there is no preflight pass and no membership-epoch publication
/// protocol. The membership state the guard reads inside the applying `wtxn`
/// is the state the transaction applies against, which removes the TOCTOU
/// class outright.
#[expect(
    clippy::too_many_arguments,
    reason = "batch write plumbing keeps gate persistence modes and the write origin explicit at call sites"
)]
pub(crate) fn apply_ops_with_origin(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin,
    promote_member_of: PromoteMemberOf<'_>,
) -> Result<()> {
    debug_assert_eq!(
        promote_member_of.is_some(),
        origin == BaseWriteOrigin::PromoteReplay,
        "the promote-membership channel is Some iff the origin is PromoteReplay"
    );
    let record_gate_decisions = gate_mode.record_decisions;
    let persist_gate_pending_consent = gate_mode.persist_pending_consent;
    let include_source_in_gate_input = gate_mode.include_source_in_gate_input;
    let claim_gate_prechecked = gate_mode.claim_gate_prechecked;

    secret_scan::scan_batch_ops(&ops)?;
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;
    let mut materialized_entity_ids = BTreeSet::new();
    // ONE-1604-D1: shell-edge sources orphaned by a dominance eviction. Their
    // inducing type-76 rows are gone, so the full reconciler's
    // surviving-events derivation can no longer reach them. Non-empty here
    // also SIGNALS that a row left the ledger, which is what forces the
    // wider post-eviction union pass at the end of the batch.
    let mut evicted_shell_sources = BTreeSet::new();
    let mut text_manifest_checked = false;
    let later_text_coverage_by_op = text_coverage_after_op(&ops);
    let write_policy = if contains_local_claim_put(&ops) && !claim_gate_prechecked {
        Some(crate::gate::resolve_policy_manifest(store, &*wtxn)?)
    } else {
        None
    };
    let pending_gate_consent_at_batch_start = if persist_gate_pending_consent {
        pending_gate_consent_ids_at_batch_start(store, &*wtxn, &ops)?
    } else {
        HashSet::new()
    };
    // Legacy (pre-symmetric-migration) graphs answer a vector refresh with a
    // full snapshot rebuild. Batched vector updates coalesce that into at
    // most ONE rebuild per transaction: once pending, per-op graph mutations
    // are skipped (the end-of-batch rebuild re-derives the graph from the
    // `vectors` DB) and the rebuild runs after the op loop (ONE-324 AC11).
    let mut pending_hnsw_rebuild = false;
    let mut pending_embedding_tokens_written = HashMap::<EntityId, Vec<u8>>::new();
    #[cfg(feature = "sync")]
    let mut pending_embedding_enqueue_priorities = HashMap::<EntityId, u8>::new();
    let companion_retired_histories = companion_retired_histories_in_batch(&ops)?;

    for (op_index, op) in ops.into_iter().enumerate() {
        // K4: the op-decode point, inside the applying transaction. Every arm
        // below decodes an op that may carry overlay ids, so this is where
        // membership is judged — before the arm can stage a byte.
        check_decode_point_taint_guard(store, &op, origin, promote_member_of)?;
        match op {
            BatchOp::Put {
                id,
                entity_type,
                occurred,
                learned_at,
                data,
                allow_maintenance,
                allow_reserved_predicate,
                hub_sync_imported,
            } => {
                if hub_sync_imported
                    && (entity_type != ENTITY_TYPE_SKILL
                        || allow_maintenance
                        || allow_reserved_predicate)
                {
                    return Err(Error::InvariantViolation(
                        "hub-sync imported flag is only valid for a local SKILL Put",
                    ));
                }
                // Public writes reject the engine-authored maintenance band via
                // the public entity-type gate; the sync rematerialization path
                // sets `allow_maintenance` so REDACTION_AUDIT (120) receipts
                // survive CRDT→LMDB replay (registry-only entity-type validation
                // still rejects genuinely unknown type bytes).
                if allow_maintenance
                    && allow_reserved_predicate
                    && matches!(
                        entity_type,
                        crate::registry::ENTITY_TYPE_POLICY_MANIFEST
                            | ENTITY_TYPE_ACCESS_GRANT
                            | ENTITY_TYPE_OUTBOUND_GRANT
                    )
                {
                    return Err(Error::MaintenanceKindNotWritable(entity_type));
                }
                // ONE-1865 arm-pending seal (SECRET-01, ONE-1919): the custody
                // record is the secret VALUE's home, so a replicated carry of
                // byte 77 would materialize a peer-supplied plaintext
                // `value_bytes` straight into LMDB. `Vault::register_secret`
                // is the ONE write path and it uses the engine-internal shape
                // (`allow_maintenance` WITHOUT `allow_reserved_predicate`);
                // the both-flags shape here is exclusively the CRDT replay
                // door (`window::forward_rematerialize` → `put_replicated`),
                // which must never admit the byte. The custody module owns the
                // rejection constructor so one grep audits the whole seal.
                if allow_maintenance
                    && allow_reserved_predicate
                    && entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                {
                    return Err(crate::secret_custody::reject_secret_custody_byte());
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
                    hub_sync_imported,
                    later_text_coverage_by_op[op_index],
                    write_policy.as_ref(),
                    None,
                    false,
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                    Some(&companion_retired_histories),
                )?;
                evicted_shell_sources.extend(applied.evicted_shell_sources);
                #[cfg(feature = "sync")]
                let pending_embedding_priority = if allow_maintenance && allow_reserved_predicate {
                    crate::embed::EMBED_PRIORITY_SERVER
                } else {
                    crate::embed::EMBED_PRIORITY_DEVICE
                };
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities
                        .entry(id)
                        .and_modify(|priority| {
                            *priority = (*priority).min(pending_embedding_priority);
                        })
                        .or_insert(pending_embedding_priority);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
                had_vector_mutation |= applied.had_vector_mutation;
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && !(allow_maintenance && allow_reserved_predicate)
                    && !applied.is_lexical_query_hint_claim
                {
                    let deleted = delete_lexical_query_hint_claims_for_target(
                        store,
                        wtxn,
                        &id,
                        &HashSet::new(),
                    )?;
                    for (deleted_id, neighbors) in &deleted.deleted {
                        pending_embedding_tokens_written.remove(deleted_id);
                        #[cfg(feature = "sync")]
                        pending_embedding_enqueue_priorities.remove(deleted_id);
                        ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
                    }
                    had_graph_mutation |= deleted.had_graph_mutation;
                    had_vector_mutation |= deleted.had_vector;
                }
                if let Some((target, query_hint)) = lexical_query_hint_for_replayed_put(
                    &id,
                    entity_type,
                    allow_maintenance && allow_reserved_predicate,
                    &data,
                )? {
                    let mut text_indexing = LexicalHintTextIndexing {
                        analyzer,
                        manifest_checked: &mut text_manifest_checked,
                        trusted: text_index_trusted,
                    };
                    let materialized = materialize_lexical_query_hint_text_if_target_ready(
                        store,
                        wtxn,
                        &mut text_indexing,
                        id,
                        &target,
                        query_hint,
                    )?;
                    had_graph_mutation |= materialized;
                }
                if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    let mut text_indexing = LexicalHintTextIndexing {
                        analyzer,
                        manifest_checked: &mut text_manifest_checked,
                        trusted: text_index_trusted,
                    };
                    let materialized = materialize_lexical_query_hints_for_target(
                        store,
                        wtxn,
                        &mut text_indexing,
                        &id,
                    )?;
                    had_graph_mutation |= materialized;
                }
                // Type-76 rows are never legal participants/actors. Their
                // dedicated ingest door reconciles after the seq join, so
                // feeding event ids into the generic participant hook would
                // enumerate the append-only family once per appended event.
                if entity_type != crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    materialized_entity_ids.insert(id);
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
                    record_gate_decisions,
                    persist_gate_pending_consent,
                    pending_gate_consent_at_batch_start.contains(&id),
                    include_source_in_gate_input,
                    claim_gate_prechecked,
                )?;
                if applied.had_graph_mutation {
                    had_graph_mutation = true;
                }
                if applied.had_vector_mutation {
                    had_vector_mutation = true;
                }
                if let Some(token) = applied.pending_embedding_token {
                    pending_embedding_tokens_written.insert(id, token);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities
                        .entry(id)
                        .and_modify(|priority| {
                            *priority = (*priority).min(crate::embed::EMBED_PRIORITY_DEVICE);
                        })
                        .or_insert(crate::embed::EMBED_PRIORITY_DEVICE);
                }
                if applied.cleared_pending_embedding {
                    pending_embedding_tokens_written.remove(&id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
                materialized_entity_ids.insert(id);
            }
            BatchOp::ReconcileLexicalQueryHints { source, keep } => {
                let keep: HashSet<EntityId> = keep.into_iter().collect();
                let deleted =
                    delete_lexical_query_hint_claims_for_target(store, wtxn, &source, &keep)?;
                for (deleted_id, neighbors) in &deleted.deleted {
                    pending_embedding_tokens_written.remove(deleted_id);
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(deleted_id);
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
                    #[cfg(feature = "sync")]
                    pending_embedding_enqueue_priorities.remove(&id);
                }
            }
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
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
                validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
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
            //
            // Ungated is not unvalidated: the ONE-1645 `FacetOf` type table
            // runs on every path INTO this arm instead, as a
            // quarantine-and-continue rejection rather than an abort —
            // `sync::window`'s forward-remat edge write and
            // `sync::bridge`'s Observer-B edge batch both call
            // `validate_facet_of_edge` after endpoint readiness, and
            // `sync::selector`'s federation admission door drops a provably
            // off-table row before it ever enters the admitted document. A
            // federation peer therefore cannot replay a facet stamp local
            // writers may not write.
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
                if !text_index_trusted {
                    return Err(Error::CorruptedIndex(
                        "text index handshake bypassed on populated index",
                    ));
                }
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
                reject_engine_authored_delete(store, wtxn, &id)?;
                let (_existed, had_vector, deleted_graph_state, neighbors) =
                    deindex_entity(store, wtxn, &id)?;
                if persist_gate_pending_consent {
                    store.let_go_pending_gate_consent_in_txn(
                        wtxn,
                        &id,
                        crate::unix_seconds_now(),
                    )?;
                }
                pending_embedding_tokens_written.remove(&id);
                #[cfg(feature = "sync")]
                pending_embedding_enqueue_priorities.remove(&id);
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

    crate::identity_topology::reconcile_identity_topology_for_materialized_entities_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &materialized_entity_ids,
    )?;
    // ONE-1604-D1 (fix-leg 5): the dominance eviction removed a type-76 event
    // ROW, which both hides the removed event's own participants from the
    // reconciler above (it enumerates SURVIVING rows) and replays the entire
    // fold, so LATER events can flip effective/rejected and strand THEIR
    // sources' edges too. Recompute the union of both families against one
    // final fold. Ordered after the materialization pass so both see the same
    // ledger, and a no-op on every batch without an eviction.
    crate::identity_topology::reconcile_shell_edges_after_eviction_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &evicted_shell_sources,
    )?;

    #[cfg(feature = "sync")]
    for (id, token) in &pending_embedding_tokens_written {
        if store.pending_embedding_token_in_txn(wtxn, id)?.as_deref() == Some(token.as_slice()) {
            let priority = pending_embedding_enqueue_priorities
                .get(id)
                .copied()
                .unwrap_or(crate::embed::EMBED_PRIORITY_DEVICE);
            crate::sync::queue::push_embed_job_in_txn(store, wtxn, id, priority)?;
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

/// The session apply entry (ONE-1728 K4/K11): stages one witness program into
/// the session overlay and NEVER enters the base apply.
///
/// # Why this is a sibling of `apply_ops_with_origin`, not a mode flag on it
///
/// The base apply's body is base-shaped in ways a session has no answer for:
/// it publishes gate decisions to the durable ledger, enqueues `pe:` embed
/// jobs, reconciles the identity-topology fold across the whole ledger, and
/// schedules legacy HNSW rebuilds off the base `vectors` DB. Threading a
/// target through it would put a live `if session { skip }` in front of each —
/// four chances for a later edit to leak a room into base. Here the leak is
/// structurally impossible instead: this function has no access to a `Store`,
/// so there is no base row it *could* write.
///
/// What it shares with base is exactly what must not drift — the row STAGING
/// (`stage_entity_body_row`, `stage_entity_index_rows`, `stage_edge_rows`,
/// `stage_vector_row`, `index_text`, `hnsw_insert_batched`) — reached through
/// the same [`ManifestDbs`] accessors base uses. That is what makes promote a
/// replay of bytes rather than a re-derivation of them.
///
/// # What the session path deliberately does NOT do
///
/// * **No `pe:` markers or embed jobs** (K6): session content embeds inline at
///   witness time or has no vectors until promote. No overlay `pe:` keyspace
///   exists, so this is skip, not redirect.
/// * **No base entity door** (`guard_off_record_entity_put`): that guard
///   REJECTS live-overlay membership, so running it here would refuse the
///   room's own witness writes. The separation is structural — the session
///   path never enters the base apply — not an added exemption.
/// * **No graph/vector version bump**: those counters gate the BASE PPR and
///   HNSW caches. A room's writes must not invalidate the base's caches, and
///   the session's own reads compose over the snapshot, not the cache.
/// * **No legacy HNSW rebuild**: `hnsw_insert_batched` takes `&impl
///   ManifestDbs` while the rebuild arm takes `&Store`, so a session target
///   cannot reach a rebuild — it does not typecheck.
///
/// Every op is journaled with its [`JournalRole`] and the witnessing write's
/// own `occurred`/`learned_at`, because the typed journal is promote's ONLY
/// legal closure source (ARCH-0052 D4); ownership must never be inferable from
/// index keys.
///
/// [`JournalRole`]: crate::session_overlay::JournalRole
/// # The op list IS the journal
///
/// This entry takes [`JournalEntry`] values, not bare [`BatchOp`]s: staging a
/// row and journaling it are one act, so an op cannot reach the overlay
/// without its role tag and preserved timestamps. A `Vec<BatchOp>` parameter
/// would have made "tag every op" a discipline someone can forget; this makes
/// it a thing you cannot express.
pub(crate) fn apply_ops_session(
    view: &crate::store::SessionStoreView<'_>,
    route: &SessionWriteRoute,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    entries: Vec<JournalEntry>,
) -> Result<()> {
    // A route minted before the most recent mode publication names a mode
    // epoch that no longer authorizes overlay writes. Refuse BEFORE staging a
    // byte, so a flip landing mid-call cannot leave half a turn in a room the
    // caller no longer believes it is in. `batch.rs` never reads route fields;
    // the route revalidates itself.
    route.revalidate()?;
    if route.target() != RouteTarget::Overlay {
        return Err(Error::InvariantViolation(
            "session apply needs an Overlay route; a Base route witnesses through the ordinary apply",
        ));
    }
    let overlay = route.overlay();

    for entry in entries {
        match &entry.op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } => {
                // Same registry discipline as base: a room is not a place
                // where unknown or engine-authored type bytes become writable.
                // Promote replays these rows into base, so a byte that would
                // be rejected there is rejected here.
                crate::registry::validate_public_entity_type(*entity_type)?;
                // D18, on the same terms: a CLAIM body is structurally
                // validated before a byte of it is staged. The type-byte gate
                // above is not enough — it admits the byte, not the shape.
                //
                // The op's OWN `allow_reserved_predicate` is what promote will
                // replay this body under (`apply_put` reads the same field off
                // the same op), so validating under it makes in-room admission
                // byte-exactly promote's admission. Hardcoding `false` here
                // would instead refuse in-room a body promote would accept —
                // trading a claim that cannot land for one that cannot be
                // written, which is the same divergence facing the other way.
                if *entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                    crate::claim::validate_claim_body_and_decode(data, *allow_reserved_predicate)?;
                }
                // The ENTRY's stamps, not the op's: they are the witnessing
                // write's own and are what promote replays into the right
                // month window (ARCH-0052 D4).
                stage_entity_body_row(
                    view,
                    wtxn,
                    id,
                    *entity_type,
                    entry.occurred,
                    entry.learned_at,
                    data,
                )?;
                stage_entity_index_rows(
                    view,
                    wtxn,
                    id,
                    *entity_type,
                    entry.occurred,
                    entry.learned_at,
                )?;
            }
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                validate_edge_weight(*weight)?;
                if let Some((component, value)) = vad.invalid_component() {
                    return Err(Error::InvalidVad { component, value });
                }
                // `created_at` is the witness's `learned_at`, never
                // `unix_seconds_now()` — a promoted edge must carry the time
                // the turn happened, not the time it was promoted.
                let value = encode_edge_value(*kind, *weight, entry.learned_at, *vad, None)?;
                stage_edge_rows(view, wtxn, src, *kind, tgt, &value)?;
            }
            BatchOp::Text { id, fields } => {
                crate::bm25::index_text(view, wtxn, analyzer, id, fields)?;
            }
            BatchOp::Vector { id, vector, .. } => {
                stage_vector_row(view, config, wtxn, id, vector)?;
                // `pending_rebuild` can only come back false: the legacy arm
                // that would set it needs a base `&Store` this call does not
                // have. Passing a local sink states that and keeps the shared
                // staging body byte-identical with base.
                let mut pending_rebuild = false;
                crate::hnsw::hnsw_insert_batched(
                    view,
                    config,
                    wtxn,
                    id,
                    vector,
                    &mut pending_rebuild,
                )?;
                debug_assert!(
                    !pending_rebuild,
                    "a session target cannot schedule a base graph rebuild"
                );
            }
            _ => {
                return Err(Error::InvariantViolation(
                    "session witness stages only put, edge, text, and vector ops",
                ));
            }
        }
        overlay.stage_journal_entry(entry)?;
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
            *entity_type == crate::registry::ENTITY_TYPE_CLAIM
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
                } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && !(*allow_maintenance && *allow_reserved_predicate)
            )
    })
}

fn companion_retired_histories_in_batch(ops: &[BatchOp]) -> Result<CompanionRetiredHistoryOverlay> {
    let mut histories = CompanionRetiredHistoryOverlay::new();
    for op in ops {
        let BatchOp::Put {
            entity_type, data, ..
        } = op
        else {
            continue;
        };
        if *entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            continue;
        }
        let record = decode_companion_record_body(data)?;
        record.validate_current_schema_lifecycle_events()?;
        if record.lifecycle == ClaimLifecycleStatus::Retracted {
            histories.insert((record.key(), record.lifecycle_events));
        }
    }
    Ok(histories)
}

fn pending_gate_consent_ids_at_batch_start(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<HashSet<EntityId>> {
    let mut pending = HashSet::new();
    for op in ops {
        let Some(id) = local_claim_op_id(op) else {
            continue;
        };
        if store.pending_gate_consent_in_txn(txn, &id)?.is_some() {
            pending.insert(id);
        }
    }
    Ok(pending)
}

fn local_claim_op_id(op: &BatchOp) -> Option<EntityId> {
    match op {
        BatchOp::ClaimCandidate {
            id,
            internal_lexical_query_hint,
            ..
        } if !*internal_lexical_query_hint => Some(*id),
        BatchOp::Put {
            id,
            entity_type,
            allow_maintenance,
            allow_reserved_predicate,
            ..
        } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && !(*allow_maintenance && *allow_reserved_predicate) =>
        {
            Some(*id)
        }
        _ => None,
    }
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
            let parent = parse_strict_edge_record(&key, &value)?.target;

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

fn reject_engine_authored_delete(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(());
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(());
    };
    // Single source of truth: the registry owns the delete-protected kind set
    // (ONE-1741 added the content anchor); the batch/bulk delete door and the
    // deletion path both consult it, so the guards cannot drift out of sync.
    if crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return Err(Error::MaintenanceKindNotWritable(header.entity_type));
    }
    Ok(())
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
    let blob_cleanup =
        crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(store, wtxn, id)?;
    had_vector |= blob_cleanup.had_vector;
    had_graph_mutation |= blob_cleanup.had_graph_mutation;
    neighbors.extend(blob_cleanup.neighbors);
    store.clear_pending_embedding(wtxn, id)?;
    had_vector |= store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    let related_neighbors = delete_related_edges(store, wtxn, id)?;
    had_graph_mutation |= !related_neighbors.is_empty();
    neighbors.extend(related_neighbors);

    delete_short_id_rows_for_id(store, wtxn, id)?;

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        let cleanup = crate::affect::delete_vad_annotation_metadata_in_txn(store, wtxn, id)?;
        had_vector |= cleanup.had_vector;
        had_graph_mutation |= cleanup.had_graph_mutation;
        neighbors.extend(cleanup.neighbors);
        neighbors.sort_unstable();
        neighbors.dedup();
        return Ok((false, had_vector, had_graph_mutation, neighbors));
    };
    had_graph_mutation = true;

    let (entity_type, occurred, learned_at) = parse_entity_metadata(&entity_record)?;
    if entity_type == ENTITY_TYPE_SKILL {
        let body = &entity_record[ENTITY_METADATA_HEADER_LEN..];
        match crate::skill::decode_skill_record(body) {
            Ok(record) => {
                if let Some(content_hash) = record.content_hash {
                    crate::skill_hub::maintain_skill_content_hash_index_for_delete(
                        store,
                        wtxn,
                        id,
                        content_hash,
                    )?;
                }
            }
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) => {}
            Err(error) => return Err(error),
        }
    }
    let mut cleanup = crate::affect::VadAnnotationCleanup::default();
    crate::affect::delete_vad_annotation_metadata_for_type_in_txn(
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

    crate::dreamer_runner::deindex_dreamer_milestone_claim(store, wtxn, id)?;
    crate::llm::deindex_dreamer_step_claim(store, wtxn, id)?;
    store.entities.delete(wtxn, id.as_bytes())?;
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((true, had_vector, had_graph_mutation, neighbors))
}

#[cfg(test)]
pub(crate) fn deindex_entity_for_test(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let _ = deindex_entity_without_lexical_query_hint_cascade(store, wtxn, id)?;
    Ok(())
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
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
    can_resolve_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
) -> Result<AppliedClaimCandidate> {
    crate::gate::validate_write_envelope(envelope)?;

    let actor = envelope.actor();
    let actor_raw = store
        .entities
        .get(wtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let actor_header =
        EntityMetadataHeader::parse(&actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
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
        crate::registry::ENTITY_TYPE_CLAIM,
        occurred,
        learned_at,
        &data,
        false,
        false,
        false,
        has_later_covering_text_op,
        write_policy,
        Some(envelope),
        internal_lexical_query_hint,
        record_gate_decisions,
        persist_gate_pending_consent,
        can_resolve_pending_consent,
        include_source_in_gate_input,
        claim_gate_prechecked,
        None,
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
        let subject = parse_strict_edge_record(&key, &value)?.target;
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
    is_lexical_query_hint_claim: bool,
    /// Shell-edge sources an ONE-1604-D1 dominance eviction orphaned, for the
    /// caller's explicit-source reconciliation. Empty on every other path.
    evicted_shell_sources: BTreeSet<EntityId>,
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
    hub_sync_imported: bool,
    has_later_covering_text_op: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    write_envelope: Option<&WriteEnvelope>,
    internal_lexical_query_hint: bool,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
    can_resolve_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
    companion_retired_histories: Option<&CompanionRetiredHistoryOverlay>,
) -> Result<AppliedPut> {
    // OFRC-2i: this is the shared entity materialization choke point for
    // public/typed puts, claim candidates, and replicated replay. A live
    // fence admits only the local tag-before-write path; replicated writes
    // and closed fences reject before any validation or side effect can mint
    // an index row, gate receipt, or late entity body.
    crate::off_record::guard_off_record_entity_put(store, wtxn, &id, replicated)?;
    // The six pinned system-agent actor ids ([0xA1; 16]..[0xA6; 16]) are
    // write-door-reserved (design-pass 2026-07-10 §7a; the sixth, [0xA6; 16], is
    // the always-available default base preset): a definition stored at
    // one of them would resolve at the gate as a system preset with its
    // compiled ceiling — an authority-bearing identity collision. Guarded here
    // at the one choke point every entity materialization funnels through
    // (public raw puts, typed puts, claim candidates, sync replay). The ids
    // stay constructible via `EntityId::from_bytes` so they can serve as
    // actor-provenance identities.
    //
    // The same choke point censuses a LEGACY occupant of those ids (only
    // reachable in a pre-reservation vault) before it can be deleted: a
    // deleted occupant would otherwise leave the reserved id
    // byte-indistinguishable from a pristine one and resurrect the preset's
    // compiled Auto.
    crate::agent_def::scan_reserved_actor_ids_once(store, wtxn)?;
    if crate::agent_def::SystemAgentPreset::from_actor_entity_id(&id).is_some() {
        return Err(Error::InvalidKey);
    }
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
    let mut new_skill_record = None;
    let mut new_agent_definition = None;
    let mut decoded_claim_body = None;
    let mut authority_entry_hash_pin: Option<crate::authority::AuthorityEntryHash> = None;
    // ONE-1604-D1 dominance VERDICT, recorded by the AUTHORITY_LOG arm below
    // and acted on only at the pre-write site: see the eviction comment there
    // for why the mutation cannot ride along with the check.
    let mut authority_dominates_key_squatter = false;
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
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
                let Some(target_header) = EntityMetadataHeader::parse(&target_raw) else {
                    return Err(Error::CorruptedIndex("entity header"));
                };
                if target_header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be claim",
                    ));
                }
                let Ok(target_body) = crate::claim::decode_claim_body(
                    &target_raw[ENTITY_METADATA_HEADER_LEN..],
                    true,
                ) else {
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
        if body.session_tag.is_some()
            && !replicated
            && !claim_gate_prechecked
            && !write_envelope.is_some_and(|envelope| {
                crate::claim::session_claim_producer(&body) == Some(envelope.actor().entity_ref())
            })
        {
            return Err(Error::InvalidClaimBody(
                "sess requires an envelope-bound producer actor",
            ));
        }
        if !(replicated
            || is_lexical_query_hint_claim && internal_lexical_query_hint
            || claim_gate_prechecked)
        {
            let policy = write_policy.ok_or(Error::InvariantViolation(
                "local claim write policy snapshot missing",
            ))?;
            if allow_reserved_predicate {
                crate::gate::check_reserved_claim_policy(&body, policy)?;
            } else if let Some(write_envelope) = write_envelope {
                crate::gate::check_claim_policy_for_write(
                    store,
                    wtxn,
                    &id,
                    &body,
                    Some(write_envelope),
                    policy,
                    crate::gate::GateWriteMode {
                        record_decision: record_gate_decisions,
                        persist_pending_consent: persist_gate_pending_consent,
                        resolve_pending: true,
                        can_resolve_pending_consent,
                        include_source_in_gate_input,
                    },
                )?;
            } else {
                crate::gate::check_claim_policy_for_write(
                    store,
                    wtxn,
                    &id,
                    &body,
                    None,
                    policy,
                    crate::gate::GateWriteMode {
                        record_decision: record_gate_decisions,
                        persist_pending_consent: persist_gate_pending_consent,
                        resolve_pending: true,
                        can_resolve_pending_consent,
                        include_source_in_gate_input,
                    },
                )?;
            }
        }
        decoded_claim_body = Some(body);
    } else if entity_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
        crate::code_artifact::validate_code_artifact_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
        crate::blob_artifact::validate_blob_artifact_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        if replicated {
            validate_replicated_authority_log_for_local_vault(store, wtxn, &id, data)?;
        } else {
            crate::authority::validate_authority_log_entry_body_bytes(data)?;
        }
        let entry = crate::authority::decode_authority_log_entry_body(data)?;
        let entry_hash = crate::authority::authority_entry_hash(&entry)?;
        // ONE-1604-D1 chokepoint: every materialization path funnels through
        // here, so the store-key bind, the append-only guard, and the
        // cross-type dominance verdict are computed on every import/replay
        // door in one place. The CHECK runs here (it can still reject); the
        // eviction it authorizes is deferred to the pre-write site below.
        authority_dominates_key_squatter =
            check_authority_log_store_key(store, wtxn, &id, &entry_hash, data)?
                == AuthorityLogKeyOccupant::CrossTypeSquatter;
        authority_entry_hash_pin = Some(entry_hash);
    } else if entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
        crate::federation::validate_federation_grant_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT {
        crate::access_grant::validate_access_grant_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
        crate::channel_identity::validate_channel_identity_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_COUNTERPARTY_CONTACT {
        crate::counterparty_contact::validate_counterparty_contact_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_COMM_RECORD {
        crate::comm::validate_comm_record_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_OUTBOUND_GRANT {
        crate::outbound_grant::validate_standing_outbound_grant_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PSYCH_PROFILE {
        crate::psych_profile::validate_psych_profile_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
        crate::persona_snapshot::validate_persona_snapshot_export_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_SKILL {
        new_skill_record = Some(crate::skill::decode_skill_record(data)?);
    } else if entity_type == ENTITY_TYPE_AGENT_DEF {
        new_agent_definition = Some(crate::agent_def::decode_agent_definition(data)?);
    } else if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
        validate_companion_register_put(store, wtxn, &id, data, companion_retired_histories)?;
    } else if entity_type == ENTITY_TYPE_TASK {
        let task_role = crate::habit::task_role_from_body_bytes(data)?;
        validate_task_role_put_invariants(store, &*wtxn, &id, task_role)?;
    }
    if occurred.start > occurred.end {
        return Err(Error::InvalidTimeRange {
            start: occurred.start,
            end: occurred.end,
        });
    }
    // ONE-1604-D1 dominance MUTATION (fix-leg 2, P2): every side-effect-free
    // check that can reject this row REMOTELY has now run — including the
    // envelope's time-range validation directly above. That ordering is the
    // whole point: `InvalidTimeRange` is a `remote_rejection_reason`, so
    // Observer B quarantines it and COMMITS the transaction (sync/bridge.rs
    // quarantine-and-continue). An eviction performed before that check would
    // therefore survive the rejection as a durable side effect — a rejected
    // authority row would empty the key it failed to claim. A rejected input
    // must be a pure no-op, so the squatter is deindexed only here, past the
    // last remotely-rejectable gate.
    //
    // Placed BEFORE short-id planning and the old-record arm below (rather
    // than at the `store.entities.put` line) because both read the row this
    // eviction removes: the old-record arm would otherwise reject the
    // dominant row with `EntityTypeImmutable`, and a short-id plan built from
    // the squatter's rows would outlive them. Everything still fallible
    // between here and the write is LOCAL-class (storage/overflow), which
    // aborts the whole batch instead of committing — so it cannot strand this
    // mutation either.
    let evicted_shell_sources = if authority_dominates_key_squatter {
        evict_authority_log_store_key_squatter(store, wtxn, &id)?
    } else {
        BTreeSet::new()
    };
    // The AUTHORITY_LOG arm above already decoded the body and hashed it for
    // the store-key bind; reuse that hash instead of decoding a second time.
    let authority_first_seen_key = authority_entry_hash_pin
        .as_ref()
        .map(crate::authority::authority_first_seen_sync_key);
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
    let mut previous_skill_record = None;
    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(&old_record)?;
        if old_type == ENTITY_TYPE_SKILL {
            let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
            previous_skill_record = match crate::skill::decode_skill_record(prior_body) {
                Ok(record) => Some(record),
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
        }
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
            if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
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
        if old_type == ENTITY_TYPE_TASK {
            validate_task_checkin_immutable(
                &old_record,
                old_occurred,
                old_learned,
                occurred,
                learned_at,
                data,
                body_changed,
            )?;
        }
        if old_type == ENTITY_TYPE_SKILL && body_changed {
            let updated = new_skill_record
                .as_ref()
                .ok_or(Error::InvariantViolation("validated SKILL record missing"))?;
            let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
            match crate::skill::decode_skill_record(prior_body) {
                Ok(prior) if hub_sync_imported => {
                    crate::skill::validate_hub_sync_skill_update(&prior, updated)?;
                }
                Ok(prior) => crate::skill::validate_skill_update(&prior, updated)?,
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(prior_body) => {}
                Err(error) => return Err(error),
            }
        }
        if old_type == ENTITY_TYPE_AGENT_DEF && body_changed {
            let updated = new_agent_definition
                .as_ref()
                .ok_or(Error::InvariantViolation(
                    "validated AGENT_DEF record missing",
                ))?;
            // No legacy-opaque escape hatch (contrast SKILL): AGENT_DEF is a
            // brand-new kind with no pre-existing bodies, so a prior body that
            // fails to decode is corruption — fail closed.
            let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
            let prior = crate::agent_def::decode_agent_definition(prior_body)?;
            crate::agent_def::validate_agent_definition_update(&prior, updated)?;
        }
        if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT
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
    } else if entity_type == ENTITY_TYPE_SKILL && !replicated {
        // ONE-1735 birth law at the chokepoint, LOCAL creates only — sync
        // remat (`replicated`) keeps writing already-lifecycled records.
        // Legacy-opaque upgrades take the update arm above (a prior record
        // exists), so this gate sees genuine creates only. New skills are
        // born candidate, and fork lineage must name a real type-7 SKILL
        // parent (the DerivedFrom edge is door-authored and cannot precede
        // this create in the txn, so it is not required here).
        let created = new_skill_record
            .as_ref()
            .ok_or(Error::InvariantViolation("validated SKILL record missing"))?;
        if created.lifecycle_status != crate::skill::SkillLifecycle::Candidate {
            return Err(Error::InvalidSkillBody(
                "new skills are born candidate; the admission gate activates them",
            ));
        }
        if let Some(parent) = created.forked_from {
            if parent == id {
                return Err(Error::InvalidSkillBody(
                    "forkedFrom cannot name the fork itself",
                ));
            }
            let parent_raw =
                store
                    .entities
                    .get(wtxn, parent.as_bytes())?
                    .ok_or(Error::InvalidSkillBody(
                        "forkedFrom parent must exist as a type-7 SKILL",
                    ))?;
            let parent_header = EntityMetadataHeader::parse(&parent_raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if parent_header.entity_type != ENTITY_TYPE_SKILL {
                return Err(Error::InvalidSkillBody(
                    "forkedFrom parent must exist as a type-7 SKILL",
                ));
            }
        }
    }

    stage_entity_body_row(store, wtxn, &id, entity_type, occurred, learned_at, data)?;
    if let Some(record) = new_skill_record.as_ref() {
        crate::skill_hub::maintain_skill_content_hash_index_for_put(
            store,
            wtxn,
            &id,
            previous_skill_record
                .as_ref()
                .and_then(|previous| previous.content_hash),
            record.content_hash,
        )?;
        // ONE-1447: the reverse "which skills cite this message" index, kept at
        // the same chokepoint as the content-hash index so every road that can
        // land a SKILL body — typed doors, hub import, sync remat — maintains
        // it without a call site of its own.
        crate::skill_convert::maintain_skill_source_index_for_put(
            store,
            wtxn,
            &id,
            previous_skill_record.as_ref(),
            record,
        )?;
    }
    if let Some(body) = decoded_claim_body.as_ref() {
        crate::dreamer_runner::index_dreamer_milestone_claim_for_put(
            store, wtxn, &id, body, learned_at,
        )?;
        crate::llm::index_dreamer_step_claim_for_put(store, wtxn, &id, body, learned_at)?;
    }
    if let Some(key) = authority_first_seen_key {
        let observed_secs =
            authority_observation_secs_for_write(store, wtxn, crate::unix_seconds_now())?;
        if store.sync_state.get(wtxn, key.as_str())?.is_none() {
            let first_seen = crate::authority::encode_authority_first_seen_secs(observed_secs);
            store.sync_state.put(wtxn, key.as_str(), &first_seen)?;
        }
    }

    stage_entity_index_rows(store, wtxn, &id, entity_type, occurred, learned_at)?;

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
        if entity_type == crate::registry::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {
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
        is_lexical_query_hint_claim,
        evicted_shell_sources,
    })
}

/// Stages one entity's body row: the ARCH-0019 metadata header followed by the
/// caller's body bytes (ONE-1728 K11).
///
/// Target-parameterized, so a session witness writes the SAME header layout
/// into the overlay that base writes durably — promote replays the row without
/// re-encoding it.
fn stage_entity_body_row(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);
    store.entities().put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

/// Stages the type and temporal index rows every materialized entity carries
/// (ONE-1728 K11). Target-parameterized alongside [`stage_entity_body_row`]:
/// the session's type/temporal readers compose over these overlay rows, so an
/// in-room enumeration or time-range walk sees the turn it just witnessed.
///
/// `occurred`/`learned_at` are the WITNESSING write's own stamps — never
/// restamped here — so a promoted row lands in the month window it belongs to
/// (ARCH-0052 D4).
fn stage_entity_index_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index().put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start()
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end()
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned().put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        let occurred_start_value = occurred.start.to_be_bytes();
        store
            .temporal_long_intervals()
            .put(wtxn, &long_interval_key, &occurred_start_value)?;
    }
    Ok(())
}

/// Stages one edge's paired `edges_out`/`edges_in` rows (ONE-1728 K11).
///
/// PAIRED-WRITE INVARIANT: both directions carry byte-identical value bytes.
/// Extracted from [`apply_edge_with_created_at`] so the session path cannot
/// drift from it — a caller that wrote only one direction would leave the
/// overlay's edge readers asymmetric and promote a half-edge.
fn stage_edge_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    value: &[u8],
) -> Result<()> {
    let key_out = Store::encode_edge_key(src, kind, tgt);
    let key_in = Store::encode_edge_key(tgt, kind, src);
    store.edges_out().put(wtxn, &key_out, value)?;
    store.edges_in().put(wtxn, &key_in, value)?;
    Ok(())
}

pub(crate) struct ReplicatedAuthorityLogValidation {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) signer_key: crate::authority::AuthorityKey,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) signer_known: bool,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) local_vault_id: crate::authority::AuthorityVaultId,
}

/// What currently occupies a validated type-122 row's content-derived store
/// key. `CrossTypeSquatter` is NOT a rejection — see
/// [`check_authority_log_store_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityLogKeyOccupant {
    /// The key is free, or already holds this exact authority row.
    Admissible,
    /// A non-authority row occupies the key and must be evicted before the
    /// authority row is written.
    CrossTypeSquatter,
}

/// ONE-1604-D1 store-key checks shared by every AUTHORITY_LOG write door:
/// the row's id must equal the key derived from its canonical signed body
/// hash (store-key bind: replacement-at-key cannot edit fold history), and
/// an existing AUTHORITY_LOG row's BODY is immutable at that key (append-only
/// guard). Byte-identical body re-puts stay admitted — idempotent replay with
/// metadata-only occurred/learned updates — so no legitimate convergence path
/// is narrowed. A NON-authority occupant is reported, not rejected: see the
/// cross-type squat reasoning inline.
fn check_authority_log_store_key(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entry_hash: &crate::authority::AuthorityEntryHash,
    data: &[u8],
) -> Result<AuthorityLogKeyOccupant> {
    if crate::authority::authority_log_entity_id_from_hash(entry_hash)? != *id {
        return Err(Error::AuthorityLogStoreKeyMismatch { id: *id });
    }
    let Some(existing) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(AuthorityLogKeyOccupant::Admissible);
    };
    let existing_type = EntityMetadataHeader::parse(&existing)
        .ok_or(Error::CorruptedIndex("entity header"))?
        .entity_type;
    // ONE-1604-D1 cross-type squat: the derived id lives in the SAME global
    // entity namespace every other kind is keyed in, and signing is
    // deterministic over predictable RevokeDevice/Dissolve bodies — so a
    // hostile peer (including the very device a pending RevokeDevice names)
    // can precompute the revocation's derived id and pre-occupy it with an
    // ordinary row. If that squatter won, the append-only guard below would
    // quarantine the REVOCATION and the revoked key would stay active: the
    // guard meant to protect authority history would suppress it instead.
    //
    // A type-122 write that reaches this check has already cleared FULL
    // validation at its door — canonical encoding, origin signature, and (at
    // the replicated door) the local vault-id fold — and its id is a pure
    // function of exactly those verified bytes. That is what licenses
    // dominance, and it is why a FORGED authority row cannot use it: such a
    // row fails validation and never gets here, so any occupant a real entry
    // displaces is by construction a squatter at a key it could not have
    // derived. Same-type occupants keep the append-only rule unchanged.
    if existing_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        if existing[ENTITY_METADATA_HEADER_LEN..] != *data {
            return Err(Error::AuthorityLogAppendOnlyViolation { id: *id });
        }
        return Ok(AuthorityLogKeyOccupant::Admissible);
    }
    Ok(AuthorityLogKeyOccupant::CrossTypeSquatter)
}

/// Evicts a non-authority occupant of a validated type-122 row's store key so
/// the authority row can be written (ONE-1604-D1 dominance). Index rows and
/// incident edges go with it — a squatter must leave no stale carrier — and
/// the eviction is confined to the single write chokepoint so the replicated
/// validator stays side-effect-free.
///
/// The edge half is [`deindex_entity`] → `delete_related_edges`, which drops
/// BOTH directions (`edges_out` and `edges_in`) of every incident edge. That
/// is load-bearing, not incidental: a surviving edge row keeps a revoked
/// squatter traversable through the graph after its entity row is gone, so
/// any future narrowing of the eviction must keep the edge sweep. Pinned by
/// `authority_log_put_evicts_cross_type_squatter_incident_edges`; the CRDT
/// mirror of this rule lives on the reverse-remat door in `sync/window.rs`.
///
/// Call ONLY from `apply_put`'s pre-write site, never from
/// `check_authority_log_store_key`: the check runs while remotely-rejectable
/// preflight is still outstanding, and a remote rejection COMMITS
/// (quarantine-and-continue), so an eviction taken at check time would
/// outlive a rejected row.
///
/// DOMINANCE OUTRANKS DELETE PROTECTION — deliberately, and this is the one
/// place in the engine where it does. The eviction does NOT exempt kinds in
/// [`registry::is_delete_protected_engine_record`] (POLICY_MANIFEST,
/// AUTHORITY_LOG, SKILL_CONTENT_ANCHOR, IDENTITY_TOPOLOGY_EVENT), because:
/// (a) the key is a pure function of FULLY VALIDATED authority bytes, so any
/// non-122 occupant sits at an address its own kind could never derive and is
/// adversarial by construction; (b) the eviction UNWINDS the squatter's
/// induced shell effects rather than orphaning them — a type-76 squatter that
/// arrived by replicated ingest was enumerated by the ARCH-0055 reconciler
/// like any ledger event, so it may have installed real `merged_into` /
/// `split_into` edges on live participants, and both those participants and
/// every surviving merge/split source are reconciled against the fold that
/// remains after the eviction; for a copied row this is curative (the fold
/// would otherwise see one event twice); (c) an
/// exemption would hand attackers a protected band to squat from, letting a
/// planted row suppress a pending `RevokeDevice` — exactly the ONE-1604-D1
/// attack this dominance exists to close. Pinned by
/// `authority_log_put_evicts_delete_protected_squatter`; narrowing the
/// eviction to spare protected kinds is a design decision, not an edit.
///
/// Returns the shell-edge sources the evicted row induced (empty unless the
/// occupant was a type-76 event). A non-empty return means a row LEFT the
/// ledger, and the caller MUST hand it to
/// [`identity_topology::reconcile_shell_edges_after_eviction_in_txn`], which
/// reconciles it together with the surviving family. Both halves are needed:
/// `deindex_entity` drops only edges incident to the EVENT id while the
/// redirect edges sit on the merge/split PARTICIPANTS, and the removed event
/// stops being enumerable (so the surviving-set derivation misses them);
/// meanwhile the removal replays the whole fold, so later events can flip
/// effective/rejected and strand THEIR sources' edges (so the explicit
/// capture alone misses those). Left unreconciled either way they are shell
/// edges with no ledger writer: the ARCH-0055 wedge (participant undo →
/// [`Error::EntityNotFound`]) reached through authority dominance, which is
/// the state type-76 delete protection exists to prevent.
///
/// [`registry::is_delete_protected_engine_record`]: crate::registry::is_delete_protected_engine_record
/// [`identity_topology::reconcile_shell_edges_after_eviction_in_txn`]: crate::identity_topology::reconcile_shell_edges_after_eviction_in_txn
fn evict_authority_log_store_key_squatter(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    tracing::warn!(
        entity = %id.to_hex(),
        "authority log admission displaced a non-authority row squatting its content-derived store key"
    );
    // Captured BEFORE the deindex: afterwards the action bytes are gone and
    // the induced sources are unrecoverable.
    let induced_shell_sources =
        crate::identity_topology::identity_topology_shell_sources_for_store_in_txn(
            store, wtxn, id,
        )?
        .unwrap_or_default();
    let (_existed, had_vector, had_graph_mutation, neighbors) = deindex_entity(store, wtxn, id)?;
    ppr::invalidate_ppr_for_delete(store, wtxn, id, &neighbors)?;
    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }
    Ok(induced_shell_sources)
}

pub(crate) fn validate_replicated_authority_log_for_local_vault(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<ReplicatedAuthorityLogValidation> {
    crate::authority::validate_authority_log_entry_body_bytes(data)?;
    let entry = crate::authority::decode_authority_log_entry_body(data)?;
    let entry_hash = crate::authority::authority_entry_hash(&entry)?;
    // ONE-1604-D1 mirror at the replicated door: content-address + append-only
    // are STORE checks, not ancestry checks — the door stays structural +
    // origin-sig + vault_id (ONE-1604-D2). Rejecting here (before the quota
    // debit) quarantines hostile rows without consuming ingest quota. A
    // cross-type squatter is not a rejection — this row dominates it — and
    // the eviction itself belongs to the `apply_put` chokepoint that writes
    // the row, so this validator stays a pure check.
    let _ = check_authority_log_store_key(store, wtxn, id, &entry_hash, data)?;
    let entry_vault_id = match &entry.op {
        crate::authority::AuthorityOp::Genesis { .. } => {
            crate::authority::genesis_vault_id(&entry)?
        }
        _ => entry
            .vault_id
            .ok_or(Error::InvalidAuthorityLogBody("missing authority vault id"))?,
    };
    let local_fold =
        crate::authority::fold_authority_log(&stored_authority_log_entries(store, wtxn)?);
    let local_vault_id = local_fold.vault_id.ok_or(Error::InvalidAuthorityLogBody(
        "missing local authority root",
    ))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        ));
    }
    Ok(ReplicatedAuthorityLogValidation {
        signer_known: local_fold.roster.contains_key(&entry.signer.public_key),
        signer_key: entry.signer.public_key,
        local_vault_id,
    })
}

fn stored_authority_log_entries(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
) -> Result<Vec<crate::authority::AuthorityLogEntry>> {
    let mut entries = Vec::new();
    for entry in store
        .type_index
        .prefix_iter(wtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
    {
        let (key, _) = entry?;
        let id = authority_type_index_entity_id(&key)?;
        let raw = store
            .entities
            .get(wtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        entries.push(crate::authority::decode_authority_log_entry_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?);
    }
    Ok(entries)
}

fn authority_type_index_entity_id(key: &[u8]) -> Result<EntityId> {
    if key.len() != 1 + ENTITY_ID_LEN || key[0] != ENTITY_TYPE_AUTHORITY_LOG {
        return Err(Error::CorruptedIndex("type index key shape"));
    }
    let raw: [u8; ENTITY_ID_LEN] = key[1..]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("type index entity id"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("type index entity id"))
}

fn validate_companion_register_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
    companion_retired_histories: Option<&CompanionRetiredHistoryOverlay>,
) -> Result<()> {
    let record = decode_companion_record_body(data)?;
    record.validate_current_schema_lifecycle_events()?;
    let key = record.key();

    if let Some(existing_raw) = store.entities.get(&*wtxn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&existing_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER {
            let existing =
                decode_companion_record_body(&existing_raw[ENTITY_METADATA_HEADER_LEN..])?;
            if existing.key() != key {
                return Err(Error::InvalidClaimBody(
                    "companion record key cannot change",
                ));
            }
            if existing.lifecycle != ClaimLifecycleStatus::Active
                && &existing_raw[ENTITY_METADATA_HEADER_LEN..] != data
                && !is_retired_relationship_end_rescrub(&existing, &record)
            {
                return Err(Error::InvalidClaimBody("companion record is retired"));
            }
            if existing.lifecycle == ClaimLifecycleStatus::Active {
                if record.lifecycle == ClaimLifecycleStatus::Active {
                    if !existing.lifecycle_events.is_empty()
                        && record.lifecycle_events != existing.lifecycle_events
                    {
                        return Err(Error::InvalidClaimBody(
                            "companion lifecycle events cannot change through update",
                        ));
                    }
                } else if !existing.lifecycle_events.is_empty()
                    && !record
                        .lifecycle_events
                        .as_slice()
                        .starts_with(existing.lifecycle_events.as_slice())
                {
                    return Err(Error::InvalidClaimBody(
                        "companion lifecycle events must preserve history",
                    ));
                }
            }
            if existing.export_classification != CompanionExportClassification::LocalOnly
                && record.export_classification == CompanionExportClassification::LocalOnly
            {
                return Err(Error::InvalidClaimBody(
                    "companion record export cannot be downgraded to local_only",
                ));
            }
        }
    }

    if record.lifecycle == ClaimLifecycleStatus::Active {
        let terminal_lifecycle_event_kind = record.terminal_lifecycle_event_kind();
        let prior_lifecycle_events =
            if terminal_lifecycle_event_kind == Some(CompanionLifecycleEventKind::Revived) {
                Some(&record.lifecycle_events[..record.lifecycle_events.len() - 1])
            } else {
                None
            };
        let lookup = crate::companion::companion_record_key_lookup_in_txn(
            store,
            &*wtxn,
            &key,
            prior_lifecycle_events,
        )?;
        if let Some(existing_id) = lookup.active_id
            && existing_id != *id
        {
            return Err(Error::CompanionRecordAlreadyExists);
        }
        if let Some(prior_lifecycle_events) = prior_lifecycle_events {
            let persisted_retired = lookup.retired_history_id.is_some();
            let same_batch_retired = companion_retired_histories.is_some_and(|histories| {
                histories.contains(&(key.clone(), prior_lifecycle_events.to_vec()))
            });
            if !(persisted_retired || same_batch_retired) {
                return Err(Error::InvalidClaimBody(
                    "companion record revive requires retired history",
                ));
            }
        } else {
            if terminal_lifecycle_event_kind != Some(CompanionLifecycleEventKind::Created)
                || record.lifecycle_events.len() != 1
            {
                return Err(Error::InvalidClaimBody(
                    "companion create lifecycle history must be canonical",
                ));
            }
            if let Some(existing_id) = lookup.any_id
                && existing_id != *id
            {
                return Err(Error::CompanionRecordAlreadyExists);
            }
        }
    }

    Ok(())
}

struct AppliedVector {
    wrote_vector: bool,
    cleared_pending_embedding: bool,
}

fn apply_vector(
    store: &Store,
    config: &crate::config::VaultConfig,
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
    stage_vector_row(store, config, wtxn, &id, vector)?;
    let cleared_pending_embedding = match pending_embedding_token {
        Some(token) => store.clear_pending_embedding_if_token_matches(wtxn, &id, token)?,
        None => false,
    };
    Ok(AppliedVector {
        wrote_vector: true,
        cleared_pending_embedding,
    })
}

/// Validates one vector against the vault's embedding contract and stages its
/// row (ONE-1728 K11). Target-parameterized so a session witness stages the
/// identical bytes into the overlay: the `pe:` bookkeeping around it is
/// base-only (K6) and stays in [`apply_vector`].
fn stage_vector_row(
    store: &impl ManifestDbs,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
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
    store.vectors().put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

/// Reads an entity's registry type byte. `None` means no entity row exists —
/// the type is unknowable, not merely unexpected. A row that exists but whose
/// header will not parse is a LOCAL defect ([`Error::CorruptedIndex`]), never
/// an unknowable type: callers must fail closed on it rather than charge it to
/// a peer.
pub(crate) fn stored_entity_type(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// ONE-1645 write-time type table for `FacetOf` (u8 17) edges: a facet stamp
/// may only run `CLAIM | TURN | EVENT → FACET`. Anything else — including an
/// endpoint with no entity row, whose type is unknowable — is a typed
/// [`Error::InvalidFacetOfEdge`] that aborts the batch atomically. This
/// mirrors the fail-closed-on-missing shape [`Error::InvalidFacet`] already
/// uses on the read side: a stamp's endpoints must be established facts
/// before the stamp.
///
/// TWO SEMANTICS ride one edge kind, and the table admits both:
///
/// * `CLAIM | TURN → FACET` — DISCLOSURE-SCOPING. These are the stamps
///   [`crate::pipeline`]'s facet filter reads: `claim_facet_scope`
///   prefix-scans `edges_out` under a CLAIM source, and strict mode drops
///   claims scoped exclusively to other facets. TURN is admitted alongside
///   CLAIM because per-turn facet stamps are what transcript filtering rides;
///   the write door must accept the stamp the design requires.
/// * `EVENT → FACET` — WORLD-MODEL traversal, and disclosure-effective on the
///   FEDERATION door. It exists for ARCH-0039 PPR traversal, where `facet_of`
///   carries a pinned λ of 0.05 ([`crate::ppr::lambda_for_kind`]) — rejecting
///   it would make a ratified traversal contract unwritable — but "world-model"
///   is not "disclosure-inert". See the two-door reading below.
///
/// TWO DISCLOSURE DOORS read `FacetOf`, and a source type may be effective on
/// one while inert on the other. Neither door is the whole exposure surface:
///
/// * LOCAL QUERY door — [`crate::pipeline`]'s facet filter. `apply_facet_filter`
///   keeps every non-CLAIM entity unconditionally and `claim_facet_scope`
///   prefix-scans `edges_out` under a CLAIM source only. CLAIM-sourced stamps
///   are effective here; TURN- and EVENT-sourced stamps are INERT on this door.
/// * FEDERATION door — `crate::sync::selector`. `facet_scope_by_source` builds
///   a `FacetScope` for every `FacetOf` row THIS TABLE ADMITS ON BOTH ENDS (it
///   runs [`facet_of_endpoint_types_on_table`] as a read mirror), and
///   `entity_selector_decision` withholds an entity of ANY type whose scope is
///   malformed or touches an unselected facet from a facet-limited peer.
///   CLAIM-, TURN-, AND EVENT-sourced stamps are all disclosure-EFFECTIVE here:
///   an EVENT stamped to an unselected facet is withheld from that peer. A row
///   OFF the table on either end carries no scope on this door — the shape is
///   unwritable, so a copy that slipped past a write door is not honored on
///   read.
///
/// The teeth are unchanged by the widening: a missing endpoint still fails
/// closed, the target must still be a FACET, and every source type outside
/// {CLAIM, TURN, EVENT} is still rejected.
///
/// Ordering: ops apply in order inside one write txn, so an entity put and
/// the edge that stamps it commit together in a single batch. An edge that
/// precedes its endpoint's put fails closed.
///
/// Seam (ONE-1646): the exposure-consent gate — rejecting a private→public
/// restamp without a consent-ledger row, and gating `FacetOf` deletes on
/// exposure state — lands at THIS call site once facet exposure state exists.
/// That gate keys on ALL admitted source types (`CLAIM | TURN | EVENT`): each
/// is disclosure-effective on at least one of the two doors above, so none may
/// bypass exposure gating. The gate table is derived from CURRENT door
/// behavior — `crate::sync::selector::tests` pins the federation half — and it
/// stays derivable BY CONSTRUCTION now that the selector mirrors this very
/// pair predicate: widening or narrowing the table here moves both doors and
/// the gate table together. This function is the hook; it deliberately
/// validates types only.
pub(crate) fn validate_facet_of_edge(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    if kind != EdgeKind::FacetOf {
        return Ok(());
    }
    let src_type = stored_entity_type(store, rtxn, &src)?;
    let tgt_type = stored_entity_type(store, rtxn, &tgt)?;
    if let (Some(src_type), Some(tgt_type)) = (src_type, tgt_type)
        && facet_of_endpoint_types_on_table(src_type, tgt_type)
    {
        return Ok(());
    }
    Err(Error::InvalidFacetOfEdge {
        src,
        src_type,
        tgt,
        tgt_type,
    })
}

/// The ONE-1645 `FacetOf` table as a pure predicate over KNOWN endpoint types.
///
/// Every door runs the same table and they resolve types differently, so the
/// table itself lives here exactly once, decomposed into its two independent
/// per-endpoint halves ([`facet_of_source_type_admitted`] /
/// [`facet_of_target_type_admitted`]) so a door that knows only ONE endpoint
/// can still consult it without forking a second copy:
///
/// * [`validate_facet_of_edge`] — the write/replay door. Types come from
///   STORED entity rows, and an endpoint with no row is unknowable, which that
///   door treats as fail-closed (a stamp's endpoints must be established facts
///   before the stamp).
/// * the FEDERATION ADMISSION boundary
///   (`crate::sync::selector::admit_federated_window_update`). Types come from
///   the local vault OR from the admitted update's own entities map, and it
///   rejects on ANY SUFFICIENT FACT via
///   [`facet_of_endpoints_provably_off_table`] — an endpoint that stays
///   unknowable DEFERS to the replay door instead of failing closed, because a
///   not-yet-arrived endpoint must not wedge out-of-order delivery (H2).
/// * the FEDERATION SELECTOR's read mirror
///   (`crate::sync::selector::facet_scope_by_source`). It honors a `FacetOf`
///   scope only when BOTH endpoints resolve onto this table, so it calls the
///   PAIR predicate. Types resolve STORED-FIRST (as at the admission door),
///   and where the stored row and the document blob DISAGREE the stored type
///   WINS, in BOTH endpoint roles: the conflicting blob is a write the
///   immutability gate rejected, and a rejected write is never consulted for
///   anything. STORED TRUTH NEVER LOSES TO A REJECTED WRITE, IN EITHER ROLE,
///   so a peer-controlled conflict can never move a row from withheld to
///   exported, nor from contained to seeded. A row failing either half is
///   SCOPE-INERT — never a seed, never a withhold — because letting an
///   unwritable row DENY would hand a peer a suppression primitive against
///   the host's own entities.
///
/// A second copy of the pair table would drift from this one silently; the
/// admission door's whole job is to reject exactly what the replay door
/// rejects, one layer earlier, and the selector's is to READ exactly what the
/// write doors would have let be WRITTEN.
#[must_use]
pub(crate) const fn facet_of_endpoint_types_on_table(src_type: u8, tgt_type: u8) -> bool {
    facet_of_source_type_admitted(src_type) && facet_of_target_type_admitted(tgt_type)
}

/// Source half of the table: the types that may STAMP a facet.
#[must_use]
pub(crate) const fn facet_of_source_type_admitted(src_type: u8) -> bool {
    matches!(
        src_type,
        ENTITY_TYPE_CLAIM | ENTITY_TYPE_TURN | ENTITY_TYPE_EVENT
    )
}

/// Target half of the table: the only type a facet stamp may point AT.
#[must_use]
const fn facet_of_target_type_admitted(tgt_type: u8) -> bool {
    tgt_type == ENTITY_TYPE_FACET
}

/// ONE-SIDED verdict over PARTIALLY-known endpoint types: is this row's
/// off-table status already PROVEN by the facts in hand?
///
/// The table is a CONJUNCTION of two independent per-endpoint predicates, so
/// either conjunct alone can falsify it. Requiring both endpoints to be known
/// before rejecting — the over-narrow reading fix-4 shipped — hands a forger a
/// free pass: bundle a provably-bad PERSON source with a target that has not
/// arrived, and a "both known" check reads the row as merely unknowable and
/// copies it through.
///
/// * source known and outside the admitted set → PROVEN off-table, whatever
///   the target turns out to be;
/// * target known and not a FACET → PROVEN off-table, whatever the source
///   turns out to be;
/// * everything else (both known and on-table, or the deciding endpoint still
///   unknowable) → NOT proven here. Both-known-and-on-table is a genuine pass;
///   genuinely-unknowable defers to the replay door (H2).
///
/// `false` therefore means "no proof yet", never "proven fine".
#[must_use]
pub(crate) const fn facet_of_endpoints_provably_off_table(
    src_type: Option<u8>,
    tgt_type: Option<u8>,
) -> bool {
    let source_disproves = match src_type {
        Some(src_type) => !facet_of_source_type_admitted(src_type),
        None => false,
    };
    let target_disproves = match tgt_type {
        Some(tgt_type) => !facet_of_target_type_admitted(tgt_type),
        None => false,
    };
    source_disproves || target_disproves
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
        .map(|value| value.to_vec())
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
    validate_task_checkin_child_of_edge(store, &*wtxn, &src, kind, &tgt)?;

    let value = encode_edge_value(kind, weight, created_at, vad, provenance)?;
    stage_edge_rows(store, wtxn, &src, kind, &tgt, &value)
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
        validate_task_checkin_child_parent(store, rtxn, &child, parent)?;
    }

    Ok(())
}

fn stored_task_role(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<TaskRole>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn validate_task_checkin_child_parent(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child: &EntityId,
    parent: &EntityId,
) -> Result<()> {
    if stored_task_role(store, rtxn, child)? != Some(TaskRole::HabitCheckin) {
        return Ok(());
    }
    validate_habit_checkin_parent_role(store, rtxn, parent)
}

fn validate_habit_checkin_parent_role(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    parent: &EntityId,
) -> Result<()> {
    match stored_task_role(store, rtxn, parent)? {
        Some(TaskRole::Habit) => Ok(()),
        Some(_) => Err(Error::InvalidTaskBody(
            "habit check-in parent must be Habit TASK",
        )),
        None => Err(Error::InvalidTaskBody(
            "habit check-in parent must be a TASK",
        )),
    }
}

fn validate_task_checkin_child_of_edge(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf {
        validate_task_checkin_child_parent(store, rtxn, src, tgt)?;
    }
    Ok(())
}

fn validate_task_role_put_invariants(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    role: TaskRole,
) -> Result<()> {
    if role == TaskRole::HabitCheckin {
        let prefix = child_of_prefix(id);
        for entry in store.edges_out.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            let parent = parse_strict_edge_record(&key, &value)?.target;
            validate_habit_checkin_parent_role(store, rtxn, &parent)?;
        }
    }

    if role != TaskRole::Habit {
        let prefix = child_of_prefix(id);
        for entry in store.edges_in.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            let child = parse_strict_edge_record(&key, &value)?.target;
            if stored_task_role(store, rtxn, &child)? == Some(TaskRole::HabitCheckin) {
                return Err(Error::InvalidTaskBody(
                    "Habit TASK with check-ins cannot change role",
                ));
            }
        }
    }

    Ok(())
}

fn validate_task_checkin_immutable(
    old_record: &[u8],
    old_occurred: TimeRange,
    old_learned: u64,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
    body_changed: bool,
) -> Result<()> {
    let old_role =
        crate::habit::task_role_from_body_bytes(&old_record[ENTITY_METADATA_HEADER_LEN..])?;
    let new_role = crate::habit::task_role_from_body_bytes(data)?;
    if old_role != TaskRole::HabitCheckin && new_role != TaskRole::HabitCheckin {
        return Ok(());
    }
    if old_role == TaskRole::HabitCheckin
        && new_role == TaskRole::HabitCheckin
        && !body_changed
        && old_occurred == occurred
        && old_learned == learned_at
    {
        return Ok(());
    }
    Err(Error::InvalidTaskBody(
        "habit check-in records are immutable",
    ))
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
        let edge = parse_strict_edge_record(&key, &value)?;
        if edge.kind != EdgeKind::ClaimOf {
            continue;
        }
        let source = edge.target;
        let Some(raw) = store.entities.get(wtxn, source.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
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
    prefix.push(crate::registry::ENTITY_TYPE_CLAIM);
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
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    Ok(header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
}

fn stored_claim_body(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<crate::claim::ClaimBody>> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
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

/// Stages one entity's phonetic postings and its forward code row.
///
/// Pure-accessor body, so ONE-1728 K11 parameterizes it by write target by
/// signature alone: a session witness stages the identical postings into the
/// overlay and the base path is byte-identical because it is the same code.
fn apply_phonetic(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: &[String],
) -> Result<()> {
    let mut forward_codes = match store.phonetic_forward().get(wtxn, id.as_bytes())? {
        Some(raw) => match decode_phonetic_forward_codes(&raw) {
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

        let existing = store.phonetic_index().get(wtxn, code.as_bytes())?;
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
        store
            .phonetic_index()
            .put(wtxn, code.as_bytes(), &posting)?;

        if !forward_codes.iter().any(|known| known == code) {
            forward_codes.push(code.clone());
            forward_changed = true;
        }
    }

    if forward_changed {
        forward_codes.sort();
        forward_codes.dedup();
        let encoded = encode_phonetic_forward_codes(&forward_codes);
        store
            .phonetic_forward()
            .put(wtxn, id.as_bytes(), &encoded)?;
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
    store: &impl ManifestDbs,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    short_id_prefix: &str,
    data: &[u8],
) -> Result<ShortIdPlan> {
    let content_hash = (xxh32(data, 0) % 256) as u8;

    if let Some(existing) = store.short_ids_reverse().get(txn, id.as_bytes())? {
        let (short_id, old_content_hash) = parse_short_id_value(&existing)?;
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
    let current = match store.vault_meta().get(txn, &counter_key)? {
        Some(raw) => {
            let buf: [u8; SHORT_ID_COUNTER_LEN] = raw
                .as_ref()
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
    store: &impl ManifestDbs,
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
                store.short_ids().delete(wtxn, &old_forward_key)?;
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
                .vault_meta()
                .put(wtxn, &counter_key, &next_counter.to_le_bytes())?;
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
    }

    Ok(())
}

fn delete_short_id_rows_for_id(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let forward_key = match store.short_ids_reverse().get(wtxn, id.as_bytes())? {
        Some(value) => {
            let (short_id, content_hash) = parse_short_id_value(&value)?;
            Some(encode_short_id_forward_key(short_id, content_hash))
        }
        None => None,
    };
    if let Some(forward_key) = forward_key {
        store.short_ids().delete(wtxn, &forward_key)?;
        store.short_ids_reverse().delete(wtxn, id.as_bytes())?;
    }
    Ok(())
}

/// Writes both pinned ARCH-0019 short-id rows for one entity:
/// row n3 `short_ids`: key `(short_id bytes ‖ content_hash u8)` -> 16-byte
/// entity id; row n4 `short_ids_reverse`: key entity id -> value
/// `(short_id bytes ‖ content_hash u8)` (same bytes as the forward key).
fn write_short_id_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    short_id: &str,
    content_hash: u8,
) -> Result<()> {
    let forward_key = encode_short_id_forward_key(short_id, content_hash);
    store.short_ids().put(wtxn, &forward_key, id.as_bytes())?;
    store
        .short_ids_reverse()
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
        let edge = parse_strict_edge_record(&key, &value)?;
        outbound.push((edge.kind, edge.target));
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
        let edge = parse_strict_edge_record(&key, &value)?;
        inbound.push((edge.kind, edge.target));
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
        match decode_phonetic_forward_codes(&raw) {
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
        let Some(updated) = posting_without_entity(&posting, id)? else {
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
        let updated = posting_without_entity(&posting, id)?.ok_or(Error::MissingPostingEntry)?;

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

#[cfg(test)]
mod tests;
