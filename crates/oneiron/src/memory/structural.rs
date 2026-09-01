//! Structural puts (habit checkins, companion records, imported-claim
//! admission, blob artifacts) and `author_take`.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::claims::*;
use super::support::*;
use super::*;

use std::sync::atomic::Ordering;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::ErrorKind;
use crate::habit::TaskRole;
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    NormalizedIngestClaim, admit_imported_evidence_claim,
};
use crate::note::{NoteBody, NoteKind, TakeTarget, encode_note_body};
use crate::registry::{
    ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_REGISTRY,
};
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

/// Typed read-back view of one entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short-id ref, when one is assigned.
    pub short_ref: Option<String>,
    /// Registry kind string (e.g. `MESSAGE`); `TYPE_<n>` for unregistered.
    pub kind: String,
    /// Occurred interval start (Unix seconds).
    pub occurred_start: u64,
    /// Occurred interval end (Unix seconds).
    pub occurred_end: u64,
    /// Learned-at (Unix seconds).
    pub learned_at: u64,
    /// Body decoded MessagePack→JSON; `None` when absent or not
    /// JSON-shaped (binary values are redacted per the companion codec).
    pub body: Option<serde_json::Value>,
}

/// One BM25 text-index field for a structural put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextIndexField {
    /// Analyzer field name (e.g. `content`, `name`).
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralEdgeSpec {
    /// snake_case `EdgeKind` name (e.g. `belongs_to`, `attached`).
    pub edge_kind: String,
    /// Target entity ref (short-id ref or hex).
    pub target_ref: String,
    /// Edge weight in `[0, 1]`; `None` ⇒ the kind's default (1.0 fallback).
    pub weight: Option<f32>,
}

/// Structural put carrying text-index fields and edges (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralPutInput {
    /// Caller-supplied deterministic 32-hex id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (`MESSAGE`, `PERSON`, `TASK`, `ASSET`, …).
    /// `CLAIM` is rejected — claims go through [`Memory::commit`].
    pub kind: String,
    /// Entity body as a JSON object (stored as MessagePack).
    pub body: serde_json::Value,
    /// BM25 fields to index for this entity.
    pub text_fields: Option<Vec<TextIndexField>>,
    /// Outgoing edges from this entity.
    pub edges: Option<Vec<StructuralEdgeSpec>>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// Receipt for a structural write (put/checkin/companion/blob artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRefReceipt {
    /// Short-id ref of the written entity (hex fallback).
    pub entity_ref: String,
    /// 32-hex id of the written entity.
    pub id_hex: String,
    /// Facade write marker (`put:<hex>`); structural puts produce no gate
    /// decision at base.
    pub receipt_ref: String,
}

/// One habit check-in append (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HabitCheckinInput {
    /// Habit-role TASK ref (short-id ref or hex); must exist.
    pub habit_ref: String,
    /// Caller-supplied deterministic 32-hex checkin id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Extra body fields (JSON object). The facade injects the pinned
    /// `role` key (`HabitCheckin`); supplying `role` here is rejected.
    pub data: Option<serde_json::Value>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One companion persona registration (B2 migrator group, design §2.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionRecordInput {
    /// Caller-supplied deterministic 32-hex record id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Owner PERSON ref (personal scope).
    pub owner_ref: String,
    /// Companion persona PERSON ref.
    pub persona_ref: String,
    /// Opaque record value (JSON, stored as MessagePack).
    pub value: serde_json::Value,
    /// Provenance source string; `None` ⇒ `user_stated`.
    pub source: Option<String>,
    /// When set, the record is retired at this time after creation
    /// (migration of `isActive == false` rows).
    pub retired_at: Option<u64>,
    /// Creation time (Unix seconds) — stamps the `created` lifecycle event.
    pub learned_at: u64,
}

/// One imported-evidence claim admission (B1a migration-admission verb over
/// `ingest.rs` `admit_imported_evidence_claim`; the gate still decides).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdmitImportedClaimInput {
    /// Registered ingest source id; unknown sources fail closed.
    pub source_id: String,
    /// Stable source record id (idempotency/provenance anchor).
    pub source_record_id: String,
    /// Caller-supplied deterministic 32-hex claim id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Subject entity ref (must exist).
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value (JSON).
    pub value: serde_json::Value,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One blob artifact registration (B8 blob door).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobArtifactInput {
    /// Caller-supplied deterministic 32-hex artifact id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Display name (≤512 bytes).
    pub name: String,
    /// Media type (≤256 bytes).
    pub media_type: String,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// View of one appended blob artifact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// Version number (1-based, append-only).
    pub version: u64,
    /// blake3 content hash, lowercase hex.
    pub content_hash_hex: String,
    /// 32-hex id of the `blob.version` LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: u64,
}

pub(super) fn edge_kind_from_str(value: &str) -> Option<EdgeKind> {
    let kind = match value {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        "blocked_by" => EdgeKind::BlockedBy,
        "blocks" => EdgeKind::Blocks,
        "same_as" => EdgeKind::SameAs,
        _ => return None,
    };
    Some(kind)
}

/// The contract's registered stored prior for `kind`, falling back to the same
/// `1.0` [`Memory::put_structural`] uses for the three kinds whose
/// `pprWeight` column is null (`child_of` / `assigned_to` / `blocked_by`).
fn registered_edge_weight(kind: EdgeKind) -> f32 {
    kind.default_weight().unwrap_or(1.0)
}

fn type_byte_for_kind(kind: &str) -> MemoryResult<u8> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.type_byte)
        .ok_or_else(|| {
            MemoryError::bad_request_with(
                format!("unknown entity kind {kind:?}"),
                &["Use a registry kind string such as MESSAGE, PERSON, TASK, ASSET."],
            )
        })
}

pub(super) fn kind_string_for_type(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}

/// ONE-1889: the broad structural door is CREATE-ONLY. Any stored row at `id`
/// refuses the put, whatever its kind and whatever kind is incoming — the
/// guard reads the STORED type, never the caller's, so reusing a live id with
/// a different kind cannot clobber its body.
///
/// Call this inside the would-be put's own write transaction, after the
/// hard-delete marker check and before any staging, so a refusal costs no
/// entity bytes, edges, text postings, temporal rows, or short ids, and a
/// concurrent create resolves to exactly one winner and one refusal.
fn ensure_structural_create_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<()> {
    let Some(stored_type) = vault.get_entity_type_in_txn(txn, id)? else {
        return Ok(());
    };
    Err(structural_overwrite_refusal(stored_type))
}

/// The one stable refusal [`ensure_structural_create_in_txn`] returns. Keyed
/// solely on the STORED kind, so same-kind and cross-kind retries at the same
/// id are indistinguishable: the caller learns which kind owns the id and
/// which door to use, never anything about the stored body.
fn structural_overwrite_refusal(stored_type: u8) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{} entities cannot be overwritten through the structural door",
            kind_string_for_type(stored_type),
        ),
        &[
            "put_structural is create-only; this id already holds a stored entity.",
            "Create a new entity, or use the stored kind's typed mutation verb.",
        ],
    )
}

impl Memory<'_> {
    // ── B2 migrator write-verb group ────────────────────────────────────

    /// Structural put carrying text-index fields and outgoing edges, in one
    /// atomic batch. CLAIM-kind writes are rejected — claims go through
    /// [`Self::commit`] so the gate always sees them.
    ///
    /// Actor-capable kinds are provisioning-gated (the facade is not an
    /// actor-forgery door): MACHINE (the `system` class type) is never
    /// writable here — system actors are provisioned by the engine host —
    /// and PERSON (rebindable as `human`/`agent`, where the default
    /// manifest grants the human class an auto ceiling) may be minted
    /// only by a VERIFIED human-class owner actor. Companion-persona and
    /// owner PERSON creation stays available to the owner-bound migrator
    /// (design §2.3/§2.8); no non-owner actor can create an entity that
    /// binds to any actor class.
    ///
    /// CREATE-ONLY (ONE-1889). This is a migration/create door, not a generic
    /// update verb: every id that already holds a stored entity is refused,
    /// whatever its stored kind and whatever kind is incoming. Fresh mints
    /// stay fully available — caller-supplied fresh ids and generated ids
    /// alike — and still commit body, resolved outgoing edges, and text
    /// fields atomically. Mutating a stored entity is its typed verb's job;
    /// the prior row is the snapshot of record, so a refusal here destroys
    /// nothing and mints nothing.
    pub fn put_structural(&self, input: &StructuralPutInput) -> MemoryResult<EntityRefReceipt> {
        let type_byte = type_byte_for_kind(&input.kind)?;
        if type_byte == ENTITY_TYPE_CLAIM {
            return Err(MemoryError::bad_request_with(
                "CLAIM entities cannot be written structurally",
                &["Use commit/claim_upsert so the write gate sees the claim."],
            ));
        }
        if type_byte == ENTITY_TYPE_MACHINE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MACHINE entities cannot be written through the facade",
                &[
                    "MACHINE is the system-actor class type; minting one would forge an actor.",
                    "System actors are provisioned by the engine host, not the bridge.",
                ],
            ));
        }
        // NOTE bodies carry `author_ref`, and attribution is engine-stamped by
        // construction: a caller who could hand-write the body could forge
        // another actor's take. This broad door has no way to bind one, so it
        // refuses the kind outright rather than validating a body it cannot
        // trust.
        if type_byte == ENTITY_TYPE_NOTE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "NOTE entities cannot be written through the structural door",
                &[
                    "NOTE bodies are actor-attributed; a caller-supplied author_ref would be a forgery.",
                    "Use author_take, which stamps the bound facade actor.",
                ],
            ));
        }
        if type_byte == ENTITY_TYPE_PERSON && self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                    self.actor_class.gate_actor_class(),
                ),
                &[
                    "PERSON entities rebind as human/agent actors; only the owner mints them.",
                    "Bind a verified human-class owner actor key to create people.",
                ],
            ));
        }
        if !input.body.is_object() {
            return Err(MemoryError::bad_request(
                "structural body must be a JSON object",
            ));
        }
        let id = id_from_optional_hex(input.id.as_deref())?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        let data = encode_rmpv(&json_to_rmpv(&input.body))?;

        let mut resolved_edges = Vec::new();
        if let Some(edges) = &input.edges {
            for spec in edges {
                let kind = edge_kind_from_str(&spec.edge_kind).ok_or_else(|| {
                    MemoryError::bad_request_with(
                        format!("unknown edge kind {:?}", spec.edge_kind),
                        &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                    )
                })?;
                // ONE-1414: `same_as` asserts cross-vault identity, and the
                // assertion is only meaningful together with the status Claim
                // and per-pact consent surface that
                // `federation::put_coreference_link` writes in ONE actor-gated
                // transaction. A raw link minted here would be an identity
                // claim with no status, no consent, and no attributed actor —
                // and the export filter reads the link's consent to decide
                // what crosses a grant, so a forgeable link is a disclosure
                // surface. The federation helper is the owning write door.
                if kind == EdgeKind::SameAs {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "same_as edges cannot be written through the structural door",
                        &[
                            "same_as is a cross-vault identity link carrying status and per-pact share consent.",
                            "Use the federation coreference door so the link and its status claim land atomically.",
                        ],
                    ));
                }
                let target = self.resolve_ref(&spec.target_ref)?;
                let weight = spec.weight.or_else(|| kind.default_weight()).unwrap_or(1.0);
                resolved_edges.push((kind, target, weight));
            }
        }
        let text_fields: Vec<(String, String)> = input
            .text_fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| (field.field.clone(), field.value.clone()))
            .collect();
        let text_index_trusted = if text_fields.is_empty() {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        } else {
            self.vault.ensure_text_index_trusted()?;
            true
        };

        // Marker check and put share ONE write transaction (A1): a
        // concurrent hard delete either commits first (refused here) or
        // after this txn (its purge then erases what we wrote).
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            // Minting a PERSON mints a future actor identity, so it is an
            // owner verb. The pre-txn class check above gives the fast typed
            // error; the authority-log teeth run in-txn (TOCTOU-free).
            if type_byte == ENTITY_TYPE_PERSON {
                verify_owner_actor_binding_in_txn(self.vault, &*wtxn, self.actor)?;
            }
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Ok(true);
            }
            ensure_structural_create_in_txn(self.vault, &*wtxn, &id)?;
            let mut batch = self
                .vault
                .batch_in()
                .put(&id, type_byte, occurred, learned_at, &data);
            for (kind, target, weight) in &resolved_edges {
                batch = batch.edge(&id, *kind, target, *weight);
            }
            batch.apply(wtxn)?;
            if !text_fields.is_empty() {
                apply_ops(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    vec![BatchOp::Text {
                        id,
                        fields: text_fields.clone(),
                    }],
                    text_index_trusted,
                    false,
                    true,
                )?;
            }
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt(&id)
    }

    /// Appends one immutable habit check-in child (`ChildOf` edge written by
    /// the pack contract). The pinned `role` body key is facade-injected.
    pub fn put_habit_checkin(&self, input: &HabitCheckinInput) -> MemoryResult<EntityRefReceipt> {
        let habit_id = self.resolve_ref(&input.habit_ref)?;
        let checkin_id = id_from_optional_hex(input.id.as_deref())?;
        let mut entries = vec![(
            Value::from("role"),
            Value::from(u64::from(TaskRole::HabitCheckin.role_byte())),
        )];
        if let Some(data) = &input.data {
            let Some(map) = data.as_object() else {
                return Err(MemoryError::bad_request(
                    "checkin data must be a JSON object",
                ));
            };
            for (key, value) in map {
                if key == "role" {
                    return Err(MemoryError::bad_request_with(
                        "checkin data must not carry the pinned role key",
                        &["Drop the role field; the facade stamps HabitCheckin."],
                    ));
                }
                entries.push((Value::from(key.as_str()), json_to_rmpv(value)));
            }
        }
        let data = encode_rmpv(&Value::Map(entries))?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // Marker check and checkin put share one write transaction (A1).
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &checkin_id)?
            {
                return Ok(true);
            }
            self.vault
                .batch_in()
                .put_habit_checkin(&habit_id, &checkin_id, occurred, learned_at, &data)
                .apply(wtxn)?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&checkin_id));
        }
        self.entity_ref_receipt(&checkin_id)
    }

    /// Appends one attributed `opinion/take` NOTE beside `target`
    /// (ARCH-0032 · OF-330).
    ///
    /// Attribution is engine-stamped: the stored `author_ref` and the
    /// mandatory `NOTE ─AuthoredBy→ actor` edge both come from the actor
    /// bound to this facade, revalidated against the store inside this write
    /// transaction. The input carries no author field, so there is nothing a
    /// caller can spoof, and this is the only NOTE writer there is: the raw
    /// batch put refuses the type, leaving no second door to hand-write a
    /// body through.
    ///
    /// Neutrality is the whole point (ARCH-0003). A take over a CLAIM writes
    /// a NOTE plus an inbound `ClaimOf` edge and NOTHING else — no put,
    /// supersede, or retract reaches the target — so the target's raw body,
    /// lifecycle, learned-at, and content hash are byte-identical afterwards.
    /// Takes are append-only entities, not an upsert keyed by
    /// `(actor, target)`: two actors over one claim produce two NOTE ids and
    /// two independent `AuthoredBy` edges.
    ///
    /// Every rejection — unbound or wrong-class actor, missing target, and a
    /// `TakeTarget::Claim` that is not type-0 — happens before a single row is
    /// staged, so a refused take leaves no orphan NOTE or edge.
    ///
    /// Exempt from the hard-delete recreation refusal BY CONSTRUCTION: the
    /// NOTE id is a fresh [`EntityId::now`], never caller-supplied.
    pub fn author_take(
        &self,
        target: TakeTarget,
        markdown: impl Into<String>,
    ) -> MemoryResult<EntityRefReceipt> {
        let body = encode_note_body(&NoteBody {
            kind: NoteKind::OpinionTake,
            author_ref: self.actor,
            markdown: markdown.into(),
        })?;
        let note_id = EntityId::now();
        let at = crate::unix_seconds_now();
        let occurred = TimeRange { start: at, end: at };
        let (target_id, link, target_must_be_claim) = match target {
            TakeTarget::Subject(id) => (id, EdgeKind::About, false),
            TakeTarget::Claim(id) => (id, EdgeKind::ClaimOf, true),
        };

        self.with_verified_actor_write_txn(|wtxn| {
            let Some(stored_type) = self.vault.get_entity_type_in_txn(&*wtxn, &target_id)? else {
                return Err(MemoryError::not_found(format!(
                    "take target {} does not exist",
                    target_id.to_hex()
                )));
            };
            if target_must_be_claim && stored_type != ENTITY_TYPE_CLAIM {
                return Err(MemoryError::bad_request_with(
                    format!("take target {} is not a CLAIM", target_id.to_hex()),
                    &["Use TakeTarget::Subject to take a position on a non-claim entity."],
                ));
            }
            self.vault
                .batch_in()
                .put_authored_note(&note_id, &self.actor, occurred, at, &body)
                .edge(
                    &note_id,
                    EdgeKind::AuthoredBy,
                    &self.actor,
                    registered_edge_weight(EdgeKind::AuthoredBy),
                )
                .edge(&note_id, link, &target_id, registered_edge_weight(link))
                .apply(wtxn)?;
            Ok(())
        })?;
        self.entity_ref_receipt(&note_id)
    }

    /// Registers a companion persona record (personal scope) with a
    /// `created` lifecycle event, retiring it when `retired_at` is set.
    pub fn put_companion_record(
        &self,
        input: &CompanionRecordInput,
    ) -> MemoryResult<EntityRefReceipt> {
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let owner = self.resolve_ref(&input.owner_ref)?;
        let persona = self.resolve_ref(&input.persona_ref)?;
        let source = match &input.source {
            Some(source) => parse_claim_source(source)?,
            None => ClaimSource::UserStated,
        };
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor, self.actor_class),
            source,
            WriteProvenance::new(facade_provenance("put_companion_record"))?,
            ClaimApprovalStatus::Approved,
        );
        let record = CompanionRecord::persona(
            CompanionScope::personal(owner),
            persona,
            json_to_rmpv(&input.value),
            CompanionProvenance::from_envelope(&envelope),
            CompanionExportClassification::LocalOnly,
        );
        self.with_verified_actor_write_txn(|wtxn| {
            // The early refusal above is only a fast path. Recheck in this
            // transaction so a concurrent hard delete cannot land between
            // the probe and companion creation, resurrecting a purged id.
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Err(hard_deleted_refusal(&id));
            }
            self.vault
                .create_companion_record_in_txn(wtxn, &id, &record, input.learned_at)?;
            if let Some(retired_at) = input.retired_at {
                self.vault
                    .retire_companion_record_in_txn(wtxn, &id, retired_at)?;
            }
            Ok(())
        })?;
        self.entity_ref_receipt(&id)
    }

    /// Admits one imported-evidence claim through the registered ingest
    /// source's trust ceiling (B1a). Unknown sources fail closed. The
    /// requested approval is `auto` only when the ceiling permits it at
    /// band 0; the gate still decides, and a refused `auto` request is
    /// resubmitted `proposed`.
    pub fn admit_imported_claim(
        &self,
        input: &AdmitImportedClaimInput,
    ) -> MemoryResult<CommitReceipt> {
        self.verified_actor_class()?;
        let Some(config) = INGEST_SOURCE_REGISTRY.get_config(&input.source_id) else {
            return Err(MemoryError::bad_request_with(
                format!("unknown ingest source {:?}", input.source_id),
                &["Register the source in the ingest source registry first."],
            ));
        };
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(MemoryError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let claim = NormalizedIngestClaim {
            source_record_id: input.source_record_id.clone(),
            predicate: input.predicate.clone(),
            value: input.value.clone(),
        };
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        let mut approval = if config.trust_ceiling.permits_auto(Some(0)) {
            ClaimApprovalStatus::Auto
        } else {
            config.default_admission
        };
        let admit = |approval: ClaimApprovalStatus| {
            let admission = ImportedEvidenceAdmission::proposed(
                input.source_id.clone(),
                id,
                ImportedEvidenceEntityResolution::subject(subject),
                WriteActor::new(self.actor, self.actor_class),
                occurred,
                learned_at,
            )
            .with_approval(approval);
            admit_imported_evidence_claim(self.vault, &claim, admission)
        };
        match admit(approval) {
            Ok(()) => {}
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                admit(approval)?;
            }
            Err(err) => return Err(err.into()),
        }
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    /// Registers a blob artifact (B8 blob door; bytes ride
    /// [`Self::append_blob_version`]).
    pub fn put_blob_artifact(&self, input: &BlobArtifactInput) -> MemoryResult<EntityRefReceipt> {
        let id = id_from_optional_hex(input.id.as_deref())?;
        let body = crate::blob_artifact::BlobArtifactBody::new(
            input.name.clone(),
            input.media_type.clone(),
        );
        let data = crate::blob_artifact::encode_blob_artifact_body(&body)?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // Marker check and artifact put share one write transaction (A1);
        // the encoded body matches Vault::put_blob_artifact exactly.
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Ok(true);
            }
            self.vault
                .batch_in()
                .put(&id, ENTITY_TYPE_BLOB_ARTIFACT, occurred, learned_at, &data)
                .apply(wtxn)?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt(&id)
    }

    /// Appends one content-addressed version to a blob artifact. The whole
    /// append (ASSET bytes + `blob.version` LEDGER claim + version chain)
    /// is one engine transaction; re-appending head bytes is a dedupe no-op.
    ///
    /// Exempt from the hard-delete recreation refusal BY CONSTRUCTION: no
    /// caller-supplied id is written here — the ASSET id is content-derived
    /// inside the engine (module-private derivation) and the LEDGER claim
    /// id is a fresh `EntityId::now()`. The inherent edge of erasure
    /// integrity for content-addressed storage remains: a hard-deleted
    /// ASSET can be re-materialized by re-supplying identical bytes to a
    /// live artifact.
    pub fn append_blob_version(
        &self,
        artifact_ref: &str,
        bytes: &[u8],
        run_ref: Option<&str>,
        occurred_at: u64,
        learned_at: Option<u64>,
    ) -> MemoryResult<BlobVersionView> {
        let artifact_id = self.resolve_ref(artifact_ref)?;
        let provenance = match run_ref {
            Some(run_ref) => crate::blob_artifact::BlobVersionProvenance::AgentRun {
                run_ref: run_ref.to_owned(),
            },
            None => crate::blob_artifact::BlobVersionProvenance::UserUpload,
        };
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        let record = self.with_verified_actor_write_txn(|wtxn| {
            self.vault
                .append_blob_artifact_version_in_txn(
                    wtxn,
                    &artifact_id,
                    bytes,
                    &provenance,
                    WriteActor::new(self.actor, self.actor_class),
                    occurred,
                    learned_at.unwrap_or(occurred_at),
                )
                .map_err(MemoryError::from)
        })?;
        Ok(BlobVersionView {
            artifact_ref: artifact_id.to_hex(),
            version: record.version,
            content_hash_hex: hex_string(&record.content_hash),
            claim_ref: record.claim_id.to_hex(),
            created_at: record.created_at,
        })
    }

    /// Reads one blob artifact version's bytes (hash-verified by the engine).
    pub fn read_blob_version(
        &self,
        artifact_ref: &str,
        version: u64,
    ) -> MemoryResult<Option<Vec<u8>>> {
        let artifact_id = self.resolve_ref(artifact_ref)?;
        self.vault
            .read_blob_artifact_version(&artifact_id, version)
            .map_err(MemoryError::from)
    }
}
