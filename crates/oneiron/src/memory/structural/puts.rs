//! Generic structural puts, habit check-ins, and blob artifact verbs.

use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::batch::{BatchOp, apply_ops};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::habit::TaskRole;
use crate::memory::support::{
    encode_rmpv, hard_deleted_refusal, hex_string, id_from_optional_hex, json_to_rmpv,
    verify_owner_actor_binding_in_txn,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::{
    ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON,
};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::{
    BlobArtifactInput, BlobVersionView, EntityRefReceipt, HabitCheckinInput, StructuralPutInput,
    edge_kind_from_str, ensure_structural_create_in_txn, type_byte_for_kind,
};
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
        // ONE-1686 (RT-04): MESSAGE bodies carry the six-axis witness envelope
        // — author, type, content, metadata, visibility, order — and the
        // approval-ceiling door authorizes exactly those axes at the witness
        // write boundary. A caller who could hand-write the body here would
        // author an unattributed `system` row, hide a row, or smuggle a
        // metadata side channel through a door that never asked. Same posture
        // as the NOTE refusal above: this broad door has no envelope to bind,
        // so it refuses the kind rather than validating a body it cannot trust.
        if type_byte == ENTITY_TYPE_MESSAGE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MESSAGE entities cannot be written through the structural door",
                &[
                    "MESSAGE bodies are gated envelopes; a caller-supplied body would bypass the witness ceiling.",
                    "Use witness, which binds author, type, content, metadata, visibility and order to the acting actor.",
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
