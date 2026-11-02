//! Generic structural puts, habit check-ins, and blob artifact verbs.

use rmpv::Value;

use crate::edge::{EdgeActorClass, EdgeKind};
use crate::habit::TaskRole;
use crate::memory::support::{
    encode_rmpv, hard_deleted_refusal, hex_string, id_from_optional_hex, json_to_rmpv,
    verify_owner_actor_binding_in_txn,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{
    ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use crate::temporal::TimeRange;

use super::{
    BlobArtifactInput, BlobVersionView, EntityRefReceipt, HabitCheckinInput, StructuralPutInput,
    ensure_structural_create_in_txn, type_byte_for_kind,
};

mod guarded;

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
        self.put_structural_guarded(input, |_| Ok(()))
    }

    /// Appends one immutable habit check-in child (`ChildOf` edge written by
    /// the pack contract). The pinned `role` body key is facade-injected.
    pub fn put_habit_checkin(&self, input: &HabitCheckinInput) -> MemoryResult<EntityRefReceipt> {
        let habit_id = self.resolve_ref(&input.habit_ref)?;
        let checkin_id = id_from_optional_hex(self.vault, input.id.as_deref())?;
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
        let refused = self.with_actor_content_write_txn(|content| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(content.read(), &checkin_id)?
            {
                return Ok(true);
            }
            content.apply_batch(self.vault.batch_in().put_habit_checkin(
                &habit_id,
                &checkin_id,
                occurred,
                learned_at,
                &data,
            ))?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&checkin_id));
        }
        self.entity_ref_receipt_of(&checkin_id, crate::registry::ENTITY_TYPE_TASK)
    }

    /// Registers a blob artifact (B8 blob door; bytes ride
    /// [`Self::append_blob_version`]).
    pub fn put_blob_artifact(&self, input: &BlobArtifactInput) -> MemoryResult<EntityRefReceipt> {
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
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
        let refused = self.with_actor_content_write_txn(|content| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
            {
                return Ok(true);
            }
            content.apply_batch(self.vault.batch_in().put(
                &id,
                ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                learned_at,
                &data,
            ))?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt_of(&id, ENTITY_TYPE_BLOB_ARTIFACT)
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
        let record = self.with_actor_content_write_txn(|content| {
            Ok(content.update_artifact(artifact_id, |txn| {
                self.vault.append_blob_artifact_version_in_txn(
                    txn,
                    &artifact_id,
                    bytes,
                    &provenance,
                    self.write_actor(),
                    occurred,
                    learned_at.unwrap_or(occurred_at),
                )
            })?)
        })?;
        Ok(BlobVersionView {
            artifact_ref: artifact_id.to_hex(),
            version: record.version,
            content_hash_hex: hex_string(&record.content_hash),
            claim_ref: record.claim_id.to_hex(),
            created_at: record.created_at,
            artifact: Some(crate::lens::RecordRef::from_id(
                ENTITY_TYPE_BLOB_ARTIFACT,
                &artifact_id,
                None,
            )),
            claim: Some(crate::lens::RecordRef::from_id(
                crate::registry::ENTITY_TYPE_CLAIM,
                &record.claim_id,
                None,
            )),
        })
    }

    /// Reads one blob artifact version's bytes (hash-verified by the engine),
    /// with any keys in them masked unless the bound actor is the owner.
    pub fn read_blob_version(
        &self,
        artifact_ref: &str,
        version: u64,
    ) -> MemoryResult<Option<Vec<u8>>> {
        let artifact_id = self.resolve_ref(artifact_ref)?;
        self.vault
            .read_blob_artifact_version_as(&artifact_id, version, self.secret_sight()?)
            .map_err(MemoryError::from)
    }
}
