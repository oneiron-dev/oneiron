//! Vault record APIs for companion profiles, relationships, and register snapshots.

use super::codec::{decode_companion_record_body, encode_companion_record_body};
use super::keys::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, COMPANION_TASK_ATTEMPT_KIND,
    ENTITY_TYPE_COMPANION_REGISTER,
};
use super::model::{
    CompanionExportClassification, CompanionRecord, CompanionRecordKey, CompanionSubject,
};
use super::queue::{
    CompanionTask, CompanionTaskKind, CompanionTaskStatus, EndCompanionRelationship,
    EndCompanionRelationshipOutcome, EnqueueCompanionTaskOutcome, encode_companion_task_payload,
};
use super::register::CompanionRegister;
use super::store::{companion_record_any_id_for_key_in_txn, companion_record_id_for_key_in_txn};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, RegistryError, Result};
use crate::registry::{EntityClassification, TypeByteZone, entity_type_registry_entry};
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;
use rmpv::Value;

impl Vault {
    /// Returns the active grant id authorizing a companion profile, if any.
    pub fn companion_profile_access_grant(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        persona_ref: &EntityId,
    ) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        crate::gate::companion_profile_access_grant(
            &self.store,
            &rtxn,
            principal_ref,
            person_ref,
            persona_ref,
        )
    }

    /// Creates a companion register record when neither the entity id nor the
    /// `(scope, subject)` register key is already present.
    pub fn create_companion_record(
        &self,
        id: &EntityId,
        record: &CompanionRecord,
        learned_at: u64,
    ) -> Result<()> {
        self.ensure_companion_register_kind()?;
        let mut wtxn = self.store.env.write_txn()?;
        self.create_companion_record_in_txn(&mut wtxn, id, record, learned_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Transaction-composable body of [`Vault::create_companion_record`].
    pub(crate) fn create_companion_record_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &CompanionRecord,
        learned_at: u64,
    ) -> Result<()> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record create must be active",
            ));
        }
        let record = record.created_at(learned_at)?;
        let data = encode_companion_record_body(&record)?;
        let key = record.key();
        if self.store.entities.get(&*wtxn, id.as_bytes())?.is_some()
            || companion_record_any_id_for_key_in_txn(&self.store, &*wtxn, &key)?.is_some()
        {
            return Err(Error::Record(RecordError::CompanionRecordAlreadyExists));
        }
        self.apply_companion_record_body(wtxn, id, learned_at, data)?;
        Ok(())
    }

    /// Writes or replaces a companion register record for an existing id.
    ///
    /// The register key is immutable for an existing record; callers that need
    /// a different `(scope, subject)` should create a new record and retire the
    /// old one.
    pub fn update_companion_record(
        &self,
        id: &EntityId,
        record: &CompanionRecord,
        learned_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record update must be active",
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_companion_record_in_txn(&wtxn, id)?;
        if existing.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody("companion record is retired"));
        }
        if existing.key() != record.key() {
            return Err(Error::InvalidClaimBody(
                "companion record key cannot change",
            ));
        }
        if existing.export_classification != CompanionExportClassification::LocalOnly
            && record.export_classification == CompanionExportClassification::LocalOnly
        {
            return Err(Error::InvalidClaimBody(
                "companion record export cannot be downgraded to local_only",
            ));
        }
        let mut updated = record.clone();
        updated.lifecycle_events = existing.lifecycle_events;
        if updated.lifecycle_events.is_empty() {
            let ev = crate::companion::CompanionLifecycleEvent::created(learned_at);
            updated.lifecycle_events.push(ev);
        }
        let data = encode_companion_record_body(&updated)?;
        self.apply_companion_record_body(&mut wtxn, id, learned_at, data)?;
        wtxn.commit()?;
        Ok(updated)
    }

    /// Reads and decodes one companion register record by entity id.
    pub fn get_companion_record(&self, id: &EntityId) -> Result<Option<CompanionRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Retires a companion register record by rewriting it as retracted and
    /// stamping an auditable lifecycle event. Repeating retire on an already
    /// retracted record is an idempotent no-op that returns the stored record
    /// without adding another lifecycle event.
    pub fn retire_companion_record(
        &self,
        id: &EntityId,
        retired_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        let mut wtxn = self.store.env.write_txn()?;
        let retired = self.retire_companion_record_in_txn(&mut wtxn, id, retired_at)?;
        wtxn.commit()?;
        Ok(retired)
    }

    /// Transaction-composable body of [`Vault::retire_companion_record`].
    pub(crate) fn retire_companion_record_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        retired_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        let existing = self.read_companion_record_in_txn(&*wtxn, id)?;
        if existing.lifecycle == ClaimLifecycleStatus::Retracted {
            return Ok(existing);
        }
        let retired = existing.retired_at(retired_at)?;
        let data = encode_companion_record_body(&retired)?;
        self.apply_companion_record_body(wtxn, id, retired_at, data)?;
        Ok(retired)
    }

    /// Ends an active companion relationship by breaking the active binding,
    /// scrubbing the private relationship payload, and optionally enqueueing a
    /// goodbye-artifact generation task. General vault entities are not
    /// deleted by this teardown path.
    pub fn end_companion_relationship(
        &self,
        id: &EntityId,
        input: EndCompanionRelationship,
    ) -> Result<EndCompanionRelationshipOutcome> {
        self.ensure_companion_register_kind()?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_companion_record_in_txn(&wtxn, id)?;
        if !matches!(&existing.subject, CompanionSubject::Relationship { .. }) {
            return Err(Error::InvalidClaimBody(
                "companion relationship end requires relationship record",
            ));
        }
        let already_ended = existing.lifecycle == ClaimLifecycleStatus::Retracted;

        let mut scrubbed = existing;
        scrubbed.value = Value::Map(vec![
            (Value::from("kind"), Value::from("relationship_ended")),
            (Value::from("private_memory"), Value::from("removed")),
            (Value::from("ended_at"), Value::from(input.ended_at)),
        ]);
        let ended = if already_ended {
            scrubbed.validate_current_schema_lifecycle_events()?;
            scrubbed
        } else {
            scrubbed.retired_at(input.ended_at)?
        };
        let data = encode_companion_record_body(&ended)?;
        self.apply_companion_record_body(&mut wtxn, id, input.ended_at, data)?;

        let goodbye_artifact = if input.ended_badly || already_ended {
            None
        } else {
            let task = CompanionTask::new(CompanionTaskKind::GoodbyeArtifact, ended.key())?;
            let payload = encode_companion_task_payload(&task)?;
            let outcome = AttemptQueue::new(self).enqueue_in_txn(
                &mut wtxn,
                EnqueueAttempt {
                    kind: COMPANION_TASK_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key: Some(task.dedupe_key()),
                    run_id: input.run_id,
                    now: input.ended_at,
                },
            )?;
            let status = |attempt| CompanionTaskStatus {
                attempt,
                task: task.clone(),
            };
            Some(match outcome {
                EnqueueOutcome::Enqueued(attempt) => {
                    EnqueueCompanionTaskOutcome::Enqueued(status(attempt))
                }
                EnqueueOutcome::Existing(attempt) => {
                    EnqueueCompanionTaskOutcome::Existing(status(attempt))
                }
            })
        };

        wtxn.commit()?;
        Ok(EndCompanionRelationshipOutcome {
            record: ended,
            goodbye_artifact,
            already_ended,
        })
    }

    /// Revives a retired companion register record as a new active row.
    ///
    /// The retired row remains readable and inactive; the new id receives an
    /// active copy with a typed revive event. Raw updates to retired rows still
    /// fail closed through the generic companion-register put validator.
    pub fn revive_companion_record(
        &self,
        retired_id: &EntityId,
        revived_id: &EntityId,
        record: &CompanionRecord,
        revived_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record revive payload must be active",
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let retired = self.read_companion_record_in_txn(&wtxn, retired_id)?;
        if retired.lifecycle != ClaimLifecycleStatus::Retracted {
            return Err(Error::InvalidClaimBody(
                "companion record revive requires retired record",
            ));
        }
        if retired.key() != record.key() {
            return Err(Error::InvalidClaimBody(
                "companion record revive key cannot change",
            ));
        }
        let mut revived_seed = record.clone();
        revived_seed.lifecycle = ClaimLifecycleStatus::Retracted;
        revived_seed.lifecycle_events = retired.lifecycle_events;
        let revived = revived_seed.revived_at(revived_at)?;
        let key = revived.key();
        if self
            .store
            .entities
            .get(&wtxn, revived_id.as_bytes())?
            .is_some()
            || companion_record_id_for_key_in_txn(&self.store, &wtxn, &key)?.is_some()
        {
            return Err(Error::Record(RecordError::CompanionRecordAlreadyExists));
        }
        let data = encode_companion_record_body(&revived)?;
        self.apply_companion_record_body(&mut wtxn, revived_id, revived_at, data)?;
        wtxn.commit()?;
        Ok(revived)
    }

    /// Returns the entity id for a companion register key, if present.
    pub fn companion_record_id_for_key(
        &self,
        key: &CompanionRecordKey,
    ) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        companion_record_id_for_key_in_txn(&self.store, &rtxn, key)
    }

    /// Reads all companion records into an in-memory register snapshot.
    pub fn companion_register(&self) -> Result<CompanionRegister> {
        let rtxn = self.store.env.read_txn()?;
        let mut register = CompanionRegister::new();
        for index_entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COMPANION_REGISTER])?
        {
            let (type_key, _) = index_entry?;
            let id = entity_id_from_type_index_key(&type_key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("companion register type index"));
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
                return Err(Error::CorruptedIndex("companion register type index"));
            }
            let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.lifecycle != ClaimLifecycleStatus::Active {
                continue;
            }
            if register.register(record)?.is_some() {
                return Err(Error::CorruptedIndex("companion register duplicate key"));
            }
        }
        Ok(register)
    }

    pub(crate) fn ensure_companion_register_kind(&self) -> Result<()> {
        if self.companion_register_kind_registered()? {
            Ok(())
        } else {
            Err(Error::InvalidEntityType(ENTITY_TYPE_COMPANION_REGISTER))
        }
    }

    fn companion_register_kind_registered(&self) -> Result<bool> {
        let static_registered = entity_type_registry_entry(ENTITY_TYPE_COMPANION_REGISTER)
            .is_some_and(|entry| {
                entry.short_id_prefix == Some(COMPANION_REGISTER_SHORT_ID_PREFIX)
                    && entry.classification == EntityClassification::Pack
                    && entry.zone == TypeByteZone::System
            });
        if !static_registered {
            return Ok(false);
        }

        if let Some(registration) = self
            .store
            .structural_kind_registration(ENTITY_TYPE_COMPANION_REGISTER)
        {
            let compatible_legacy_row = registration.short_id_prefix
                == COMPANION_REGISTER_SHORT_ID_PREFIX
                && registration.zone == TypeByteZone::System
                && registration.pack == COMPANION_REGISTER_PACK_ID;
            if !compatible_legacy_row {
                tracing::warn!(
                    type_byte = ENTITY_TYPE_COMPANION_REGISTER,
                    short_id_prefix = %registration.short_id_prefix,
                    pack = %registration.pack,
                    "companion register static kind collides with incompatible dynamic metadata"
                );
                return Err(Error::Registry(
                    RegistryError::StructuralKindTypeByteCollision(ENTITY_TYPE_COMPANION_REGISTER),
                ));
            }
            tracing::warn!(
                type_byte = ENTITY_TYPE_COMPANION_REGISTER,
                "companion register static kind found a redundant legacy dynamic metadata row"
            );
        }

        Ok(true)
    }

    fn read_companion_record_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CompanionRecord> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_companion_record_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_COMPANION_REGISTER,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}
