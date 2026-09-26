//! Canonical adapter for narrow metadata-preserving operational entity updates.
use super::{ChangeOp, EntityStoreMaintenance, EntityStoreRead, MutationAudit, ScrubbedRecord};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::*;
use crate::{
    EntityId,
    error::{Error, Result},
    store::Store,
};
use heed::RwTxn;
/// The stored record and its parsed header, owned so the caller may write in the same txn.
fn stored_record(store: &Store, txn: &RwTxn<'_>, id: &EntityId) -> Result<(Vec<u8>, u8)> {
    let stored = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?
        .to_vec();
    let header =
        EntityMetadataHeader::parse(&stored).ok_or(Error::CorruptedIndex("entity metadata"))?;
    Ok((stored, header.entity_type))
}

/// Whether a body is one MessagePack map carrying exactly one `entity_doc_ref` string.
#[cfg(feature = "sync")]
fn carries_one_document_pointer(body: &[u8]) -> bool {
    let mut cursor = std::io::Cursor::new(body);
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    let mut pointers = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("entity_doc_ref"));
    cursor.position() == body.len() as u64
        && matches!((pointers.next(), pointers.next()), (Some((_, value)), None) if value.is_str())
}

impl EntityStoreMaintenance for Store {
    fn port_entity_scrub(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        record: ScrubbedRecord,
        recorded_at: u64,
    ) -> Result<bool> {
        let (stored, entity_type) = stored_record(self, txn, id)?;
        let mut scrubbed = stored[..ENTITY_METADATA_HEADER_LEN].to_vec();
        if let ScrubbedRecord::AuthorStampRemoved(body) = record {
            if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                return Err(Error::CorruptedIndex("identity topology event type"));
            }
            let event = crate::identity_topology::decode_identity_topology_event_body(&body)
                .map_err(|_| Error::InvariantViolation("an author-stamp scrub writes an event"))?;
            if event.actor.is_some() {
                return Err(Error::InvariantViolation(
                    "an author-stamp scrub leaves no author stamp",
                ));
            }
            scrubbed.extend_from_slice(&body);
        }
        if scrubbed == stored {
            return Ok(false);
        }
        self.entities.put(txn, id.as_bytes(), &scrubbed)?;
        super::audit_mutation_in_txn(
            self,
            txn,
            MutationAudit {
                entity: *id,
                op: ChangeOp::Redact,
                actor_principal: None,
                occurred_at: recorded_at,
                input: id.as_bytes(),
                reason: None,
            },
        )?;
        Ok(true)
    }
    #[cfg(feature = "sync")]
    fn port_entity_document_pointer_put(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        body: &[u8],
    ) -> Result<()> {
        let (stored, _) = stored_record(self, txn, id)?;
        if !carries_one_document_pointer(body) {
            return Err(Error::InvariantViolation(
                "a document pointer body carries exactly one entity_doc_ref",
            ));
        }
        let mut payload = stored[..ENTITY_METADATA_HEADER_LEN].to_vec();
        payload.extend_from_slice(body);
        self.entities.put(txn, id.as_bytes(), &payload)
    }
    fn port_redaction_receipt_sweep_complete(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        completed_at: u64,
    ) -> Result<()> {
        let (stored, entity_type) = stored_record(self, txn, id)?;
        if entity_type != ENTITY_TYPE_REDACTION_AUDIT {
            return Err(Error::CorruptedIndex("redaction audit entity type"));
        }
        let mut receipt =
            crate::deletion::decode_redaction_audit_receipt(&stored[ENTITY_METADATA_HEADER_LEN..])?;
        if receipt.sweep_complete_at.is_some() {
            return Err(Error::InvariantViolation(
                "a redaction audit receipt completes its sweep once",
            ));
        }
        receipt.sweep_complete_at = Some(completed_at);
        let body = rmp_serde::to_vec_named(&receipt)
            .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
        crate::deletion::validate_redaction_receipt_body(&body)?;
        let mut payload = stored[..ENTITY_METADATA_HEADER_LEN].to_vec();
        payload.extend_from_slice(&body);
        crate::vault::entity_revision::capture_entity_revision(self, txn, id, &payload)?;
        self.entities.put(txn, id.as_bytes(), &payload)
    }
    #[cfg(feature = "sync")]
    fn port_retained_shell_restore(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        header: &[u8],
    ) -> Result<()> {
        if header.len() != ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvariantViolation(
                "a retained shell is a header without a body",
            ));
        }
        self.entities.put(txn, id.as_bytes(), header)
    }
    #[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
    fn port_raw_record_seed(&self, txn: &mut RwTxn<'_>, id: &EntityId, raw: &[u8]) -> Result<()> {
        self.entities.put(txn, id.as_bytes(), raw)
    }
    fn port_contact_cache_evict(&self, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
        let Some(row) = self.port_entity_record(txn, id)? else {
            return Ok(());
        };
        if row.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::CorruptedIndex("counterparty contact cache type"));
        }
        self.type_index
            .delete(txn, &Store::encode_type_key(row.entity_type, id))?;
        self.temporal_occurred_start
            .delete(txn, &Store::encode_temporal_key(row.occurred.start, id))?;
        self.temporal_occurred_end
            .delete(txn, &Store::encode_temporal_key(row.occurred.end, id))?;
        self.temporal_long_intervals
            .delete(txn, &Store::encode_temporal_key(row.occurred.end, id))?;
        self.temporal_learned
            .delete(txn, &Store::encode_temporal_key(row.learned_at, id))?;
        self.entities.delete(txn, id.as_bytes())?;
        Ok(())
    }
    fn port_connector_key_rewrite(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        record: &crate::connector_key::ConnectorKeyRecord,
    ) -> Result<()> {
        let mut row = self
            .port_entity_record(txn, id)?
            .ok_or(Error::EntityNotFound)?;
        if row.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
            return Err(Error::CorruptedIndex("connector key entity type"));
        }
        row.body = crate::connector_key::encode_connector_key_body(record)?;
        let payload = row.encode();
        crate::vault::entity_revision::capture_entity_revision(self, txn, id, &payload)?;
        self.entities.put(txn, id.as_bytes(), &payload)
    }
    fn port_outbound_grant_touch(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        grant: crate::outbound_grant::StandingOutboundGrant,
        used_at: u64,
    ) -> Result<()> {
        let mut row = self
            .port_entity_record(txn, id)?
            .ok_or(Error::EntityNotFound)?;
        if row.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::CorruptedIndex("outbound grant entity type"));
        }
        row.body =
            crate::outbound_grant::encode_standing_outbound_grant_body(&grant.touched(used_at)?)?;
        let payload = row.encode();
        crate::vault::entity_revision::capture_entity_revision(self, txn, id, &payload)?;
        self.entities.put(txn, id.as_bytes(), &payload)
    }
    fn port_habit_streak_materialize(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        streak: crate::habit::HabitStreak,
    ) -> Result<()> {
        let Some(mut row) = self.port_entity_record(txn, id)? else {
            return Ok(());
        };
        let body = crate::habit::rewrite_habit_streak_fields(&row.body, streak)?;
        if body != row.body {
            row.body = body;
            let payload = row.encode();
            crate::vault::entity_revision::capture_entity_revision(self, txn, id, &payload)?;
            self.entities.put(txn, id.as_bytes(), &payload)?;
        }
        Ok(())
    }
    fn port_redaction_audit_append(
        &self,
        _permit: &crate::off_record::FloorWrites<'_>,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        let row = super::EntityRecord {
            entity_type: ENTITY_TYPE_REDACTION_AUDIT,
            occurred: crate::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            body: body.to_vec(),
        };
        self.entities.put(txn, id.as_bytes(), &row.encode())?;
        self.type_index
            .put(txn, &Store::encode_type_key(row.entity_type, id), &[])?;
        let key = Store::encode_temporal_key(learned_at, id);
        self.temporal_occurred_start.put(txn, &key, &[])?;
        self.temporal_learned.put(txn, &key, &[])?;
        Ok(())
    }
}
