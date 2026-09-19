//! Canonical adapter for narrow metadata-preserving operational entity updates.
use super::{EntityStoreMaintenance, EntityStoreRead};
use crate::registry::*;
use crate::{
    EntityId,
    error::{Error, Result},
    store::Store,
};
use heed::RwTxn;
impl EntityStoreMaintenance for Store {
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
        self.entities.put(txn, id.as_bytes(), &row.encode())
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
        self.entities.put(txn, id.as_bytes(), &row.encode())
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
            self.entities.put(txn, id.as_bytes(), &row.encode())?;
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
