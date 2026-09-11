//! Vault doors for AccessGrant put, create, revoke, read, and calendar registry.

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

use super::codec::{decode_access_grant_body, encode_access_grant_body, invalid_grant};
use super::record::{AccessGrant, AccessGrantScope, CalendarAccessGrantRow};
use crate::error::RecordError;

impl Vault {
    fn check_channel_identity_access_write(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        grant: &AccessGrant,
    ) -> Result<()> {
        if matches!(grant.scope, AccessGrantScope::ChannelIdentity { .. }) {
            return Err(invalid_grant());
        }
        if let Some(raw) = self.store.entities.get(txn, id.as_bytes())?
            && EntityMetadataHeader::parse(&raw)
                .is_some_and(|h| h.entity_type == ENTITY_TYPE_ACCESS_GRANT)
            && matches!(
                decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?.scope,
                AccessGrantScope::ChannelIdentity { .. }
            )
        {
            return Err(invalid_grant());
        }
        Ok(())
    }

    /// Engine-authored write door for AccessGrant control-plane records.
    ///
    /// Public generic entity puts for `ENTITY_TYPE_ACCESS_GRANT` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// pinned AccessGrant body before using the maintenance write path.
    pub fn put_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.check_channel_identity_access_write(&wtxn, id, grant)?;
        crate::share::check_generic_grant_write(self, &wtxn, id, grant)?;
        self.apply_access_grant_body(&mut wtxn, id, grant.created_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Creates an AccessGrant only when no entity already exists at `id`.
    pub fn create_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.check_channel_identity_access_write(&wtxn, id, grant)?;
        crate::share::check_generic_grant_write(self, &wtxn, id, grant)?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::Record(RecordError::AccessGrantAlreadyExists));
        }
        self.apply_access_grant_body(&mut wtxn, id, grant.created_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Revokes an AccessGrant by rewriting the same record as revoked.
    pub fn revoke_access_grant(&self, id: &EntityId, revoked_at: u64) -> Result<AccessGrant> {
        self.revoke_admitted_access_grant(id, revoked_at, |_| Ok(()))
    }

    /// Revokes the record at `id` only when `admit` accepts the grant that the
    /// write transaction itself read.
    ///
    /// The admission check rides the same `wtxn` as the rewrite: no second
    /// snapshot exists for [`Vault::put_access_grant`] to replace between the
    /// decision and the write.
    fn revoke_admitted_access_grant(
        &self,
        id: &EntityId,
        revoked_at: u64,
        admit: impl FnOnce(&AccessGrant) -> Result<()>,
    ) -> Result<AccessGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let grant = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        crate::share::check_generic_grant_write(self, &wtxn, id, &grant)?;
        admit(&grant)?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_access_grant_body(&revoked)?;
        self.apply_access_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes an AccessGrant record.
    pub fn get_access_grant(&self, id: &EntityId) -> Result<Option<AccessGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Lists every access grant whose scope names `calendar_ref`, revoked rows
    /// included, so the registry can show and un-share in one view.
    pub fn list_calendar_access_grants(
        &self,
        calendar_ref: &EntityId,
    ) -> Result<Vec<CalendarAccessGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_ACCESS_GRANT])?
        {
            let (key, _) = entry?;
            let grant_ref = entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&rtxn, grant_ref.as_bytes())? else {
                return Err(Error::CorruptedIndex("access grant entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("access grant entity header"))?;
            if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
                return Err(Error::CorruptedIndex("access grant entity type"));
            }
            let grant = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope.calendar_rung(calendar_ref).is_some() {
                rows.push(CalendarAccessGrantRow { grant_ref, grant });
            }
        }
        Ok(rows)
    }

    /// Revokes a calendar disclosure grant through the calendar surface.
    ///
    /// Fails closed on a grant that is not a calendar grant: the calendar
    /// registry must not be a general revoke door for other scopes. The scope
    /// check and the revoked rewrite share one write transaction, so the record
    /// this door admits is exactly the record it revokes.
    pub fn revoke_calendar_access_grant(
        &self,
        grant_ref: &EntityId,
        revoked_at: u64,
    ) -> Result<AccessGrant> {
        self.revoke_admitted_access_grant(grant_ref, revoked_at, |grant| {
            if matches!(grant.scope, AccessGrantScope::Calendar { .. }) {
                Ok(())
            } else {
                Err(Error::Record(RecordError::InvalidAccessGrantBody(
                    "grant is not a calendar disclosure grant",
                )))
            }
        })
    }

    pub(crate) fn apply_access_grant_body(
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
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
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
