//! Vault doors for AccessGrant put, create, revoke, read, and calendar registry.

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::temporal::TimeRange;

use super::codec::{decode_access_grant_body, encode_access_grant_body, invalid_grant};
use super::record::{AccessGrant, AccessGrantScope, CalendarAccessGrantRow};
use crate::error::RecordError;

impl Vault {
    /// A companion-profile grant names a live PERSON, and a live FACET when
    /// it is bounded to one. No other scope shape is judged here.
    pub(super) fn check_companion_profile_target(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: &AccessGrant,
    ) -> Result<()> {
        let Some((person_ref, facet_ref)) = grant.scope.companion_profile_refs() else {
            return Ok(());
        };
        let live_as = |id: &EntityId, kind: u8| match crate::vault::live_entity_row_in_txn(
            &self.store,
            txn,
            id,
        )? {
            crate::vault::LiveEntityRow::Live { entity_type, .. } if entity_type == kind => Ok(()),
            _ => Err(invalid_grant()),
        };
        live_as(&person_ref, crate::registry::ENTITY_TYPE_PERSON)?;
        facet_ref.map_or(Ok(()), |facet_ref| {
            live_as(&facet_ref, crate::registry::ENTITY_TYPE_FACET)
        })
    }

    fn check_channel_identity_access_write(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        grant: &AccessGrant,
    ) -> Result<()> {
        if matches!(
            grant.scope,
            AccessGrantScope::ChannelIdentity { .. } | AccessGrantScope::DiaryCoreference { .. }
        ) {
            return Err(invalid_grant());
        }
        if let Some(raw) = self
            .store
            .port_entity_record(txn, id)?
            .map(|row| row.encode())
            && EntityMetadataHeader::parse(&raw)
                .is_some_and(|h| h.entity_type == ENTITY_TYPE_ACCESS_GRANT)
            && matches!(
                decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?.scope,
                AccessGrantScope::ChannelIdentity { .. }
                    | AccessGrantScope::DiaryCoreference { .. }
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
    /// A revoked or expired grant stays so under its id (FIX 8639): a put
    /// that would make it active again is refused, and renewed access takes
    /// a new grant id. Active edits and terminal re-puts land as before.
    pub fn put_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        let now = self.store.authorization_now().ok();
        let mut wtxn = self.store.env.write_txn()?;
        self.check_terminal_grant_revival(&wtxn, id, grant, now)?;
        self.check_channel_identity_access_write(&wtxn, id, grant)?;
        self.check_companion_profile_target(&wtxn, grant)?;
        crate::share::check_generic_grant_write(self, &wtxn, id, grant)?;
        self.apply_access_grant_body(&mut wtxn, id, grant.created_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Refuses `grant` at `id` when the live grant there is terminal at the
    /// authorization clock `now` and `grant` is active at it. A clock, row
    /// or body that cannot be read leaves the put as it was.
    fn check_terminal_grant_revival(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        grant: &AccessGrant,
        now: Option<u64>,
    ) -> Result<()> {
        use super::record::AccessGrantStatus;
        use crate::vault::LiveEntityRow;
        let Some(now) = now else {
            return Ok(());
        };
        let standing = match crate::vault::live_entity_row_in_txn(&self.store, txn, id) {
            Ok(LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                body,
            }) => decode_access_grant_body(&body).ok(),
            _ => None,
        };
        if standing.is_some_and(|standing| {
            standing.effective_status_at(now) != AccessGrantStatus::Active
                && grant.effective_status_at(now) == AccessGrantStatus::Active
        }) {
            return Err(Error::Record(RecordError::InvalidAccessGrantBody(
                "a revoked or expired grant is renewed under a new grant id",
            )));
        }
        Ok(())
    }

    /// Creates an AccessGrant only when no entity already exists at `id`.
    pub fn create_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.check_channel_identity_access_write(&wtxn, id, grant)?;
        self.check_companion_profile_target(&wtxn, grant)?;
        crate::share::check_generic_grant_write(self, &wtxn, id, grant)?;
        if self.store.port_entity_record(&wtxn, id)?.is_some() {
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

    /// Revokes a companion-profile grant through the companion surface. A
    /// grant this door may not revoke is `EntityNotFound`, as a missing or
    /// deleted one is: a grant of another scope, or, when `principal` binds
    /// the caller, another principal's grant. The admission and the rewrite
    /// share one write transaction, so the record this door admits is
    /// exactly the record it revokes.
    pub fn revoke_companion_access_grant(
        &self,
        grant_ref: &EntityId,
        revoked_at: u64,
        principal: Option<EntityId>,
    ) -> Result<AccessGrant> {
        self.revoke_admitted_access_grant(grant_ref, revoked_at, |grant| {
            if grant.scope.companion_profile_refs().is_some()
                && principal.is_none_or(|bound| grant.principal_ref == bound)
            {
                Ok(())
            } else {
                Err(Error::EntityNotFound)
            }
        })
    }

    /// Revokes the record at `id` only when `admit` accepts the grant that the
    /// write transaction itself read. A deleted grant is no grant left to
    /// revoke.
    ///
    /// The admission check rides the same `wtxn` as the rewrite: no second
    /// snapshot exists for [`Vault::put_access_grant`] to replace between the
    /// decision and the write. It runs before any other check, so a refused
    /// grant tells nothing of its scope.
    fn revoke_admitted_access_grant(
        &self,
        id: &EntityId,
        revoked_at: u64,
        admit: impl FnOnce(&AccessGrant) -> Result<()>,
    ) -> Result<AccessGrant> {
        use crate::vault::LiveEntityRow;
        let mut wtxn = self.store.env.write_txn()?;
        let grant = match crate::vault::live_entity_row_in_txn(&self.store, &wtxn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                body,
            } => decode_access_grant_body(&body)?,
            LiveEntityRow::Live { entity_type, .. } => {
                return Err(Error::InvalidEntityType(entity_type));
            }
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                return Err(Error::EntityNotFound);
            }
        };
        admit(&grant)?;
        crate::share::check_generic_grant_write(self, &wtxn, id, &grant)?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_access_grant_body(&revoked)?;
        self.apply_access_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Writes the grant `admit` makes of the record that the write
    /// transaction itself reads at `id`: an AccessGrant, or none. `admit`
    /// answers the grant as it is to stand and whether to write it, so the
    /// admission and the write share one write transaction, as a revoke's
    /// do. The write passes every check [`Vault::put_access_grant`] runs and
    /// lands at `learned_at`. A deleted grant is no grant to write over.
    pub(crate) fn put_admitted_access_grant(
        &self,
        id: &EntityId,
        learned_at: u64,
        admit: impl FnOnce(&heed::RoTxn<'_>, Option<AccessGrant>) -> Result<(AccessGrant, bool)>,
    ) -> Result<(AccessGrant, bool)> {
        use crate::vault::LiveEntityRow;
        let mut wtxn = self.store.env.write_txn()?;
        let standing = match crate::vault::live_entity_row_in_txn(&self.store, &wtxn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                body,
            } => Some(decode_access_grant_body(&body)?),
            LiveEntityRow::Live { entity_type, .. } => {
                return Err(Error::InvalidEntityType(entity_type));
            }
            LiveEntityRow::Absent => None,
            LiveEntityRow::DeletedShell => return Err(Error::EntityNotFound),
        };
        let (grant, write) = admit(&wtxn, standing)?;
        if write {
            let data = encode_access_grant_body(&grant)?;
            self.check_channel_identity_access_write(&wtxn, id, &grant)?;
            self.check_companion_profile_target(&wtxn, &grant)?;
            crate::share::check_generic_grant_write(self, &wtxn, id, &grant)?;
            self.apply_access_grant_body(&mut wtxn, id, learned_at, data)?;
            wtxn.commit()?;
        }
        Ok((grant, write))
    }

    /// Reads and decodes an AccessGrant record.
    pub fn get_access_grant(&self, id: &EntityId) -> Result<Option<AccessGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .port_entity_record(&rtxn, id)?
            .map(|row| row.encode())
        else {
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
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_ACCESS_GRANT, None)?
        {
            let grant_ref = entry?;
            // A deleted grant is no registry row (FIX 8640); a live revoked
            // one still is. A row the live resolver cannot read is read raw,
            // as before it.
            let (entity_type, body) =
                match crate::vault::live_entity_row_in_txn(&self.store, &rtxn, &grant_ref) {
                    Ok(crate::vault::LiveEntityRow::Absent)
                    | Ok(crate::vault::LiveEntityRow::DeletedShell) => continue,
                    Ok(crate::vault::LiveEntityRow::Live { entity_type, body }) => {
                        (entity_type, body)
                    }
                    Err(_) => {
                        let Some(raw) = self.store.port_entity_record(&rtxn, &grant_ref)? else {
                            return Err(Error::CorruptedIndex("access grant entity row"));
                        };
                        (raw.entity_type, raw.body)
                    }
                };
            if entity_type != ENTITY_TYPE_ACCESS_GRANT {
                return Err(Error::CorruptedIndex("access grant entity type"));
            }
            let Some(grant) = super::codec::decode_live_access_grant_body(&body)? else {
                continue;
            };
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
