//! The scoped read doors: a record's current stamp, and the records a slip may read.

use super::*;

impl Vault {
    /// Read the current positive stamp. Missing or stale stamps are not inferred.
    pub fn record_scope(&self, id: &EntityId) -> Result<Option<Scope>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, id)?
        else {
            return Ok(None);
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
        disclosure_scope_for_stored_row(
            &self.store,
            &txn,
            *id,
            h.entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
    }

    /// Scoped reads bind a selector, the authenticated slip's Scope and channel.
    /// Debug additionally requires an explicit `debug` class on that slip.
    /// A SECRET_CUSTODY row is never a scoped record, in either view: its body
    /// carries the value, which only its binding door reads. Nor is an LFS
    /// chunk that no published object holds yet.
    pub fn records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
        view: ScopeView,
    ) -> Result<Vec<ScopedRecord>> {
        if view == ScopeView::Debug {
            let mut root = Scope::top();
            root.verbs = singleton("debug".to_owned());
            if !slip.admits("debug", &root, channel) {
                return Err(Error::InvalidClaimBody(
                    "unattenuated debug capability required",
                ));
            }
        }
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (id, raw) = row?;
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                || crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                    &self.store,
                    &txn,
                    &id,
                    h.entity_type,
                )?
            {
                continue;
            }
            let scope = disclosure_scope_for_stored_row(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            let fences_pass = |door: [&Scope; 3]| -> Result<bool> {
                Ok(
                    crate::authority::row_causal_admitted(self, &txn, &id, &raw)?
                        && self.epoch_fence_in(&txn, id, &raw, door, "read")?
                        && self.text_fence_in(&txn, id, &raw, door, "read", |_| Ok(false))?,
                )
            };
            let withdrawn = !crate::ports::raw_readable_in_txn(&self.store, &txn, &id, &raw)?;
            let door = [selector, slip, channel];
            let allowed = !withdrawn
                && scope.as_ref().is_some_and(|scope| {
                    note_world::admits_at(&self.store, &txn, id, h.entity_type, scope, door, "read")
                })
                && fences_pass(door)?;
            if !allowed && view == ScopeView::Normal {
                continue;
            }
            // Debug reveals what the selector suppressed, never words that
            // are withdrawn or that a fence refuses: such a row keeps only
            // its header.
            let words = allowed || (!withdrawn && fences_pass([&Scope::top(), slip, channel])?);
            let bytes = if words {
                self.scoped_row_bytes_in_txn(&txn, &id, raw)?
            } else {
                let mut bytes = raw;
                bytes.truncate(ENTITY_METADATA_HEADER_LEN);
                bytes
            };
            out.push(ScopedRecord {
                id,
                bytes,
                scope,
                suppressed: !allowed,
                birth: None,
            });
        }
        Ok(out)
    }
}
