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
                        && self.text_fence_in(&txn, id, &raw, door, "read", |_| Ok(false))?
                        && self
                            .word_source_fence_in(&txn, id, &raw, door, "read", |_| Ok(false))?,
                )
            };
            let withdrawn = !crate::ports::raw_readable_in_txn(&self.store, &txn, &id, &raw)?;
            let door = [selector, slip, channel];
            let allowed = !withdrawn
                && scope.as_ref().is_some_and(|scope| {
                    note_world::admits_at(&self.store, &txn, id, h.entity_type, scope, door, "read")
                })
                && fences_pass(door)?
                && self.esign_dependencies_admitted_in(
                    &txn,
                    h.entity_type,
                    &raw,
                    |dep, ty, dep_raw| self.read_admitted_in(&txn, dep, ty, dep_raw, door),
                )?;
            if !allowed && view == ScopeView::Normal {
                continue;
            }
            // Debug reveals what the selector suppressed, never words that
            // are withdrawn or that a fence refuses: such a row keeps only
            // its header.
            let debug_door = [&Scope::top(), slip, channel];
            let words = allowed
                || (!withdrawn
                    && fences_pass(debug_door)?
                    && self.esign_dependencies_admitted_in(
                        &txn,
                        h.entity_type,
                        &raw,
                        |dep, ty, dep_raw| {
                            self.read_admitted_in(&txn, dep, ty, dep_raw, debug_door)
                        },
                    )?);
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

    /// The word-source fence at a scoped door (FIX SLIP-DOOR-DERIVED-SUMMARY-FENCE):
    /// a row carrying other rows' words passes only while this door, under
    /// its selector, slip, channel and verb, admits every source. Missing,
    /// withdrawn (by the doors' own rule, `raw_readable_in_txn`), withheld or
    /// unresolved sources refuse the row, so a copy cannot disclose words its
    /// source would not. The sync member gate applies the same rule (FIX
    /// SELECTOR-SCOPE-SUMMARY-WORDS). An epoch summary is a root too: its
    /// `DerivedFrom` targets, walked transitively through each target's own
    /// word sources. The epoch fence stays a separate conjunct. A filed
    /// compaction step's response bytes, as the content ASSET of its
    /// response artifact's version, are a root as well
    /// ([`Self::fence_word_sources_in`]).
    pub(super) fn word_source_fence_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        door: [&Scope; 3],
        verb: &str,
        mut withheld: impl FnMut(&EntityId) -> Result<bool>,
    ) -> Result<bool> {
        use crate::ports::EntityStoreRead;
        use crate::scope_summary::WordSources;

        // The roots this fence judges: every row whose words came from others.
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
            return Ok(true);
        }
        let mut pending = match self.fence_word_sources_in(txn, &id, raw) {
            Ok(WordSources::Own) => return Ok(true),
            Ok(WordSources::Unresolved) | Err(Error::InvalidClaimBody(_)) => return Ok(false),
            Ok(WordSources::From(sources)) => sources,
            Err(error) => return Err(error),
        };
        let mut seen = std::collections::BTreeSet::from([id]);
        while let Some(source) = pending.pop() {
            if !seen.insert(source) {
                continue;
            }
            let Some(row) = self.store.port_entity_record(txn, &source)? else {
                return Ok(false);
            };
            let source_raw = row.encode();
            if !crate::ports::raw_readable_in_txn(&self.store, txn, &source, &source_raw)?
                || withheld(&source)?
                || !disclosure_scope_for_stored_row(
                    &self.store,
                    txn,
                    source,
                    row.entity_type,
                    &row.body,
                )?
                .is_some_and(|scope| {
                    note_world::admits_at(
                        &self.store,
                        txn,
                        source,
                        row.entity_type,
                        &scope,
                        door,
                        verb,
                    )
                })
            {
                return Ok(false);
            }
            if !crate::authority::row_causal_admitted(self, txn, &source, &source_raw)?
                || !self.text_fence_in(txn, source, &source_raw, door, verb, &mut withheld)?
            {
                return Ok(false);
            }
            match self.fence_word_sources_in(txn, &source, &source_raw) {
                Ok(WordSources::Own) => {}
                Ok(WordSources::From(nested)) => pending.extend(nested),
                Ok(WordSources::Unresolved) | Err(Error::InvalidClaimBody(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    /// The word sources [`Self::word_source_fence_in`] walks for one row:
    /// [`crate::scope_summary::word_sources_in`], except that an ASSET holding
    /// a filed compaction step's response bytes carries the compactor's words
    /// as its response artifact does, so its sources are every response
    /// artifact holding those bytes, each then walked through its own
    /// `DerivedFrom` lineage (REVIEW-10629 round 2). The scoped read
    /// (`compaction_response_bytes_readable_in`) and the sync member gate
    /// (`epoch_egress`) judge that ASSET by the same holders. The door reads
    /// base, so no holder is a room's.
    fn fence_word_sources_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<crate::scope_summary::WordSources> {
        if raw.first() == Some(&crate::registry::ENTITY_TYPE_ASSET) {
            let holders: Vec<EntityId> =
                crate::llm::compaction_response_holders_in(&self.store.read(), txn, id, raw)?
                    .into_iter()
                    .map(|holder| holder.id)
                    .collect();
            if !holders.is_empty() {
                return Ok(crate::scope_summary::WordSources::From(holders));
            }
        }
        crate::scope_summary::word_sources_in(self, txn, id, raw)
    }

    /// One row as this door's Normal view judges it, for an `esign.*`
    /// claim's dependencies (ESIGN-AUDIT-CLAIM-FACET): the row readable,
    /// its disclosure scope admitted at `door` under `read`, then the
    /// causal, epoch and text fences. The dependency's raw row and parsed
    /// type come from the same snapshot `txn`.
    fn read_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        entity_type: u8,
        raw: &[u8],
        door: [&Scope; 3],
    ) -> Result<bool> {
        if !crate::ports::raw_readable_in_txn(&self.store, txn, &id, raw)? {
            return Ok(false);
        }
        let Some(scope) = disclosure_scope_for_stored_row(
            &self.store,
            txn,
            id,
            entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?
        else {
            return Ok(false);
        };
        if !note_world::admits_at(&self.store, txn, id, entity_type, &scope, door, "read") {
            return Ok(false);
        }
        if !crate::authority::row_causal_admitted(self, txn, &id, raw)? {
            return Ok(false);
        }
        if !self.epoch_fence_in(txn, id, raw, door, "read")? {
            return Ok(false);
        }
        if !self.text_fence_in(txn, id, raw, door, "read", |_| Ok(false))? {
            return Ok(false);
        }
        Ok(true)
    }

    /// The project and world the stored row `id` is read at, its
    /// [`scope_for_blob`] position, when that names one of each: where a
    /// record derived from the row's words is born, so the derivation keeps
    /// its source's exposure (ONE-1592 P3; ARCH-0022 #task-facet-not-built).
    /// `None` for a row that is absent, has no position, or is read at more
    /// than one project or world.
    pub(crate) fn derivation_project_and_world_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<(EntityId, EntityId)>> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
        else {
            return Ok(None);
        };
        let Some(scope) = scope_for_blob(&self.store, txn, id, &raw)? else {
            return Ok(None);
        };
        let one = |axis: &ScopeAxis<ScopeId>| match axis {
            ScopeAxis::Some(ids) if ids.len() == 1 => ids.first().map(|id| id.0),
            _ => None,
        };
        Ok(one(&scope.audience).zip(one(&scope.worlds)))
    }
}
