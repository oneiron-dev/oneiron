use super::*;

/// What a hard erase of a blob artifact took beside the artifact itself.
#[derive(Debug, Default)]
pub(in crate::deletion) struct ErasedBlobReferences {
    /// The ASSETs carrying the bytes, the erased references, and the texts derived from the
    /// bytes: one line each on the erase's redaction receipt and sweep row.
    pub(in crate::deletion) carriers: Vec<EntityId>,
    /// The other artifacts whose references the erase took, and every scrubbed carrier: their
    /// local reads changed.
    pub(in crate::deletion) changed: Vec<EntityId>,
    /// The references and ASSETs this erase tombstones under its own request, read before the
    /// scrub tore their bodies: every replica pierces the bytes from any one of them, including a
    /// replica that never saw the erased artifact.
    pub(in crate::deletion) tombstoned: Vec<PiercedCarrier>,
}

/// A carrier a hard erase pierced and tombstones, addressed as its own delete would be.
#[derive(Debug, Clone)]
pub(in crate::deletion) struct PiercedCarrier {
    pub(in crate::deletion) id: EntityId,
    pub(in crate::deletion) learned_at: u64,
    pub(in crate::deletion) window_label: String,
}

/// What a hard erase reaches, read before anything is torn.
struct BlobReferenceWalk {
    holdings: Vec<crate::blob_artifact::Holding>,
    /// The holdings' ASSET ids that hold an ASSET here, or nothing: an unrelated row at the id the
    /// bytes would take is not theirs to sweep.
    assets: Vec<EntityId>,
    /// Every reference to the bytes.
    references: Vec<EntityId>,
    /// The carriers the walk scrubs: those references and the texts derived from the bytes.
    scrubbed: Vec<EntityId>,
}

impl Vault {
    /// ARCH-0005a / ARCH-0038 carrier 13: "HardErase pierces refcounting". A hard erase of an
    /// artifact takes its version bytes and every reference to them in one walk, never one
    /// artifact's hold while the bytes stay alive for another.
    ///
    /// Every `blob.version` claim naming the bytes, on whichever artifact, becomes an erased
    /// reference valued with `tombstone` (the erase's wire value). Its body is scrubbed through
    /// the same shell-preserving SoftErase `user_delete` uses, and so is every ASSET_TEXT derived
    /// from the bytes. Every other artifact's hold on the bytes goes, with any fingerprint tree it
    /// computed over them, so the artifact's own scrub or purge, which the caller runs next in
    /// this transaction, releases them: the ASSET is fenced and deindexed. A replica applying the
    /// erase's tombstone walks its own references the same way. So does a replica applying the
    /// tombstone of a reference or of the ASSET: when `tombstoning` (the vault that decided the
    /// erase), the result names each reference and ASSET to tombstone under the same request.
    ///
    /// MUST run BEFORE the artifact's own scrub or purge, in the SAME transaction: that tear
    /// drops the version chain and claim pairs this walk reads, and a reference left readable
    /// while the bytes it names are erased is the leak.
    ///
    /// The walk holds no count bound and refuses nothing for size: it touches a few rows per
    /// reference, inside the one write transaction. A held gate partition on a scrubbed carrier or
    /// on the ASSET refuses the whole erase, as it does for a redirect shell.
    ///
    /// What this does not yet erase: a copy of the same bytes another ASSET id already held before
    /// the erase (an id the bytes' hash does not name) stays readable. The erase takes the ASSET
    /// the hash names and refuses the bytes under any id from then on; it does not take them from
    /// the whole vault. A body-hash index at admission, with a backfill, is the follow-up.
    pub(in crate::deletion) fn cascade_hard_erase_to_blob_references_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        tombstone: &[u8],
        tombstoning: bool,
    ) -> Result<ErasedBlobReferences> {
        let Some(walk) = self.blob_reference_walk_in_txn(wtxn, id)? else {
            return Ok(ErasedBlobReferences::default());
        };
        let tombstoned = if tombstoning {
            self.pierced_carriers_in_txn(wtxn, id, &walk)?
        } else {
            Vec::new()
        };
        let mut erased = self.pierce_walk_in_txn(wtxn, id, walk, tombstone)?;
        erased.tombstoned = tombstoned;
        Ok(erased)
    }

    /// Tears what `walk` reached: holds, erased marks, scrubbed and fenced carriers, released bytes.
    fn pierce_walk_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        walk: BlobReferenceWalk,
        tombstone: &[u8],
    ) -> Result<ErasedBlobReferences> {
        let BlobReferenceWalk {
            holdings,
            assets,
            references,
            scrubbed,
        } = walk;
        for carrier in scrubbed.iter().chain(&assets) {
            self.store
                .reject_held_gate_partition_in_txn(wtxn, carrier.as_bytes())?;
        }
        let holders = crate::blob_artifact::erase_holds_in_txn(
            &self.store,
            wtxn,
            id,
            &holdings,
            &references,
            tombstone,
        )?;
        let mut had_vector = false;
        for carrier in &scrubbed {
            if crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, carrier)?
                .is_none_or(|raw| raw.len() <= ENTITY_METADATA_HEADER_LEN)
            {
                continue;
            }
            let fenced = ROW_DELETION_FENCE.contains(&self.store, wtxn, &HexId(*carrier))?;
            let (_existed, carrier_had_vector, _ledger_changed) =
                self.soft_erase_active_store_in_txn(wtxn, carrier)?;
            had_vector |= carrier_had_vector;
            crate::blob_artifact::fence_erased_carrier(&self.store, wtxn, carrier, fenced)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        // A text derived from one of them that arrives later goes with it.
        crate::blob_artifact::mark_erased_assets_in_txn(&self.store, wtxn, &assets, tombstone)?;
        crate::blob_artifact::release_erased_bytes_in_txn(&self.store, wtxn, id, &holdings)?;
        let mut carriers = assets;
        carriers.extend(&scrubbed);
        let mut changed = holders;
        changed.extend(&scrubbed);
        Ok(ErasedBlobReferences {
            carriers,
            changed,
            tombstoned: Vec::new(),
        })
    }

    /// Each reference and ASSET `walk` reached that still holds its body, other than `id`, with
    /// the window its tombstone goes to, read before the scrub tears the body.
    fn pierced_carriers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        walk: &BlobReferenceWalk,
    ) -> Result<Vec<PiercedCarrier>> {
        let mut tombstoned = Vec::new();
        for carrier in walk.references.iter().chain(&walk.assets) {
            if carrier == id {
                continue;
            }
            let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, carrier)?
            else {
                continue;
            };
            if raw.len() <= ENTITY_METADATA_HEADER_LEN {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("entity metadata"))?;
            let mut window_label = tombstone::window_label_from_timestamp(header.learned_at);
            if header.entity_type == ENTITY_TYPE_CLAIM
                && let Ok(body) =
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
                && let Some(world) = body.world
            {
                window_label.push('@');
                window_label.push_str(&world.to_hex());
            }
            tombstoned.push(PiercedCarrier {
                id: *carrier,
                learned_at: header.learned_at,
                window_label,
            });
        }
        Ok(tombstoned)
    }

    /// Refuses a hard erase of `id` BEFORE its tombstone publishes when a carrier its blob-reference
    /// walk would scrub, or the ASSET it would release, sits in a held gate partition, as
    /// `reject_held_redirect_shells_in_txn` does for a redirect shell. The walk re-checks in the
    /// transaction that tears.
    pub(in crate::deletion) fn reject_held_blob_references_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if let Some(walk) = self.blob_reference_walk_in_txn(txn, id)? {
            for carrier in walk.scrubbed.iter().chain(&walk.assets) {
                self.store
                    .reject_held_gate_partition_in_txn(txn, carrier.as_bytes())?;
            }
        }
        Ok(())
    }

    /// What a hard erase of `id` reaches, read before anything is torn: the bytes it holds, every
    /// reference to them, and the carriers it scrubs (those references and every ASSET_TEXT
    /// derived from the bytes, never `id` itself). `None` when it holds no version bytes.
    fn blob_reference_walk_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<BlobReferenceWalk>> {
        let holdings = self.erased_holdings_in_txn(txn, id)?;
        if holdings.is_empty() {
            return Ok(None);
        }
        let references = crate::blob_artifact::references_in_txn(&self.store, txn, id, &holdings)?;
        self.walk_holdings_in_txn(txn, id, holdings, references)
            .map(Some)
    }

    fn walk_holdings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        holdings: Vec<crate::blob_artifact::Holding>,
        references: Vec<EntityId>,
    ) -> Result<BlobReferenceWalk> {
        let mut assets = Vec::new();
        let mut derived = Vec::new();
        for holding in &holdings {
            match crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &holding.asset)?
                .as_deref()
                .map(EntityMetadataHeader::parse)
            {
                None => {
                    assets.push(holding.asset);
                    continue;
                }
                Some(Some(header)) if header.entity_type == crate::registry::ENTITY_TYPE_ASSET => {
                    assets.push(holding.asset);
                }
                Some(_) => continue,
            }
            for row in crate::ports::EdgeStoreRead::port_edges(
                &self.store,
                txn,
                &holding.asset,
                crate::ports::EdgeDirection::In,
                Some(crate::EdgeKind::DerivedFrom),
                None,
            )? {
                let source = row?.target;
                if crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &source)?
                    .as_deref()
                    .and_then(EntityMetadataHeader::parse)
                    .is_some_and(|header| {
                        header.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT
                    })
                {
                    derived.push(source);
                }
            }
        }
        let mut scrubbed: Vec<EntityId> = references
            .iter()
            .chain(&derived)
            .filter(|carrier| *carrier != id)
            .copied()
            .collect();
        scrubbed.sort_unstable();
        scrubbed.dedup();
        Ok(BlobReferenceWalk {
            holdings,
            assets,
            references,
            scrubbed,
        })
    }

    /// The bytes a hard erase of `id` takes: an artifact's version bytes, a blob's own bytes when
    /// `id` is the ASSET carrying them, or the bytes a `blob.version` claim names. Read from the
    /// stored row itself: the erase's own marker hides it from the live getters. Bytes a walk here
    /// already took are left out: nothing new holds them, and `id`'s own delete drops its rows.
    pub(in crate::deletion) fn erased_holdings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<crate::blob_artifact::Holding>> {
        let holdings = crate::blob_artifact::holdings_in_txn(&self.store, txn, id)?;
        if !holdings.is_empty() {
            return crate::blob_artifact::unerased_holdings_in_txn(&self.store, txn, holdings);
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
        else {
            return Ok(holdings);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(holdings);
        };
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let holding = match header.entity_type {
            crate::registry::ENTITY_TYPE_ASSET => {
                crate::blob_artifact::asset_holding_in_txn(&self.store, txn, id, body)?
            }
            ENTITY_TYPE_CLAIM => {
                crate::blob_artifact::claim_holding_in_txn(&self.store, txn, body)?
            }
            _ => None,
        };
        crate::blob_artifact::unerased_holdings_in_txn(
            &self.store,
            txn,
            holding.into_iter().collect(),
        )
    }

    /// ARCH-0005a (Engine ruling (b) on #1465): an ASSET_TEXT `source` derived from `target`, an
    /// ASSET whose bytes a hard erase's walk here took, is scrubbed and fenced as that walk
    /// scrubs every text derived from the bytes, with a sweep row: it arrived after the walk.
    /// Returns whether it was, so the edge is not written.
    ///
    /// Only the walk's own mark on `target` counts, and never while another kind's row stands
    /// there: a hard-delete marker a peer can cause on an id it controls names no erased bytes.
    /// A `source` not stored here yet leaves an obligation keyed by its id, and its body is
    /// scrubbed and fenced when it arrives, so the edge and the text give the same result in
    /// either order (Engine ruling on #1465 R3).
    #[cfg(feature = "sync")]
    pub(crate) fn scrub_text_derived_from_erased_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        source: &EntityId,
        target: &EntityId,
    ) -> Result<bool> {
        if !crate::blob_artifact::asset_erased(&self.store, wtxn, target)? {
            return Ok(false);
        }
        if crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, target)?.is_some_and(
            |raw| {
                EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
                    != Some(crate::registry::ENTITY_TYPE_ASSET)
            },
        ) {
            return Ok(false);
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, source)?
        else {
            crate::blob_artifact::record_erased_derivation_in_txn(
                &self.store,
                wtxn,
                source,
                target,
            )?;
            return Ok(true);
        };
        if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
            != Some(crate::registry::ENTITY_TYPE_ASSET_TEXT)
        {
            return Ok(false);
        }
        if raw.len() > ENTITY_METADATA_HEADER_LEN {
            if self
                .store
                .gate_partition_held_in_txn(wtxn, Some(source.as_bytes()))?
            {
                // A legal hold defers it: the edge waits, and the next pass tries again.
                return Ok(true);
            }
            let fenced = ROW_DELETION_FENCE.contains(&self.store, wtxn, &HexId(*source))?;
            let (_existed, had_vector, _ledger_changed) =
                self.soft_erase_active_store_in_txn(wtxn, source)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, wtxn)?;
            }
            crate::blob_artifact::fence_erased_carrier(&self.store, wtxn, source, fenced)?;
            self.enqueue_hard_erase_sweep_in_txn(
                wtxn,
                RedactionScope {
                    entity_ids: vec![source.to_hex()],
                    revision_ids: Vec::new(),
                },
                HardEraseSweepExtras::default(),
                self.store.clock.now_recorded_at(),
            )?;
        }
        Ok(true)
    }

    /// ARCH-0005a at replicated ingest, BEFORE the delete-wins shortcut: an ASSET carrying bytes a
    /// hard erase took here, a late `blob.version` claim (a `LateReference`), and a text a
    /// DerivedFrom edge named as derived from an ASSET a hard erase took, never materialize. A
    /// refused id is fenced, so the export door drops its carrier, with a sweep row for it.
    ///
    /// A claim that is the first word here of the erased bytes runs the erase's walk for them now:
    /// a sweep row covers what it scrubbed, and each reference and ASSET it newly pierced is
    /// tombstoned under the erase's own request, so a replica holding only another reference
    /// learns of the erase too. Only typed evidence of the erase counts (`late_reference_in_txn`).
    ///
    /// Nothing is refused or touched before the put's own checks would pass: another kind at the
    /// id, or a claim the replicated put would not admit, is left to the put. A walk that would
    /// tear a carrier under a legal hold defers: the body is skipped with nothing marked, and the
    /// window's next pass tries again. Returns whether the body is refused.
    #[cfg(any(feature = "sync", test))]
    pub(crate) fn refuse_erased_blob_arrival_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        header: &EntityMetadataHeader,
        data: &[u8],
    ) -> Result<bool> {
        use crate::blob_artifact::LateReach;
        use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
        let entity_type = header.entity_type;
        if ![ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM].contains(&entity_type) {
            return Ok(false);
        }
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, id)?
            && EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
                != Some(entity_type)
        {
            return Ok(false);
        }
        let late = match entity_type {
            ENTITY_TYPE_CLAIM => {
                let Ok(body) = crate::claim::decode_claim_body(data, true) else {
                    return Ok(false);
                };
                let Some(late) =
                    crate::blob_artifact::late_reference_in_txn(&self.store, wtxn, id, &body)?
                else {
                    return Ok(false);
                };
                // A body widens an erase only as the replicated put would admit it: a forged
                // machine claim changes nothing.
                let occurred = crate::TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                };
                if crate::batch::admit_replicated_claim_in_txn(
                    &self.store,
                    wtxn,
                    *id,
                    occurred,
                    header.learned_at,
                    data,
                    self.privacy_posture(),
                )
                .is_err()
                {
                    return Ok(false);
                }
                Some(late)
            }
            // The bytes themselves are no reference: an ASSET at any id carrying them brings
            // nothing new but its own carrier.
            ENTITY_TYPE_ASSET => {
                if !crate::blob_artifact::bytes_erased(&self.store, wtxn, data)? {
                    return Ok(false);
                }
                None
            }
            // A text a DerivedFrom edge named as derived from an erased ASSET before it arrived.
            _ => {
                if !crate::blob_artifact::erased_derivation_pending(&self.store, wtxn, id)? {
                    return Ok(false);
                }
                if self
                    .store
                    .gate_partition_held_in_txn(wtxn, Some(id.as_bytes()))?
                {
                    return Ok(true);
                }
                crate::blob_artifact::discharge_erased_derivation_in_txn(&self.store, wtxn, id)?;
                None
            }
        };
        let deleted_before = ROW_DELETION_FENCE.contains(&self.store, wtxn, &HexId(*id))?
            || HARD_DELETE_MARKER.contains(&self.store, wtxn, &HexId(*id))?;
        let Some(crate::blob_artifact::LateReference {
            holding,
            erase,
            reach,
        }) = late
        else {
            return self.fence_refused_arrival_in_txn(wtxn, id, deleted_before, Vec::new());
        };
        let mut carriers = Vec::new();
        match reach {
            LateReach::Taken => return Ok(true),
            LateReach::Reference => {
                if self
                    .store
                    .gate_partition_held_in_txn(wtxn, Some(id.as_bytes()))?
                {
                    return Ok(true);
                }
                let holdings = std::slice::from_ref(&holding);
                crate::blob_artifact::erase_holds_in_txn(
                    &self.store,
                    wtxn,
                    &holding.asset,
                    holdings,
                    std::slice::from_ref(id),
                    &erase,
                )?;
                crate::blob_artifact::release_erased_bytes_in_txn(
                    &self.store,
                    wtxn,
                    &holding.asset,
                    holdings,
                )?;
            }
            LateReach::Bytes => {
                // The arriving body is the walk's own record: every holder's hold goes, and the
                // release that follows tears the bytes' ASSET, which is never the walk's own.
                let asset = holding.asset;
                let holdings = vec![holding];
                let mut references =
                    crate::blob_artifact::references_in_txn(&self.store, wtxn, id, &holdings)?;
                references.push(*id);
                let walk = self.walk_holdings_in_txn(wtxn, id, holdings, references)?;
                for carrier in walk.scrubbed.iter().chain(&walk.assets).chain([id]) {
                    if self
                        .store
                        .gate_partition_held_in_txn(wtxn, Some(carrier.as_bytes()))?
                    {
                        return Ok(true);
                    }
                }
                let mut tombstoned = self.pierced_carriers_in_txn(wtxn, id, &walk)?;
                // The bytes' ASSET is tombstoned even when no body of it was ever stored here,
                // unless a tombstone already took it: a vault holding it learns the erase.
                if !tombstoned.iter().any(|carrier| carrier.id == asset)
                    && !HARD_DELETE_MARKER.contains(&self.store, wtxn, &HexId(asset))?
                {
                    let learned_at = tombstone::decode_tombstone_value(&erase).deleted_at;
                    tombstoned.push(PiercedCarrier {
                        id: asset,
                        learned_at,
                        window_label: tombstone::window_label_from_timestamp(learned_at),
                    });
                }
                carriers.extend(self.pierce_walk_in_txn(wtxn, id, walk, &erase)?.carriers);
                self.stage_late_walk_tombstones_in_txn(wtxn, tombstoned, &erase)?;
            }
        }
        self.fence_refused_arrival_in_txn(wtxn, id, deleted_before, carriers)
    }

    /// Fences `id`, a body the ingest gate refused, unless a delete fenced it before, and queues
    /// one sweep row for it and the `carriers` its walk scrubbed. Returns that it is refused.
    #[cfg(any(feature = "sync", test))]
    fn fence_refused_arrival_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        deleted_before: bool,
        mut carriers: Vec<EntityId>,
    ) -> Result<bool> {
        if !deleted_before {
            crate::blob_artifact::fence_erased_carrier(&self.store, wtxn, id, false)?;
            carriers.push(*id);
        }
        if carriers.is_empty() {
            return Ok(true);
        }
        carriers.sort_unstable();
        carriers.dedup();
        self.enqueue_hard_erase_sweep_in_txn(
            wtxn,
            RedactionScope {
                entity_ids: carriers.iter().map(EntityId::to_hex).collect(),
                revision_ids: Vec::new(),
            },
            HardEraseSweepExtras::default(),
            self.store.clock.now_recorded_at(),
        )?;
        Ok(true)
    }

    /// Stages the tombstones of what a late walk newly pierced, under the erase's own request:
    /// a legacy or soft value names no request to tombstone under.
    #[cfg(any(feature = "sync", test))]
    fn stage_late_walk_tombstones_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        tombstoned: Vec<PiercedCarrier>,
        erase: &[u8],
    ) -> Result<()> {
        let decoded = tombstone::decode_tombstone_value(erase);
        let (Some(reason), Some(request_id)) = (decoded.reason, decoded.request_id) else {
            return Ok(());
        };
        if !reason.is_hard() {
            return Ok(());
        }
        let value = tombstone::TombstoneValueV2 {
            reason,
            deleted_at: decoded.deleted_at,
            request_id,
        };
        self.stage_late_pierced_tombstones_in_txn(wtxn, tombstoned, &value)
    }
}
