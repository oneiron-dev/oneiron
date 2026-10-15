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
    /// reference, inside the one write transaction. A held gate partition on a scrubbed carrier
    /// refuses the whole erase, as it does for a redirect shell.
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
        for carrier in &scrubbed {
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
    /// walk would scrub sits in a held gate partition, as `reject_held_redirect_shells_in_txn`
    /// does for a redirect shell. The walk re-checks in the transaction that tears.
    pub(in crate::deletion) fn reject_held_blob_references_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if let Some(walk) = self.blob_reference_walk_in_txn(txn, id)? {
            for carrier in walk.scrubbed {
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
    /// stored row itself: the erase's own marker hides it from the live getters.
    pub(in crate::deletion) fn erased_holdings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<crate::blob_artifact::Holding>> {
        let holdings = crate::blob_artifact::holdings_in_txn(&self.store, txn, id)?;
        if !holdings.is_empty() {
            return Ok(holdings);
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
        Ok(holding.into_iter().collect())
    }

    /// ARCH-0005a at replicated ingest, before the put: an ASSET carrying bytes a hard erase took
    /// here, and a late `blob.version` claim ([`crate::blob_artifact::LateReference`]), never
    /// materialize. Their ids are fenced, so the export door drops their carriers. A late claim
    /// pierces the bytes it names on arrival: it is recorded erased, and when it is the first
    /// word here that those bytes were the erased artifact's, the erase's walk runs for them now,
    /// with a sweep row for what it scrubbed. Returns whether the carrier is refused.
    #[cfg(any(feature = "sync", test))]
    pub(crate) fn refuse_erased_blob_arrival_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        data: &[u8],
    ) -> Result<bool> {
        let refused = match entity_type {
            crate::registry::ENTITY_TYPE_ASSET => {
                crate::blob_artifact::bytes_erased(&self.store, wtxn, data)?
            }
            ENTITY_TYPE_CLAIM => {
                let Ok(body) = crate::claim::decode_claim_body(data, true) else {
                    return Ok(false);
                };
                match crate::blob_artifact::late_reference_in_txn(&self.store, wtxn, id, &body)? {
                    Some(late) => {
                        self.pierce_late_reference_in_txn(wtxn, id, late)?;
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if refused {
            let fenced = ROW_DELETION_FENCE.contains(&self.store, wtxn, &HexId(*id))?;
            crate::blob_artifact::fence_erased_carrier(&self.store, wtxn, id, fenced)?;
        }
        Ok(refused)
    }

    #[cfg(any(feature = "sync", test))]
    fn pierce_late_reference_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim: &EntityId,
        late: crate::blob_artifact::LateReference,
    ) -> Result<()> {
        let crate::blob_artifact::LateReference {
            artifact,
            holding,
            erase,
            pierced,
        } = late;
        let mut carriers = vec![*claim];
        if pierced {
            // A walk here already took the bytes: only this reference is new.
            crate::blob_artifact::erase_holds_in_txn(
                &self.store,
                wtxn,
                &artifact,
                std::slice::from_ref(&holding),
                &[*claim],
                &erase,
            )?;
            crate::blob_artifact::release_erased_bytes_in_txn(
                &self.store,
                wtxn,
                &artifact,
                std::slice::from_ref(&holding),
            )?;
        } else {
            let holdings = vec![holding];
            let mut references =
                crate::blob_artifact::references_in_txn(&self.store, wtxn, &artifact, &holdings)?;
            references.push(*claim);
            let walk = self.walk_holdings_in_txn(wtxn, &artifact, holdings, references)?;
            carriers.extend(
                self.pierce_walk_in_txn(wtxn, &artifact, walk, &erase)?
                    .carriers,
            );
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
        Ok(())
    }
}
