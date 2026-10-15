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
}

/// What a hard erase reaches, read before anything is torn.
struct BlobReferenceWalk {
    holdings: Vec<crate::blob_artifact::Holding>,
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
    /// erase's tombstone walks its own references the same way.
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
        artifact: &EntityId,
        tombstone: &[u8],
    ) -> Result<ErasedBlobReferences> {
        let Some(BlobReferenceWalk {
            holdings,
            references,
            scrubbed,
        }) = self.blob_reference_walk_in_txn(wtxn, artifact)?
        else {
            return Ok(ErasedBlobReferences::default());
        };
        for carrier in &scrubbed {
            self.store
                .reject_held_gate_partition_in_txn(wtxn, carrier.as_bytes())?;
        }
        let holders = crate::blob_artifact::erase_holds_in_txn(
            &self.store,
            wtxn,
            artifact,
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
        let mut carriers: Vec<EntityId> = holdings.iter().map(|holding| holding.asset).collect();
        carriers.extend(&scrubbed);
        let mut changed = holders;
        changed.extend(&scrubbed);
        Ok(ErasedBlobReferences { carriers, changed })
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
        let mut derived = Vec::new();
        for holding in &holdings {
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
        Ok(Some(BlobReferenceWalk {
            holdings,
            references,
            scrubbed,
        }))
    }

    /// The bytes a hard erase of `id` takes: an artifact's version bytes, or a blob's own bytes
    /// when `id` is the ASSET carrying them.
    pub(in crate::deletion) fn erased_holdings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<crate::blob_artifact::Holding>> {
        let holdings = crate::blob_artifact::holdings_in_txn(&self.store, txn, id)?;
        if !holdings.is_empty() {
            return Ok(holdings);
        }
        let Some(row) = crate::ports::EntityStore::port_entity_get(self, txn, id)? else {
            return Ok(holdings);
        };
        if row.entity_type != crate::registry::ENTITY_TYPE_ASSET {
            return Ok(holdings);
        }
        Ok(
            crate::blob_artifact::asset_holding_in_txn(&self.store, txn, id, &row.body)?
                .into_iter()
                .collect(),
        )
    }
}
