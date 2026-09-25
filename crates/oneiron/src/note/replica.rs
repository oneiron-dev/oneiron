//! Canonical authority-to-replica import and citation-closed NOTE disclosure.
//!
//! This is not a public raw import door. Only the sync client's explicit
//! authenticated-authority lane calls it. Upstream peers send NoteOperation.
use super::document::{NoteDocument, invalid};
use super::document_store::{load, persist};
use super::{NotePin, NoteSpanResolution};
use crate::sync::transport::document_sub_tags;
use crate::sync::{SyncSelector, SyncSelectorWorld};
use crate::{EntityId, FederationGrantScope, Result, Vault};

pub(super) fn admit_pin_disclosure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    pin: &NotePin,
) -> Result<()> {
    super::citation_erase::validate_pins(vault, txn, std::slice::from_ref(pin))?;
    let position =
        crate::sync::selector::admit_note_in_txn(vault, txn, pin.document, scope, selector, None)?;
    let claim = vault
        .get_claim_in_txn(txn, &pin.claim)?
        .ok_or_else(|| invalid("citation claim missing"))?;
    let identity = crate::federation::selector_range_of(crate::registry::ENTITY_TYPE_CLAIM)
        .ok_or_else(|| invalid("citation claim outside selector"))?;
    let band_passes = match &position.bands {
        crate::federation::FederationScopeBands::All => true,
        crate::federation::FederationScopeBands::Some(bands) => {
            bands.iter().any(|band| band.includes(identity))
        }
        crate::federation::FederationScopeBands::Bottom => false,
    };
    if !band_passes {
        return Err(invalid("citation claim outside selector"));
    }
    if let Some(world) = claim.world {
        match selector.world {
            SyncSelectorWorld::All => {}
            SyncSelectorWorld::World(selected) if selected.entity_id() == world => {}
            _ => return Err(invalid("citation claim outside selector world")),
        }
    }
    // Coreference disclosure requires pact-specific consent, not merely
    // naming a CLAIM. NOTE citations do not widen that separate boundary.
    if claim
        .predicate
        .starts_with(crate::claim::PREDICATE_COREFERENCE_PREFIX)
    {
        return Err(invalid(
            "coreference citation requires its consent export door",
        ));
    }
    Ok(())
}

pub(crate) fn validate_note_export(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    crate::sync::selector::admit_note_in_txn(vault, txn, id, scope, selector, None)?;
    for pin in load(vault, txn, id)?.pins()? {
        admit_pin_disclosure(vault, txn, scope, selector, &pin)?;
    }
    Ok(())
}

pub(crate) fn import_note_from_authority(
    vault: &Vault,
    id: EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    let (head, rest) = bytes
        .split_at_checked(crate::entity_id::ENTITY_ID_LEN)
        .ok_or_else(|| invalid("NOTE frame head"))?;
    let (seq, bytes) = rest
        .split_at_checked(8)
        .ok_or_else(|| invalid("NOTE frame head"))?;
    let head = EntityId::from_bytes(head.try_into().map_err(|_| invalid("NOTE frame head"))?)
        .map_err(|_| invalid("NOTE frame head"))?;
    let seq = u64::from_be_bytes(seq.try_into().map_err(|_| invalid("NOTE frame head"))?);
    vault.with_write_txn(|txn| {
        if vault
            .store
            .sync_state
            .get(txn, &format!("ds:e:{}", id.to_hex()))?
            .is_none()
        {
            return Err(invalid("unsolicited NOTE authority state"));
        }
        let previous = load(vault, txn, id)?;
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
            return Err(invalid("NOTE was erased"));
        }
        // A new head arrives only as a STATE with a higher head sequence; an
        // UPDATE must name the head this replica holds. A stale frame cannot
        // undo a later switch.
        let (own_head, own_seq) = super::documents::head_in(&vault.store, txn, id)?;
        let new_head = match kind {
            document_sub_tags::STATE if seq > own_seq => true,
            document_sub_tags::STATE | document_sub_tags::UPDATE
                if head == own_head && seq == own_seq =>
            {
                false
            }
            _ => return Err(invalid("stale NOTE head")),
        };
        let staged = match kind {
            document_sub_tags::STATE => loro::LoroDoc::new(),
            document_sub_tags::UPDATE => {
                crate::sync::loro_support::doc_from_snapshot(&previous.snapshot()?)?
            }
            _ => return Err(invalid("invalid NOTE authority frame")),
        };
        crate::sync::documents::storage::import_complete(&staged, bytes)?;
        if new_head {
            // A STATE for a new head replaces the document; the checks below
            // compare documents of one head.
            super::documents::set_head(&vault.store, txn, id, head, seq)?;
            let next = NoteDocument::from_loro(id, staged)?;
            let floor_key = super::citation_scrub::authority_floor_key(id);
            if vault
                .store
                .vault_meta
                .get(txn, floor_key.as_bytes())?
                .is_some()
            {
                vault.store.vault_meta.put(
                    txn,
                    floor_key.as_bytes(),
                    &next.doc.oplog_vv().encode(),
                )?;
            }
            super::citation_erase::validate_pins(vault, txn, &next.pins()?)?;
            for pin in &next.view()?.pins {
                pin.validate()?;
            }
            return persist(vault, txn, &next);
        }
        let floor_key = super::citation_scrub::authority_floor_key(id);
        let authority_floor = vault.store.vault_meta.get(txn, floor_key.as_bytes())?;
        let required = match &authority_floor {
            Some(bytes) => crate::sync::documents::storage::decode_vv(bytes)?,
            None => previous.doc.oplog_vv(),
        };
        if authority_floor.is_some()
            && kind == document_sub_tags::UPDATE
            && previous.doc.oplog_vv() != required
        {
            // Local erasure operations are not authority operations. A STATE
            // rebase must retire them before normal authority deltas resume.
            return Err(invalid("NOTE erasure requires authority state"));
        }
        if !matches!(
            staged.oplog_vv().partial_cmp(&required),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
        ) {
            return Err(invalid(
                "NOTE authority state would discard local operations",
            ));
        }
        let next = NoteDocument::from_loro(id, staged)?;
        super::citation_erase::validate_pins(vault, txn, &next.pins()?)?;
        // Once this document was scrubbed, a full authority snapshot must not
        // restore the removed quote through deleted map values in its oplog.
        let next = if authority_floor.is_some() {
            let vv = next.doc.oplog_vv().encode();
            let clean =
                NoteDocument::load(id, &crate::sync::documents::storage::state_copy(&next.doc)?)?;
            vault.store.vault_meta.put(txn, floor_key.as_bytes(), &vv)?;
            clean
        } else {
            next
        };
        let old = previous.view()?;
        let new = next.view()?;
        if old.pins.iter().any(|pin| !new.pins.contains(pin))
            || old
                .authorship
                .iter()
                .any(|record| !new.authorship.contains(record))
        {
            return Err(invalid("NOTE authority state would discard provenance"));
        }
        let guards = super::operations::cited_by(vault, txn, id)?;
        for pin in old
            .pins
            .iter()
            .chain(&guards)
            .filter(|pin| pin.document == id)
        {
            if matches!(previous.resolve(pin)?, NoteSpanResolution::Mapped { .. })
                && !matches!(next.resolve(pin)?, NoteSpanResolution::Mapped { .. })
            {
                return Err(invalid(
                    "NOTE authority state conflicts with a local citation",
                ));
            }
        }
        // Pins are admitted metadata from the authority, not an upstream peer
        // map. Sources may arrive later; retain identity/quote/cursors now and
        // let resolve_note_pin report unavailable/drifted instead of remapping.
        for pin in &new.pins {
            pin.validate()?;
        }
        persist(vault, txn, &next)
    })?;
    vault.notify_note_document(id);
    Ok(())
}
