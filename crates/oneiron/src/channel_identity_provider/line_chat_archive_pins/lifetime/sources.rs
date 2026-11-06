//! An accepted native source erase keeps its exact observation selectors
//! across a hold and the source's graph teardown. No public reference is
//! ever converted into ownership of an archive version.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::{ArchiveRelease, PINS, RELEASES, retirement};
use crate::counterparty_contact::ClaimHeadWriter;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
use crate::secret_custody::CustodyWrite;

/// Accepts only native capture rows of this stored MACHINE or artifact.
/// Every selector is recorded before any observation goes, including one
/// a hold keeps. A MACHINE erase borrows a text archive. An erase of the
/// actual source artifact already authorizes that artifact's bytes; its
/// accepted source id, not the observation, carries that authority.
/// The full artifact-delete caller must preserve held captured versions;
/// this door does not replace that caller's whole-chain lifecycle.
pub(crate) fn erase_line_chat_source_observations_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let store = write.store;
    let kind = store
        .port_entity_raw(txn, source)?
        .and_then(|raw| raw.first().copied());
    let machine = kind == Some(ENTITY_TYPE_MACHINE)
        && *source == super::super::super::line_chat_binding::provider_inbound_actor()?;
    let artifact = kind == Some(ENTITY_TYPE_BLOB_ARTIFACT);
    if !machine && !artifact {
        return Ok(());
    }
    for (claim, pin) in PINS.scan(store, txn)? {
        if !machine && pin.artifact_id != *source {
            continue;
        }
        let mut release = RELEASES
            .get(store, txn, &claim)?
            .unwrap_or_else(|| ArchiveRelease {
                pin,
                erase: false,
                sources: BTreeSet::new(),
                detached: false,
                released: false,
                inventory: None,
            });
        release.erase = true;
        release.sources.extend([claim, *source]);
        retirement::capture_in_txn(store, txn, &mut release)?;
        RELEASES.put(store, txn, &claim, &release)?;
    }
    // A prior observation erase can already have detached the capture.
    // Join its accepted native selector before this source's graph goes too.
    for (claim, mut release) in RELEASES.scan(store, txn)? {
        if (machine || release.pin.artifact_id == *source)
            && (!release.sources.contains(source) || !release.erase)
        {
            release.erase = true;
            release.sources.extend([claim, *source]);
            retirement::capture_in_txn(store, txn, &mut release)?;
            RELEASES.put(store, txn, &claim, &release)?;
        }
    }
    // No ClaimOf or source row is needed when a later pass retries these.
    settle_source_observations_in_txn(write, txn)?;
    super::settle_line_chat_archive_releases_except_in_txn(write, txn, None)
}

pub(super) fn settle_source_observations_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    let store = write.store;
    for claim in RELEASES.scan_keys(store, txn, &[])? {
        let Some(release) = RELEASES.get(store, txn, &claim)? else {
            continue;
        };
        if release.detached || crate::store::legal_hold::held_in_txn(store, txn, claim.as_bytes())?
        {
            continue;
        }
        if let Some(raw) = store.port_entity_raw(txn, &claim)?
            && raw.first() != Some(&ENTITY_TYPE_CLAIM)
        {
            // Never delete an unrelated row restored at this key.
            continue;
        }
        // Erase the selected observation's own native carriers before the
        // ordinary batch delete. The archive release is independently exact.
        crate::provenance::erase_row_provenance_in_txn(write, txn, &claim, true)?;
        super::release_line_chat_archive_pin_in_txn(write, txn, &claim, true)?;
        let writer = ClaimHeadWriter {
            store,
            config: write.config,
            analyzer: write.analyzer,
            text_index_trusted: write.text_index_trusted,
        };
        let now = crate::ports::recorded_at_in_txn(store, txn)?;
        super::super::super::line_chat_erase::hard_delete_row_in_txn(
            &writer,
            txn,
            &claim,
            ENTITY_TYPE_CLAIM,
            now,
        )?;
    }
    Ok(())
}
