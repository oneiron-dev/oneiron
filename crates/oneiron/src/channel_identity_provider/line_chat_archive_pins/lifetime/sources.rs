//! An accepted native source erase keeps its exact observation selectors
//! across a hold and the source's graph teardown. No public reference is
//! ever converted into ownership of an archive version.

use std::collections::BTreeMap;

use heed::RwTxn;

use super::{ArchiveRelease, EraseSource, PINS, RELEASES, retirement};
use crate::counterparty_contact::ClaimHeadWriter;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
use crate::secret_custody::CustodyWrite;

/// Records an observation selected by the native identity selector. A
/// public-only observation gets a record-only continuation, never a pin.
pub(crate) fn accept_line_chat_observation_erase_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    claim: &EntityId,
) -> Result<()> {
    accept_observation_erase_in_txn(store, txn, source, claim, EraseSource::Identity)
}

fn accept_observation_erase_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    claim: &EntityId,
    kind: EraseSource,
) -> Result<()> {
    let prior = RELEASES.get(store, txn, claim)?;
    let release = match (prior, PINS.get(store, txn, claim)?) {
        (Some(release), _) => release,
        (None, Some(pin)) => ArchiveRelease {
            pin: Some(pin),
            erase: false,
            sources: BTreeMap::new(),
            detached: false,
            released: false,
            inventory: None,
        },
        (None, None) => ArchiveRelease {
            pin: None,
            erase: false,
            sources: BTreeMap::new(),
            detached: false,
            released: false,
            inventory: None,
        },
    };
    let mut release = release;
    release.erase = true;
    release
        .sources
        .entry(*claim)
        .or_insert(EraseSource::Observation);
    if kind == EraseSource::Artifact {
        release.sources.insert(*source, kind);
    } else {
        release.sources.entry(*source).or_insert(kind);
    }
    retirement::capture_in_txn(store, txn, &mut release)?;
    RELEASES.put(store, txn, claim, &release)?;
    Ok(())
}

/// Accepts provider observation records of this stored MACHINE or artifact.
/// Public archive references select records only; native captures alone
/// establish the exact versions a source erase may release.
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
    let source_kind = if artifact {
        EraseSource::Artifact
    } else {
        EraseSource::Machine
    };
    // Select record-only observations before the source's graph goes too.
    // This repeats no archive-byte inference from a public payload_ref.
    let subject = super::super::super::line_chat_binding::provider_inbound_actor()?;
    let mut selected = Vec::new();
    for entry in store.type_index.prefix_iter(txn, &[ENTITY_TYPE_CLAIM])? {
        let (key, _) = entry?;
        let claim = crate::vault::entity_id_from_type_index_key(&key)?;
        let Some(raw) = store.port_entity_raw(txn, &claim)? else {
            continue;
        };
        if raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN || raw[0] != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        if body.subject != crate::claim::ClaimSubject::Entity(subject)
            || body.predicate != super::super::super::LINE_CHAT_OBSERVATION_PREDICATE
        {
            continue;
        }
        let Ok(observation) =
            rmpv::ext::from_value::<super::super::super::LineChatObservation>(body.value)
        else {
            continue;
        };
        if machine
            || super::super::super::line_chat_erase::archived_version(&observation.payload_ref)
                .is_some_and(|(artifact, _)| artifact == *source)
        {
            selected.push(claim);
        }
    }
    for claim in selected {
        accept_observation_erase_in_txn(store, txn, source, &claim, source_kind)?;
    }
    for (claim, pin) in PINS.scan(store, txn)? {
        if machine || pin.artifact_id == *source {
            accept_observation_erase_in_txn(store, txn, source, &claim, source_kind)?;
        }
    }
    // A prior observation erase can already have detached the capture.
    // Join its accepted native selector before this source's graph goes too.
    for (claim, release) in RELEASES.scan(store, txn)? {
        if (machine || release.pin.is_some_and(|pin| pin.artifact_id == *source))
            && (!release.sources.contains_key(source)
                || !release.erase
                || (artifact && release.sources.get(source) != Some(&EraseSource::Artifact)))
        {
            accept_observation_erase_in_txn(store, txn, source, &claim, source_kind)?;
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
