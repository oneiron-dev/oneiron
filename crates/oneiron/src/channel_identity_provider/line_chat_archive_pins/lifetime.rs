//! Exact native join-version release. The CONTENT capture ends at claim
//! teardown; an unfinished release is LIVE until its last holder lets go.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

mod retirement;
mod sources;

pub(crate) use sources::accept_line_chat_observation_erase_in_txn;
pub(crate) use sources::erase_line_chat_source_observations_in_txn;

use super::{LineChatArchivePin, PINS};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::secret_custody::CustodyWrite;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum EraseSource {
    Observation,
    Identity,
    Machine,
    Artifact,
}

#[derive(Serialize, Deserialize)]
struct ArchiveRelease {
    pin: Option<LineChatArchivePin>,
    erase: bool,
    sources: BTreeMap<EntityId, EraseSource>,
    detached: bool,
    released: bool,
    inventory: Option<retirement::ReleaseInventory>,
}

impl ArchiveRelease {
    fn owns_version(&self) -> bool {
        self.pin.is_some_and(|pin| {
            pin.own_join || self.sources.get(&pin.artifact_id) == Some(&EraseSource::Artifact)
        })
    }
}

const RELEASES: SideTable<EntityId, ArchiveRelease, Named> =
    SideTable::new(&side_table::LINE_CHAT_ARCHIVE_RELEASE);

/// Detaches a native capture before its claim's provenance goes. A borrowed
/// text capture releases only its link. An owned join schedules only the
/// exact version the archive receipt proved; no public payload_ref can
/// create a release. Other retained consumers and legal holds keep it
/// pending, not refused and not silently forgotten.
pub(crate) fn release_line_chat_archive_pin_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    erase: bool,
) -> Result<()> {
    let store = write.store;
    let prior = RELEASES.get(store, txn, claim)?;
    let pin = match PINS.get(store, txn, claim)? {
        Some(pin) => {
            PINS.delete(store, txn, claim)?;
            Some(pin)
        }
        // A content image may omit the capture. The accepted LIVE source
        // continuation still owns its original immutable selector.
        None => match prior.as_ref() {
            Some(release) => release.pin,
            None => return Ok(()),
        },
    };
    if pin.is_some_and(|pin| pin.own_join) || prior.is_some() {
        let mut release = prior.unwrap_or_else(|| ArchiveRelease {
            pin,
            erase: false,
            sources: BTreeMap::new(),
            detached: false,
            released: false,
            inventory: None,
        });
        release.erase |= erase;
        release
            .sources
            .entry(*claim)
            .or_insert(EraseSource::Observation);
        release.detached = true;
        retirement::capture_in_txn(store, txn, &mut release)?;
        RELEASES.put(store, txn, claim, &release)?;
    }
    // A borrowed capture may have been the last consumer of an earlier
    // owned join release too. Its own bytes are never selected here.
    settle_line_chat_archive_releases_except_in_txn(write, txn, Some(claim))
}

/// Retries unfinished native releases after holds lift or another capture
/// leaves. The live release rows survive an older content restore.
pub(crate) fn settle_line_chat_archive_releases_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    sources::settle_source_observations_in_txn(write, txn)?;
    settle_line_chat_archive_releases_except_in_txn(write, txn, None)
}

fn settle_line_chat_archive_releases_except_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
    detaching: Option<&EntityId>,
) -> Result<()> {
    let store = write.store;
    for claim in RELEASES.scan_keys(store, txn, &[])? {
        // A prior group or recursive native teardown may have settled this row.
        let Some(release) = RELEASES.get(store, txn, &claim)? else {
            continue;
        };
        if !release.detached {
            continue;
        }
        if !release.owns_version() || release.released {
            if release.released {
                retirement::note_sources_in_txn(store, txn, &release)?;
            }
            retirement::finish_in_txn(store, txn, &claim, release)?;
            continue;
        }
        let Some(pin) = release.pin.as_ref() else {
            continue;
        };
        // Missing version metadata does not erase a native owner's
        // custody obligation: retained copies can still owe retirement.
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&pin.content_hash)?;
        let stands = exact_version_stands(store, txn, pin)?;
        if version_held(store, txn, pin, &asset)?
            || (stands
                && (captured_elsewhere(store, txn, &claim, detaching, pin)?
                    || crate::llm::step_response_version_pinned_in_txn(
                        store,
                        txn,
                        &claim,
                        &pin.artifact_id,
                        pin.version,
                        &pin.content_hash,
                    )?))
        {
            continue;
        }
        // Capture every erase owner's instance facts before the first
        // release can tear down the shared carrier. Several observations
        // may have captured the same native join version.
        let releases: Vec<_> = RELEASES
            .scan(store, txn)?
            .into_iter()
            .filter(|(_, other)| {
                other.detached
                    && other
                        .pin
                        .as_ref()
                        .is_some_and(|other| same_version(other, pin))
            })
            .collect();
        for (owner, mut release) in releases {
            retirement::capture_in_txn(store, txn, &mut release)?;
            retirement::note_sources_in_txn(store, txn, &release)?;
            RELEASES.put(store, txn, &owner, &release)?;
        }
        crate::blob_artifact::release_archive_version_in_txn(
            write,
            txn,
            &pin.artifact_id,
            pin.version,
            &pin.content_hash,
            &pin.version_claim,
        )?;
        // The blob lifecycle's hold and exact-record checks remain the
        // final authority. A version it kept leaves every release live.
        if exact_version_stands(store, txn, pin)? {
            continue;
        }
        for (owner, mut release) in RELEASES.scan(store, txn)? {
            if !release.detached
                || !release
                    .pin
                    .as_ref()
                    .is_some_and(|other| same_version(other, pin))
            {
                continue;
            }
            release.released = true;
            retirement::finish_in_txn(store, txn, &owner, release)?;
        }
    }
    Ok(())
}

fn same_version(a: &LineChatArchivePin, b: &LineChatArchivePin) -> bool {
    a.artifact_id == b.artifact_id
        && a.version == b.version
        && a.content_hash == b.content_hash
        && a.version_claim == b.version_claim
}

fn exact_version_stands(store: &Store, txn: &RoTxn<'_>, pin: &LineChatArchivePin) -> Result<bool> {
    crate::blob_artifact::archive_version_stands_in_txn(
        store,
        txn,
        &pin.artifact_id,
        pin.version,
        &pin.content_hash,
        &pin.version_claim,
    )
}

fn version_held(
    store: &Store,
    txn: &RoTxn<'_>,
    pin: &LineChatArchivePin,
    asset: &EntityId,
) -> Result<bool> {
    for id in [&pin.artifact_id, &pin.version_claim, asset] {
        if crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn retained_row(store: &Store, txn: &RoTxn<'_>, id: &EntityId, kind: u8) -> Result<bool> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(false);
    };
    Ok(raw.len() > ENTITY_METADATA_HEADER_LEN
        && raw[0] == kind
        && !crate::deletion::row_deletion_marked(store, txn, id, Some(&raw))?)
}

/// Other native captures, including historical and legally held claims,
/// keep their version. A public LINE observation reference can keep a
/// version too, but cannot schedule its deletion or mint ownership.
fn captured_elsewhere(
    store: &Store,
    txn: &RoTxn<'_>,
    releasing: &EntityId,
    detaching: Option<&EntityId>,
    pin: &LineChatArchivePin,
) -> Result<bool> {
    // A held accepted observation may have no CONTENT capture in a restored
    // image. Its original LIVE selector still keeps this exact version.
    for (other, pending) in RELEASES.scan(store, txn)? {
        if other != *releasing
            && Some(&other) != detaching
            && !pending.detached
            && pending
                .pin
                .as_ref()
                .is_some_and(|other| same_version(other, pin))
        {
            return Ok(true);
        }
    }
    for (other, capture) in PINS.scan(store, txn)? {
        if other != *releasing
            && Some(&other) != detaching
            && same_version(&capture, pin)
            && retained_row(store, txn, &other, ENTITY_TYPE_CLAIM)?
        {
            return Ok(true);
        }
    }
    let subject = super::super::line_chat_binding::provider_inbound_actor()?;
    for entry in store.type_index.prefix_iter(txn, &[ENTITY_TYPE_CLAIM])? {
        let (key, _) = entry?;
        let other = crate::vault::entity_id_from_type_index_key(&key)?;
        if other == *releasing
            || Some(&other) == detaching
            || release_pending_in_txn(store, txn, &other)?
        {
            continue;
        }
        let Some(raw) = store.port_entity_raw(txn, &other)? else {
            continue;
        };
        if !retained_row(store, txn, &other, ENTITY_TYPE_CLAIM)? {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        if body.subject != crate::claim::ClaimSubject::Entity(subject)
            || body.predicate != super::super::LINE_CHAT_OBSERVATION_PREDICATE
        {
            continue;
        }
        let Ok(observation) =
            rmpv::ext::from_value::<super::super::LineChatObservation>(body.value)
        else {
            continue;
        };
        if super::super::line_chat_erase::archived_version(&observation.payload_ref)
            == Some((pin.artifact_id, pin.version))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A LIVE release outranks an older CONTENT capture of the same owner.
pub(super) fn release_pending_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    claim: &EntityId,
) -> Result<bool> {
    Ok(RELEASES
        .get(store, txn, claim)?
        .is_some_and(|release| release.detached))
}

/// A truthful pending completion for the native observation's erase.
/// These rows contain ids and cause only, never event bytes.
pub(crate) fn line_chat_archive_releases_owed_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    sources: &[EntityId],
) -> Result<bool> {
    for (_, release) in RELEASES.scan(store, txn)? {
        if release.erase
            && sources
                .iter()
                .any(|source| release.sources.contains_key(source))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// An accepted erase of this actual source artifact keeps its exact
/// version through the native full-chain cleanup while its continuation
/// waits on a held observation or another retained version consumer.
pub(crate) fn line_chat_archive_keeps_version_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; 32],
    version_claim: &EntityId,
) -> Result<bool> {
    for (_, release) in RELEASES.scan(store, txn)? {
        if !release.released
            && release.sources.get(artifact) == Some(&EraseSource::Artifact)
            && release.pin.is_some_and(|pin| {
                pin.artifact_id == *artifact
                    && pin.version == version
                    && pin.content_hash == *content_hash
                    && pin.version_claim == *version_claim
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}
