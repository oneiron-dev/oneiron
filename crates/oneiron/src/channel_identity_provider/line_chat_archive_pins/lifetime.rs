//! Exact native join-version release. The CONTENT capture ends at claim
//! teardown; an unfinished release is LIVE until its last holder lets go.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{LineChatArchivePin, PINS};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::secret_custody::CustodyWrite;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[derive(Serialize, Deserialize)]
struct ArchiveRelease {
    pin: LineChatArchivePin,
    erase: bool,
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
    let Some(pin) = PINS.get(store, txn, claim)? else {
        return Ok(());
    };
    PINS.delete(store, txn, claim)?;
    if pin.own_join {
        let prior = RELEASES.get(store, txn, claim)?;
        RELEASES.put(
            store,
            txn,
            claim,
            &ArchiveRelease {
                pin,
                erase: erase || prior.is_some_and(|release| release.erase),
            },
        )?;
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
    settle_line_chat_archive_releases_except_in_txn(write, txn, None)
}

fn settle_line_chat_archive_releases_except_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
    detaching: Option<&EntityId>,
) -> Result<()> {
    let store = write.store;
    for (claim, release) in RELEASES.scan(store, txn)? {
        let pin = &release.pin;
        // Missing version metadata does not erase a native owner's
        // custody obligation: retained copies can still owe retirement.
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&pin.content_hash)?;
        if version_held(store, txn, pin, &asset)?
            || captured_elsewhere(store, txn, &claim, detaching, pin)?
            || crate::llm::step_response_version_pinned_in_txn(
                store,
                txn,
                &claim,
                &pin.artifact_id,
                pin.version,
                &pin.content_hash,
            )?
        {
            continue;
        }
        // Capture every erase owner's instance facts before the first
        // release can tear down the shared carrier. Several observations
        // may have captured the same native join version.
        let releases: Vec<_> = RELEASES
            .scan(store, txn)?
            .into_iter()
            .filter(|(_, other)| same_version(&other.pin, pin))
            .collect();
        #[cfg(unix)]
        let (held, inline) = {
            let held: Vec<[u8; 32]> =
                crate::provenance::body::owned_bodies_in_txn(store, txn, &asset)?
                    .iter()
                    .filter_map(|body| body.state.held().map(|held| held.blake3))
                    .collect();
            (held, crate::store::INLINE_ASSETS.get(store, txn, &asset)?)
        };
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
        #[cfg(unix)]
        let kept = retained_row(store, txn, &asset, crate::registry::ENTITY_TYPE_ASSET)?;
        for (owner, release) in releases {
            #[cfg(unix)]
            if release.erase {
                crate::store::erase_bodies_for_owner_in_txn(
                    store, txn, &owner, &asset, &held, kept,
                )?;
                crate::store::note_settled_inline_in_txn(store, txn, &owner, &asset, inline)?;
            }
            #[cfg(not(unix))]
            let _ = release;
            RELEASES.delete(store, txn, &owner)?;
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
            || RELEASES.contains(store, txn, &other)?
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

/// A truthful pending completion for the native observation's erase.
/// These rows contain ids and cause only, never event bytes.
pub(crate) fn line_chat_archive_releases_owed_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    sources: &[EntityId],
) -> Result<bool> {
    for (owner, release) in RELEASES.scan(store, txn)? {
        if release.erase && (sources.contains(&owner) || sources.contains(&release.pin.artifact_id))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
