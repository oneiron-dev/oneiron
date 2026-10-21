//! The exact artifact version a terminal `dreamer.step` claim's oversize
//! response lives in, held by the claim (FIX 6225): an LLM step's and a
//! compaction step's alike.
//!
//! Each writer that appends a response version pins it to its claim in the
//! write that files both. The claim's teardown, by any door, takes its pins
//! before anything of it goes: an erase and a delete alike release each
//! exact version no other retained claim still pins, its generated
//! `blob.version` claim, support rows and unheld bytes with it, and an empty
//! response artifact goes too. An erase also retires the version's kept
//! body copies, or owes their retirement to the last holder of shared bytes
//! (ERASE-SHARED = B); it is never refused for another holder.
//!
//! A restore and an activation take a claim's pins with what they no longer
//! hold: a claim whose pinned version's body its source retired takes the
//! erase's shell, a shell's pins release, and an omitted claim's or
//! version's pin goes without releasing anything (an omission is no erase).
//! The pins are found by walking this one forward table; no reverse index.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Where an oversize step response lives: its artifact, and the one version
/// the step appended there, by number and content hash. Replay reads exactly
/// that version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StepResponseRef {
    pub(crate) artifact_id: EntityId,
    pub(crate) version: u64,
    pub(crate) content_hash: [u8; 32],
}

/// The response versions each terminal step claim holds. Key: id16(claim).
const PINS: SideTable<EntityId, Vec<StepResponseRef>, Named> =
    SideTable::new(&side_table::DREAMER_STEP_RESPONSE_PIN);

/// Pins `claim`'s response to the exact version `pin` names, in the write
/// that files the claim and appends the version: both commit or roll back
/// with it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn register_step_response_pin_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    pin: &StepResponseRef,
) -> Result<()> {
    let mut pins = PINS.get(store, txn, claim)?.unwrap_or_default();
    if !pins.contains(pin) {
        pins.push(*pin);
    }
    PINS.put(store, txn, claim, &pins)
}

/// Takes every pin `claim` holds at its teardown, before anything of it
/// goes, by any door (`erase`: an erase, not a delete). Each exact version
/// no other retained claim pins is released with its support rows and
/// unheld bytes. An erase retires the version's kept body copies, the
/// claim's receipt naming each; while another holder still keeps the bytes
/// their retirement waits on its release. Never a refusal: a claim with no
/// pins is a no-op.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn release_step_response_pins_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    erase: bool,
) -> Result<()> {
    let Some(pins) = PINS.get(store, txn, claim)? else {
        return Ok(());
    };
    PINS.delete(store, txn, claim)?;
    for pin in &pins {
        release_pin_in_txn(store, txn, claim, pin, erase)?;
    }
    Ok(())
}

/// One pin of `claim`'s teardown: the bytes' descriptors are read before
/// any of them goes, the version released when no other retained claim pins
/// it, then an erase's retirement staged or owed.
fn release_pin_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    pin: &StepResponseRef,
    erase: bool,
) -> Result<()> {
    #[cfg(unix)]
    let custody = if erase {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&pin.content_hash)?;
        let held: Vec<[u8; 32]> = crate::provenance::body::owned_bodies_in_txn(store, txn, &asset)?
            .iter()
            .filter_map(|body| body.state.held().map(|held| held.blake3))
            .collect();
        Some((asset, held))
    } else {
        None
    };
    #[cfg(not(unix))]
    let _ = erase;
    if !pinned_elsewhere_in_txn(store, txn, claim, pin)? {
        crate::blob_artifact::release_response_version_in_txn(
            store,
            txn,
            &pin.artifact_id,
            pin.version,
            &pin.content_hash,
        )?;
    }
    // The bytes another version, artifact or claim still holds keep their
    // ASSET and binding; the erase owes their retirement.
    #[cfg(unix)]
    if let Some((asset, held)) = custody {
        let kept = row_retained(store, txn, &asset, crate::registry::ENTITY_TYPE_ASSET)?;
        crate::store::erase_bodies_for_owner_in_txn(store, txn, claim, &asset, &held, kept)?;
    }
    Ok(())
}

/// Whether a retained claim other than `claim` pins the exact version `pin`
/// names. Every pin row is read, none skipped: a closed historical claim
/// still holds its recorded answer.
fn pinned_elsewhere_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    claim: &EntityId,
    pin: &StepResponseRef,
) -> Result<bool> {
    for row in PINS.iter_from(store, txn, &[])? {
        let (other, pins) = row?;
        if other != *claim
            && pins.contains(pin)
            && row_retained(store, txn, &other, ENTITY_TYPE_CLAIM)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A stored row of `kind` with its body, under no delete this vault holds.
fn row_retained(store: &Store, txn: &RoTxn<'_>, id: &EntityId, kind: u8) -> Result<bool> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(false);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN || raw[0] != kind {
        return Ok(false);
    }
    Ok(!crate::deletion::row_deletion_marked(
        store,
        txn,
        id,
        Some(raw.as_slice()),
    )?)
}

/// Whether the bytes `pin` names rest in a body a prune retired: an inline
/// ASSET's binding, or a file's instance row.
fn rests_in_retired(
    pin: &StepResponseRef,
    assets: &BTreeSet<EntityId>,
    digests: &BTreeSet<[u8; 32]>,
) -> Result<bool> {
    Ok(digests.contains(&pin.content_hash)
        || assets.contains(&crate::blob_artifact::blob_artifact_asset_entity_id(
            &pin.content_hash,
        )?))
}

/// Takes the pins a restore's or an activation's rows no longer hold, in
/// its write (the type index back): a claim whose pinned version's bytes
/// rest in a body its source retired (`erased_assets`, `erased_digests`)
/// takes the erase's shell and its pins release; a shell's or a deleted
/// claim's pins release; an absent claim's pin goes and releases nothing,
/// and so does a pin whose exact version is not there. A version whose
/// bytes are missing keeps its pin, for its claim's release.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn prune_step_response_pins_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    erased_assets: &BTreeSet<EntityId>,
    erased_digests: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    for (claim, pins) in PINS.scan(store, txn)? {
        if store.port_entity_raw(txn, &claim)?.is_none() {
            PINS.delete(store, txn, &claim)?;
            continue;
        }
        if !row_retained(store, txn, &claim, ENTITY_TYPE_CLAIM)? {
            release_step_response_pins_in_txn(store, txn, &claim, false)?;
            continue;
        }
        let mut erased = false;
        for pin in &pins {
            erased |= rests_in_retired(pin, erased_assets, erased_digests)?;
        }
        if erased {
            super::response_bodies::retire_step_claim_in_txn(store, txn, claim.as_bytes())?;
            continue;
        }
        let mut standing = Vec::with_capacity(pins.len());
        for pin in &pins {
            if crate::blob_artifact::response_version_stands_in_txn(
                store,
                txn,
                &pin.artifact_id,
                pin.version,
                &pin.content_hash,
            )? {
                standing.push(*pin);
            }
        }
        if standing.is_empty() {
            PINS.delete(store, txn, &claim)?;
        } else if standing.len() != pins.len() {
            PINS.put(store, txn, &claim, &standing)?;
        }
    }
    Ok(())
}

/// Leaves each step claim whose pinned version's bytes rest in a body a
/// restore's prune retired (`assets`, `digests`) the erase's shell in raw
/// image rows, before anything lands, as a retired inline response's claim
/// takes it: its header alone, its projection and step-index rows gone and
/// its soft-delete marker and fence set. Its pins stay for the restore's
/// write to release ([`prune_step_response_pins_in_txn`]). Rows stay in
/// order.
///
/// # Errors
///
/// A pin row that does not decode.
pub(crate) fn retire_erased_step_responses_in_rows(
    databases: &mut BTreeMap<String, Rows>,
    assets: &BTreeSet<EntityId>,
    digests: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if assets.is_empty() && digests.is_empty() {
        return Ok(());
    }
    let Some(rows) = databases.get("vault_meta") else {
        return Ok(());
    };
    let prefix = PINS.decl().prefix;
    let start = rows.partition_point(|(key, _)| key.as_slice() < prefix);
    let mut erased = Vec::new();
    for (key, value) in &rows[start..] {
        let Some(rest) = key.strip_prefix(prefix) else {
            break;
        };
        let claim =
            EntityId::decode_key(rest).ok_or(Error::CorruptedIndex("step response pin key"))?;
        let mut retired = false;
        for pin in &PINS.decode_value(value)? {
            retired |= rests_in_retired(pin, assets, digests)?;
        }
        if retired {
            erased.push(claim);
        }
    }
    for claim in erased {
        let Some(entities) = databases.get_mut("entities") else {
            return Ok(());
        };
        let Ok(at) = entities.binary_search_by(|(row, _)| row.as_slice().cmp(claim.as_bytes()))
        else {
            continue;
        };
        let value = &mut entities[at].1;
        if value.len() <= ENTITY_METADATA_HEADER_LEN || value[0] != ENTITY_TYPE_CLAIM {
            continue;
        }
        value.truncate(ENTITY_METADATA_HEADER_LEN);
        super::response_bodies::retire_step_claim_in_rows(databases, claim.as_bytes())?;
    }
    Ok(())
}
