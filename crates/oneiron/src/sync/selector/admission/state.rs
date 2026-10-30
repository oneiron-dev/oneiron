//! Admitted-update state for one federation import.
//! The entry point is `AdmittedUpdate`, with `staged_births` for staged artifacts.
//! Owned by `super`; the old `admission::` paths are re-exported there.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

#[cfg(feature = "sync")]
use super::super::edge::{
    EarlyStamps, HeldStamp, ReleasedStamps, hold_stamps, pending_births, release_born_stamps,
};
use super::staged_lane;

/// An update the federation door admitted, and the facet stamps it sent onto
/// rows this vault lacks, which wait out of its bytes: the ones whose rows it
/// brings until those births apply here, the rest held under its sender.
///
/// A guest's update can land in more than one window ([`super::routing::Routes`], FIX 3497):
/// this part imports first, then each part in [`Self::parts`] after it.
#[cfg(feature = "sync")]
pub(crate) struct AdmittedUpdate {
    pub(super) key: WindowKey,
    pub(super) bytes: Vec<u8>,
    pub(super) rows: u64,
    pub(super) early: EarlyStamps,
    pub(super) births: Vec<(EntityId, Vec<u8>)>,
    pub(super) peer_rows: Vec<(EntityId, [u8; 32])>,
    pub(super) delivered: BTreeMap<EntityId, [u8; 32]>,
    pub(super) born_with: Vec<super::super::born_with::CarriedText>,
    pub(super) lane: Option<String>,
    pub(super) routed: Vec<AdmittedUpdate>,
}

#[cfg(feature = "sync")]
impl AdmittedUpdate {
    /// The window these bytes import into: the update's own, or for a
    /// guest's update in one of its WORLD windows, that world's foreign copy
    /// (FIX 3497).
    pub(crate) const fn key(&self) -> &WindowKey {
        &self.key
    }

    /// This part, then each part a guest's update routed into a foreign
    /// WORLD window (FIX 3497), in the order they import.
    pub(crate) fn parts(&self) -> impl Iterator<Item = &Self> {
        std::iter::once(self).chain(&self.routed)
    }

    /// The admitted bytes to import.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The writes the update asks of this vault: its rows and edges, and the
    /// stamps that wait out of it (Astra-b F2 on #1432).
    pub(crate) fn writes(&self) -> u64 {
        self.parts()
            .map(|part| {
                let early = part.early.held.len() + part.early.with_birth.len();
                part.rows.saturating_add(early as u64)
            })
            .fold(0, u64::saturating_add)
            .max(1)
    }

    /// Holds the stamps ahead of their rows under the peer that sent the
    /// update and the `grant` it sent them under, within the peer's caps.
    pub(crate) fn hold_from_peer(
        &self,
        vault: &Vault,
        key: &WindowKey,
        grant: EntityId,
    ) -> Result<()> {
        match &self.lane {
            Some(lane) => hold_stamps(vault, key, (lane, Some(grant)), &self.early.held, true),
            None => Ok(()),
        }
    }

    /// Holds every stamp of a staged artifact under its receipt, the ones
    /// whose rows it brings too: those births apply only at its confirmation.
    pub(crate) fn hold_staged(&self, vault: &Vault, key: &WindowKey) -> Result<()> {
        let Some(lane) = &self.lane else {
            return Ok(());
        };
        hold_stamps(vault, key, (lane, None), &self.early.held, false)?;
        hold_stamps(vault, key, (lane, None), &self.early.with_birth, false)
    }

    /// The record of every stamp [`Self::hold_staged`] holds, which the
    /// receipt keeps while it is Pending.
    pub(crate) fn staged_stamps(&self) -> Vec<u8> {
        HeldStamp::record(&[&self.early.held, &self.early.with_birth])
    }

    /// The rows the update brings whose births its import must watch, each
    /// with the bytes it brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// The rows whose door judges a peer's row apart from this vault's own,
    /// each with the digest of the bytes the update brings.
    pub(crate) fn peer_rows(&self) -> &[(EntityId, [u8; 32])] {
        &self.peer_rows
    }

    /// Every row the update brings, with the digest of its bytes: what a
    /// pact delivers when the update's import writes it (FIX 321).
    pub(crate) const fn delivered(&self) -> &BTreeMap<EntityId, [u8; 32]> {
        &self.delivered
    }

    /// After the update's import, keeps the born-with text the sender let
    /// travel beside each row that landed (OF-491).
    pub(crate) fn keep_born_with(&self, vault: &Vault) -> Result<()> {
        super::super::born_with::keep_carried(vault, &self.born_with)
    }

    /// After the update's import, the stamps on the rows that import birthed
    /// (`born`, [`release_born_stamps`]).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        match &self.lane {
            Some(lane) => {
                release_born_stamps(vault, key, lane, &self.births, born, &self.early.with_birth)
            }
            None => Ok(None),
        }
    }
}

/// The rows a staged artifact's admitted bytes bring that this vault lacks
/// and that its receipt holds stamps on, read before the confirmation imports
/// them.
#[cfg(feature = "sync")]
pub(crate) struct StagedBirths {
    lane: String,
    births: Vec<(EntityId, Vec<u8>)>,
}

#[cfg(feature = "sync")]
impl StagedBirths {
    /// The rows the confirmation's import must watch, each with the bytes
    /// the artifact brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// After the confirmation's import, the stamps on the rows that import
    /// birthed (`born`).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        release_born_stamps(vault, key, &self.lane, &self.births, born, &[])
    }
}

/// [`StagedBirths`] of the artifact staged under `receipt_id`.
#[cfg(feature = "sync")]
pub(in crate::sync) fn staged_births(
    vault: &Vault,
    key: &WindowKey,
    (receipt_id, stamps_digest): (&[u8; 32], Option<[u8; 32]>),
    admitted_update: &[u8],
) -> Result<StagedBirths> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    let lane = staged_lane(receipt_id);
    // The held table restores live and maintenance sweeps it, so a hold can
    // be gone while its receipt is Pending. The receipt's own record holds
    // every staged stamp again before its birth is judged: an owner's import
    // never lands a row without the facets it staged (Astra-c F1 on #1432).
    let record = crate::batch::export::vault_import_staged_stamps(vault, receipt_id)?;
    let stamps = HeldStamp::from_receipt_record(&record.unwrap_or_default(), stamps_digest)?;
    hold_stamps(vault, key, (&lane, None), &stamps, false)?;
    let births = pending_births(vault, &lane, &admitted.get_map("entities"), &[])?;
    Ok(StagedBirths { lane, births })
}
