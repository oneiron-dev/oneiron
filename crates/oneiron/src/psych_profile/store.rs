//! Vault put/get/state maintenance-gated persistence for profiles.

use std::sync::atomic::Ordering;

use super::codec::{
    canonical_expected_source_revision_ids, decode_psych_profile_body, encode_psych_profile_body,
};
use super::keys::{PsychProfileKey, psych_profile_entity_id};
use super::record::{
    PsychProfile, PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PSYCH_PROFILE;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

impl crate::Vault {
    /// Stores an engine-authored PsychProfile snapshot record.
    ///
    /// Generic public puts of `ENTITY_TYPE_PSYCH_PROFILE` remain rejected as a
    /// maintenance kind; this helper validates the pinned body schema before
    /// using the internal maintenance write path.
    pub fn put_psych_profile(&self, id: &EntityId, profile: &PsychProfile) -> Result<()> {
        let data = encode_psych_profile_body(profile)?;
        let learned_at = self.store.clock.now_recorded_at();
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_PSYCH_PROFILE,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted.load(Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads and decodes a PsychProfile snapshot record.
    pub fn get_psych_profile(&self, id: &EntityId) -> Result<Option<PsychProfile>> {
        decode_psych_profile_row(self.get_raw(id)?)
    }

    /// [`Self::get_psych_profile`] in the caller's snapshot. A profile row
    /// whose own deletion is recorded is gone, whatever bytes it still holds
    /// (FIX 10056); a deletion marker that cannot be read leaves the read as
    /// it was.
    pub(crate) fn get_psych_profile_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<PsychProfile>> {
        if crate::ports::removed_in_txn(&self.store, rtxn, id).unwrap_or(false) {
            return Ok(None);
        }
        decode_psych_profile_row(self.get_raw_in(rtxn, id)?)
    }

    /// [`Self::psych_profile_state`] in the caller's snapshot, read under
    /// [`Self::get_raw`]'s seal and absent rules, as the public read is.
    pub(crate) fn psych_profile_sealed_state_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_source_revision_ids: Option<&[EntityId]>,
    ) -> Result<PsychProfileState> {
        Ok(psych_profile_state_of(
            decode_psych_profile_row(self.get_raw_sealed_in_txn(rtxn, id)?)?,
            expected_source_revision_ids,
        ))
    }

    /// List-safe read: a deleted/archived profile is absent, while malformed
    /// live profile bytes still fail closed in the same transaction snapshot.
    pub fn get_live_psych_profile(&self, id: &EntityId) -> Result<Option<PsychProfile>> {
        let txn = self.store.env.read_txn()?;
        match live_entity_row_in_txn(&self.store, &txn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PSYCH_PROFILE,
                body,
            } => decode_psych_profile_body(&body).map(Some),
            LiveEntityRow::Live { entity_type, .. } => Err(Error::InvalidEntityType(entity_type)),
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => Ok(None),
        }
    }

    /// Returns a typed missing/fresh/stale state for a PsychProfile snapshot.
    ///
    /// `expected_source_revision_ids = None` checks only the stored stale
    /// marker. Supplying a source set also compares against the persisted
    /// canonical sourceRevisionIds.
    /// Looks up the profile addressed by a Person x Facet x World key.
    pub fn psych_profile_for(&self, key: &PsychProfileKey) -> Result<PsychProfileState> {
        self.psych_profile_state(&psych_profile_entity_id(key), None)
    }

    pub fn psych_profile_state(
        &self,
        id: &EntityId,
        expected_source_revision_ids: Option<&[EntityId]>,
    ) -> Result<PsychProfileState> {
        Ok(psych_profile_state_of(
            self.get_psych_profile(id)?,
            expected_source_revision_ids,
        ))
    }

    /// [`Self::psych_profile_state`] in the caller's snapshot.
    pub(crate) fn psych_profile_state_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_source_revision_ids: Option<&[EntityId]>,
    ) -> Result<PsychProfileState> {
        Ok(psych_profile_state_of(
            self.get_psych_profile_in_txn(rtxn, id)?,
            expected_source_revision_ids,
        ))
    }
}

fn decode_psych_profile_row(raw: Option<Vec<u8>>) -> Result<Option<PsychProfile>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_PSYCH_PROFILE {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_psych_profile_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn psych_profile_state_of(
    profile: Option<PsychProfile>,
    expected_source_revision_ids: Option<&[EntityId]>,
) -> PsychProfileState {
    let Some(profile) = profile else {
        return PsychProfileState::Missing;
    };
    if profile.status == PsychProfileSnapshotStatus::Stale {
        return PsychProfileState::Stale {
            profile,
            reason: PsychProfileStaleReason::MarkedStale,
        };
    }
    if let Some(expected) = expected_source_revision_ids {
        let expected = canonical_expected_source_revision_ids(expected.to_vec());
        if expected != profile.source_revision_ids {
            let actual = profile.source_revision_ids.clone();
            return PsychProfileState::Stale {
                profile,
                reason: PsychProfileStaleReason::SourceRevisionMismatch { expected, actual },
            };
        }
    }
    PsychProfileState::Fresh(profile)
}
