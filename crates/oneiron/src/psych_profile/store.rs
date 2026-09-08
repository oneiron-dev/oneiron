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

impl crate::Vault {
    /// Stores an engine-authored PsychProfile snapshot record.
    ///
    /// Generic public puts of `ENTITY_TYPE_PSYCH_PROFILE` remain rejected as a
    /// maintenance kind; this helper validates the pinned body schema before
    /// using the internal maintenance write path.
    pub fn put_psych_profile(&self, id: &EntityId, profile: &PsychProfile) -> Result<()> {
        let data = encode_psych_profile_body(profile)?;
        let learned_at = crate::unix_seconds_now();
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
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_PSYCH_PROFILE {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_psych_profile_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
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
        let Some(profile) = self.get_psych_profile(id)? else {
            return Ok(PsychProfileState::Missing);
        };
        if profile.status == PsychProfileSnapshotStatus::Stale {
            return Ok(PsychProfileState::Stale {
                profile,
                reason: PsychProfileStaleReason::MarkedStale,
            });
        }
        if let Some(expected) = expected_source_revision_ids {
            let expected = canonical_expected_source_revision_ids(expected.to_vec());
            if expected != profile.source_revision_ids {
                let actual = profile.source_revision_ids.clone();
                return Ok(PsychProfileState::Stale {
                    profile,
                    reason: PsychProfileStaleReason::SourceRevisionMismatch { expected, actual },
                });
            }
        }
        Ok(PsychProfileState::Fresh(profile))
    }
}
