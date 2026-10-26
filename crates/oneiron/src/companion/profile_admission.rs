//! The admitted companion profile read (FIX 8141). Which grant admits a
//! reader's read of one profile, the profile as it stands, and whether the
//! owner's recipient choice lets it go where the read goes are judged in one
//! snapshot, so the bytes returned are the bytes admitted. The reader is the
//! request's authenticated principal and its destination is the one its
//! connection proved; a query parameter is never either. A recipient
//! judgement that cannot be read leaves the read as it was before this door.

use crate::access_grant::decode_live_access_grant_body;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::psych_profile::{PsychProfileKey, PsychProfileState, psych_profile_entity_id};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::settings::ReadDestination;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Policy hook (CALLS "OF-8141 mixed-source snapshot", open): a snapshot
/// any of whose sources lies in a world the destination may not read is
/// withheld whole, since its prose cannot be cut by source.
pub const COMPANION_PROFILE_WITHHOLDS_MIXED_SOURCES: bool = true;

/// What an admitted companion profile read returns.
#[derive(Debug, Clone, PartialEq)]
pub enum CompanionProfileAdmission {
    /// No active grant admits this reader's read of this profile.
    Denied,
    /// `grant` admits the read: the profile as it stands.
    Admitted {
        grant: EntityId,
        state: PsychProfileState,
    },
    /// `grant` admits the read, but the owner's recipient choice keeps the
    /// world it names, or a world one of its sources lies in, from where the
    /// read goes: nothing of the profile is returned.
    Withheld { grant: EntityId },
}

impl Vault {
    /// `principal_ref`'s read of the profile at `key` toward `destination`,
    /// judged in one snapshot: every live grant is tried, and the first that
    /// admits the read, its issuer bounds included, admits it. `selected`
    /// is the caller's source set for the freshness check.
    pub fn companion_profile_snapshot_admitted(
        &self,
        principal_ref: &EntityId,
        key: &PsychProfileKey,
        destination: &ReadDestination,
        selected: Option<&[EntityId]>,
    ) -> Result<CompanionProfileAdmission> {
        let now = self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let Some(grant) = self.companion_profile_grant_in(&txn, principal_ref, key, now)? else {
            return Ok(CompanionProfileAdmission::Denied);
        };
        let state =
            self.psych_profile_sealed_state_in_txn(&txn, &psych_profile_entity_id(key), selected)?;
        if self.companion_profile_withheld_in(&txn, key, &state, destination) {
            return Ok(CompanionProfileAdmission::Withheld { grant });
        }
        Ok(CompanionProfileAdmission::Admitted { grant, state })
    }

    /// The first live grant that admits `principal_ref`'s read at `key`.
    /// A deleted grant admits nothing; a malformed live one fails closed.
    fn companion_profile_grant_in(
        &self,
        txn: &heed::RoTxn<'_>,
        principal_ref: &EntityId,
        key: &PsychProfileKey,
        now: u64,
    ) -> Result<Option<EntityId>> {
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_ACCESS_GRANT, None)?
        {
            let id = entry?;
            let body = match live_entity_row_in_txn(&self.store, txn, &id)? {
                LiveEntityRow::Absent | LiveEntityRow::DeletedShell => continue,
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_ACCESS_GRANT,
                    body,
                } => body,
                LiveEntityRow::Live { .. } => {
                    return Err(Error::CorruptedIndex("access grant entity type"));
                }
            };
            let Some(grant) = decode_live_access_grant_body(&body)
                .map_err(|_| Error::CorruptedIndex("access grant body"))?
            else {
                continue;
            };
            if grant.allows_companion_profile_read(principal_ref, &key.person, key.facet.as_ref(), now)
                && grant
                    .companion_bounds
                    .as_ref()
                    .is_none_or(|bounds| bounds.admits_profile_key(key))
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Whether the owner's recipient choice keeps the profile at `key` from
    /// `destination`: the world the read names, or the world one of its
    /// sources lies in. A profile no world or source places stays readable.
    fn companion_profile_withheld_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &PsychProfileKey,
        state: &PsychProfileState,
        destination: &ReadDestination,
    ) -> bool {
        let Ok(withheld) = crate::settings::withheld_worlds_in(self, txn, destination) else {
            return false;
        };
        if withheld.is_empty() {
            return false;
        }
        if key.world.is_some_and(|world| withheld.contains(&world)) {
            return true;
        }
        let profile = match state {
            PsychProfileState::Missing => return false,
            PsychProfileState::Fresh(profile) | PsychProfileState::Stale { profile, .. } => profile,
        };
        COMPANION_PROFILE_WITHHOLDS_MIXED_SOURCES
            && profile
                .sources
                .iter()
                .any(|source| source.world_ref.is_some_and(|world| withheld.contains(&world)))
    }
}
