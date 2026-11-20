//! The admitted companion profile read (FIX 8141). Which grant admits a
//! reader's read of one profile, the profile as it stands, and whether the
//! owner's recipient choice lets it go where the read goes are judged in one
//! snapshot, so the bytes returned are the bytes admitted. The reader is the
//! request's authenticated principal and its destination is the one its
//! connection proved; a query parameter is never either. The reader's own
//! credential is judged on the world the read names and on the exact words
//! behind each recorded source (FIX 11174, 11766), so a source it keeps out
//! keeps the profile out. A recipient or credential judgement that cannot be
//! read leaves the read as it was before this door. The stored row's source
//! audience, its own binding and that of each claim it copies, is asked for
//! the reader's authenticated person as every scoped read asks it, since the
//! sealed state is read past the scoped row gate (REVIEW-9906): a profile of
//! a claim learned from a private mailbox reads only to that mailbox's
//! readers, and a judgement of it that cannot be read keeps the profile out. A row of an earlier
//! schema, whose sources name no exact words, reads as no profile and says
//! nothing of itself (FIX 11766, Engine B): no payload, source hints or
//! regeneration hint, and no payload of it is decoded.

use crate::access_grant::decode_live_access_grant_body;
use crate::claim::{CompanionProfileSourceJudgement, ScopedRead};
use crate::error::{Error, Result};
use crate::psych_profile::{
    PsychProfileKey, PsychProfileSource, PsychProfileState, psych_profile_entity_id,
};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::settings::ReadDestination;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Policy hook (CALLS "OF-8141 mixed-source snapshot", open): a snapshot
/// any of whose sources lies in a world the destination may not read, or
/// that the reader's own credential keeps out, is withheld whole, since its
/// prose cannot be cut by source.
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
    /// `grant` names this profile, but nothing of it is returned: the
    /// owner's recipient choice keeps the world the read names, or a world
    /// one of its sources lies in, from where the read goes, the reader's
    /// own credential keeps that world or the exact words of a source out,
    /// the profile's source audience does not read to the reader, the
    /// grant's own delegated bounds leave this read outside it, or the
    /// stored row is of an earlier schema whose sources name no exact words
    /// (FIX 11766).
    Withheld { grant: EntityId },
}

/// What the live grants say of one profile read.
enum GrantMatch {
    /// This grant admits it.
    Admits(EntityId),
    /// No grant admits it, but this one names the profile and its delegated
    /// bounds leave the read outside it.
    Bounded(EntityId),
    /// No grant names it.
    None,
}

impl Vault {
    /// `principal_ref`'s read of the profile at `key` toward `destination`,
    /// judged in one snapshot: every live grant is tried, and the first that
    /// admits the read, its delegated bounds included, admits it. A read
    /// only a grant's bounds keep out is withheld, not refused. `reader` is
    /// the read lane of the request's authenticated caller, when one was
    /// built; `selected` is the caller's source set for the freshness check.
    pub fn companion_profile_snapshot_admitted(
        &self,
        principal_ref: &EntityId,
        key: &PsychProfileKey,
        destination: &ReadDestination,
        reader: Option<&ScopedRead<'_>>,
        selected: Option<&[EntityId]>,
    ) -> Result<CompanionProfileAdmission> {
        let now = self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let grant = match self.companion_profile_grant_in(&txn, principal_ref, key, now)? {
            GrantMatch::Admits(grant) => grant,
            GrantMatch::Bounded(grant) => return Ok(CompanionProfileAdmission::Withheld { grant }),
            GrantMatch::None => return Ok(CompanionProfileAdmission::Denied),
        };
        let Some(state) =
            self.psych_profile_sealed_state_in_txn(&txn, &psych_profile_entity_id(key), selected)?
        else {
            return Ok(CompanionProfileAdmission::Withheld { grant });
        };
        if self.companion_profile_withheld_in(&txn, key, &state, destination, reader) {
            return Ok(CompanionProfileAdmission::Withheld { grant });
        }
        Ok(CompanionProfileAdmission::Admitted { grant, state })
    }

    /// The first live grant that admits `principal_ref`'s read at `key`,
    /// else the first whose delegated bounds alone keep the read out. A
    /// deleted grant admits nothing; a malformed live one fails closed.
    fn companion_profile_grant_in(
        &self,
        txn: &heed::RoTxn<'_>,
        principal_ref: &EntityId,
        key: &PsychProfileKey,
        now: u64,
    ) -> Result<GrantMatch> {
        let mut bounded = None;
        // The grants the companion grant index names for this pair, else
        // every grant, in grant id order either way (census L3-28E).
        for entry in crate::access_grant::companion_grant_candidates_in_txn(
            &self.store,
            txn,
            principal_ref,
            &key.person,
        )? {
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
            if !grant.allows_companion_profile_read(
                principal_ref,
                &key.person,
                key.facet.as_ref(),
                now,
            ) {
                continue;
            }
            if grant
                .companion_bounds
                .as_ref()
                .is_none_or(|bounds| bounds.admits_profile_key(key))
            {
                return Ok(GrantMatch::Admits(id));
            }
            bounded.get_or_insert(id);
        }
        Ok(bounded.map_or(GrantMatch::None, GrantMatch::Bounded))
    }

    /// Whether the profile at `key`, as `state` stands, is kept from this
    /// read: by the owner's recipient choice toward `destination`, by
    /// `reader`'s own credential (FIX 11174, 11766), which keeps it out only
    /// on a positive exclusion (a judgement it could not read keeps today's
    /// response), or by the stored row's source audience
    /// ([`Self::companion_profile_audience_withheld_in`]). The snapshot's
    /// recorded sources are judged as
    /// [`COMPANION_PROFILE_WITHHOLDS_MIXED_SOURCES`] says.
    fn companion_profile_withheld_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &PsychProfileKey,
        state: &PsychProfileState,
        destination: &ReadDestination,
        reader: Option<&ScopedRead<'_>>,
    ) -> bool {
        let sources: &[PsychProfileSource] = match state {
            PsychProfileState::Missing => &[],
            _ if !COMPANION_PROFILE_WITHHOLDS_MIXED_SOURCES => &[],
            PsychProfileState::Fresh(profile) | PsychProfileState::Stale { profile, .. } => {
                &profile.sources
            }
        };
        self.companion_profile_withheld_toward_in(txn, key, sources, destination)
            || reader.is_some_and(|reader| {
                reader.companion_profile_excluded_in(txn, key.world, sources)
                    == CompanionProfileSourceJudgement::Excluded
            })
            || self.companion_profile_audience_withheld_in(txn, key, reader)
    }

    /// Whether the stored profile at `key` does not read to `reader`'s
    /// authenticated person under the source audience (REVIEW-9906, FIX-LIST
    /// SOURCE-AUDIENCE-WALK-MISSES-PSYCH-PROFILE-SOURCES): its own binding,
    /// and that of each CLAIM it copies and of what each was learned from,
    /// judged by [`crate::source_audience::readable_with_read_in`], the
    /// conjunct every scoped read's private-thread check meets (owner
    /// MAIL-SHARE = A). A read with no lane, or one that authenticates no
    /// person, reads no bound lineage, as a scoped read does (FIX 2951). A
    /// row gone reads as nothing restricted; a judgement that cannot be read
    /// keeps the profile out.
    fn companion_profile_audience_withheld_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &PsychProfileKey,
        reader: Option<&ScopedRead<'_>>,
    ) -> bool {
        let viewers: Vec<EntityId> = reader
            .and_then(|reader| reader.actor_key().authenticated_person())
            .into_iter()
            .collect();
        let id = psych_profile_entity_id(key);
        let dbs = self.store.read();
        let readable = crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, &id).and_then(
            |raw| match raw {
                Some(raw) => crate::source_audience::readable_with_read_in(
                    self, &dbs, txn, id, &raw, &viewers,
                ),
                None => Ok(true),
            },
        );
        match readable {
            Ok(readable) => !readable,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "a companion profile's source audience could not be read; the profile is \
                     withheld"
                );
                true
            }
        }
    }

    /// Whether the owner's recipient choice keeps the profile at `key` from
    /// `destination`: the world the read names, or the world one of
    /// `sources` lies in. A profile no world or source places stays
    /// readable.
    fn companion_profile_withheld_toward_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &PsychProfileKey,
        sources: &[PsychProfileSource],
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
        sources.iter().any(|source| {
            source
                .world_ref
                .is_some_and(|world| withheld.contains(&world))
        })
    }
}
