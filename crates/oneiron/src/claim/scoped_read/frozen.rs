//! OF-506 (FIX 1857): a read lane frozen when work is saved for later, and
//! rebuilt each time that work reads.
//!
//! A saved question, or a queued summary, reads long after the caller that
//! saved it has gone, and no credential travels with it. [`FrozenReadLane`]
//! keeps the SCOPE the saver's live lane read under: its credential's id,
//! read Scope and records caveat, the worlds it asked for and the room whose
//! facets bound it. It never keeps a proof: nothing here deserializes into a
//! `VerifiedSlip`, and a frozen lane authorizes nothing on its own.
//!
//! Each rebuild ([`FrozenReadLane::narrow_in_txn`]) starts from the
//! principal's own live key and only narrows it, so a rebuilt lane is the
//! frozen scope met with live authority: the credential must still be live
//! in the rebuild's snapshot (unexpired, unrevoked, its grant, invitation
//! and delegation standing), the owner exemption is proved again on every
//! read, and the principal's relationship grants are read live. A revocation
//! after the save therefore never widens what the work reads. A lane that
//! read under no narrowing freezes as its principal's own
//! ([`FrozenReadLane::principal`]), which is how every saved read was built
//! before: its principal's live authority alone, owner and Grants included.
//!
//! Sight is never frozen: a door that serves a secret derives it again from
//! the rebuilt lane.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::pipeline::WorldAuthoritySet;

/// [`FrozenReadLane::freeze`]'s refusal of a narrowed guest credential's lane.
const GUEST_LANE_NOT_SAVED: &str = "a narrowed guest credential's read lane is not saved";

/// The scope a read lane read under when its work was saved (OF-506). The
/// engine mints it from the saver's live lane ([`Self::freeze`]) or as the
/// principal's own ([`Self::principal`]); no caller authors one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReadLane {
    /// The id of the credential that narrowed the saved lane. Every rebuild
    /// reads nothing once it is no longer live. `None` on a lane no
    /// credential narrowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<[u8; 32]>,
    /// The read Scope the saved lane was held to, as every read door checks
    /// a credential's; `None` on a lane held to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<Scope>,
    /// The credential's records caveat, as entity ids in hex; empty when it
    /// named none.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    records: BTreeSet<String>,
    /// The worlds the saved lane asked for, as a Scope worlds axis; `None`
    /// when it asked for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worlds: Option<ScopeAxis<ScopeId>>,
    /// The room whose signed facets the saved lane read inside (FIX 643).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    room_facets: Option<EntityId>,
}

impl FrozenReadLane {
    /// The principal's own lane: no narrowing beyond the principal's live
    /// authority. An engine-built record that no caller's lane saved (an
    /// internal one-off ask, a review's dissent question) keeps it, and so
    /// does a full lane.
    #[must_use]
    pub fn principal() -> Self {
        Self::default()
    }

    /// Whether this is the principal's own lane ([`Self::principal`]).
    #[must_use]
    pub fn is_principal(&self) -> bool {
        *self == Self::default()
    }

    /// `lane`, frozen. A lane under no narrowing (the owner's key, a full
    /// credential, an un-narrowed principal key) freezes as the principal's
    /// own. Otherwise the credential's id, read Scope and records caveat,
    /// the asked worlds and the room facets are kept. A channel caveat the
    /// lane did not meet freezes as a Scope that reads nothing, as the live
    /// lane read nothing under it.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for a lane whose bound has no frozen form,
    /// so dropping it would widen the saved read: a room turn, an audience
    /// or peer reads, or a narrowed guest credential, whose grant's current
    /// Scope binds only through its proof.
    pub fn freeze(lane: &ScopedRead<'_>) -> Result<Self> {
        let key = &lane.actor_key;
        if key.room_turn.is_some() || lane.audience.is_some() || !lane.peer_reads.is_empty() {
            return Err(Error::InvalidConfig(
                "a saved read lane carries no room turn, audience or peer read".into(),
            ));
        }
        let claims = key
            .proof
            .as_ref()
            .map(crate::authority::VerifiedSlip::claims);
        let mut records = claims
            .map(|claims| claims.records.clone())
            .unwrap_or_default();
        // A key rebuilt from a frozen lane holds its records caveat as a
        // bound, not in its proof: keep it, met with the proof's caveat. A
        // bound that meets to no row reads nothing.
        let mut bound_reads_nothing = false;
        if let Some(bound) = &key.record_bound {
            records = if records.is_empty() {
                bound.clone()
            } else {
                records.intersection(bound).cloned().collect()
            };
            bound_reads_nothing = records.is_empty();
        }
        let channel_refused = claims.is_some_and(|claims| !lane.credential_channel_allows(claims))
            || bound_reads_nothing;
        let scope_narrows = key.authority_scope().is_some_and(|scope| {
            Scope {
                verbs: ScopeAxis::All,
                ..scope.clone()
            } != Scope::top()
        });
        let worlds = key.worlds.as_ref().map(WorldAuthoritySet::scope_axis);
        if !scope_narrows
            && records.is_empty()
            && !channel_refused
            && worlds.is_none()
            && key.room_facets.is_none()
        {
            return Ok(Self::principal());
        }
        if claims.is_some_and(|claims| claims.grant_ref.is_some()) {
            return Err(Error::InvalidConfig(GUEST_LANE_NOT_SAVED.into()));
        }
        let authority = if channel_refused {
            Scope::default()
        } else {
            key.authority_scope().cloned().unwrap_or_else(Scope::top)
        };
        Ok(Self {
            credential: claims.map(|claims| claims.slip_id),
            authority: Some(authority),
            records,
            worlds,
            room_facets: key.room_facets,
        })
    }

    /// Whether `error` is [`Self::freeze`]'s refusal of a narrowed guest
    /// credential's lane (FIX 12059), which a door that admitted that lane
    /// answers as its own typed record-scope refusal.
    #[must_use]
    pub fn is_guest_lane_refusal(error: &Error) -> bool {
        matches!(error, Error::InvalidConfig(message) if message.as_str() == GUEST_LANE_NOT_SAVED)
    }

    /// `key`, the principal's own live key, narrowed by this frozen lane in
    /// `txn`: held to the frozen Scope, records caveat, worlds and room
    /// facets, each only narrowing. A narrowed lane whose credential is no
    /// longer live in `txn` reads nothing. The principal's own lane returns
    /// `key` unchanged.
    ///
    /// # Errors
    /// A store, fold or clock failure judging the credential.
    pub fn narrow_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        if self.is_principal() {
            return Ok(key);
        }
        if let Some(credential) = &self.credential
            && !vault.capability_slip_id_is_live_in_txn(txn, credential)?
        {
            return ScopedReadActorKey::read_nothing(
                key.actor_ref(),
                key.actor_class().unwrap_or_default(),
            )
            .ok_or(Error::InvariantViolation("frozen read lane actor"));
        }
        let mut key = key.within_authority(self.authority.clone().unwrap_or_else(Scope::top));
        if !self.records.is_empty() {
            key = key.within_records(&self.records);
        }
        if let Some(worlds) = self
            .worlds
            .as_ref()
            .map(WorldAuthoritySet::from_scope_axis)
            .transpose()?
            .flatten()
        {
            key = key.within_worlds(worlds);
        }
        if let Some(room) = self.room_facets {
            key = key.within_room_facets(room);
        }
        Ok(key)
    }

    /// [`Self::narrow_in_txn`] in its own snapshot.
    ///
    /// # Errors
    /// As [`Self::narrow_in_txn`], and a store failure opening the snapshot.
    pub fn narrow(
        &self,
        vault: &crate::Vault,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        let txn = vault.store.env.read_txn()?;
        self.narrow_in_txn(vault, &txn, key)
    }
}

impl ScopedRead<'_> {
    /// This lane, frozen ([`FrozenReadLane::freeze`]).
    ///
    /// # Errors
    /// As [`FrozenReadLane::freeze`].
    pub fn freeze(&self) -> Result<FrozenReadLane> {
        FrozenReadLane::freeze(self)
    }

    /// A frozen lane's records caveat on the row `id`: the rows a rebuilt
    /// key's records bound names, as a credential's records caveat holds
    /// them. A key with no records bound is unbound here.
    pub(super) fn record_bound_allows(&self, id: &EntityId) -> bool {
        self.actor_key
            .record_bound
            .as_ref()
            .is_none_or(|records| records.contains(&id.to_hex()))
    }
}
