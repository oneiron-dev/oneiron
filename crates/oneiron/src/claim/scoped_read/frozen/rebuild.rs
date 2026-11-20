//! [`FrozenReadLane::narrow_in_txn`] and its kin: each rebuild of a frozen
//! lane, which narrows a live key and never widens it (OF-506).

use super::super::ScopedReadActorKey;
use super::super::actor_key::KeyClassOrigin;
use super::{
    FrozenReadLane, NativeGrantGate, NativeOwnerStanding, NativeReadBasis, SavedCredential,
};
use crate::claim::world_access::WorldAuthoritySet;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use oneiron_authority::federation::Scope;

impl FrozenReadLane {
    /// `key`, a caller's own key for the lane's principal, narrowed by this
    /// frozen lane in `txn`: held to the saved key's grant basis and actor
    /// class, the frozen Scope, records caveat, worlds and room facets, each
    /// only narrowing. A key of another class than the saved one has no meet
    /// with the lane and reads nothing, whether a proof or the caller named
    /// its class (FIX SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS; Sol F1 on
    /// #8134). A rebuild over a key built from the principal's row narrows
    /// it with `Self::narrow_row_key_in_txn` instead. A lane whose
    /// credential no longer holds in `txn` (`SavedCredential`) reads
    /// nothing, and the rebuilt key
    /// carries that credential, so each later read judges it again in its
    /// own snapshot. The principal's own lane returns `key` unchanged, and a
    /// lane that reads as its principal's own
    /// ([`Self::reads_as_principal`]) returns it held to its credential
    /// alone, each while its asker is a live owner in `txn`; for any other
    /// asker either returns it under the access gate (FIX
    /// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
    ///
    /// # Errors
    /// A store, fold or clock failure judging the credential or the asker's
    /// owner standing.
    pub fn narrow_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        self.narrow_key_in_txn(vault, txn, key, KeyClassOrigin::Caller)
    }

    /// `key`, built from the principal's row for this rebuild (its class
    /// the row type's, or the class a saved declaration stored for its
    /// actor), narrowed by this frozen lane in `txn` as
    /// [`Self::narrow_in_txn`] narrows a caller's key, except that a key
    /// with no proof reads as the class the lane was saved under: its own
    /// class is the row's, not one any live key was proved as (FIX
    /// SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS).
    ///
    /// # Errors
    /// As [`Self::narrow_in_txn`].
    pub(crate) fn narrow_row_key_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        self.narrow_key_in_txn(vault, txn, key, KeyClassOrigin::PrincipalRow)
    }

    /// [`Self::narrow_in_txn`] or [`Self::narrow_row_key_in_txn`], by
    /// where `key` took its class from.
    fn narrow_key_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        key: ScopedReadActorKey,
        origin: KeyClassOrigin,
    ) -> Result<ScopedReadActorKey> {
        if self.is_principal() {
            return rebuild_without_basis_in(vault, txn, key);
        }
        let saved = self.saved_credential();
        if let Some(credential) = saved
            && !credential.holds_in(vault, txn)?
        {
            return ScopedReadActorKey::read_nothing(
                key.actor_ref(),
                key.actor_class().unwrap_or_default(),
            )
            .ok_or(Error::InvariantViolation("frozen read lane actor"));
        }
        // A key held past this snapshot judges the credential at each read
        // (review R1 of #8029): rebuilt while it held, it reads nothing once
        // it no longer does. A key whose own proof is the credential of a
        // lane that reads as its principal's own already judges it at each
        // use. A narrowed lane's credential binds even a key whose proof
        // shares its id: a transferred credential keeps its mint's id, so
        // the rebuilt key, frozen again, keeps this lane's Scope and basis
        // (blind review P1 on #8061), and a proof of the same slip under
        // other caveats, or none, is not held to a caveat's earlier end
        // (FIX SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY).
        let proof_id = key.proof.as_ref().map(|proof| proof.claims().slip_id);
        let mut key = match saved {
            Some(credential)
                if matches!(credential, SavedCredential::Live { .. })
                    || proof_id != Some(credential.slip_id()) =>
            {
                key.bound_by_saved_credential(credential)
            }
            _ => key,
        };
        if self.reads_as_principal() {
            return rebuild_without_basis_in(vault, txn, key);
        }
        // The principal's own key never lends the rebuild an owner standing
        // the saved key lacked (FIX 14344, Astra F2 on #8029), nor a class it
        // was not proved as: policy rows match on class (FIX
        // SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS).
        if let Some(basis) = &self.native_basis {
            key = key
                .within_saved_actor_class(basis.actor_class.as_deref(), basis.classless, origin)
                .ok_or(Error::InvariantViolation("frozen read lane actor"))?
                .within_native_basis(basis.clone());
        }
        // A lane that keeps a grant basis holds no Scope its live key lacked
        // (Sol F1/F2 on #8065; FIX FROZEN-LANE-FREEZES-ABSENT-AUTHORITY-AS-TOP);
        // a lane saved before the basis was kept reads under top.
        if self.authority.is_some() || self.native_basis.is_none() {
            key = key.within_authority(self.authority.clone().unwrap_or_else(Scope::top));
        }
        if let Some(alternatives) = &self.grant_alternatives {
            key = key.within_grant_alternatives(alternatives);
        }
        // The Grants of the save bind beside those of each snapshot that
        // serves a row: a Grant revoked or lapsed since the save narrows the
        // rebuilt lane (REVIEW-7051 P1). The principal is the credential's
        // holder; a principal no Grant has ever named is not narrowed.
        if (self.credential.is_some() || self.grant_alternatives.is_some())
            && let Ok(holder) = EntityId::from_hex(key.actor_ref())
        {
            key = key.bound_by_live_agent_grants(holder);
        }
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
        if self.home_unnamed {
            key = key.homed_unnamed();
        }
        // A homed reader reads its room's stamped claims only while it
        // stands in the room in this snapshot, as when the lane was saved.
        if let Some(room) = self.room_facets {
            key = key.standing_in_room_in(vault, txn, room)?;
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

    /// [`Self::narrow_row_key_in_txn`] in its own snapshot.
    ///
    /// # Errors
    /// As [`Self::narrow_row_key_in_txn`], and a store failure opening the
    /// snapshot.
    pub(crate) fn narrow_row_key(
        &self,
        vault: &crate::Vault,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        let txn = vault.store.env.read_txn()?;
        self.narrow_row_key_in_txn(vault, &txn, key)
    }
}

/// `key`, its principal's own live key, rebuilt for a lane that keeps no
/// grant basis (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS): unchanged
/// while its actor is a live owner in `txn`
/// (`ScopedReadActorKey::actor_is_live_owner_in`), and otherwise met with
/// the access gate on the grants of the key's own principal, with no owner
/// standing. Such a lane does not say which gate its key read under: it was
/// saved before the basis was kept, or by an engine path that froze no live
/// lane (a question created or edited with no lane, an internal one-off
/// ask, a review's dissent question), so it fails closed. An access grant
/// on a row's conversation still admits that row.
///
/// # Errors
/// A store failure reading the owner binding or the live-owner census.
fn rebuild_without_basis_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    key: ScopedReadActorKey,
) -> Result<ScopedReadActorKey> {
    if key.actor_is_live_owner_in(vault, txn)? {
        return Ok(key);
    }
    let grant_principal = key.principal_ref;
    // No class was saved: the key keeps its own.
    let actor_class = key.actor_class().map(str::to_owned);
    Ok(key.within_native_basis(NativeReadBasis {
        owner_standing: NativeOwnerStanding::Absent,
        grant_gate: NativeGrantGate::Access,
        grant_principal,
        actor_class,
        classless: false,
    }))
}
