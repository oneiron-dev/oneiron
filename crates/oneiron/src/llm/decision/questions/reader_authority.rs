//! FIX 7461: a question's reader keeps its own live authority (owner
//! principle 2). FIX 7440 gave the task validator this shape; every other
//! question read site uses it here.
//!
//! Each permission a question site checks for one reader stays exactly as it
//! was (B) and is tried first, B's error included. Only once B refuses is
//! the reader's own authority (A) resolved, and it only ever adds:
//! - a live owner of the vault reads under the owner's key;
//! - a live agent (an agent definition, or a base agent's MACHINE) whose
//!   standing for "read" holds reads under one live Grant the owner gave it.
//!   Each Grant that names it, confers now, was given by a live owner and
//!   keeps its pact membership is judged alone by its own Scope, never met
//!   with another.
//!
//! Any other reader has no other authority here. No caller location is
//! consulted, nothing is borrowed from another reader and two readers each
//! still stand on their own. The authority is read through a vault handle,
//! or through the `Store` and the posture its vault opened with where a
//! materializing batch holds no `Vault` (outcome arrival); both read the
//! same rule ([`crate::authority::StandingHome`]). A store, fold, clock or
//! decode failure of A is an error, as it was in the task validator.
//!
//! A full scoped read keeps its own lane instead: [`question_lane`] opts a
//! question's locally built reader into the read lane's own owner
//! alternative, after its row admission and its own Grants (FIX 7462).

use std::cell::OnceCell;

use super::arrival;
use crate::authority::StandingHome;
use crate::claim::{ClaimBody, ScopedRead, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::federation::Scope;
use crate::gate::PolicyManifestResolution;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE};
use crate::vault::live_entity_row_in_txn;
use crate::{EntityId, Error, Result, Vault};

/// What one reader may read under beyond its old admission, in one snapshot.
enum OwnAuthority {
    /// Nothing: the reader is no live owner and no standing agent.
    Absent,
    /// The reader is a live owner of the vault.
    Owner,
    /// The reader is a live agent standing for "read": the Scope of each of
    /// its live Grants, each judged alone.
    Grants(Vec<Scope>),
}

/// `actor`'s own authority in `txn`, read through `home`: the owner branch
/// first, then the agent branch.
fn own_authority_in(
    home: StandingHome<'_>,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<OwnAuthority> {
    if is_live_owner_in(home, txn, &actor)? {
        return Ok(OwnAuthority::Owner);
    }
    let class = match live_entity_row_in_txn(home.store(), txn, &actor)?.live_type() {
        Some(ENTITY_TYPE_AGENT_DEF) => EdgeActorClass::Agent,
        Some(ENTITY_TYPE_MACHINE) => EdgeActorClass::System,
        _ => return Ok(OwnAuthority::Absent),
    };
    if crate::authority::principal_standing_in(home, txn, actor, class, "read")?.is_none() {
        return Ok(OwnAuthority::Absent);
    }
    let now = home.instant_secs_in(txn)?;
    let owners = home.owners_in(txn)?;
    let scopes = crate::federation::agent_grants_for_store_in_txn(home.store(), txn)?
        .into_iter()
        .filter(|standing| {
            standing.grant.member_ref == actor
                && standing.grant.confers_at(now)
                && owners.contains(&standing.delegated_by)
                && !standing.pact_standing_lapsed_for_store_in_txn(
                    home.store(),
                    home.posture(),
                    txn,
                )
        })
        .map(|standing| standing.grant.authority_scope)
        .collect();
    Ok(OwnAuthority::Grants(scopes))
}

/// Whether `actor` is one of the vault's live owners, co-owners included
/// (`policy_model::is_live_vault_owner_in_txn`).
fn is_live_owner_in(
    home: StandingHome<'_>,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<bool> {
    match home {
        StandingHome::Vault(vault) => {
            crate::policy_model::is_live_vault_owner_in_txn(vault, txn, actor)
        }
        StandingHome::Store(store, posture) => {
            crate::policy_model::is_live_vault_owner_for_store_in_txn(store, posture, txn, actor)
        }
    }
}

/// `unit` read by `actor` under `own`, the authority it holds of its own:
/// [`arrival::readable`]'s row prerequisites, the CLAIM read judged under the
/// owner's key, or under `key` holding one Grant's Scope.
fn own_readable(
    own: &OwnAuthority,
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    actor: EntityId,
    key: &ScopedReadActorKey,
    unit: &EntityId,
) -> Result<bool> {
    match own {
        OwnAuthority::Absent => Ok(false),
        OwnAuthority::Owner => {
            let owner = ScopedReadActorKey::vault_owner(actor);
            arrival::readable(store, txn, policy, &owner, unit)
        }
        OwnAuthority::Grants(scopes) => arrival::readable_with(store, txn, unit, |body, facets| {
            scopes.iter().any(|scope| {
                crate::gate::scoped_read_claim_allowed_with_scope(
                    policy,
                    key,
                    body,
                    facets,
                    Some(scope),
                )
            })
        }),
    }
}

/// FIX 7440: `unit` read by `actor` under its own authority in this
/// snapshot, tried only once `bare_reader`, its bare key, has been refused.
/// A live owner of the vault reads it under the owner's key. A live agent
/// (an agent definition, or a base agent's MACHINE) reads it under one live
/// Grant the owner gave it: each Grant that names it, confers now and was
/// given by a live owner is judged alone by its own Scope, never met with
/// another. Any other actor, and an agent with no such Grant, has no other
/// authority here. No caller location is consulted.
///
/// # Errors
/// A store, fold, clock or decode failure; never absent or refusing
/// authority.
pub(super) fn own_authority_readable_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    actor: EntityId,
    bare_reader: &ScopedReadActorKey,
    unit: &EntityId,
) -> Result<bool> {
    let own = own_authority_in(StandingHome::Vault(vault), txn, actor)?;
    own_readable(&own, &vault.store, txn, policy, actor, bare_reader, unit)
}

/// One reader of a question's rows in one snapshot: its old key, judged first
/// exactly as before, and the identity whose own authority is resolved, at
/// most once, only after that key refuses. Built for one transaction and
/// asked only in it.
pub(super) struct Reader<'a> {
    home: StandingHome<'a>,
    actor: EntityId,
    key: ScopedReadActorKey,
    own: OnceCell<OwnAuthority>,
}

impl<'a> Reader<'a> {
    /// `actor`, read first under `key`, its old key, exactly as before.
    pub(super) fn new(home: StandingHome<'a>, actor: EntityId, key: ScopedReadActorKey) -> Self {
        Self {
            home,
            actor,
            key,
            own: OnceCell::new(),
        }
    }

    /// `actor` under its bare identity key.
    pub(super) fn bare(home: StandingHome<'a>, actor: EntityId) -> Result<Self> {
        let key = ScopedReadActorKey::new(actor.to_hex())
            .ok_or(Error::InvariantViolation("canonical question reader"))?;
        Ok(Self::new(home, actor, key))
    }

    /// This reader's own authority in `txn`, resolved at its first ask. A
    /// key held to a Scope (a saved question's narrowed lane, OF-506) has
    /// none beside it, as the read lane's own alternatives leave such a key
    /// exactly as it is.
    fn own_in(&self, txn: &heed::RoTxn<'_>) -> Result<&OwnAuthority> {
        if let Some(own) = self.own.get() {
            return Ok(own);
        }
        let own = if self.key.authority_scope().is_some() {
            OwnAuthority::Absent
        } else {
            own_authority_in(self.home, txn, self.actor)?
        };
        Ok(self.own.get_or_init(|| own))
    }

    /// Whether `unit` reads for this reader: [`arrival::readable`] under its
    /// old key, else under its own authority.
    pub(super) fn readable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        unit: &EntityId,
    ) -> Result<bool> {
        let store = self.home.store();
        if arrival::readable(store, txn, policy, &self.key, unit)? {
            return Ok(true);
        }
        own_readable(
            self.own_in(txn)?,
            store,
            txn,
            policy,
            self.actor,
            &self.key,
            unit,
        )
    }

    /// The positive CLAIM gate alone (`gate::scoped_read_claim_allowed`)
    /// for `body` under `facets`: the old key's, else this reader's own. A
    /// caller keeps every row, status and integrity check it makes beside it.
    pub(super) fn claim_allowed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        body: &ClaimBody,
        facets: &[EntityId],
    ) -> Result<bool> {
        Ok(
            crate::gate::scoped_read_claim_allowed(policy, &self.key, body, facets)
                || self.own_claim_allowed_in_txn(txn, policy, body, facets)?,
        )
    }

    /// The positive CLAIM gate under this reader's own authority alone: the
    /// owner's key, or its key holding one live Grant's Scope.
    pub(super) fn own_claim_allowed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        body: &ClaimBody,
        facets: &[EntityId],
    ) -> Result<bool> {
        Ok(match self.own_in(txn)? {
            OwnAuthority::Absent => false,
            OwnAuthority::Owner => {
                let owner = ScopedReadActorKey::vault_owner(self.actor);
                crate::gate::scoped_read_claim_allowed(policy, &owner, body, facets)
            }
            OwnAuthority::Grants(scopes) => scopes.iter().any(|scope| {
                crate::gate::scoped_read_claim_allowed_with_scope(
                    policy,
                    &self.key,
                    body,
                    facets,
                    Some(scope),
                )
            }),
        })
    }

    /// The positive gate of a record at `record`
    /// (`gate::scoped_read_record_allowed`): the old key's, else the owner's
    /// key, else its key holding one live Grant's Scope, never a row's
    /// non-CLAIM shortcut.
    pub(super) fn record_allowed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        record: &Scope,
    ) -> Result<bool> {
        if crate::gate::scoped_read_record_allowed(policy, &self.key, record) {
            return Ok(true);
        }
        Ok(match self.own_in(txn)? {
            OwnAuthority::Absent => false,
            OwnAuthority::Owner => {
                let owner = ScopedReadActorKey::vault_owner(self.actor);
                crate::gate::scoped_read_record_allowed(policy, &owner, record)
            }
            OwnAuthority::Grants(scopes) => scopes.iter().any(|scope| {
                crate::gate::scoped_read_record_allowed_with_scope(
                    policy,
                    &self.key,
                    record,
                    Some(scope),
                )
            }),
        })
    }
}

/// The authority home of a reader that holds `store` and no `Vault` (a
/// materializing batch's outcome arrival, and the windows and calibration
/// reads that judge its labels again): the posture the store opened with,
/// the one its vault reads under.
pub(super) fn store_home(store: &crate::store::Store) -> StandingHome<'_> {
    StandingHome::Store(store, store.privacy_posture)
}

/// A question's own locally built read lane over `key`, the key exactly as
/// its site built it, opted into its reader's own live owner authority
/// (FIX 7461): a row its admission and its reader's own Grants (FIX 7462)
/// refuse is read again, whole, under the reader's owner key while the
/// reader is a live owner. Never for a lane a caller supplied.
pub(crate) fn question_lane(vault: &Vault, key: ScopedReadActorKey) -> ScopedRead<'_> {
    vault.scoped_read(key).with_own_owner_authority()
}
