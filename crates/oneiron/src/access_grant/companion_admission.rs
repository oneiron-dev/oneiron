//! The companion grant writer that carries its issuer's bounds (FIX 8140).
//!
//! A credential that may write companion grants grants no more than it
//! reads: the grant's whole reach (every world, its facet, the profile kind,
//! audience and sensitivity) must lie inside the issuing slip's effective
//! ceiling, and a slip bound to named records or channels, spent on one act,
//! handed on or bound to a pact makes no reusable grant
//! ([`super::delegation`]). A request inside that ceiling lands as an active
//! grant that carries the issuer's ceiling; one past it is kept whole, as a
//! pending access request the owner answers, never trimmed to fit. The
//! issuing slip is judged again, and the decision and the write made, in one
//! write transaction. Every live owner of the vault, co-Owners included, is
//! bound by no ceiling, and a check that cannot be read leaves the write as
//! it was before this door.

use crate::authority::VerifiedSlip;
use crate::error::{Error, GateError, RecordError, Result};
use crate::federation::Scope;
use crate::psych_profile::PsychProfileKey;
use crate::{EntityId, Vault};

use super::codec::{encode_access_grant_body, invalid_grant};
use super::delegation::{companion_profile_position, whole_companion_bounds};
use super::{AccessGrant, AccessRequest};

/// Policy hook (CALLS "OF-8140 companion grant excess", open): a requested
/// companion grant past its issuer's bounds is filed whole as a pending
/// access request for the owner. False would refuse it instead.
pub const COMPANION_GRANT_EXCESS_PENDS: bool = true;

/// The bounds a delegated companion grant carries: the slip that issued or
/// approved it, and that slip's whole effective record ceiling (worlds,
/// facets, kind bands, audience, sensitivity; verbs are not compared).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompanionGrantBounds {
    /// The delegating slip's id, lower hex.
    pub issuer_slip: String,
    /// The delegating slip's effective record ceiling.
    pub ceiling: Scope,
}

impl CompanionGrantBounds {
    /// Whether a profile read at `key` lies inside these bounds: its world
    /// (every world for the world-free profile), its facet (every facet for
    /// the unfaceted one), the profile kind, the default project and the
    /// profile's sensitivity all inside the ceiling.
    #[must_use]
    pub fn admits_profile_key(&self, key: &PsychProfileKey) -> bool {
        companion_profile_position(key.world, key.facet).is_narrowing_of(&self.ceiling)
    }
}

/// Who issues a companion grant, as the request's credential shows it.
#[derive(Clone, Copy)]
pub enum CompanionGrantIssuer<'a> {
    /// A credential that carries no record bounds: the owner's own secret,
    /// a self-hosted root or the dev mode acting as the owner, a managed
    /// vault's attested owner.
    Unbounded,
    /// A verified capability slip; its bounds are the grant's ceiling.
    Slip(&'a VerifiedSlip),
}

/// What a companion grant write came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionGrantOutcome {
    /// The grant stands, active, carrying its issuer's bounds.
    Active(AccessGrant),
    /// The grant asked past its issuer's bounds; the request waits, whole,
    /// for the owner. It grants nothing until he approves it.
    Pending(AccessRequest),
}

impl Vault {
    /// Creates the companion grant `grant` at `id` as `issuer` may make it,
    /// or files it whole as a pending request when it reaches past the
    /// issuer's bounds (FIX 8140). The bounds are read, and the grant or
    /// request written, in one write transaction. An id held by an entity
    /// or a request is `AccessGrantAlreadyExists`, as
    /// [`Self::create_access_grant`] answers.
    pub fn create_companion_access_grant_admitted(
        &self,
        id: &EntityId,
        grant: &AccessGrant,
        issuer: CompanionGrantIssuer<'_>,
    ) -> Result<CompanionGrantOutcome> {
        if grant.scope.companion_profile_refs().is_none() {
            return Err(invalid_grant());
        }
        grant.validate()?;
        let mut wtxn = self.store.env.write_txn()?;
        // The issuing slip still holds in this writer: one revoked, expired
        // or of another vault since it was verified grants and asks nothing.
        if let CompanionGrantIssuer::Slip(slip) = issuer
            && matches!(self.capability_slip_is_live_in_txn(&wtxn, slip), Ok(false))
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "the issuing credential no longer holds",
            )));
        }
        self.check_companion_profile_target(&wtxn, grant)?;
        // A request already filed at this id is a collision; the request
        // keyspace failing to read keeps the create as it was before it.
        let requested = self
            .access_request_exists_in(&wtxn, id)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, id = %id.to_hex(), "access request collision lookup failed");
                false
            });
        if crate::ports::EntityStoreRead::port_entity_present(&self.store, &wtxn, id)? || requested
        {
            return Err(Error::Record(RecordError::AccessGrantAlreadyExists));
        }
        let bounds = match issuer {
            CompanionGrantIssuer::Unbounded => Some(None),
            CompanionGrantIssuer::Slip(slip) => self.slip_grant_bounds_in(&wtxn, slip, grant),
        };
        let outcome = match bounds {
            Some(companion_bounds) => {
                let granted = AccessGrant {
                    companion_bounds,
                    ..grant.clone()
                };
                let data = encode_access_grant_body(&granted)?;
                crate::share::check_generic_grant_write(self, &wtxn, id, &granted)?;
                self.apply_access_grant_body(&mut wtxn, id, granted.created_at, data)?;
                CompanionGrantOutcome::Active(granted)
            }
            None if COMPANION_GRANT_EXCESS_PENDS => CompanionGrantOutcome::Pending(
                self.insert_access_request_in(&mut wtxn, *id, grant.clone(), None)?,
            ),
            None => {
                return Err(Error::Record(RecordError::InvalidAccessGrantBody(
                    "the grant reaches past its issuer's bounds",
                )));
            }
        };
        wtxn.commit()?;
        Ok(outcome)
    }

    /// The bounds `slip` lets `grant` carry, read in `txn`: `Some(None)`
    /// for an owner of the vault or the owner's own unattenuated credential,
    /// `Some(bounds)` for a grant inside the slip's ceiling, `None` for one
    /// past it. An owner check that cannot be read keeps the grant as the
    /// writer made it before this door.
    fn slip_grant_bounds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        slip: &VerifiedSlip,
        grant: &AccessGrant,
    ) -> Option<Option<CompanionGrantBounds>> {
        if slip.is_full_vault_owner_grade() {
            return Some(None);
        }
        let holder = EntityId::from_hex(&slip.claims().holder_ref)
            .ok()
            .filter(|_| !slip.is_transferred());
        if let Some(holder) = holder {
            match crate::policy_model::is_live_vault_owner_in_txn(self, txn, &holder) {
                Ok(false) => {}
                Ok(true) | Err(_) => return Some(None),
            }
        }
        whole_companion_bounds(slip, grant).map(Some)
    }
}
