//! Who pays for a booking a person makes after their owner sign-in went
//! stale (FIX 5327, Engine ruling (a) 10-20): the person, as themselves,
//! while a live grant here names them as a member or a guest; else the
//! page's publisher, as for an anonymous visitor.
//!
//! This is payer evidence and nothing more. It answers only a grant id or
//! whether that one grant still stands: never an owner proof, a read key or
//! a view of anything. Whoever books still sees only what the public sees.
//!
//! One read snapshot, one scan of this vault's FEDERATION_GRANT rows, and one
//! row predicate shared by the scan and the keyed recheck, so the grant that
//! made someone the payer is judged again by itself before a model call
//! spends, never by a second scan. No index, no cache, no migration.

use super::membership_gate::FIRST_PARTY_MEMBER_ROLES;
use super::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::authority::AuthorityFold;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Which eligible grant names the payer when one person holds several.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BookingPayerGrantSelection {
    /// Every grant row is read once and the eligible one with the lowest id
    /// is kept. Grants never combine, and every eligible grant gives the
    /// same payer and the same public view, so the choice only fixes which
    /// one is rechecked before a spend.
    LowestEligibleId,
}

/// The selection this vault makes (CALLS "FIX 5327 grant selection").
pub(crate) const BOOKING_PAYER_GRANT_SELECTION: BookingPayerGrantSelection =
    BookingPayerGrantSelection::LowestEligibleId;

/// Grace past a grant's expiry, in seconds, before it stops making its
/// member the payer. None: the expiry second itself denies, as
/// [`FederationGrant::confers_at`] says.
pub(crate) const BOOKING_PAYER_EXPIRY_SKEW_SECS: u64 = 0;

/// What a lookup that could not decide comes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BookingPayerLookupFailure {
    /// No grant: the page's publisher pays and the caller sees the public
    /// view. Uncertainty about the person, a grant row, the authority fold
    /// or a withdrawal never charges that person.
    PublisherPublic,
}

/// The fallback this vault takes (CALLS "FIX 5327 lookup failure").
pub(crate) const BOOKING_PAYER_LOOKUP_FAILURE: BookingPayerLookupFailure =
    BookingPayerLookupFailure::PublisherPublic;

impl Vault {
    /// The grant that makes `person` the payer of a booking they make here
    /// after their owner sign-in went stale, or `None`: the lowest-id live,
    /// unwithdrawn member or guest grant naming them that confers now and
    /// whose purpose stands on this vault (`payer_purpose_stands`). One
    /// snapshot and one scan of the grant rows. `person` is proved again in
    /// that snapshot as a live person, never as an owner. A lookup that
    /// cannot decide answers `None` (`BOOKING_PAYER_LOOKUP_FAILURE`).
    ///
    /// # Errors
    ///
    /// Only when the vault cannot open a read.
    pub fn booking_payer_grant(&self, person: &AuthenticatedOwner) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(decided(self.booking_payer_grant_in_txn(&txn, person)))
    }

    /// Whether `grant`, the one [`Self::booking_payer_grant`] chose, still
    /// makes `person` the payer now: the same row predicate, on that one row,
    /// in one snapshot, with no scan for another. A lookup that cannot decide
    /// answers `false` (`BOOKING_PAYER_LOOKUP_FAILURE`).
    ///
    /// # Errors
    ///
    /// Only when the vault cannot open a read.
    pub fn booking_payer_grant_stands(
        &self,
        person: &AuthenticatedOwner,
        grant: EntityId,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(decided(
            self.booking_payer_grant_stands_in_txn(&txn, person, grant),
        ))
    }

    fn booking_payer_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: &AuthenticatedOwner,
    ) -> Result<Option<EntityId>> {
        let Some(context) = self.payer_context_in_txn(txn, person)? else {
            return Ok(None);
        };
        let mut chosen: Option<EntityId> = None;
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = entry?;
            if !self.payer_row_stands_in_txn(txn, &context, id)? {
                continue;
            }
            chosen = Some(match (BOOKING_PAYER_GRANT_SELECTION, chosen) {
                (BookingPayerGrantSelection::LowestEligibleId, Some(kept)) => kept.min(id),
                (BookingPayerGrantSelection::LowestEligibleId, None) => id,
            });
        }
        Ok(chosen)
    }

    fn booking_payer_grant_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: &AuthenticatedOwner,
        grant: EntityId,
    ) -> Result<bool> {
        match self.payer_context_in_txn(txn, person)? {
            Some(context) => self.payer_row_stands_in_txn(txn, &context, grant),
            None => Ok(false),
        }
    }

    /// What every row is judged against, in the caller's snapshot: the
    /// person, proved again as a live person; the authority fold; this
    /// shared vault's id, if it is one; and the vault's recorded clock.
    /// `None`: a deleted shared vault, where no grant stands.
    fn payer_context_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: &AuthenticatedOwner,
    ) -> Result<Option<PayerContext>> {
        let person = person.revalidate_person_in_txn(self, txn)?;
        if self.shared_vault_deletion_in_txn(txn)?.is_some() {
            return Ok(None);
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(undecided());
        }
        Ok(Some(PayerContext {
            person,
            fold,
            shared_vault: self
                .shared_vault_creation_in_txn(txn)?
                .map(|creation| creation.vault_id),
            now: self.store.clock.now_recorded_at(),
        }))
    }

    /// The one row predicate: `id` is a live FEDERATION_GRANT row, not
    /// withdrawn, naming the person, conferring now, whose purpose stands
    /// here and whose pact lets it confer. An own-device residence grant
    /// and an owner's grant to a named agent are no human's standing.
    fn payer_row_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        context: &PayerContext,
        id: EntityId,
    ) -> Result<bool> {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(false);
        };
        if entity_type != ENTITY_TYPE_FEDERATION_GRANT {
            return Err(undecided());
        }
        if body.is_empty() {
            return Ok(false);
        }
        let grant = decode_federation_grant_body(&body)?;
        if grant.member_ref != context.person
            || grant.owner_agent
            || super::is_own_device_grant(&grant)
            || !confers_for_payer(&grant, context.now)
            || !payer_purpose_stands(&grant, context.shared_vault)
            || !super::pact_admits_grant(&context.fold, &id, &grant)
        {
            return Ok(false);
        }
        Ok(!self.guest_grant_withdrawn_in_txn(txn, &id)?)
    }
}

/// [`Vault::payer_context_in_txn`]'s answer.
struct PayerContext {
    person: EntityId,
    fold: AuthorityFold,
    shared_vault: Option<u64>,
    now: u64,
}

/// A grant confers for a payer as it confers for a read
/// ([`FederationGrant::confers_at`]: the read verb, unexpired, no bottom
/// world, band, audience or sensitivity), with no bottom facet either, at
/// the vault's recorded `now` less [`BOOKING_PAYER_EXPIRY_SKEW_SECS`].
fn confers_for_payer(grant: &FederationGrant, now: u64) -> bool {
    !grant.authority_scope.facets.is_bottom()
        && grant.confers_at(now.saturating_sub(BOOKING_PAYER_EXPIRY_SKEW_SECS))
}

/// The purposes whose grant makes its member the payer (CALLS "FIX 5327
/// payer purposes"): the standing purposes, as they already stand. A member
/// grant (Owner, Admin, Member, Viewer or Delegate) of this shared vault, by
/// its nonzero id; an Ask guest's grant, with its guest payload, on a shared
/// vault; a Connect guest's grant, on a shared or a personal vault. No grant
/// verb names booking, and none is needed: standing to pay is not a view.
fn payer_purpose_stands(grant: &FederationGrant, shared_vault: Option<u64>) -> bool {
    match grant.scope {
        FederationGrantScope::Vault { vault_id } => {
            vault_id != 0
                && shared_vault == Some(vault_id)
                && FIRST_PARTY_MEMBER_ROLES.contains(&grant.role)
        }
        FederationGrantScope::Ask { .. } => {
            grant.role.is_guest() && grant.guest.is_some() && shared_vault.is_some()
        }
        FederationGrantScope::Connect { .. } => grant.role.is_guest(),
    }
}

/// A lookup's answer under [`BOOKING_PAYER_LOOKUP_FAILURE`]: what it found,
/// or no grant when it could not decide.
fn decided<T: Default>(found: Result<T>) -> T {
    match (found, BOOKING_PAYER_LOOKUP_FAILURE) {
        (Ok(found), _) => found,
        (Err(_), BookingPayerLookupFailure::PublisherPublic) => T::default(),
    }
}

/// A grant row the type index holds that is not one, or a conflicted
/// authority root: this lookup cannot decide.
fn undecided() -> crate::error::Error {
    crate::error::Error::Claim(crate::error::ClaimError::ActorLacksClaimAuthority {
        reason: "the booking payer's grants could not be read",
    })
}
