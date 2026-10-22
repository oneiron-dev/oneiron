//! OF-499 A3: a real, current Admin proof for the weave, behind an MFA
//! step-up witness.
//!
//! An [`AuthenticatedWeaveAdmin`] is one live person's request instrument
//! (a verified capability slip) bound to ONE exact live Admin membership
//! grant over this shared vault, and to the [`AdminStepUp`] witness that
//! person's step-up left. Canon: an Admin cannot skip MFA, because any one
//! admin can act alone (ARCH-0043, MFA-1 A, 2026-10-09). Only real step-up
//! ingress may mint the witness, and none exists yet: the witness has no
//! public constructor, so no served route can present an Admin proof until
//! that ingress lands (FIX-LIST `[→L13]`).
//!
//! The proof only ADDS a path. A Person, Owner or Agent read never asks for
//! it, and a live vault Owner, co-Owners included, never needs it: an
//! Owner reads as the Owner. `FederationGrantRole::is_admin` (which an Owner
//! also passes), a room role, an organization power and the operator root
//! prove nothing here. Every read under the proof revalidates it in its own
//! transaction ([`AuthenticatedWeaveAdmin::revalidate_in_txn`]); a proof
//! that no longer holds refuses that Admin request alone, typed
//! [`WEAVE_ADMIN_NOT_CURRENT`].

use std::path::PathBuf;

use super::{VerifiedSlip, authority_refusal_as, authority_refused};
use crate::error::Result;
use crate::federation::{
    FederationGrantRole, FederationGrantScope, MembershipStanding, Scope,
    decode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The typed reason an Admin weave request names when its proof is not
/// current (CALLS `OF-499 A3 not current`): a missing, revoked, demoted,
/// withdrawn, expired or wrong-vault membership, a credential no longer
/// live, or a step-up witness that is not this holder's. Its code leads the
/// text.
pub const WEAVE_ADMIN_NOT_CURRENT: &str = "weave_admin_not_current: weave admin membership or \
     credential is no longer current";

/// Whether an Admin weave proof needs a step-up witness (CALLS `OF-499 A3
/// MFA required`): always, by canon (ARCH-0043 :51, :213).
pub const WEAVE_ADMIN_MFA_REQUIRED: bool = true;
const _: () = assert!(WEAVE_ADMIN_MFA_REQUIRED);

/// The one membership role that makes a weave Admin (CALLS `OF-499 A3 admin
/// role`): exactly Admin on the named grant, never Owner through
/// `is_admin`, never a room role or an organization power.
const WEAVE_ADMIN_ROLE: FederationGrantRole = FederationGrantRole::Admin;

/// The verb the Admin's met grant and credential Scope must carry to read.
const WEAVE_ADMIN_READ_VERB: &str = "read";

/// The witness one person's MFA step-up leaves: whose step-up, over which
/// request instrument, and when. Opaque: no caller JSON, flag or field
/// builds one. The only constructor is the crate-internal seam
/// [`AdminStepUp::after_step_up`], which real step-up ingress fills once it
/// exists (FIX-LIST `[→L13]`); until then nothing mints one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminStepUp {
    holder: EntityId,
    slip_id: [u8; 32],
    stepped_up_at: u64,
}

impl AdminStepUp {
    /// The witness for `holder`'s completed step-up over `request` at
    /// `stepped_up_at`. Only the ingress that verified the step-up itself
    /// may call this; it never takes a caller's word that a step-up
    /// happened.
    #[allow(
        dead_code,
        reason = "L13's MFA step-up ingress is its first caller; none mints a witness yet"
    )]
    pub(crate) fn after_step_up(
        holder: EntityId,
        request: &VerifiedSlip,
        stepped_up_at: u64,
    ) -> Self {
        Self {
            holder,
            slip_id: request.claims().slip_id,
            stepped_up_at,
        }
    }

    /// Whether this witness is `holder`'s over exactly `request`.
    fn binds(&self, holder: EntityId, request: &VerifiedSlip) -> bool {
        self.holder == holder && self.slip_id == request.claims().slip_id
    }
}

/// One person's current Admin standing for the weave in this vault: the
/// vault and its open, the verified request instrument, the person, the one
/// Admin membership grant and the step-up witness. Private fields and no
/// from-parts constructor; never converted to or from an Owner proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedWeaveAdmin {
    vault_path: PathBuf,
    vault_open: [u8; 16],
    request: Box<VerifiedSlip>,
    actor: EntityId,
    membership_grant: EntityId,
    mfa: AdminStepUp,
}

impl Vault {
    /// [`Self::authenticate_weave_admin_in_txn`] in its own read
    /// transaction. Each read under the proof still revalidates it in its
    /// own.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold; a storage fault as itself.
    pub fn authenticate_weave_admin(
        &self,
        request: &VerifiedSlip,
        membership_grant: EntityId,
        mfa: &AdminStepUp,
    ) -> Result<AuthenticatedWeaveAdmin> {
        let txn = self.store.env.read_txn()?;
        self.authenticate_weave_admin_in_txn(&txn, request, membership_grant, mfa)
    }

    /// The Admin weave proof for the holder of `request` under the Admin
    /// membership grant `membership_grant`, with the step-up witness `mfa`,
    /// judged in `txn` ([`AuthenticatedWeaveAdmin::revalidate_in_txn`]).
    /// The person is the slip's holder; a slip handed to another key, a
    /// support, guest or invitee slip, or a holder who is not the grant's
    /// member proves no one here.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold; a storage fault as itself.
    pub fn authenticate_weave_admin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &VerifiedSlip,
        membership_grant: EntityId,
        mfa: &AdminStepUp,
    ) -> Result<AuthenticatedWeaveAdmin> {
        let actor = EntityId::from_hex(&request.claims().holder_ref)
            .map_err(|_| authority_refused(WEAVE_ADMIN_NOT_CURRENT))?;
        let proof = AuthenticatedWeaveAdmin {
            vault_path: self.store.env.path().to_path_buf(),
            vault_open: self.store.open_nonce,
            request: Box::new(request.clone()),
            actor,
            membership_grant,
            mfa: mfa.clone(),
        };
        proof.revalidate_in_txn(self, txn)?;
        Ok(proof)
    }
}

#[allow(
    dead_code,
    reason = "L07-A's Admin weave readers (OF-499 A3) are their first callers"
)]
impl AuthenticatedWeaveAdmin {
    /// The person this proof stands for. Never a proof by itself: a door
    /// revalidates first.
    pub(crate) fn actor(&self) -> EntityId {
        self.actor
    }

    /// The one Admin membership grant this proof stands on.
    pub(crate) fn membership_grant(&self) -> EntityId {
        self.membership_grant
    }

    /// Whether this proof still holds in `txn`: the same vault open, the
    /// step-up witness this holder's over this request, the request still a
    /// live capability of this vault held by its own holder, the person a
    /// live PERSON, the vault shared and not deleted, the grant exactly a
    /// live Admin membership of that person over this vault (unexpired, its
    /// pact standing, the root not conflicted), not withdrawn, and reading
    /// under the grant's Scope met with the request's. Run on every read,
    /// correction and pre-model render; never cached from authentication.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when any part does not
    /// hold; a storage fault as itself, refusing this Admin request alone.
    pub(crate) fn revalidate_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.read_scope_in_txn(vault, txn).map(drop)
    }

    /// [`Self::revalidate_in_txn`], answering the Scope the Admin reads
    /// within: the membership grant's Scope met with the request's. A
    /// vault-global shape inside it, never the Owner's.
    ///
    /// # Errors
    /// As [`Self::revalidate_in_txn`].
    pub(crate) fn read_scope_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Scope> {
        let not_current = || authority_refused(WEAVE_ADMIN_NOT_CURRENT);
        let checked = authority_refusal_as(WEAVE_ADMIN_NOT_CURRENT);
        let request = &*self.request;
        let claims = request.claims();
        if self.vault_path.as_path() != vault.store.env.path()
            || self.vault_open != vault.store.open_nonce
            || !self.mfa.binds(self.actor, request)
            || request.is_transferred()
            || claims.holder_ref != self.actor.to_hex()
            || claims.delegation.is_some()
            || claims.grant_ref.is_some()
            || claims.invitation_ref.is_some()
        {
            return Err(not_current());
        }
        if !vault
            .capability_slip_is_live_in_txn(txn, request)
            .map_err(&checked)?
            || !crate::consent::person_is_live_in_txn(vault, txn, &self.actor).map_err(&checked)?
        {
            return Err(not_current());
        }
        let Some(shared) = vault.shared_vault_creation_in_txn(txn).map_err(&checked)? else {
            return Err(not_current());
        };
        let scope = FederationGrantScope::vault(shared.vault_id);
        match vault
            .authenticated_grant_membership_in_txn(txn, scope, self.actor, self.membership_grant)
            .map_err(&checked)?
        {
            Some(MembershipStanding::Member { grant, role })
                if grant == self.membership_grant && role == WEAVE_ADMIN_ROLE => {}
            _ => return Err(not_current()),
        }
        if vault
            .guest_grant_withdrawn_in_txn(txn, &self.membership_grant)
            .map_err(&checked)?
        {
            return Err(not_current());
        }
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &self.membership_grant).map_err(&checked)?
        else {
            return Err(not_current());
        };
        let grant = decode_federation_grant_body(&body).map_err(&checked)?;
        let now = vault.instant_in_txn(txn).map_err(&checked)?.secs();
        let read = grant.authority_scope.meet(&claims.scope);
        if grant.member_ref != self.actor
            || grant.role != WEAVE_ADMIN_ROLE
            || !grant.confers_at(now)
            || !read.verbs.contains(&WEAVE_ADMIN_READ_VERB.to_owned())
            || read.worlds.is_bottom()
            || read.bands.is_bottom()
            || read.audience.is_bottom()
        {
            return Err(not_current());
        }
        Ok(read)
    }

    /// When the step-up behind this proof happened.
    pub(crate) fn stepped_up_at(&self) -> u64 {
        self.mfa.stepped_up_at
    }
}
