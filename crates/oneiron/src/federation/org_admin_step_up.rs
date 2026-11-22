//! An org Admin's act stands on a current MFA step-up (L7-17 PR 2). Canon
//! (identity.md #pqc-1-mfa, MFA-1 A, 2026-10-09): "Org admins must use MFA,
//! because any one admin can act alone". Engine rulings
//! L7-17-ORG-ADMIN-MFA = A (14 Nov 03:02: the weave Admin's step-up, bound
//! to the session slip) and L7-17-ORG-ADMIN-ACTS = A (14 Nov 18:29).
//!
//! Each named Admin power ([`OrgAdminPower`]) and the delegate mint check,
//! in the acting writer, that the request asking for the act shows a
//! step-up that still stands:
//! - the slip the request came on (a person's proof carries it, a served
//!   handle presents it): the step-up recorded on that exact slip, for the
//!   acting person, with a factor still enrolled
//!   ([`Vault::person_stepped_up_on_in_txn`]), so one step-up serves one
//!   session;
//! - or, for a managed person who holds no slip, the supervisor's signed
//!   `mfa_verified` claim on that one person action
//!   ([`Vault::bind_managed_mfa_verified`]). The engine never assumes the
//!   control plane did MFA: a managed Admin's act without the claim is
//!   refused.
//!
//! An act a live Owner grant admits needs none: the Owner is exempt, judged
//! over every grant the writer holds ([`Vault::owner_grant_admits_in_txn`]).
//! MFA is a person's: an agent definition's or a machine's Admin grant stands
//! alone, as the house mind's role does (HOUSE-BIND = A, the owner 10 Nov
//! 07:43: the gate judges the house "by that role and by nothing else"). The
//! writer's stored kind decides, never the class it asserts: a PERSON row
//! steps up whatever class its slip declares. Every other
//! admitted act with no standing step-up is refused
//! [`ORG_ADMIN_STEP_UP_REQUIRED`]. An invitation's accept keeps its
//! inviter's standing check alone: the step-up binds at the invitation's
//! creation, the inviter's own AddMember act.

use super::{OrgAdminPower, SharedVaultWrite};
use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;

/// An org Admin's act refused because its request shows no standing MFA
/// step-up.
pub const ORG_ADMIN_STEP_UP_REQUIRED: &str = "org_admin_step_up_required: an org Admin's act \
     needs a current MFA step-up on this request's own credential; step up, then try again";

/// What the request asking for an org Admin's act shows of its MFA step-up.
#[derive(Clone, Debug)]
pub(crate) enum OrgAdminStepUp {
    /// The slip the request came on: the step-up recorded on it counts.
    Slip(Box<VerifiedSlip>),
    /// A managed person action its supervisor signed `mfa_verified`.
    SupervisorVerified,
    /// No instrument a step-up could stand on.
    Absent,
}

/// The writer of an org Admin's act, with the MFA step-up its request
/// shows. A plain [`WriteActor`] converts to a writer that shows none: an
/// act a live Owner grant admits still lands, and an Admin's is refused
/// [`ORG_ADMIN_STEP_UP_REQUIRED`].
#[derive(Clone, Debug)]
pub struct OrgAdminWriter {
    actor: WriteActor,
    step_up: OrgAdminStepUp,
}

impl OrgAdminWriter {
    /// `actor`, whose request came on `request`: the step-up recorded on
    /// that slip counts while its holder is `actor`.
    #[must_use]
    pub fn on_slip(actor: WriteActor, request: &VerifiedSlip) -> Self {
        Self::showing(actor, OrgAdminStepUp::Slip(Box::new(request.clone())))
    }

    /// `actor`, showing the step-up `proof`'s request shows: the slip the
    /// proof carries, or its managed supervisor's `mfa_verified` claim.
    #[must_use]
    pub fn of_proof(actor: WriteActor, proof: &AuthenticatedOwner) -> Self {
        Self::showing(actor, proof.org_admin_step_up())
    }

    /// `actor`, showing `step_up`.
    pub(crate) fn showing(actor: WriteActor, step_up: OrgAdminStepUp) -> Self {
        Self { actor, step_up }
    }

    /// The acting writer.
    #[must_use]
    pub const fn actor(&self) -> &WriteActor {
        &self.actor
    }
}

impl From<WriteActor> for OrgAdminWriter {
    fn from(actor: WriteActor) -> Self {
        Self {
            actor,
            step_up: OrgAdminStepUp::Absent,
        }
    }
}

impl From<&WriteActor> for OrgAdminWriter {
    fn from(actor: &WriteActor) -> Self {
        Self::from(*actor)
    }
}

impl From<&OrgAdminWriter> for OrgAdminWriter {
    fn from(writer: &OrgAdminWriter) -> Self {
        writer.clone()
    }
}

impl Vault {
    /// `writer` may use `power` over shared vault `vault_id`, judged in
    /// `txn`: the gate admits the act
    /// ([`Self::authorize_shared_vault_write_in_txn`]), and a live Owner
    /// grant admits it, or the writer is stored as an agent definition or a
    /// machine, or the request's step-up stands ([`Self::require_org_admin_step_up_in_txn`]).
    ///
    /// # Errors
    /// The gate's refusal; `AuthorityRefused(ORG_ADMIN_STEP_UP_REQUIRED)`;
    /// a storage fault as itself.
    pub(crate) fn authorize_org_admin_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        writer: &OrgAdminWriter,
        power: OrgAdminPower,
    ) -> Result<()> {
        let requested = SharedVaultWrite::Admin(power);
        self.authorize_shared_vault_write_in_txn(txn, vault_id, &writer.actor, &requested)?;
        // The stored kind, not the asserted class: a person may declare any
        // class on a slip, and a PERSON row may be a person or an agent.
        let factorless = matches!(
            self.get_entity_type_in_txn(txn, &writer.actor.entity_ref())?,
            Some(crate::registry::ENTITY_TYPE_AGENT_DEF | crate::registry::ENTITY_TYPE_MACHINE)
        );
        if factorless || self.owner_grant_admits_in_txn(txn, vault_id, &writer.actor, &requested)? {
            return Ok(());
        }
        self.require_org_admin_step_up_in_txn(txn, writer.actor.entity_ref(), &writer.step_up)
    }

    /// `person`'s request shows a step-up that stands in `txn`: the one
    /// recorded on the slip it came on, or a managed supervisor's
    /// `mfa_verified` claim on that one action.
    ///
    /// # Errors
    /// `AuthorityRefused(ORG_ADMIN_STEP_UP_REQUIRED)` when none stands; a
    /// storage fault as itself.
    pub(crate) fn require_org_admin_step_up_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        step_up: &OrgAdminStepUp,
    ) -> Result<()> {
        let stands = match step_up {
            OrgAdminStepUp::Slip(request) => {
                self.person_stepped_up_on_in_txn(txn, request, person)?
            }
            OrgAdminStepUp::SupervisorVerified => true,
            OrgAdminStepUp::Absent => false,
        };
        if stands {
            Ok(())
        } else {
            Err(crate::authority::authority_refused(
                ORG_ADMIN_STEP_UP_REQUIRED,
            ))
        }
    }
}
