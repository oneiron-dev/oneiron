//! FIX 6108: work a holder's request queued keeps the slip that request was
//! admitted on, and stops once that slip no longer stands (FIX 5952). The
//! holder may rebind the work to a live slip of theirs, explicitly, at the
//! door of that kind of work. Nothing rebinds on its own, and work no one
//! rebinds stays stopped (CALLS "FIX 6108 retained-work rebind proof").
//!
//! As a renewal ([`Vault::renew_owner_device_slip`]) keeps a credential in
//! its lineage, a rebind keeps the work's: the work records the slip it
//! stood on before, and the door answers both. The proof, judged in the
//! writer that swaps the binding:
//! - the work's slip no longer stands, yet still proves the request it was
//!   admitted on: its logged mint and every signature;
//! - the successor stands in this snapshot, every check a queued request's
//!   slip meets included ([`Vault::capability_slip_is_live_in_txn`]);
//! - [`holder_continues`]: owner work rebinds only to a live slip of the
//!   same owner EntityId, and a member's or guest's work only to one whose
//!   holder and class are the work's;
//! - [`keeps_grant`]: the successor names the Grant the work's slip named,
//!   or neither names one, so every read the work makes stays clamped by the
//!   same Grant and pact;
//! - [`keeps_bounds`]: the successor never widens the work. Its effective
//!   scope, records, channels, comm reach, pact and delegation sit within
//!   what the work's slip and its caveats signed.
//!
//! The normal standing checks then run on the successor whenever the work's
//! standing is judged, as they ran on the slip it replaced. Each refusal is
//! a typed `AuthorityRefused` naming its reason.

use super::*;
use crate::error::Result;
use crate::{EntityId, Vault};

/// The work's slip still stands: there is nothing to rebind.
pub const REBIND_STILL_STANDS: &str = "the work's credential still stands; nothing to rebind";
/// The work's slip does not prove the request it was admitted on.
pub const REBIND_ORIGIN: &str =
    "the work's credential does not prove the request it was admitted on";
/// The successor is not a live slip of the work's own holder.
pub const REBIND_HOLDER: &str = "a rebind takes a live credential of the work's own holder: the \
                                 same owner for owner work, the same holder and class for a \
                                 member's or a guest's";
/// The successor reaches past what the work's slip signed.
pub const REBIND_WIDENS: &str =
    "the new credential reaches past what the work's credential signed; a rebind never widens";
/// The successor names another Grant than the work's slip, or only one of
/// them names a Grant.
pub const REBIND_GRANT: &str = "a rebind keeps the work under the Grant its credential named: the \
                                new credential must name the same Grant, or neither names one";

/// One rebind, as its door answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstrumentRebind {
    /// The slip the work stood on: its predecessor.
    pub predecessor: [u8; 32],
    /// The live slip the work stands on now.
    pub successor: [u8; 32],
    /// The work's requester owns this vault now: owner work.
    pub owner_work: bool,
}

/// What the rebind writer found, in its own snapshot.
struct RebindFacts<'a> {
    /// Who queued the work, and their gate actor class.
    requester: EntityId,
    class: &'a str,
    /// The requester is a live owner of this vault.
    owner_work: bool,
    /// The claims the work's slip was minted with.
    predecessor: &'a SlipClaims,
    /// The successor, verified in this snapshot.
    successor: &'a VerifiedSlip,
}

/// Policy hook (FIX 6108, CALLS "FIX 6108 retained-work rebind proof"):
/// whether the successor holds for the work's own holder. Both slips name
/// the requester as holder at the work's class, and no caveat handed the
/// successor to another key. Owner work also takes the same owner
/// EntityId, named canonically: never another of the vault's owners.
fn holder_continues(facts: &RebindFacts<'_>) -> bool {
    let successor = facts.successor.claims();
    let requester = facts.requester.to_hex();
    let same_holder = !facts.successor.is_transferred()
        && successor.slip_id != facts.predecessor.slip_id
        && facts.predecessor.holder_ref == requester
        && successor.holder_ref == requester
        && facts.predecessor.actor_class.as_deref() == Some(facts.class)
        && successor.actor_class.as_deref() == Some(facts.class);
    if facts.owner_work {
        same_holder
            && EntityId::from_hex(&successor.holder_ref)
                .is_ok_and(|holder| holder == facts.requester)
    } else {
        same_holder
    }
}

/// Policy hook (FIX 6108, lead fix round 1): the successor names the very
/// Grant the work's slip named, or neither names one (owner work). The
/// work's reads stay clamped by that Grant's current scope and pact as
/// before; a successor under another Grant, or under none where the work
/// had one, is refused, however its own scope reads.
fn keeps_grant(predecessor: &SlipClaims, successor: &VerifiedSlip) -> bool {
    successor.claims().grant_ref == predecessor.grant_ref
}

/// Policy hook (FIX 6108): the successor keeps the work within what its
/// slip signed. Records and channels are held apart: each set the work's
/// slip named holds the successor to a named subset of it, and a set it
/// left open stays open. A slip whose caveats met its sets to nothing
/// admitted no record, so no successor keeps it. A pact bound holds the
/// successor to the same grant, within the scope it requested; and the
/// delegation and org stay the work's. A later expiry or a new invitation
/// is the point of a rebind, so neither is compared.
fn keeps_bounds(successor: &VerifiedSlip, signed: &SignedBounds) -> bool {
    let now = successor.claims();
    let was = &signed.claims;
    let within = |now: &std::collections::BTreeSet<String>,
                  was: &std::collections::BTreeSet<String>| {
        was.is_empty() || (!now.is_empty() && now.is_subset(was))
    };
    let met_to_nothing = signed.records_bound && was.records.is_empty() && was.channels.is_empty();
    let records = !met_to_nothing
        && within(&now.records, &was.records)
        && within(&now.channels, &was.channels);
    let pact = match (&signed.pact, successor.pact()) {
        (None, _) => true,
        (Some((grant, scope)), Some((now_grant, now_scope))) => {
            grant == now_grant
                && crate::federation::Ceiling::new(now_scope.clone())
                    .is_within(&crate::federation::Ceiling::new(scope.clone()))
        }
        (Some(_), None) => false,
    };
    now.scope.is_narrowing_of(&was.scope)
        && successor.comm() <= effective_slip_comm(was.comm)
        && now.delegation == was.delegation
        && now.org_ref == was.org_ref
        && records
        && pact
}

impl Vault {
    /// Judges, in `txn`, whether work `requester` (gate actor class
    /// `class`) queued on `predecessor` may stand on `successor` instead
    /// (FIX 6108): the proof the module names. The caller swaps the binding
    /// in the same writer, so the judgment and the swap commit together.
    pub(crate) fn rebind_invocation_slip_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        predecessor: &InvocationSlipBinding,
        successor: &InvocationSlipBinding,
        requester: EntityId,
        class: &str,
    ) -> Result<InstrumentRebind> {
        if self.invocation_slip_in_txn(txn, predecessor).is_ok() {
            return Err(authority_refused(REBIND_STILL_STANDS));
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        predecessor
            .verify_origin(&fold)
            .map_err(authority_refusal_as(REBIND_ORIGIN))?;
        let signed = predecessor
            .slip()
            .signed_bounds()
            .map_err(authority_refusal_as(REBIND_ORIGIN))?;
        let proof = self
            .invocation_slip_in_txn(txn, successor)
            .map_err(authority_refusal_as(REBIND_HOLDER))?;
        let facts = RebindFacts {
            requester,
            class,
            owner_work: crate::policy_model::is_live_vault_owner_in_txn(self, txn, &requester)?,
            predecessor: &predecessor.slip().claims,
            successor: &proof,
        };
        if !holder_continues(&facts) {
            return Err(authority_refused(REBIND_HOLDER));
        }
        if !keeps_grant(facts.predecessor, &proof) {
            return Err(authority_refused(REBIND_GRANT));
        }
        if !keeps_bounds(&proof, &signed) {
            return Err(authority_refused(REBIND_WIDENS));
        }
        Ok(InstrumentRebind {
            predecessor: facts.predecessor.slip_id,
            successor: proof.claims().slip_id,
            owner_work: facts.owner_work,
        })
    }
}
