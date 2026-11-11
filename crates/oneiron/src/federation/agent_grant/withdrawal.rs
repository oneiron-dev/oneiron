//! A Grant an owner's signed mint made, an agent or a GitPush grant,
//! withdrawn on the record (FIX 22188, 22193, 22226): the one rule the
//! consent registry's revoked view, the agent and GitPush revoke doors, the
//! authority audit and a checkpoint restore's classes read, so none of them
//! drifts from another.
//!
//! A Grant is withdrawn on the record when the owner's counted revoke act
//! names it, or when a counted signed owner mint of its kind made it and a
//! counted membership withdrawal names it or this vault marks it withdrawn.
//! The mark is the record of a withdrawal no counted entry names: an OAuth
//! sign-in that ended with no live host to sign, a membership change whose
//! signed record is still pending, or a peer's delete applied here. It is
//! the Grant's withdrawal marker (FIX-LIST 5107), or, on a replica that never
//! held the row (its peer's delete arrived before its put), the row's
//! permanent hard-delete marker that delete left: every withdrawal erases the
//! row, so beside a signed owner mint either marker records one. Nothing is
//! signed as the owner.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::authority::{AgentGrantActRecord, AgentGrantChange, AuthorityOp};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::FederationGrantKind;

/// Signed mint fields and withdrawals the authority fold counted, retained
/// for the registry's audit view and the rule [`LoggedOwnerGrants::withdrew`]
/// reads.
#[derive(Default)]
pub(super) struct LoggedOwnerGrants {
    /// Each counted signed owner mint, with its log row's recording time,
    /// by the Grant it made.
    pub(super) mints: BTreeMap<EntityId, (AgentGrantActRecord, u64)>,
    owner_revoked: BTreeSet<EntityId>,
    membership_revoked: BTreeSet<EntityId>,
}

impl LoggedOwnerGrants {
    /// Whether `grant` is withdrawn on the record: the owner's counted
    /// revoke act names it, or a counted signed owner mint of `kind` made it
    /// and a counted membership withdrawal names it or this vault marks it
    /// withdrawn ([`Vault::grant_withdrawal_marked_in_txn`]).
    ///
    /// # Errors
    /// A store failure reading the hard-delete marker.
    pub(super) fn withdrew(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
        kind: FederationGrantKind,
    ) -> Result<bool> {
        if self.owner_revoked.contains(&grant) {
            return Ok(true);
        }
        let Some((record, _)) = self.mints.get(&grant) else {
            return Ok(false);
        };
        Ok(signed_mint_kind(&record.change) == Some(kind)
            && (self.membership_revoked.contains(&grant)
                || vault.grant_withdrawal_marked_in_txn(txn, grant)?))
    }
}

/// The kind of Grant the signed owner mint `change` made, as the rule reads
/// it: an agent grant, or a GitPush grant with its bounds; `None` for a
/// revoke or any other mint.
fn signed_mint_kind(change: &AgentGrantChange) -> Option<FederationGrantKind> {
    match change {
        AgentGrantChange::Mint {
            grant_kind: FederationGrantKind::Access,
            ..
        } => Some(FederationGrantKind::Access),
        AgentGrantChange::Mint {
            grant_kind: FederationGrantKind::GitPush,
            git_push_bounds: Some(_),
            ..
        } => Some(FederationGrantKind::GitPush),
        AgentGrantChange::Mint { .. } | AgentGrantChange::Revoke { .. } => None,
    }
}

impl Vault {
    /// Whether this vault marks `grant` withdrawn: its withdrawal marker
    /// (FIX-LIST 5107), or, on a replica that never held the row, the
    /// permanent hard-delete marker its peer's erasure left (FIX 22193).
    ///
    /// # Errors
    /// A store failure reading the hard-delete marker.
    pub(in crate::federation) fn grant_withdrawal_marked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
    ) -> Result<bool> {
        Ok(
            crate::authority::grant_known_withdrawn_in_txn(&self.store, txn, grant)
                || self.local_hard_delete_marker_exists_in_txn(txn, &grant)?,
        )
    }

    /// The clause of [`LoggedOwnerGrants::withdrew`] that no counted entry
    /// carries, for the authority audit's row of `record`, a signed owner
    /// mint the fold counted (FIX 22193): whether it made a Grant the rule
    /// reads and this vault marks that Grant withdrawn.
    ///
    /// # Errors
    /// A store failure reading the hard-delete marker.
    pub(crate) fn signed_mint_withdrawal_marked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &AgentGrantActRecord,
    ) -> Result<bool> {
        Ok(signed_mint_kind(&record.change).is_some()
            && self.grant_withdrawal_marked_in_txn(txn, record.grant)?)
    }

    /// Whether `grant`, a Grant of `kind`, is withdrawn on the record
    /// ([`LoggedOwnerGrants::withdrew`]): what an owner revoke door answers
    /// unchanged for.
    ///
    /// # Errors
    /// A store or fold failure.
    pub(in crate::federation) fn owner_grant_withdrawn_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
        kind: FederationGrantKind,
    ) -> Result<bool> {
        self.logged_owner_grants_in_txn(txn)?
            .withdrew(self, txn, grant, kind)
    }

    /// The agent and GitPush grants withdrawn on the record, for a
    /// checkpoint restore's classes: each Grant the owner's counted revoke
    /// act names, and each Grant a counted signed owner mint made that
    /// [`LoggedOwnerGrants::withdrew`] names, read with the kind its own
    /// mint made (FIX 22226). An entry whose body this vault no longer holds
    /// (an adopted checkpoint covers it) names none.
    ///
    /// # Errors
    /// A store or fold failure.
    pub(crate) fn withdrawn_owner_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        let logged = self.logged_owner_grants_in_txn(txn)?;
        let mut withdrawn = logged.owner_revoked.clone();
        for (grant, (record, _)) in &logged.mints {
            if let Some(kind) = signed_mint_kind(&record.change)
                && logged.withdrew(self, txn, *grant, kind)?
            {
                withdrawn.insert(*grant);
            }
        }
        Ok(withdrawn)
    }

    /// The counted signed owner mints and withdrawals of this vault's
    /// authority log ([`Self::counted_grant_acts_in_txn`]).
    ///
    /// # Errors
    /// A store or fold failure.
    pub(super) fn logged_owner_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<LoggedOwnerGrants> {
        let mut grants = LoggedOwnerGrants::default();
        for act in self.counted_grant_acts_in_txn(txn)? {
            match act.op {
                AuthorityOp::AgentGrantAct(record) => match &record.change {
                    AgentGrantChange::Mint { .. } => {
                        grants.mints.insert(record.grant, (record, act.recorded_at));
                    }
                    AgentGrantChange::Revoke { .. } => {
                        grants.owner_revoked.insert(record.grant);
                    }
                },
                AuthorityOp::SlipGrantRevoke { grant_ref, .. } => {
                    grants.membership_revoked.insert(grant_ref);
                }
                // A membership change no host issuer signed, signed later
                // by its carrier (FIX 12335), withdraws each Grant it names.
                AuthorityOp::MembershipExecution(record) => {
                    grants.membership_revoked.extend(record.withdrawn_grants);
                }
                _ => {}
            }
        }
        Ok(grants)
    }
}
