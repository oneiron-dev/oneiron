//! The owner's mint of a standing outbound grant, its withdrawal by the
//! owner or the engine, and the reads, all over the standing consent Grant
//! rows the grants are.

use super::bound::{StandingOutboundGrant, StandingOutboundGrantScope};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

impl Vault {
    /// Mints a standing outbound grant from an authenticated OF-336 grant
    /// intent: the owner's act, under the dial the intent names.
    ///
    /// # Errors
    ///
    /// As [`Self::mint_standing_outbound_grant_in_txn`], and
    /// [`crate::error::RecordError::InvalidOutboundGrantBody`] for an intent
    /// scope that is no standing dial.
    pub fn mint_standing_outbound_grant(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        intent: &crate::genui::GrantMintIntent,
    ) -> Result<StandingOutboundGrant> {
        let scope = StandingOutboundGrantScope::from_grant_mint_scope(&intent.scope)?;
        self.with_write_txn_grouped(|wtxn| {
            self.mint_standing_outbound_grant_in_txn(
                wtxn,
                owner,
                id,
                intent.principal_ref.trim(),
                scope,
            )
        })
    }

    /// Mints one standing outbound grant as a standing consent Grant row, in
    /// the caller's write transaction, bound to the policy frontier that
    /// transaction reads: the owner's act, receipted there as Approved. `id`
    /// is the grant's own id, which its capability keys and page dispatch
    /// name; re-minting the same grant re-affirms its row.
    ///
    /// # Errors
    ///
    /// [`crate::error::RecordError::InvalidOutboundGrantBody`] for a dial
    /// that fails validation; the owner's revalidation and storage errors.
    pub(crate) fn mint_standing_outbound_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        id: EntityId,
        principal_ref: &str,
        scope: StandingOutboundGrantScope,
    ) -> Result<StandingOutboundGrant> {
        let frontier =
            crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?.read_frontier_hash()?;
        let bound = scope.grant_bound(principal_ref, id, &frontier)?;
        let grant_ref = bound.digest().to_hex();
        self.create_outbound_standing_grant_in_txn(wtxn, owner, bound)?;
        self.consent_grant_in_txn(&*wtxn, &grant_ref)?
            .as_ref()
            .and_then(StandingOutboundGrant::from_row)
            .ok_or(Error::InvariantViolation(
                "a minted standing outbound grant reads back",
            ))
    }

    /// Ends one live standing outbound grant row in the caller's write
    /// transaction: the owner's revoke, receipted, when `owner` is present;
    /// else the engine's reduce-only retire. `false`: the row was not live.
    ///
    /// # Errors
    ///
    /// The owner's revalidation and storage errors.
    pub(crate) fn withdraw_standing_outbound_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: Option<&AuthenticatedOwner>,
        grant: &StandingOutboundGrant,
    ) -> Result<bool> {
        match owner {
            Some(owner) => Ok(self
                .revoke_consent_grant_in_txn(wtxn, owner, &grant.grant_ref())?
                .is_some()),
            None => {
                crate::consent::revoke_standing_grant_in_txn(&self.store, wtxn, &grant.grant_ref())
            }
        }
    }

    /// Reads one standing outbound grant by its id.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn get_standing_outbound_grant(
        &self,
        id: &EntityId,
    ) -> Result<Option<StandingOutboundGrant>> {
        let rtxn = self.store.env.read_txn()?;
        standing_outbound_grant_in_txn(&self.store, &rtxn, id)
    }
}

/// Every standing outbound grant, revoked ones included, in id order, on the
/// caller's transaction.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn standing_outbound_grants_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<StandingOutboundGrant>> {
    let mut grants: Vec<StandingOutboundGrant> =
        crate::consent::standing_grant_rows_in_txn(store, txn)?
            .iter()
            .filter_map(|(_, row)| StandingOutboundGrant::from_row(row))
            .collect();
    grants.sort_by_key(|grant| *grant.id.as_bytes());
    Ok(grants)
}

/// Every standing outbound grant `principal_ref` holds, revoked ones
/// included, in id order, on the caller's transaction.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn standing_outbound_grants_for_principal_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &str,
) -> Result<Vec<StandingOutboundGrant>> {
    let mut grants = standing_outbound_grants_in_txn(store, txn)?;
    grants.retain(|grant| grant.principal_ref == principal_ref);
    Ok(grants)
}

/// The standing outbound grant `id`, on the caller's transaction: its live
/// row when it has one, else the row it was revoked as.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn standing_outbound_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StandingOutboundGrant>> {
    let mut found = None;
    for grant in standing_outbound_grants_in_txn(store, txn)? {
        if grant.id != *id {
            continue;
        }
        if grant.is_active() {
            return Ok(Some(grant));
        }
        if found.is_none() {
            found = Some(grant);
        }
    }
    Ok(found)
}
