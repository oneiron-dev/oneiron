//! One residence read's admission for the machine at the other end of the
//! connection. The credential's own read, the selector's live grant and each
//! world's read setting for that machine are judged in one snapshot, so a
//! private world whose read names the proved machine reaches it, and an
//! unproved peer is an unknown destination that reads no private world.
//! Which rows a window selects stays with the selector's own filter.

use std::collections::BTreeSet;

use super::ScopedRead;
use crate::Vault;
use crate::authority::{
    Destination, FederationGrantActivation, PeerMachine, VerifiedSlip, WorldPrivacyView,
    federation_grant_activation,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
use crate::gate::PolicyManifestResolution;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::sync::SyncSelector;

fn denied() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "residence read is not admitted for this credential, grant or machine",
    })
}

/// A residence read for one credential, selector and destination machine,
/// loaded in one snapshot. Ask it in that same snapshot.
pub struct ResidenceReadContext<'v> {
    read: ScopedRead<'v>,
    policy: PolicyManifestResolution,
    destination: Destination,
    /// Every world whose read setting keeps it off `destination`.
    withheld: BTreeSet<EntityId>,
}

impl<'v> ResidenceReadContext<'v> {
    /// The credential `proof` reads under, while `selector` names a live,
    /// conferring member grant over `grant_scope` held by the selector's
    /// member, and the machine `peer` proved on this connection still stands
    /// on that key here. A peer that does not is an unknown destination.
    pub fn load_in(
        vault: &'v Vault,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
        peer: PeerMachine,
        grant_scope: FederationGrantScope,
        selector: &SyncSelector,
    ) -> Result<Self> {
        let key = vault
            .credential_read_key_in(txn, proof)?
            .ok_or_else(denied)?;
        let read = vault.scoped_read(key);
        let policy = read.live_policy_manifest_in(txn)?;
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        let raw = vault
            .get_raw_in(txn, &selector.grant_id)?
            .ok_or_else(denied)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &selector.grant_id)?
                .is_live()
        {
            return Err(denied());
        }
        let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if grant.role.is_guest()
            || grant.scope != grant_scope
            || grant.member_ref != selector.member_ref
            || !grant.confers_at(vault.store.clock.now_recorded_at())
            || matches!(
                federation_grant_activation(&fold, &selector.grant_id),
                FederationGrantActivation::Inactive(_)
            )
        {
            return Err(denied());
        }
        let destination = match peer {
            PeerMachine::Proven { machine, key }
                if fold.machine_proof_key(machine) == Some(key) =>
            {
                Destination::Machine(machine)
            }
            _ => Destination::Unknown,
        };
        let withheld = WorldPrivacyView::load_in(vault, txn)?.withheld_for(destination)?;
        Ok(Self {
            read,
            policy,
            destination,
            withheld,
        })
    }

    /// This read with `worlds` withheld too, beside those kept off its
    /// destination: a forwarded caller off its carrier (FIX 3550) reads no
    /// world an unknown destination may not.
    #[must_use]
    pub fn withholding(mut self, worlds: &BTreeSet<EntityId>) -> Self {
        self.withheld.extend(worlds);
        self
    }

    /// The machine this read serves, or `Unknown` when none stands proved.
    #[must_use]
    pub fn destination(&self) -> Destination {
        self.destination
    }

    /// Whether the credential reads `id` and its world may be read on the
    /// destination machine.
    pub fn allows_item(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        Ok(self
            .read
            .is_entity_readable_with_policy_in(txn, &self.policy, id)?
            && self.row_may_leave(txn, id)?)
    }

    /// Whether every row of `rows` may go to the destination machine: none
    /// sits in a world it may not read, and each row's world can be placed.
    pub fn rows_may_leave(&self, txn: &heed::RoTxn<'_>, rows: &[EntityId]) -> Result<bool> {
        for row in rows {
            if !self.row_may_leave(txn, row)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn row_may_leave(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        match crate::settings::device_only_withholds(
            &self.read.vault.store,
            txn,
            &self.withheld,
            id,
        ) {
            Ok(held) => Ok(!held),
            Err(Error::CorruptedIndex(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
