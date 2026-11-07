//! The leave-notice delegations a home move carries (FIX 7932; L01 20:19
//! registration map, item 6), as an adapter on the home handoff carrier
//! (`crate::sync::home_handoff`). The home answers a removed person's leave
//! notices with the delegations it holds, so a new home holds every one the
//! old home did.
//!
//! The rows travel as each delegation's canonical bytes. A delegation names
//! keys and hashes, never an actor, so no actor content travels apart. The
//! new home lands each one that decodes, verifies and names its own
//! authority vault, with its index, as the writer that settled the handoff
//! stored it. A handoff that already has a delegation here keeps it: both are
//! the same hand-on its predecessor signed, and none is ever rewritten.
//! Delegations are evidence, not state that moves on: a move never refuses
//! on them, and one that does not verify lands nothing.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{DELEGATION_BY_HANDOFF, DELEGATIONS};
use crate::Vault;
use crate::authority::{LeaveNoticeDelegation, leave_notice_delegation_digest};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt,
};

/// Every leave-notice delegation this node holds, as its canonical bytes.
#[derive(Serialize, Deserialize)]
pub(crate) struct LeaveNoticeDelegationRows {
    delegations: Vec<Vec<u8>>,
}

/// A delegation's actor content: there is none, as a delegation names no
/// actor.
#[derive(Serialize, Deserialize)]
pub(crate) enum NoActorContent {}

impl ActorContent for NoActorContent {
    #[allow(
        clippy::uninhabited_references,
        reason = "no value of this type exists, so the match is never reached"
    )]
    fn actor(&self) -> EntityId {
        match *self {}
    }
}

impl HomeTable for LeaveNoticeDelegationRows {
    type Rows = Self;
    type Actor = NoActorContent;
    const TABLE: &'static SideTableDecl = &side_table::AUTHORITY_LEAVE_NOTICE_DELEGATION;
    const SCHEMA_VERSION: u16 = 1;

    /// A delegation lands in the writer that settles its handoff: none is in
    /// flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, NoActorContent>> {
        Ok(Partitioned {
            facts: Self {
                delegations: DELEGATIONS
                    .scan(&vault.store, txn)?
                    .into_iter()
                    .map(|(_, bytes)| bytes)
                    .collect(),
            },
            actors: Vec::new(),
        })
    }

    /// Lands each carried delegation that decodes, verifies and names this
    /// vault's authority vault, under its digest and indexed by its handoff,
    /// unless that handoff already has one here. Never a Conflict.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, NoActorContent>,
    ) -> Result<TableAdopt> {
        let vault_id = vault.authority_view_readonly_in_txn(txn)?.vault_id;
        for bytes in rows.facts.delegations {
            let Ok(delegation) = LeaveNoticeDelegation::decode(&bytes) else {
                continue;
            };
            if Some(delegation.authority_vault_id) != vault_id
                || !delegation.verify()
                || DELEGATION_BY_HANDOFF.contains(&vault.store, txn, &delegation.handoff_entry)?
            {
                continue;
            }
            let digest = leave_notice_delegation_digest(&bytes);
            DELEGATIONS.put(&vault.store, txn, &digest, &bytes)?;
            DELEGATION_BY_HANDOFF.put(&vault.store, txn, &delegation.handoff_entry, &digest)?;
        }
        Ok(TableAdopt::Applied)
    }

    /// Every delegation row and every index row here.
    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        let mut keys: Vec<Vec<u8>> = DELEGATIONS
            .scan_keys(&vault.store, txn, &[])?
            .iter()
            .map(|digest| DELEGATIONS.key_bytes(digest))
            .collect();
        keys.extend(
            DELEGATION_BY_HANDOFF
                .scan_keys(&vault.store, txn, &[])?
                .iter()
                .map(|handoff| DELEGATION_BY_HANDOFF.key_bytes(handoff)),
        );
        Ok(keys)
    }

    /// Every key of both families among the image's rows: the index lands
    /// and restores with the delegations it names.
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        let prefixes = [
            DELEGATIONS.decl().prefix,
            DELEGATION_BY_HANDOFF.decl().prefix,
        ];
        Ok(image
            .iter()
            .filter(|(key, _)| prefixes.iter().any(|prefix| key.starts_with(prefix)))
            .map(|(key, _)| key.clone())
            .collect())
    }
}
