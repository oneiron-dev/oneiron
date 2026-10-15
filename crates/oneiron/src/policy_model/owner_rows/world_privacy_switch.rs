//! The owner's settings for one world: where it may be read, where its sealed
//! copies may rest, and its model order.
//!
//! The settings are a signed authority-log edit, never a WORLD body field, so
//! no generic write, import, sync ingest or restore door can change them. Only
//! a live vault owner changes them, only on a machine the owner marked "yours"
//! that holds the world (or stores an orphaned one), and each change lands its
//! receipt and a typed event in the same transaction as the edit. The receipt
//! carries ids only.
use serde::{Deserialize, Serialize};

use super::ledger::{PolicyChangedEvent, put_event_in_txn};
use crate::authority::{EditOrigin, EffectiveWorldPrivacy, WorldPrivacy};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::PolicyRowScope;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Event kind on the shared owner-policy stream for a settings change.
const WORLD_PRIVACY_CHANGED: &str = "policy.world_privacy.changed";

/// One owner change of a world's settings, in revision order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldPrivacyReceipt {
    pub receipt_id: String,
    pub revision: u64,
    /// The WORLD row, as hex.
    pub world: String,
    /// The owner actor who changed it, as hex.
    pub author: String,
    /// The machine whose install key signed the edit, as hex.
    pub machine: String,
    pub previous: EffectiveWorldPrivacy,
    pub next: EffectiveWorldPrivacy,
    /// The signed authority-log entry, the cross-machine record, as hex.
    pub entry_hash: String,
    /// When the change re-picked an orphaned world: the machines its read
    /// named, none of them still the owner's, as hex. Empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphaned_from: Vec<String>,
    pub at: u64,
}

const RECEIPTS: SideTable<u64, WorldPrivacyReceipt, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_RECEIPT);

impl Vault {
    /// Sets one world's privacy settings.
    ///
    /// Only a live vault owner may, and only on this machine: it must be one
    /// the owner marked "yours" and must hold the world, and a peer's request
    /// is refused unless that peer proved it is this machine. When no machine
    /// the world's read names is still the owner's, any machine of the
    /// owner's that stores the WORLD row may re-pick it; the receipt names the
    /// machines it was orphaned from. A one-machine setting names only a
    /// machine the owner marked "yours". The signed edit,
    /// its receipt and a `policy.world_privacy.changed` event commit in one
    /// transaction; a call that keeps the current settings is receipted too.
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] when the
    /// owner, the origin or this machine may not edit the world;
    /// [`Error::InvalidConfig`] when `world` is not a live, stored WORLD row
    /// other than base reality.
    pub fn set_world_privacy_as(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        world: EntityId,
        settings: WorldPrivacy,
    ) -> Result<WorldPrivacyReceipt> {
        // The release lock is taken under the writer and released only after
        // the commit is durable: a release verdict reading the settings waits
        // for it, and never needs the writer while it holds the read side.
        let (_release, receipt) = self.with_write_txn(|txn| {
            let release = self
                .store
                .device_only_flag_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let receipt = self.set_world_privacy_in_txn(txn, owner, origin, world, settings)?;
            Ok((release, receipt))
        })?;
        Ok(receipt)
    }

    /// The door's work in the caller's write transaction, for a door that
    /// does more in the same commit: the caller holds the release lock until
    /// the commit is durable.
    pub(crate) fn set_world_privacy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        world: EntityId,
        settings: WorldPrivacy,
    ) -> Result<WorldPrivacyReceipt> {
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let change = self.append_world_privacy_edit_in_txn(txn, actor, origin, world, settings)?;
        let last = RECEIPTS
            .iter_rev_from(&self.store, txn, &[])?
            .next()
            .transpose()?
            .map(|(revision, _)| revision);
        let revision = match last {
            None => 1,
            Some(revision) => revision.checked_add(1).ok_or(Error::InvariantViolation(
                "world privacy receipt revision overflow",
            ))?,
        };
        let receipt = WorldPrivacyReceipt {
            receipt_id: self.store.clock.entity_id()?.to_hex(),
            revision,
            world: world.to_hex(),
            author: actor.to_hex(),
            machine: change.machine.to_hex(),
            previous: change.previous,
            next: change.next,
            entry_hash: change
                .entry_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            orphaned_from: change.orphaned_from.iter().map(EntityId::to_hex).collect(),
            at: self.instant_in_txn(txn)?.secs(),
        };
        RECEIPTS.put(&self.store, txn, &revision, &receipt)?;
        put_event_in_txn(
            self,
            txn,
            &PolicyChangedEvent {
                kind: WORLD_PRIVACY_CHANGED.to_owned(),
                receipt_id: receipt.receipt_id.clone(),
                author: receipt.author.clone(),
                scope: Some(PolicyRowScope::World(receipt.world.clone())),
                target: None,
                at: receipt.at,
            },
        )?;
        Ok(receipt)
    }

    /// Every world-settings change made on this machine, in revision order.
    pub fn world_privacy_change_log(&self) -> Result<Vec<WorldPrivacyReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(RECEIPTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }
}
