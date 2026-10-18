//! The owner's settings for one world: where it may be read, where its sealed
//! copies may rest, and its model order.
//!
//! The settings are a signed authority-log edit, never a WORLD body field, so
//! no generic write, import, sync ingest or restore door can change them. Only
//! a live vault owner changes them, from any linked surface where he is
//! authenticated (the mesh ruling, 10-19), carried by any live linked machine
//! of the vault, and each change lands its receipt and a typed event in the
//! same transaction as the edit. The receipt carries ids only, and says
//! honestly whether a holder still has to do the world's key work. When one
//! does, the same commit records an owner work request naming that holder
//! (`world_keys::owner_work`), and the receipt carries where it stands.
use serde::{Deserialize, Serialize};

use super::ledger::{PolicyChangedEvent, put_event_in_txn};
use crate::authority::{
    ActSurface, EffectiveRead, EffectiveWorldPrivacy, KeyWork, OwnerWorkBody, PolicyRevision,
    WorldKeyMode, WorldPrivacy,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::PolicyRowScope;
use crate::side_table::{self, Named, SideTable};
use crate::world_keys::{OwnerWorkReceipt, WorldKeyStatus};
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
    /// The machine whose install key signed the edit, as hex: the carrier.
    pub machine: String,
    /// Where the owner said so. Audit only: no rule reads it.
    pub surface: ActSurface,
    pub previous: EffectiveWorldPrivacy,
    pub next: EffectiveWorldPrivacy,
    /// The signed authority-log entry, the cross-machine record, as hex.
    pub entry_hash: String,
    /// When the world was orphaned before the change: the machines its read
    /// named, none of them still the owner's, as hex. Empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphaned_from: Vec<String>,
    /// Whether the world's key work is done here, needs none, or awaits a
    /// holder. Never "enacted" while a holder still has to act. The commit's
    /// snapshot.
    pub key_work: KeyWork,
    /// When the key work awaits a holder: the owner work request this commit
    /// recorded for one (or why none could be named), and where it stands,
    /// read from the fold. `None` when no holder is needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_work: Option<OwnerWorkReceipt>,
    pub at: u64,
}

const RECEIPTS: SideTable<u64, WorldPrivacyReceipt, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_RECEIPT);

/// What the key step after an edit left: no key work for a world read
/// everywhere; done here when this install minted, wrapped or found every
/// reader holding the key; otherwise a holder's to do.
fn key_work_of(next: &EffectiveWorldPrivacy, status: Option<WorldKeyStatus>) -> KeyWork {
    match status {
        _ if next.read == EffectiveRead::Everywhere => KeyWork::Recorded,
        Some(WorldKeyStatus::NotPrivate) => KeyWork::Recorded,
        Some(
            WorldKeyStatus::Minted(_)
            | WorldKeyStatus::Wrapped { .. }
            | WorldKeyStatus::UpToDate(_),
        ) => KeyWork::Enacted,
        None => KeyWork::AwaitingHolder,
    }
}

impl Vault {
    /// Sets one world's privacy settings.
    ///
    /// Only a live vault owner may, from any surface where he is
    /// authenticated (`surface`, recorded for audit). This install carries
    /// his act under any live profile of the vault; it need not hold the
    /// world. `seen` is the settings revision the deciding surface showed
    /// him ([`Vault::world_privacy_revision`]); `None` takes the current one.
    /// A one-machine setting names only a machine the owner marked "yours":
    /// his recipient choice. The signed edit, its receipt and a
    /// `policy.world_privacy.changed` event commit in one transaction; a call
    /// that keeps the current settings is receipted too. When this install
    /// may read the world it does the key work in the same commit; otherwise
    /// the receipt says a holder still has to.
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] when the
    /// owner is not a live vault owner; [`Error::ConcurrentWrite`] when
    /// `seen` is not the world's current revision; [`Error::InvalidConfig`]
    /// when `world` is not a live, stored WORLD row other than base reality,
    /// when this install has no live profile to carry the act, when a
    /// one-machine target is not marked "yours", or when the edit would name
    /// more parents than one entry may.
    pub fn set_world_privacy_as(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyReceipt> {
        // The world's key follows its settings in the same commit where this
        // install may read the world (world privacy P6b): a private world it
        // may read never commits without one. Its secret is read before the
        // writer.
        let (secret, unavailable) = match self.machine_secret_outside_txn() {
            Ok(secret) => (Some(secret), None),
            Err(error) => (None, Some(error)),
        };
        // The release lock is taken under the writer and released only after
        // the commit is durable: a release verdict reading the settings waits
        // for it, and never needs the writer while it holds the read side.
        let (_release, receipt) = self.with_write_txn(|txn| {
            let release = self
                .store
                .device_only_flag_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let receipt =
                self.set_world_privacy_in_txn(txn, owner, surface, world, settings, seen)?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let secret = secret
                .as_ref()
                .ok_or_else(|| unavailable.expect("an absent secret has its error"));
            let status = self.world_key_for_edit_in_txn(txn, actor, world, secret)?;
            let receipt = self.settle_world_key_work_in_txn(txn, owner, receipt, status)?;
            Ok((release, receipt))
        })?;
        Ok(receipt)
    }

    /// The door's work in the caller's write transaction, for a door that
    /// does more in the same commit: the caller holds the release lock until
    /// the commit is durable, and settles the receipt's key work
    /// ([`Self::settle_world_key_work_in_txn`]) once its key step ran. Until
    /// then the receipt claims no key work done.
    pub(crate) fn set_world_privacy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyReceipt> {
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let change =
            self.append_world_privacy_edit_in_txn(txn, actor, surface, world, settings, seen)?;
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
        let key_work = key_work_of(&change.next, None);
        let receipt = WorldPrivacyReceipt {
            receipt_id: self.store.clock.entity_id()?.to_hex(),
            revision,
            world: world.to_hex(),
            author: actor.to_hex(),
            machine: change.machine.to_hex(),
            surface,
            previous: change.previous,
            next: change.next,
            entry_hash: change
                .entry_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            orphaned_from: change.orphaned_from.iter().map(EntityId::to_hex).collect(),
            key_work,
            owner_work: None,
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

    /// Records what the key step after `receipt`'s edit did, in the same
    /// transaction (mesh contract §5, the honest receipt). Key work counts as
    /// enacted only once every reader the settings allow, and the pinned
    /// root, holds a wrap of the world's current key: a first key minted on
    /// a bridge record (Docs Q06) still awaits the holder's next wrap. Key
    /// work that awaits a holder names one in the same commit: an owner work
    /// request for the settings revision right after the edit, signed by this
    /// install as the carrier of `owner`'s act.
    pub(crate) fn settle_world_key_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        mut receipt: WorldPrivacyReceipt,
        status: Option<WorldKeyStatus>,
    ) -> Result<WorldPrivacyReceipt> {
        let mut key_work = key_work_of(&receipt.next, status);
        let world = EntityId::from_hex(&receipt.world)
            .map_err(|_| Error::InvariantViolation("world privacy receipt world"))?;
        if key_work == KeyWork::Enacted {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let root = self.pinned_root_recipient_in_txn(txn, &fold)?;
            let wrapped = fold.current_world_key(world).is_some_and(|current| {
                crate::world_keys::recipients(&fold, world, root)
                    .iter()
                    .all(|(to, _)| current.wraps.contains_key(to))
            });
            if !wrapped {
                key_work = KeyWork::AwaitingHolder;
            }
        }
        receipt.key_work = key_work;
        if key_work == KeyWork::AwaitingHolder {
            let seen = self
                .authority_view_readonly_in_txn(txn)?
                .world_policy_revision(world);
            receipt.owner_work = Some(self.record_owner_work_in_txn(
                txn,
                owner,
                receipt.surface,
                world,
                seen.0,
                OwnerWorkBody::WorldKey {
                    mode: WorldKeyMode::Ensure,
                },
            )?);
        }
        RECEIPTS.put(&self.store, txn, &receipt.revision, &receipt)?;
        Ok(receipt)
    }

    /// Stores `receipt` again once a door that does more in the same commit
    /// settled its key work itself (the world-key re-assert door, which
    /// records its own owner work): the commit's snapshot.
    pub(crate) fn put_world_privacy_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt: &WorldPrivacyReceipt,
    ) -> Result<()> {
        RECEIPTS.put(&self.store, txn, &receipt.revision, receipt)
    }

    /// Every world-settings change made on this machine, in revision order,
    /// each one's owner work as the fold reads it now.
    pub fn world_privacy_change_log(&self) -> Result<Vec<WorldPrivacyReceipt>> {
        let txn = self.store.env.read_txn()?;
        let receipts: Vec<WorldPrivacyReceipt> = RECEIPTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect();
        if receipts.iter().all(|receipt| receipt.owner_work.is_none()) {
            return Ok(receipts);
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(receipts
            .into_iter()
            .map(|mut receipt| {
                receipt.owner_work = receipt.owner_work.map(|work| work.refreshed(&fold));
                receipt
            })
            .collect())
    }
}
