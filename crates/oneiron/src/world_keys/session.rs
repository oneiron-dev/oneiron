//! What one vault handle keeps for world privacy P6b, in memory only: this
//! install's keystore, the world keys this machine opened, and OF-520's
//! question for each world whose key no record could carry.
//!
//! A key record names every live settings edit of its world (Engine E7), and
//! one record names at most [`MAX_PARENTS`] parents. A world whose edits
//! outgrow that is a format bound, not a rate: the door that meets it raises
//! the question here, once per world in the log, and either refuses with the
//! way out or, in a pin door, withholds that one key and goes on.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron_keystore::DeviceKeystore;

use super::owner_work::PublishObserved;
use super::{WorldKey, WorldKeyId};
use crate::authority::{AuthorityEntryHash, MAX_PARENTS};
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// A world whose key record would name more rows than one record may: its
/// live settings edits, with the standing rows named beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldKeyFrontierCheck {
    pub world: EntityId,
    /// The rows the record had to name.
    pub rows: usize,
    /// The most parents one record names.
    pub bound: usize,
}

impl WorldKeyFrontierCheck {
    /// Machine-readable question discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "world_key_frontier_wide";
}

/// One image a linked machine sends in parts, as far as it came, and the
/// host's charge for its bytes (FIX 5111).
pub(crate) struct CountersignStage {
    pub(crate) image: [u8; 32],
    pub(crate) total: u64,
    pub(crate) bytes: Vec<u8>,
    /// When its last part came.
    pub(crate) touched: std::time::Instant,
    /// The host's charge for the room `bytes` holds; it goes with the stage.
    pub(crate) charge: Box<dyn crate::authority::CountersignStageCharge>,
}

/// The vault handle's world-key state. Never persisted and never shared
/// across vaults; the opened keys are wiped when the handle drops.
#[derive(Default)]
pub(crate) struct WorldKeySession {
    /// This install's this-device-only keystore. The host installs it after
    /// open.
    pub(crate) keystore: Mutex<Option<Arc<dyn DeviceKeystore>>>,
    /// This install's signing keys, loaded from that keystore outside any
    /// transaction (P6c). Cleared when another keystore is installed.
    pub(crate) signer: Mutex<Option<Arc<crate::identity::InstallSigner>>>,
    /// The world keys this machine opened.
    pub(crate) ring: Mutex<HashMap<WorldKeyId, Arc<WorldKey>>>,
    /// The vault data key, once unlocked on this handle (OF-570 E1).
    pub(crate) vault_key: Mutex<Option<Arc<super::vault_key::VaultDataKey>>>,
    /// The checkpoint root signers the host holds here (FIX 4882).
    pub(crate) checkpoint_roots: Mutex<Vec<Arc<dyn crate::authority::CheckpointRootSigner>>>,
    /// The image each linked machine is sending this home in parts to
    /// countersign (FIX 4882), until it is whole, it idles out or its socket
    /// closes (FIX 5111).
    pub(crate) checkpoint_countersign: Mutex<BTreeMap<EntityId, CountersignStage>>,
    /// Each world's question, at its latest crossing.
    frontier: Mutex<BTreeMap<EntityId, WorldKeyFrontierCheck>>,
    /// What this install's relay last observed of each bundle publication
    /// it is asked to make, by the home the pass reached (FIX 4784, 4785):
    /// in memory only, until the handle closes or the request leaves the
    /// pending list.
    pub(crate) publications:
        Mutex<BTreeMap<(AuthorityEntryHash, Option<EntityId>), PublishObserved>>,
    /// Held while a sealed window's mirror is read, extended and written back.
    #[cfg(feature = "sync")]
    pub(crate) sealing: Mutex<()>,
    /// The carrier keys this install was answered live, its asks out and
    /// the carriers whose holder refused (FIX 7402): in memory only, wiped
    /// with the handle.
    pub(crate) custody_leaves: Mutex<crate::secret_custody::CustodyLeafSession>,
}

impl WorldKeySession {
    /// Raises `world`'s question: `rows` would go in one record.
    pub(crate) fn frontier_wide(&self, world: EntityId, rows: usize) {
        let check = WorldKeyFrontierCheck {
            world,
            rows,
            bound: MAX_PARENTS,
        };
        let first = self
            .frontier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(world, check)
            .is_none();
        if first {
            tracing::warn!(
                kind = WorldKeyFrontierCheck::KIND,
                world = %world.to_hex(),
                rows,
                bound = MAX_PARENTS,
                "a world's live settings edits outgrew one key record"
            );
        }
    }

    /// Whether a door on this handle raised `world`'s question: its key's
    /// record would name more rows than one record may (FIX 4686).
    pub(crate) fn frontier_raised(&self, world: EntityId) -> bool {
        self.frontier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&world)
    }
}

impl Vault {
    /// The worlds whose key a door could not record since this handle opened,
    /// because their live settings edits outgrew one record (OF-520). Merging
    /// a world's settings from one machine that sees every edit clears the
    /// cause; the question stays until the handle closes.
    #[must_use]
    pub fn world_key_frontier_checks(&self) -> Vec<WorldKeyFrontierCheck> {
        self.world_keys
            .frontier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}
