//! What this vault holds from one other vault, by attribution (ARCH-0043
//! #leaving-a-company: "Each side gets a list of what it holds from the
//! other, by attribution"; L7-09). It reads the delivery history each
//! landing keeps, and the foreign worlds registered to a pact with that
//! vault. A copied inquiry answer is in the history only: its world is not
//! registered to the pact, so it stays after the member leaves.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::AuthorityVaultId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::{Vault, ports};

use super::delivery_record::delivery_history_from_vault_in_txn;
use super::stale::registered_worlds;

/// One world here that holds what the other vault delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldWorld {
    /// The world as this vault names it: the foreign WORLD a delivery
    /// landed in, or base reality's id.
    pub world: EntityId,
    /// The delivered records this vault still holds and has not removed.
    pub records: Vec<EntityId>,
    /// The pacts with the other vault that delivered into it or registered
    /// it, as 32 bytes each.
    pub pacts: Vec<[u8; 32]>,
    /// Whether a pact with the other vault registered the world, as a
    /// synced world is. A copied inquiry answer's world is not.
    pub registered: bool,
}

/// What this vault holds from `peer_vault_id`, world by world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holdings {
    pub peer_vault_id: AuthorityVaultId,
    pub worlds: Vec<HeldWorld>,
}

#[derive(Default)]
struct Held {
    records: BTreeSet<EntityId>,
    pacts: BTreeSet<[u8; 32]>,
    registered: bool,
}

impl Vault {
    /// What this vault holds from `peer_vault_id`, read for `owner` in one
    /// read: each world with the records a delivery from that vault landed
    /// and this vault still holds, and each world a pact with that vault
    /// registered, whether or not a record is left in it. A world with
    /// neither is left out. It reads delivery facts, not today's grants,
    /// and deletes nothing.
    ///
    /// # Errors
    ///
    /// The owner's proof no longer holds; storage errors, and a delivery
    /// row that does not decode.
    pub fn holdings_from(
        &self,
        owner: &AuthenticatedOwner,
        peer_vault_id: &AuthorityVaultId,
    ) -> Result<Holdings> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let base = crate::claim::base_world_id();
        let mut worlds = BTreeMap::<EntityId, Held>::new();
        for delivered in delivery_history_from_vault_in_txn(&self.store, &txn, peer_vault_id)? {
            let held = worlds.entry(delivered.world.unwrap_or(base)).or_default();
            held.pacts.insert(delivered.delivering_pact);
            let record = delivered.source_ref;
            if ports::EntityStoreRead::port_entity_present(&self.store, &txn, &record)?
                && !ports::removed_in_txn(&self.store, &txn, &record)?
            {
                held.records.insert(record);
            }
        }
        for (pact_id, pact) in &fold.federation_pacts {
            if pact.peer_vault_id != *peer_vault_id {
                continue;
            }
            for world in registered_worlds(&self.store, &txn, pact_id)? {
                let held = worlds.entry(world).or_default();
                held.pacts.insert(*pact_id);
                held.registered = true;
            }
        }
        Ok(Holdings {
            peer_vault_id: *peer_vault_id,
            worlds: worlds
                .into_iter()
                .filter(|(_, held)| held.registered || !held.records.is_empty())
                .map(|(world, held)| HeldWorld {
                    world,
                    records: held.records.into_iter().collect(),
                    pacts: held.pacts.into_iter().collect(),
                    registered: held.registered,
                })
                .collect(),
        })
    }
}
