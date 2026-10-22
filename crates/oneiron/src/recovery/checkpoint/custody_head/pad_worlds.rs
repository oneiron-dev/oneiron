//! Each world's pad recipients for a custody head (FIX 9178): the world
//! compartments a head seals are wrapped to its admitted machines and the
//! roots its current key is wrapped to, never the data key.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::store::PadRecipients;
use crate::world_keys::{world_keys_destroyed_in_txn, world_pad_recipients_in_txn};

impl Vault {
    /// Each world whose pads a head may carry, with its admitted machines
    /// and roots ([`world_pad_recipients_in_txn`]), read in `txn`: every
    /// world [`crate::store::Store::world_pad_worlds`] names, but those
    /// `kept_local` keeps off the member. A world whose keys were destroyed
    /// here has none. One no admitted machine or root receives is left out
    /// and reported, never guessed: its pads stay in this machine's custody,
    /// and its retirement facts ride the host-readable compartment. A lookup
    /// that faults leaves its world out (all of them, for the census), warned:
    /// the head is sealed without those pads, never held for them.
    pub(super) fn pad_world_recipients_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fold: &AuthorityFold,
        kept_local: &BTreeSet<[u8; 16]>,
    ) -> BTreeMap<EntityId, PadRecipients> {
        let worlds = match self.store.world_pad_worlds(txn, fold) {
            Ok(worlds) => worlds,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a custody head's pad worlds could not be read; its pads stay in this \
                     machine's custody this pass"
                );
                return BTreeMap::new();
            }
        };
        let mut out = BTreeMap::new();
        let mut unadmitted = 0_usize;
        let mut unread = 0_usize;
        for world in worlds {
            if kept_local.contains(world.as_bytes()) {
                continue;
            }
            let admitted = match world_keys_destroyed_in_txn(&self.store, txn, world) {
                Ok(true) => continue,
                Ok(false) => world_pad_recipients_in_txn(self, txn, world),
                Err(error) => Err(error),
            };
            match admitted {
                Ok(admitted) if !admitted.is_empty() => {
                    out.insert(world, admitted);
                }
                Ok(_) => unadmitted += 1,
                Err(error) => {
                    unread += 1;
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a world's pad recipients could not be read; its pads stay in this \
                         machine's custody this pass"
                    );
                }
            }
        }
        if unadmitted + unread > 0 {
            tracing::warn!(
                unadmitted,
                unread,
                "world pads no admitted machine or recovery root receives stay in this \
                 machine's custody: the custody head carries none of them"
            );
        }
        out
    }
}
