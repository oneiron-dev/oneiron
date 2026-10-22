//! What a carrier-only tear destroys, read from the carrier itself (OF-470,
//! FIX 3061). A window's shallow cut or rebuild drops every row's history,
//! so it destroys each value its rows ever held: the rows it carries now,
//! every insert its retained history holds, overwritten or deleted since,
//! and the winners of its shallow root. A pad among those values may live
//! nowhere else, so its world's holds are read from its own bytes, never
//! from the canonical row ([`crate::world_keys::reject_held_pad_carrier_in_txn`]).
//! The inventory is read before anything rewrites the window and checked in
//! the transaction that destroys; it is never persisted.

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::checkpoint::{Capture, Classify, Field, OwnerId};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::legal_hold::HoldActor;

/// The root maps whose keys are row ids, live or tombstoned.
const ID_ROOTS: [&str; 2] = ["entities", "tombstones"];
/// The root map whose values are rows.
const ROWS: &str = "entities";

/// Every row id and pad row a window's carriers hold, at its root and in its
/// history.
#[derive(Default)]
pub(crate) struct CarrierInventory {
    ids: BTreeSet<EntityId>,
    pads: Vec<Zeroizing<Vec<u8>>>,
}

impl CarrierInventory {
    /// The inventory of window `doc`, read before anything rewrites it: its
    /// current rows, and every value its retained history and shallow root
    /// hold. A document the checkpoint does not take is read at its current
    /// rows alone, as before, warned with no byte of it.
    pub(crate) fn of_window(doc: &LoroDoc) -> Self {
        let mut inventory = Self::default();
        for root in ID_ROOTS {
            doc.get_map(root).for_each(|key, value| match value {
                ValueOrContainer::Value(value) => inventory.take(root, key, Some(&value)),
                ValueOrContainer::Container(_) => inventory.take(root, key, None),
            });
        }
        let LoroValue::Map(roots) = doc.get_value() else {
            return inventory;
        };
        let roots: Vec<&str> = roots.keys().map(String::as_str).collect();
        let parts = match doc.export_root_map_checkpoint(&roots, &mut inventory) {
            Capture::Classified(parts) => parts,
            Capture::Unclassified(_) => {
                tracing::warn!("a window history the checkpoint does not take is read at its rows");
                return inventory;
            }
        };
        // Every key an op or the root wrote, its deletions too: a deleted
        // key carried a row before.
        let skeleton = &parts.skeleton;
        let keys = skeleton
            .changes
            .iter()
            .flat_map(|change| change.ops.iter().map(|op| (op.root, &op.key)))
            .chain(
                skeleton
                    .shallow
                    .iter()
                    .flat_map(|root| &root.winners)
                    .map(|winner| (winner.root, &winner.key)),
            );
        for (root, key) in keys {
            if let Some(root) = skeleton.roots.get(root as usize) {
                inventory.take(root, key, None);
            }
        }
        inventory
    }

    /// Takes the row `key` of root map `root`, and its value when that is a
    /// pad row.
    fn take(&mut self, root: &str, key: &str, value: Option<&LoroValue>) {
        if !ID_ROOTS.contains(&root) {
            return;
        }
        if let Ok(id) = EntityId::from_hex(key) {
            self.ids.insert(id);
        }
        if root == ROWS
            && let Some(LoroValue::Binary(raw)) = value
            && crate::world_keys::pad_body_world(raw).is_some()
            && !self
                .pads
                .iter()
                .any(|held| held.as_slice() == raw.as_slice())
        {
            self.pads.push(Zeroizing::new(raw.to_vec()));
        }
    }

    /// Refuses the tear while a legal hold names a row id it holds, or the
    /// world of a pad it holds or a claim that pad's key seals (OF-470). The
    /// refusal is queued with `actor` on the held id, world or claim. A pad
    /// that does not decode reads unheld, warned, as
    /// [`crate::world_keys::held_pad_world_in_txn`] reads it.
    pub(crate) fn reject_held_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        actor: &HoldActor,
    ) -> Result<()> {
        let ids: Vec<EntityId> = self.ids.iter().copied().collect();
        store.reject_legal_holds_in_txn(txn, &ids, actor)?;
        for raw in &self.pads {
            crate::world_keys::reject_held_pad_carrier_in_txn(store, txn, raw, actor)?;
        }
        Ok(())
    }
}

/// Every key a plain one and every value one holder's: the capture is read
/// for its values and dropped, never joined or kept.
impl Classify for CarrierInventory {
    fn plain_key(&mut self, _root: &str, _key: &str) -> bool {
        true
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        if let Field::Value {
            root, key, value, ..
        } = field
        {
            self.take(root, key, Some(value));
        }
        Some(vec![1])
    }
}
