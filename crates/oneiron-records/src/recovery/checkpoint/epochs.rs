//! Moved from `crates/oneiron/src/recovery/checkpoint/epochs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::recovery::checkpoint::pad_custody::PadRestoreNote;
use heed::RwTxn;
use oneiron_authority::authority::WorldKeyId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// What one restore epoch still owes of the world key pads its image named
/// (PAD-2, FIX 10470).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePadState {
    /// Each bare reference the restore left unrested, Pending, Withheld or
    /// in a Locked world, by its key's exact full id, until it resolves or
    /// is erased.
    pub required_refs: Vec<WorldKeyId>,
    /// What the restore said of the pads it did not land at rest, as
    /// reconciled since.
    pub remaining: Vec<PadRestoreNote>,
}

impl RestorePadState {
    /// Nothing owed and nothing to say: the row keeps today's form.
    pub fn is_empty(&self) -> bool {
        self.required_refs.is_empty() && self.remaining.is_empty()
    }

    /// `remaining` with no reference owed: an activation's erased pads.
    pub fn settled(remaining: Vec<PadRestoreNote>) -> Self {
        Self {
            required_refs: Vec::new(),
            remaining,
        }
    }

    /// The references owed in the worlds its notes name Locked, by world:
    /// what the kit or an admitted machine opens.
    pub fn locked_refs(&self) -> BTreeMap<oneiron_contracts::entity_id::EntityId, Vec<WorldKeyId>> {
        let locked: BTreeSet<&str> = self
            .remaining
            .iter()
            .filter_map(|note| match note {
                PadRestoreNote::Locked { world } => Some(world.as_str()),
                _ => None,
            })
            .collect();
        let mut owed: BTreeMap<_, Vec<WorldKeyId>> = BTreeMap::new();
        for key in &self.required_refs {
            if locked.contains(key.world.to_hex().as_str()) {
                owed.entry(key.world).or_default().push(*key);
            }
        }
        owed
    }
}
