//! Moved from `crates/oneiron/src/recovery/checkpoint/pad_custody.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::recovery::checkpoint::epochs::RestorePadState;
use heed::RwTxn;
use heed::types::Bytes;
use image::CheckpointImage;
use oneiron_authority::authority::WorldKeyId;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// What a restore says of a world key pad its image names that it did not
/// land at rest (CALLS: KS-5 restore outcomes); its epoch keeps it
/// (`RestorePadState`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PadRestoreNote {
    /// The custody the restore took retired the pad after the image was
    /// taken: its row stayed out, as the erase left it.
    ErasedUnavailable { world: String, generation: u64 },
    /// The world's sealed copies keep its pads off a custody head, and the
    /// custody this restore took does not hold this one: its row waits as a
    /// reference for the pad from one of the owner's machines.
    Withheld { world: String, generation: u64 },
    /// The live vault the restore carried this row from holds it only as a
    /// reference, its pad not there yet: it stays so here, pending.
    Pending { world: String, generation: u64 },
    /// The custody head this restore opened did not give it the world's
    /// pads: their compartment opens only with the recovery kit or a machine
    /// the world admits (FIX 9178). The world's rows wait as references,
    /// locked, never readable and never dropped, until one opens them or a
    /// machine of the owner's hydrates them. One note per world.
    Locked { world: String },
}

impl PadRestoreNote {
    pub fn erased(key: &WorldKeyId) -> Self {
        Self::ErasedUnavailable {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }

    fn withheld(key: &WorldKeyId) -> Self {
        Self::Withheld {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }

    fn pending(key: &WorldKeyId) -> Self {
        Self::Pending {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }

    fn locked(world: EntityId) -> Self {
        Self::Locked {
            world: world.to_hex(),
        }
    }
}

impl std::fmt::Display for PadRestoreNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErasedUnavailable { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad erased since the image, unavailable"
            ),
            Self::Withheld { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad withheld by the world's sealed \
                 copies setting, pending from the owner's machines"
            ),
            Self::Pending { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad pending, as in the vault restored \
                 over"
            ),
            Self::Locked { world } => write!(
                f,
                "world {world}: pads locked, pending: opens with the kit or an admitted machine"
            ),
        }
    }
}
