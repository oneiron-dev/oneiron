//! The sync lanes' wake for relayed ask intents (FIX 7494).
//!
//! A relayed intent is an ordinary TASK row to the entity transport: no
//! wire tag, timer or cap of its own carries it, and its arrival alone
//! authorizes nothing. Once an import committed rows here, a lane hands the
//! intents it landed for asks this node admitted to the ask's own consumer
//! (`task_verb::drain_ask_forward_intents`), which verifies the holder's
//! proof and consumes each once. An intent whose rows have not all landed
//! stays for the next import or the next ask sweep.

use crate::Vault;

/// Consumes the relayed ask intents an import landed here. A failure is
/// logged, and the intents stay for the next import or ask sweep.
pub fn consume_landed_intents(vault: &Vault) {
    if let Err(error) = crate::task_verb::drain_ask_forward_intents(vault) {
        tracing::warn!(%error, "relayed ask intents were not consumed after an import");
    }
}
