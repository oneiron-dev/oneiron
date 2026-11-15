//! The handle a stream's terminal reads under: its opener's (FIX 1667).

use super::Seed;
use crate::Vault;
use crate::error::Result;
use crate::memory::Memory;

/// The surface `seed`'s terminal reads and writes through: its actor's,
/// bound to the very proof its opener presented when it presented one, so
/// a narrowed credential stays narrowed, after a restart too. An opener with
/// no bound proof reads as its actor, as before. A Retry's binds the sitting
/// its replaced reply joined.
pub(super) fn terminal_memory<'v>(vault: &'v Vault, seed: &Seed) -> Result<Memory<'v>> {
    let memory = vault.memory(seed.actor, seed.class()?);
    // A Retry's new TURN joins the sitting the reply it answers again
    // joined, read here from that reply's TURN, never named by the opener
    // (FIX 1034), as FIX G230-RETRY-OMITTED-SESSION-BAND places a room's.
    let memory = match &seed.action {
        Some(action) => {
            let txn = vault.store.env.read_txn()?;
            match vault.turn_sitting_key_in_txn(&txn, &action.assistant_turn)? {
                Some(key) => memory.with_session(key),
                None => memory,
            }
        }
        None => memory,
    };
    Ok(match &seed.read_proof {
        Some(proof) => memory.with_read_proof(&proof.restore()),
        None => memory,
    })
}
