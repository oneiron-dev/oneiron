//! The handle a stream's terminal reads under: its opener's (FIX 1667).

use super::Seed;
use crate::Vault;
use crate::error::Result;
use crate::memory::Memory;

/// The surface `seed`'s terminal reads and writes through: its actor's,
/// bound to the very proof its opener presented when it presented one, so
/// a narrowed credential stays narrowed, after a restart too. An opener with
/// no bound proof reads as its actor, as before.
pub(super) fn terminal_memory<'v>(vault: &'v Vault, seed: &Seed) -> Result<Memory<'v>> {
    let memory = vault.memory(seed.actor, seed.class()?);
    Ok(match &seed.read_proof {
        Some(proof) => memory.with_read_proof(&proof.restore()),
        None => memory,
    })
}
