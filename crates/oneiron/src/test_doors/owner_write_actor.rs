//! Door for `tests/handed_on_person_sweep.rs`: the owner-verb rule
//! ([`crate::authority::write_authorization`]) as the bound handle meets it,
//! through the handle's own marked write actor. The gate is `pub(crate)` and
//! no simple public `Memory` door reaches it without an owner proof (which a
//! handed-on holder cannot mint), so the sweep tests it directly. A handed-on
//! credential acts as its key's holder, never the person it names
//! (HANDED-ON-SLIP-PERSON).

use crate::memory::Memory;

/// Runs the owner-verb rule for `memory`'s bound actor: `Ok(())` when the
/// handle acts as its own person and the owner binding holds, else the
/// gate's refusal as text.
#[must_use = "the gate's answer is the test's assertion"]
pub fn verify_for_test(memory: &Memory<'_>) -> Result<(), String> {
    let vault = memory.vault();
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| error.to_string())?;
    vault
        .verify_owner_write_actor_in_txn(&txn, &memory.write_actor())
        .map_err(|error| error.to_string())
}
