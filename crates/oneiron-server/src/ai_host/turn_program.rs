//! The host's half of DOOR-141: the wakes a landed turn's own commit owed its
//! actor's armed programs, typed refs and sealed authority included, are
//! admitted off the request path, after each turn and once at boot, through
//! the engine's one dedupe and admission.

use oneiron::Vault;

/// Admits every owed program wake, a batch at a time, until none is left or
/// a batch makes no progress. A failure is logged; the wakes it leaves wait
/// for the next turn or the next boot.
pub(super) fn drain_turn_programs(vault: &Vault) {
    loop {
        match vault.wake_turn_programs(vault.now_recorded_at()) {
            Ok(drain) if drain.more => {}
            Ok(_) => return,
            Err(error) => {
                tracing::warn!(%error, "turn program wakes not admitted");
                return;
            }
        }
    }
}
