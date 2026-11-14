//! Door for `tests/context_pack_token_budget_encodes.rs` (FIX 198, F21 B5 /
//! H68): counts the whole-pack encodes, the `serialize_prepared_pack` calls,
//! that a closure makes on this thread. A test can then hold the
//! serialized-output token budget to the ruling's bound of seven encodes per
//! serialized pack without timing anything.

use std::cell::Cell;

thread_local! {
    static PACK_ENCODES: Cell<usize> = const { Cell::new(0) };
}

/// Runs `run` and returns its value with the number of whole-pack encodes it
/// made on this thread.
pub fn count_pack_encodes<T>(run: impl FnOnce() -> T) -> (T, usize) {
    PACK_ENCODES.with(|encodes| encodes.set(0));
    let value = run();
    (value, PACK_ENCODES.with(Cell::get))
}

/// The count point, at the top of `serialize_prepared_pack`.
pub(crate) fn record_pack_encode() {
    PACK_ENCODES.with(|encodes| encodes.set(encodes.get().saturating_add(1)));
}
