//! Door for `tests/fingerprint_keep_lens_callback.rs` (PLAN-UC-04 stage 5): the dedupe key
//! of a lens card press, which the AI host computes in private code.

use oneiron::lens::LensRenderId;

/// The dedupe key a press of `card` under `credential` and `idempotency_key` is queued by.
#[must_use]
pub fn lens_callback_dedupe_key(
    credential: &str,
    card: &LensRenderId,
    idempotency_key: &str,
) -> String {
    crate::ai_host::lens_callback_dedupe_key_for_test(credential, card, idempotency_key)
}
