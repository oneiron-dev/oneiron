//! Doors for `tests/dreamer_context_refusal_settles.rs` (a Dreamer step the provider
//! refuses for its context window settles once, Engine 21 Nov 07:38): whether a failed
//! durable step is a paid scope-summary correction the provider refused for its window,
//! so the summary pages again on a smaller window. Thin wrappers over production APIs
//! only. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use crate::model_step_error::DurableStepError;

/// Whether `error` is a paid shim correction the provider refused for its context
/// window, in either typed shape.
#[doc(hidden)]
pub fn correction_overflow(error: &DurableStepError) -> bool {
    crate::dreamer_consolidation::correction_overflow_for_test(error)
}
