//! Doors for `tests/compaction_seat_exact_model.rs` (FIX-LIST
//! SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED): one pass on code mode's
//! house compaction backend, and one on an agent definition's own writer.
//! And for `tests/live_fork_refuses_erased_prefix_source.rs` (FIX-LIST
//! ERASE-SERVED-KV-CACHE-OUTLIVES-SOURCE): a live fork's bind and the
//! request its flight's call sends, on the house route.
//! Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::ai_host::pass_door::{
    PassAnswer, house_live_fork_bind, house_live_fork_request, house_pass, self_written_pass,
};
