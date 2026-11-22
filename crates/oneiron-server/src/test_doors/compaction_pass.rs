//! Doors for `tests/compaction_seat_exact_model.rs` (FIX-LIST
//! SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED): one pass on code mode's
//! house compaction backend, and one on an agent definition's own writer.
//! Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::ai_host::pass_door::{PassAnswer, house_pass, self_written_pass};
