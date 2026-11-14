//! Door for `tests/check_in_share_create_effects.rs` (ROLES-CHECKIN P2.5
//! 2k8g review): what the retry of a paced call reads when the call's turn
//! ended refused (`crate::runtime_hooks::verb::paced_replay_door`).
//! Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::runtime_hooks::verb::paced_replay_door::replayed_ended_error;
