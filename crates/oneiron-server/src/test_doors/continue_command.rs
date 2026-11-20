//! Door for `tests/continue_command.rs` (census L10-17): `oneiron continue
//! --cloud`'s hand-off commit, its session log discovery, and its steps run
//! against a scripted vault, since the command's own vault is a hosted one
//! reached through `oneiron mcp`; and its push, Git-LFS objects first, to a
//! custody repo a test serves.

pub use crate::commands::continue_test_support::{
    Script, Scripted, discovered_session, hand_off_commit, push_hand_off, run_scripted,
};
