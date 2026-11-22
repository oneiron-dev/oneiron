//! Doors for `tests/vault_inbox_doors.rs`: land one agent-health concern
//! card through the engine's own landing path (`pipeline::land`), as the
//! Coach's review lands one, so the owner inbox doors have a real card to
//! show and settle. No public verb seeds a concern card.

pub use crate::dreamer_runner::maintenance::agent_health::test_door::land_concern;
