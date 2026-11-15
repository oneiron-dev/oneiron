//! Moved from `crates/oneiron/src/dreamer_runner/program/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
pub use oneiron_verb_wire::dreamer_runner::program::types::ArmTurnProgram;
pub use oneiron_verb_wire::dreamer_runner::program::types::DisarmTurnProgram;
pub use oneiron_verb_wire::dreamer_runner::program::types::ProgramRecipePin;
pub use oneiron_verb_wire::dreamer_runner::program::types::ProgramTrigger;
pub use oneiron_verb_wire::dreamer_runner::program::types::TurnProgramRegistration;
use serde::Deserialize;
use serde::Serialize;

pub const ADMISSION_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-admission:v1";

pub const CODE_RUN_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-code-run:v1";

/// The committed turn that woke a program: the TURN, its conversation, and
/// when it landed on the vault's recording clock, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandedTurnRef {
    pub turn: EntityId,
    pub conversation: EntityId,
    pub landed_at: u64,
}

/// The queue run id one admission's attempt carries: its code run's id, as
/// the callable it calls checks it against the caller's leased run.
pub fn run_id(admission: &[u8; 32]) -> String {
    bytes_to_hex_lower(&code_run_bytes(admission))
}

/// The code run one admission's program runs as (DOOR-141 PR2), fixed by
/// the admission so every try of it names the same run.
pub fn code_run_bytes(admission: &[u8; 32]) -> [u8; 16] {
    let digest = blake3::Hasher::new()
        .update(CODE_RUN_DOMAIN)
        .update(admission)
        .finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes
}
