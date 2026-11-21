//! Doors for the oneiron-agent-runtime code sandbox lib tests, which moved out
//! of this crate with the sandbox backends and still assert against two of its
//! crate-private items: the Firecracker guest protocol's conformance test
//! (`code_sandbox::firecracker::protocol::tests`) reads a lowered guest write
//! through the pack plan's script output contract, and the QuickJS runtime's
//! refused `report_blocked` test (`code_sandbox::wasmtime_runtime::tests`)
//! looks for a row at an executor speech MESSAGE id. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::EntityId;
use crate::code_sandbox::SandboxProposalWrite;
use crate::error::Result;

/// The bytes the pack plan's script output contract admits from `write`: only a
/// new, bounded file edit at the reserved output path.
///
/// # Errors
///
/// A write outside that contract.
pub fn pack_script_output_bytes(write: &SandboxProposalWrite) -> Result<Vec<u8>> {
    crate::skill_hub::pack_catalog::script_output_bytes(write)
}

/// The standalone MESSAGE id of an executor bubble at bridge position `order`
/// of the run named `run_ref`, with no durable run id folded in.
///
/// # Errors
///
/// An id the derivation cannot form.
pub fn executor_speech_message_id(run_ref: &str, order: u32) -> Result<EntityId> {
    crate::code_run::executor_speech_message_id(run_ref, order)
}
