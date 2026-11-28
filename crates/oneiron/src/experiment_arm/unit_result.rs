//! The result binding of a line unit (row RSI-ARM-RESULT; ARCH-0053 #training-receipt): where
//! the unit's job lands its returnable outputs. The reserve, and a waiting unit's work order,
//! carry it onto the unit claim; the claim's quote carries it as `inputs.result`; the issuer
//! then lands each returnable output through the built returned-artifact path, as the
//! artifact's next version pending Keep ([`crate::gpu_job::GpuJobResultBinding`]).

use crate::gpu_job::GpuJobResultBinding;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};

/// Admits `binding` for `memory`'s caller as `vault.gpu.jobs.start` admits an agent's chunk:
/// the caller's own read lane, under the credential it presented, reads every row it names
/// (its manifest included). The owner's lane reads every row. The issuer asks again under the
/// starter's lane before the job's first dispatch. Then a manifest it names is an
/// `application/json` artifact (row RSI-ARTIFACT-HANDOFF), as the start door asks.
///
/// # Errors
///
/// `forbidden` (`result_binding_unreadable`) for a row the caller does not read;
/// `invalid_state` (`result_manifest_not_json`) for a manifest that is not JSON; a lane or
/// store failure.
pub(super) fn check_result_binding(
    memory: &Memory<'_>,
    binding: Option<&GpuJobResultBinding>,
) -> MemoryResult<()> {
    let Some(binding) = binding else {
        return Ok(());
    };
    if !memory.gpu_job_result_binding_admits(binding)? {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "result_binding_unreadable: the unit's result binds a row this credential does not read",
            &["Bind an artifact and a task this credential reads."],
        ));
    }
    if true || memory.vault().gpu_job_result_manifest_is_json(binding)? {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "result_manifest_not_json: the unit's result manifest is not an application/json artifact",
        &["Bind an application/json artifact as the manifest."],
    ))
}
