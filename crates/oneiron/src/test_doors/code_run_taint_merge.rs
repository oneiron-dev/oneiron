//! Doors for `tests/code_run_taint_merge_dup_gen.rs`
//! (CODE-RUN-TAINT-MERGE-DUP-GEN): the taint-mark inherit a result-storing
//! write runs over the sources it names.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Vault;
use crate::code_run::CodeRunRawOutput;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Marks run `owner`'s occurrence of `output` with the taint of every
/// occurrence in `from` (each by the run that holds it), as a stored-result
/// write does for the sources it names.
///
/// # Errors
///
/// The store's, or a merged ref set no row may carry.
pub fn inherit_result_marks(
    vault: &Vault,
    owner: EntityId,
    output: &CodeRunRawOutput,
    from: &[(EntityId, CodeRunRawOutput)],
) -> Result<()> {
    vault.inherit_code_run_result_marks(owner, output, from)
}
