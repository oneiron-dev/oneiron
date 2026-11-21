//! Door for `tests/staged_import_task_fact_settles.rs`: stages a foreign
//! artifact as a Pending import with no admission, as an older door staged
//! bytes today's door refuses (FIX TASK-FACT-STAGED-CONFIRM-NEVER-SETTLES).

use crate::Vault;
use crate::batch::export::{ForeignVaultImportSource, StagedVaultImport, VaultImportReceipt};
use crate::error::Result;
use crate::window_key::WindowKey;

/// Stages `remote` under `classification` and `source` in window `key` as a
/// Pending import whose one admitted part is `remote` unchanged, under the
/// receipt id a stage of the same bytes derives. No admission runs.
///
/// # Errors
///
/// A store error, or a receipt already staged under that id.
pub fn stage_unadmitted(
    vault: &Vault,
    classification: &VaultImportReceipt,
    source: ForeignVaultImportSource,
    key: &WindowKey,
    remote: &[u8],
) -> Result<StagedVaultImport> {
    crate::batch::export::stage_unadmitted_vault_import_for_test(
        vault,
        classification,
        source,
        key,
        remote,
    )
}
