//! Doors for `tests/hosted_import_job.rs` ([HOSTED-IMPORT-JOB]): the stager
//! `oneiron import <source> <file> --hosted` runs, and one pass of the
//! hosted-import worker `serve` runs, over a vault the test holds.

use std::path::Path;

use oneiron::Vault;
use oneiron::ingest::history::{HistorySource, HostedImportId};

use crate::commands::hosted_import::{HostedImports, stage as stage_export};

/// Stages `file` as a hosted import of `source` in the vault at
/// `vault_path`, as `oneiron import <source> <file> --hosted` does.
///
/// # Errors
///
/// The stager's refusal, in its own words.
pub fn stage(
    vault_path: &Path,
    source: HistorySource,
    file: &Path,
) -> Result<HostedImportId, String> {
    stage_export(vault_path, source, file)
        .map(|(id, _)| id)
        .map_err(|error| format!("{error:#}"))
}

/// One pass of the worker over `vault`, at `vault_path`, admitting every
/// conversation, as plain `serve` admits them. `budget` stops the pass after
/// that many conversations have landed, as a process that stops does.
///
/// # Errors
///
/// The pass's failure, in its own words.
pub fn pass(vault: &Vault, vault_path: &Path, budget: Option<u64>) -> Result<(), String> {
    HostedImports::new(vault_path.to_path_buf(), crate::server::admit_every_pass())
        .pass(vault, budget)
        .map_err(|error| format!("{error:#}"))
}
