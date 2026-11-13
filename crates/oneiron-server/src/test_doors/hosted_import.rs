//! Doors for `tests/hosted_import_job.rs` ([HOSTED-IMPORT-JOB]) and
//! `tests/hosted_import_verbs.rs` ([HOSTED-IMPORT-VERBS]): the stager
//! `oneiron import <source> <file> --hosted` runs, and one pass of the
//! hosted-import worker `serve` runs, over a vault the test holds.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::Vault;
use oneiron::ingest::history::{HistorySource, HostedImportCanceller, HostedImportId};

use crate::commands::hosted_import::{HostedImports, stage as stage_export};
use crate::server::HousekeepingAdmission;

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

/// One pass of the worker over `vault`, as [`pass`] runs it with no budget,
/// during which the vault's owner cancels hosted import `id` once `landed`
/// conversations of this pass have landed: the cancel comes in between two
/// conversations, as a `vault.imports.cancel` call during a pass does.
///
/// # Errors
///
/// The cancel's or the pass's failure, in its own words.
pub fn pass_cancelled_after(
    vault: &Arc<Vault>,
    vault_path: &Path,
    id: HostedImportId,
    landed: u64,
) -> Result<(), String> {
    let asked = Arc::new(AtomicU64::new(0));
    let refusal = Arc::new(Mutex::new(None::<String>));
    let cancelling = Arc::clone(vault);
    let kept = Arc::clone(&refusal);
    let admission: HousekeepingAdmission = Arc::new(move || {
        if asked.fetch_add(1, Ordering::SeqCst) == landed {
            let cancel = crate::owner::local_owner(&cancelling)
                .map_err(|error| format!("{error:#}"))
                .and_then(|owner| {
                    cancelling
                        .hosted_import_cancel(HostedImportCanceller::Owner(&owner), id)
                        .map_err(|error| error.to_string())
                });
            if let Err(error) = cancel {
                *kept
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                return None;
            }
        }
        Some(Box::new(()) as Box<dyn Send>)
    });
    HostedImports::new(vault_path.to_path_buf(), admission)
        .pass(vault, None)
        .map_err(|error| format!("{error:#}"))?;
    match refusal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        Some(error) => Err(format!("the owner's cancel failed: {error}")),
        None => Ok(()),
    }
}
