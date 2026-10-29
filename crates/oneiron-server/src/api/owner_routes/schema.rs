//! The OpenAPI schemas of the owner routes handled in [`super`] itself (FIX 11611):
//! `POST /v1/owner/backups/rehearse` and the five `POST /v1/owner/cleanup*`
//! writes. [`super`] is already past the file-size bar, so their schema fns
//! live here, beside the route files' own.

use super::{DecideCleanup, RehearseRequest, RestoreArchived, RevertCleanupRun};
use crate::owner::{backup, cleanup};

/// The OpenAPI schema of `POST /v1/owner/backups/rehearse`'s body (FIX 11611):
/// [`RehearseRequest`].
pub(crate) fn rehearse_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RehearseRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/backups/rehearse`'s answer (FIX 11611):
/// [`backup::Rehearsal`].
pub(crate) fn rehearsal_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<backup::Rehearsal>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup`'s body (FIX 11611):
/// [`cleanup::CleanupSettings`].
pub(crate) fn cleanup_settings_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<cleanup::CleanupSettings>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup`'s answer (FIX 11611), shared
/// with `/cleanup/reject` and `/cleanup/restore`: [`cleanup::CleanupReview`].
pub(crate) fn cleanup_review_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<cleanup::CleanupReview>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup/accept`'s body (FIX 11611),
/// shared with `POST /v1/owner/cleanup/reject`: [`DecideCleanup`].
pub(crate) fn decide_cleanup_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DecideCleanup>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup/accept`'s answer (FIX 11611):
/// [`cleanup::Accepted`].
pub(crate) fn cleanup_accepted_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<cleanup::Accepted>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup/restore`'s body (FIX 11611):
/// [`RestoreArchived`].
pub(crate) fn restore_archived_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RestoreArchived>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup/revert-run`'s body (FIX 11611):
/// [`RevertCleanupRun`].
pub(crate) fn revert_cleanup_run_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RevertCleanupRun>()
}

/// The OpenAPI schema of `POST /v1/owner/cleanup/revert-run`'s answer
/// (FIX 11611): [`cleanup::RunReverted`].
pub(crate) fn run_reverted_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<cleanup::RunReverted>()
}
