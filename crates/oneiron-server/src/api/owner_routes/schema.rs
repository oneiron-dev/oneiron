//! The OpenAPI schemas of the owner routes handled in [`super`] itself (FIX 11611):
//! `POST /v1/owner/backups/rehearse`, the five `POST /v1/owner/cleanup*`
//! writes, the three `POST /v1/owner/imports/*` writes and `POST
//! /v1/owner/secret-scan`. [`super`] is already past the file-size bar, so
//! their schema fns live here, beside the route files' own.

use super::{
    DecideCleanup, DecideImport, RehearseRequest, RestoreArchived, RevertCleanupRun, SetSecretScan,
};
use crate::owner::{backup, cleanup, imports};
use oneiron::policy_model::SecretScanReceipt;

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

/// The OpenAPI schema of `POST /v1/owner/imports/preview`'s body (FIX 11611):
/// [`imports::ImportBatch`].
pub(crate) fn preview_import_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<imports::ImportBatch>()
}

/// The OpenAPI schema of `POST /v1/owner/imports/preview`'s answer (FIX 11611):
/// [`imports::ImportPreview`].
pub(crate) fn import_preview_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<imports::ImportPreview>()
}

/// The OpenAPI schema of `POST /v1/owner/imports/approve`'s body (FIX 11611),
/// shared with `POST /v1/owner/imports/decline`: [`DecideImport`].
pub(crate) fn decide_import_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DecideImport>()
}

/// The OpenAPI schema of `POST /v1/owner/imports/approve`'s answer (FIX 11611):
/// [`imports::ImportApproved`].
pub(crate) fn import_approved_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<imports::ImportApproved>()
}

/// The OpenAPI schema of `POST /v1/owner/imports/decline`'s answer (FIX 11611):
/// [`imports::ImportDeclined`].
pub(crate) fn import_declined_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<imports::ImportDeclined>()
}

/// The OpenAPI schema of `POST /v1/owner/secret-scan`'s body (FIX 11611): [`SetSecretScan`].
pub(crate) fn set_secret_scan_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetSecretScan>()
}

/// The OpenAPI schema of `POST /v1/owner/secret-scan`'s answer (FIX 11611): [`SecretScanReceipt`].
pub(crate) fn secret_scan_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SecretScanReceipt>()
}
