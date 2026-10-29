//! The OpenAPI schemas of the owner routes handled in [`super`] itself (FIX 11611):
//! `POST /v1/owner/backups/rehearse`, the five `POST /v1/owner/cleanup*`
//! writes and the three `POST /v1/owner/imports/*` writes. [`super`] is
//! already past the file-size bar, so their schema fns live here, beside
//! the route files' own.

use super::{
    DecideCleanup, DecideImport, ModelCatalogSynced, RehearseRequest, RestoreArchived,
    RevertCleanupRun, SetModelCatalog,
};
use crate::owner::{backup, cleanup, imports, note_tombstones, off_record};

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

/// The OpenAPI schema of `PUT /v1/owner/model-catalog`'s body (FIX 11617): [`SetModelCatalog`].
pub(crate) fn set_model_catalog_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetModelCatalog>()
}

/// The OpenAPI schema of `PUT /v1/owner/model-catalog`'s answer (FIX 11617): [`oneiron::skill_hub::ModelCatalogSync`].
pub(crate) fn model_catalog_sync_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<oneiron::skill_hub::ModelCatalogSync>()
}

/// The OpenAPI schema of `POST /v1/owner/model-catalog/sync`'s answer (FIX 11617): [`ModelCatalogSynced`].
pub(crate) fn model_catalog_synced_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ModelCatalogSynced>()
}

/// The OpenAPI schema of `POST /v1/owner/backups`'s answer (FIX 11613): [`backup::BackupOutcome`].
pub(crate) fn backup_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<backup::BackupOutcome>()
}

/// The OpenAPI schema of the note-tombstone decides' body (FIX 11617): [`note_tombstones::Decide`].
pub(crate) fn decide_note_tombstone_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<note_tombstones::Decide>()
}

/// The OpenAPI schema of `POST /v1/owner/notes/tombstones/accept`'s answer (FIX 11617): [`note_tombstones::Tombstoned`].
pub(crate) fn tombstoned_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<note_tombstones::Tombstoned>()
}

/// The OpenAPI schema of `POST /v1/owner/notes/tombstones/decline`'s answer (FIX 11617): [`note_tombstones::TombstoneReview`].
pub(crate) fn tombstone_review_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<note_tombstones::TombstoneReview>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/mode`'s body (FIX 11617): [`off_record::Flip`].
pub(crate) fn flip_off_record_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::Flip>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/mode`'s answer (FIX 11617): [`off_record::Session`].
pub(crate) fn off_record_session_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::Session>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/promote`'s body (FIX 11617): [`off_record::Promote`].
pub(crate) fn promote_off_record_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::Promote>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/promote`'s answer (FIX 11617): [`off_record::Promoted`].
pub(crate) fn off_record_promoted_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::Promoted>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/save`'s body (FIX 11617): [`off_record::SessionName`].
pub(crate) fn save_off_record_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::SessionName>()
}

/// The OpenAPI schema of `POST /v1/owner/off-record/save`'s answer (FIX 11617): [`off_record::Saved`].
pub(crate) fn off_record_saved_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<off_record::Saved>()
}
