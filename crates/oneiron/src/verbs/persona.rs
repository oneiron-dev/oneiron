//! Typed owner doors for profile request answers and accepted persona copies.

use serde::{Deserialize, Serialize};

use crate::access_grant::AccessRequestStatus;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::persona_snapshot::{
    PersonaSnapshotArtifact, PersonaSnapshotCompileOptions, PersonaSnapshotCopyEditRequest,
    PersonaSnapshotCopyRequest,
};
use crate::settings::ReadDestination;
use crate::share_travel::{CopyRefs, effective_copy_refs};
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompanionAccessRequestAnswer {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanionAccessRequestAnswerRequest {
    pub request: EntityId,
    pub answer: CompanionAccessRequestAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompanionProfileRequestedScope {
    CompanionProfile {
        person_ref: EntityId,
        facet_ref: Option<EntityId>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CompanionAccessRequestAnswered {
    pub request: EntityId,
    pub principal_ref: EntityId,
    pub capability: String,
    pub scope: CompanionProfileRequestedScope,
    pub status: AccessRequestStatus,
    /// Approval creates exactly this grant at the request's id; denial creates none.
    pub grant_ref: Option<EntityId>,
    pub decided_by: Option<EntityId>,
    pub decided_at: Option<u64>,
}

pub fn answer_companion_access_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CompanionAccessRequestAnswerRequest,
) -> MemoryResult<CompanionAccessRequestAnswered> {
    let answered = vault.respond_companion_access_request(
        owner,
        input.request,
        matches!(input.answer, CompanionAccessRequestAnswer::Approve),
        crate::unix_seconds_now(),
    )?;
    let (person_ref, facet_ref) = answered
        .grant
        .scope
        .companion_profile_refs()
        .ok_or_else(|| MemoryError::bad_request("request is not for a companion profile"))?;
    Ok(CompanionAccessRequestAnswered {
        request: answered.id,
        principal_ref: answered.grant.principal_ref,
        capability: answered.grant.capability.as_str().to_owned(),
        scope: CompanionProfileRequestedScope::CompanionProfile {
            person_ref,
            facet_ref,
        },
        status: answered.status,
        grant_ref: (answered.status == AccessRequestStatus::Approved).then_some(answered.id),
        decided_by: answered.decided_by,
        decided_at: answered.decided_at,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotPreviewRequest {
    pub subject: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotPreviewRow {
    pub row_id: String,
    pub kind: String,
    pub text: String,
    pub provenance_refs: Vec<String>,
    pub attribution: Option<String>,
    pub struck: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotPreview {
    pub subject: EntityId,
    pub stamp: String,
    pub identity_line: String,
    pub rows: Vec<PersonaSnapshotPreviewRow>,
    /// RFC 3339 UTC compile time, as on the owner's persona surface.
    pub compiled_at: String,
    pub stale_after_secs: u64,
}

/// The structured mode-A render, from the same compile as the markdown card.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotMemoryPack {
    pub schema: String,
    pub kind: String,
    /// Absent from a copy made without its vault refs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<EntityId>,
    pub identity_line: Option<String>,
    pub audience_ref: Option<String>,
    pub takes_included: bool,
    pub compiled_at_secs: u64,
    pub stale_after_secs: u64,
    pub persona_compile_stamp: String,
    pub rows: Vec<PersonaSnapshotMemoryPackRow>,
}

/// Relationship rows carry only coarse text; the other rows retain sources.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotMemoryPackRow {
    pub row_id: String,
    pub kind: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salience: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotExportedCopy {
    pub export_id: EntityId,
    pub subject: EntityId,
    pub stamp: String,
    /// The copy edited to issue this version; null for the initial export.
    pub previous_export_id: Option<EntityId>,
    pub memory_pack: PersonaSnapshotMemoryPack,
    /// The MemoryPack-lite render's exact bytes, as the export issued them
    /// and its receipt's fingerprint covers them; `memory_pack` is their
    /// typed view.
    pub memory_pack_json: String,
    pub markdown: String,
    pub included_row_ids: Vec<String>,
    pub struck_row_ids: Vec<String>,
    pub compiled_at: String,
    pub stale_after_secs: u64,
    /// What this copy is, by digest, and what it left out (FIX 1199).
    pub receipt: PersonaSnapshotCopyReceipt,
}

/// A persona copy's local receipt (FIX 1199): the export record's digest of
/// both renders and the vault ref slots they left out. It names the copy;
/// it grants nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotCopyReceipt {
    /// The ref choice the copy was made under.
    pub refs: CopyRefs,
    /// blake3 hex over both renders as the export issued them:
    /// `memory_pack_json`, a NUL byte, then `markdown`.
    pub artifact_fingerprint: String,
    /// The vault ref slots both renders left out (`subject_ref`,
    /// `audience_ref` and `provenance_refs` dropped; `row_id` and
    /// `attribution` under copy-local labels); empty for `preserve`.
    pub omitted_refs: Vec<String>,
}

fn compiled_at(seconds: u64) -> MemoryResult<String> {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .ok_or_else(|| MemoryError::bad_request("compile time is outside RFC 3339 range"))
}

pub fn preview_persona_snapshot_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PersonaSnapshotPreviewRequest,
    destination: impl Into<ReadDestination>,
) -> MemoryResult<PersonaSnapshotPreview> {
    owner.revalidate(vault)?;
    let compile = vault.compile_persona_snapshot(
        &input.subject,
        &PersonaSnapshotCompileOptions {
            destination: destination.into(),
            ..Default::default()
        },
    )?;
    Ok(PersonaSnapshotPreview {
        subject: compile.subject_ref,
        stamp: compile.stamp.identity(),
        identity_line: compile.identity_line,
        rows: compile
            .rows
            .into_iter()
            .map(|row| PersonaSnapshotPreviewRow {
                row_id: row.row_id,
                kind: row.kind.as_str().to_owned(),
                text: row.text,
                provenance_refs: row.provenance_refs,
                attribution: row.attribution,
                struck: row.struck,
            })
            .collect(),
        compiled_at: compiled_at(compile.compiled_at_secs)?,
        stale_after_secs: compile.stale_after_secs,
    })
}

fn exported_copy(
    artifact: PersonaSnapshotArtifact,
    previous_export_id: Option<EntityId>,
    refs: CopyRefs,
) -> MemoryResult<PersonaSnapshotExportedCopy> {
    Ok(PersonaSnapshotExportedCopy {
        export_id: artifact.export_id,
        subject: artifact.subject_ref,
        stamp: artifact.stamp.identity(),
        previous_export_id,
        memory_pack: serde_json::from_str(&artifact.memory_pack_json)
            .map_err(|_| MemoryError::bad_request("invalid persona MemoryPack JSON"))?,
        memory_pack_json: artifact.memory_pack_json,
        markdown: artifact.markdown,
        included_row_ids: artifact.included_row_ids,
        struck_row_ids: artifact.struck_row_ids,
        compiled_at: compiled_at(artifact.compiled_at_secs)?,
        stale_after_secs: artifact.stale_after_secs,
        receipt: PersonaSnapshotCopyReceipt {
            refs,
            artifact_fingerprint: artifact.artifact_fingerprint,
            omitted_refs: artifact.omitted_refs,
        },
    })
}

pub fn export_persona_snapshot_copy_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PersonaSnapshotCopyRequest,
    destination: impl Into<ReadDestination>,
) -> MemoryResult<PersonaSnapshotExportedCopy> {
    exported_copy(
        vault.export_persona_snapshot_copy_as(owner, &input, destination)?,
        None,
        effective_copy_refs(input.travel.as_ref()),
    )
}

pub fn edit_persona_snapshot_copy_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PersonaSnapshotCopyEditRequest,
    destination: impl Into<ReadDestination>,
) -> MemoryResult<PersonaSnapshotExportedCopy> {
    let previous = input.export_id;
    exported_copy(
        vault.edit_persona_snapshot_copy_as(owner, &input, destination)?,
        Some(previous),
        effective_copy_refs(input.travel.as_ref()),
    )
}
