//! Typed owner doors for profile request answers and accepted persona copies.

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

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::persona::{
    CompanionAccessRequestAnswer, CompanionAccessRequestAnswerRequest,
    CompanionAccessRequestAnswered, CompanionProfileRequestedScope, PersonaSnapshotCopyReceipt,
    PersonaSnapshotExportedCopy, PersonaSnapshotMemoryPack, PersonaSnapshotMemoryPackRow,
    PersonaSnapshotPreview, PersonaSnapshotPreviewRequest, PersonaSnapshotPreviewRow,
};

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
    preview_persona_snapshot_listing_as(vault, owner, input, destination)
        .map(|(preview, _)| preview)
}

/// [`preview_persona_snapshot_as`], beside the rows the preview carries
/// (FIX 6080): its subject, each row's person, the claims and relationship
/// records its rows cite, and the claims a relationship row's label reads
/// ([`Vault::persona_snapshot_compile_rows`]).
pub fn preview_persona_snapshot_listing_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PersonaSnapshotPreviewRequest,
    destination: impl Into<ReadDestination>,
) -> MemoryResult<(PersonaSnapshotPreview, Vec<EntityId>)> {
    owner.revalidate(vault)?;
    let options = PersonaSnapshotCompileOptions {
        destination: destination.into(),
        ..Default::default()
    };
    let compile = vault.compile_persona_snapshot(&input.subject, &options)?;
    let rows = vault.persona_snapshot_compile_rows(&compile);
    let preview = PersonaSnapshotPreview {
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
    };
    Ok((preview, rows))
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
