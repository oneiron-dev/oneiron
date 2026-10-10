//! Persona snapshot, mode A (OF-325): compile a shareable card about one
//! person, let the owner strike rows at preview, and export what is left as
//! MemoryPack-lite JSON plus a markdown card, receipted as a Share.
//!
//! Export names the stamp the owner previewed. The engine recompiles and
//! refuses when the card changed since, so an export never carries rows the
//! owner did not see. A handed copy is a copy: revoking means not issuing
//! another.

use oneiron::consent::AuthenticatedOwner;
use oneiron::persona_snapshot::{
    PersonaSnapshotCompile, PersonaSnapshotCompileOptions, PersonaSnapshotStrikeList,
};
use oneiron::{ErrorKind, Vault};
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// The card as the owner reviews it before export.
#[derive(Debug, Serialize)]
pub(crate) struct Preview {
    pub(crate) subject: String,
    /// Send this back with the export: it names exactly these rows.
    pub(crate) stamp: String,
    pub(crate) identity_line: String,
    /// Rows in render order. A `struck` row stays out unless un-struck;
    /// claims about other people start struck.
    pub(crate) rows: Vec<Row>,
    pub(crate) compiled_at: String,
    /// How long after compiling a reader should treat the card as stale.
    pub(crate) stale_after_secs: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Row {
    /// Names the row in `strike` and `unstrike`.
    pub(crate) row_id: String,
    pub(crate) kind: &'static str,
    pub(crate) text: String,
    pub(crate) provenance_refs: Vec<String>,
    pub(crate) attribution: Option<String>,
    pub(crate) struck: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportRequest {
    /// The person the card is about.
    pub(crate) subject: String,
    /// The stamp the preview returned.
    pub(crate) stamp: String,
    /// Row ids to leave out.
    #[serde(default)]
    pub(crate) strike: Vec<String>,
    /// Default-struck row ids to let in.
    #[serde(default)]
    pub(crate) unstrike: Vec<String>,
}

/// The exported card.
#[derive(Debug, Serialize)]
pub(crate) struct Exported {
    /// The export record; its Share receipt carries the compile stamp.
    pub(crate) export_id: String,
    pub(crate) subject: String,
    pub(crate) stamp: String,
    /// MemoryPack-lite, for agents.
    pub(crate) memory_pack: serde_json::Value,
    /// The card for people.
    pub(crate) markdown: String,
    pub(crate) included_row_ids: Vec<String>,
    pub(crate) struck_row_ids: Vec<String>,
    pub(crate) compiled_at: String,
    pub(crate) stale_after_secs: u64,
}

pub(crate) fn preview(vault: &Vault, subject: &str) -> OwnerResult<Preview> {
    let compile = compile(vault, subject)?;
    Ok(Preview {
        subject: compile.subject_ref.to_hex(),
        stamp: compile.stamp.identity(),
        identity_line: compile.identity_line.clone(),
        rows: compile
            .rows
            .iter()
            .map(|row| Row {
                row_id: row.row_id.clone(),
                kind: row.kind.as_str(),
                text: row.text.clone(),
                provenance_refs: row.provenance_refs.clone(),
                attribution: row.attribution.clone(),
                struck: row.struck,
            })
            .collect(),
        compiled_at: rfc3339_secs(compile.compiled_at_secs),
        stale_after_secs: compile.stale_after_secs,
    })
}

pub(crate) fn export(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &ExportRequest,
) -> OwnerResult<Exported> {
    let compile = compile(vault, &request.subject)?;
    let strikes = PersonaSnapshotStrikeList {
        strike: request.strike.iter().cloned().collect(),
        unstrike: request.unstrike.iter().cloned().collect(),
    };
    let artifact = vault
        .export_persona_snapshot_as(owner, &compile, &strikes, &request.stamp)
        .map_err(|error| match error.kind() {
            ErrorKind::PersonaSnapshotConsentStale => OwnerError::Changed(
                "the card changed since its preview; preview it again".to_owned(),
            ),
            ErrorKind::InvalidPersonaSnapshot => OwnerError::Invalid(error.to_string()),
            _ => OwnerError::from(error),
        })?;
    let memory_pack = serde_json::from_str(&artifact.memory_pack_json)
        .map_err(|error| OwnerError::Host(anyhow::anyhow!("persona card JSON: {error}")))?;
    Ok(Exported {
        export_id: artifact.export_id.to_hex(),
        subject: artifact.subject_ref.to_hex(),
        stamp: artifact.stamp.identity(),
        memory_pack,
        markdown: artifact.markdown,
        included_row_ids: artifact.included_row_ids,
        struck_row_ids: artifact.struck_row_ids,
        compiled_at: rfc3339_secs(artifact.compiled_at_secs),
        stale_after_secs: artifact.stale_after_secs,
    })
}

/// The owner's own compile: no audience clamp beyond Tier A, agent takes off.
fn compile(vault: &Vault, subject: &str) -> OwnerResult<PersonaSnapshotCompile> {
    let subject_id = entity_id("subject", subject)?;
    vault
        .compile_persona_snapshot(&subject_id, &PersonaSnapshotCompileOptions::default())
        .map_err(|error| match error.kind() {
            ErrorKind::EntityNotFound => OwnerError::NotFound("person", subject.to_owned()),
            ErrorKind::InvalidPersonaSnapshot | ErrorKind::InvalidEntityType => {
                OwnerError::Invalid(error.to_string())
            }
            _ => OwnerError::from(error),
        })
}
