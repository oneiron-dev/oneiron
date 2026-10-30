//! Who drafted an amended proposal: the executor identity at revision, the
//! task type and the project its run counted in, as the attempt the proposal
//! came from was stamped (FIX 9812, 6038).
//!
//! The stamp is the one the attempt froze when its run began
//! (`AttemptRecord::executor_model`, copied onto its terminal pack receipt).
//! With no attempt stamp, a generated proposal's birth receipt names the
//! model that concluded it. It is never re-derived later from whatever model
//! serves then. A proposal neither names, and a stamp that does not read as
//! `id@revision`, has an unknown executor: recorded as unknown, never refused
//! and never guessed.

use crate::Vault;
use crate::edit_distance::ProposalArtifactRef;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;

/// The executor key of a receipt that carries no executor stamp. It holds no
/// `@`, so no stamped `id@revision` can collide with it.
pub(in crate::edit_distance) const UNKNOWN_EXECUTOR: &str = "unknown";

/// Longest executor stamp accepted: the attempt queue's own bound.
const MAX_EXECUTOR_BYTES: usize = 256;

/// What the evidence door records of one amendment's drafting run.
#[derive(Debug)]
pub(super) struct EvidenceOrigin {
    pub(super) executor: Option<String>,
    pub(super) type_ref: Option<TypeRef>,
    /// The project the run counted in; `None` is the vault's (FIX 6038).
    pub(super) project: Option<EntityId>,
}

/// A run's task type and the project it counted in.
type Placement = (TypeRef, Option<EntityId>);

/// The executor, task type and project the evidence door records for one
/// amendment: the named attempt's stamps first, then the executor the amended
/// proposal's birth receipt names, then what the host stamped, each kept only
/// when it reads as one. The project travels with the task type: an
/// attempt's type brings the project its run counted in, the vault's
/// included; with no attempt type, both are the host's.
///
/// # Errors
///
/// Storage errors reading the attempt's pack receipt or the proposal; a
/// project stamp that is not an entity id.
pub(super) fn evidence_origin(
    vault: &Vault,
    attempt_receipt: Option<&str>,
    proposal: Option<ProposalArtifactRef>,
    executor: Option<&str>,
    type_ref: Option<&TypeRef>,
    project: Option<EntityId>,
) -> Result<EvidenceOrigin> {
    let (mut stamped, placed) = match attempt_receipt {
        Some(receipt) => attempt_origin(vault, receipt)?,
        None => (None, None),
    };
    if stamped.is_none()
        && let Some(proposal) = proposal
    {
        stamped = birth_executor(vault, proposal)?;
    }
    let executor = stamped.or_else(|| executor.and_then(usable_executor));
    let (type_ref, project) = match placed {
        Some((type_ref, project)) => (Some(type_ref), project),
        None => (
            type_ref
                .filter(|type_ref| type_ref.validate().is_ok())
                .cloned(),
            project,
        ),
    };
    Ok(EvidenceOrigin {
        executor,
        type_ref,
        project,
    })
}

/// The executor the attempt behind `attempt_receipt` was stamped with, and
/// where its run was placed: its type stamp with the project frozen beside
/// it, else its frozen attribution's type and project (FIX 6038). Each `None`
/// where its terminal pack receipt records none.
fn attempt_origin(
    vault: &Vault,
    attempt_receipt: &str,
) -> Result<(Option<String>, Option<Placement>)> {
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, attempt_receipt)? else {
        return Ok((None, None));
    };
    let executor = receipt.executor_model().and_then(usable_executor);
    let placed = match receipt.task_type_ref() {
        Some(stamp) => Some((TypeRef::from(&stamp), receipt.task_project()?)),
        None => receipt
            .pack_attribution_fields()
            .ok()
            .map(|fields| (fields.type_ref, fields.project)),
    };
    Ok((executor, placed))
}

/// The executor a generated proposal's birth receipt names (FIX 9812): its
/// process, when a model concluded the proposal, as `identity@version` that
/// reads as a [`ModelId`](crate::llm::ModelId). `None` for a stated
/// proposal, an unretained document, and a process that names no model.
#[cfg(feature = "sync")]
fn birth_executor(vault: &Vault, proposal: ProposalArtifactRef) -> Result<Option<String>> {
    let Some(retained) = crate::edit_distance::retained_proposal(vault, proposal)? else {
        return Ok(None);
    };
    let Ok(document) = retained.document() else {
        return Ok(None);
    };
    Ok(crate::edit_distance::proposal_text::birth_process(vault, document)?
        .filter(|process| process.class == crate::provenance::made_by::MadeByClass::Concluded)
        .map(|process| format!("{}@{}", process.identity, process.version))
        .filter(|stamp| {
            stamp.len() <= MAX_EXECUTOR_BYTES && stamp.parse::<crate::llm::ModelId>().is_ok()
        }))
}

/// No proposal text is retained without the `sync` feature.
#[cfg(not(feature = "sync"))]
const fn birth_executor(_vault: &Vault, _proposal: ProposalArtifactRef) -> Result<Option<String>> {
    Ok(None)
}

/// `stamp` as an executor identity at revision, or `None` when it does not
/// read as one.
fn usable_executor(stamp: &str) -> Option<String> {
    let usable = stamp.len() <= MAX_EXECUTOR_BYTES
        && !stamp.chars().any(char::is_control)
        && stamp
            .rsplit_once('@')
            .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty());
    usable.then(|| stamp.to_owned())
}
