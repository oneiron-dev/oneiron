//! FIX 2783 (OF-540): a `self.team.submit` output that is one exact revision
//! of a CLAIM, `claim:<entity>@<revision>`, or one exact version of the
//! common document a record other than a CLAIM owns,
//! `document:<entity>@<revision>`.
//!
//! Exact read. The run's read lane reads the entity at that revision with
//! the vault's one exact revision reader, in the caller's transaction: the
//! submit's first snapshot, then the review's own writer. A revision the
//! store no longer holds (erased, withdrawn, purged, never written) is
//! missing, and so is one the lane does not read.
//!
//! Kinds. The two kinds are disjoint. `claim:` names a live type-0 CLAIM
//! whose bytes at that revision decode as a claim body. `document:` names a
//! live NOTE, MESSAGE or SUMMARY that owns a common document, at a version
//! that document retains. Any other kind (a CLAIM, a secret's custody, a
//! world key's pad), a bare document slot, a pending fork, and a revision of
//! the record from before its document was born are refused as missing. A
//! NOTE whose read is restricted beyond its scope position (owner-only,
//! explicit-only or relationship-scoped: its author, importer, consent or
//! relationship scope) is refused as unscoped: its review could not keep
//! that restriction, and a review reader would learn the NOTE exists.
//!
//! Scope. A CLAIM revision's review stands in that revision's own scope
//! fields, never its live head's. A document's review stands in its
//! record's position as the writer reads it: one world, one facet, one
//! project, its sensitivity ceiling, and the relationships and privacy a
//! relationship read judges it by. A position the review cannot carry
//! (several worlds, no single facet or project, no ceiling) is refused as
//! unscoped: it is never narrowed to one of its members, and the vault's
//! default never stands in for it.
//!
//! Authorship. The current rule is the one blob and code outputs follow:
//! the host-bound leader of the recorded team submits, and who wrote the
//! revision is not checked.

use heed::RoTxn;
use rmpv::Value;

use super::team_submit_output::{OUTPUT_MISSING, OUTPUT_UNSCOPED, OutputScope, Read};
use crate::claim::{ClaimReadStatus, RelationshipRead, ScopedRead, ScopedReadActorKey};
use crate::code_run::team_submit::OutputRevision;
use crate::error::{Error, Result};
use crate::federation::{ScopeAxis, ScopeId, SensitivityCeiling};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_SUMMARY,
};
use crate::store::result_body_pins::ResultBodyPin;
use crate::vault::{LiveEntityRow, ReadMode, RevisionRef};
use crate::{EntityId, Vault};

/// The claim scope key a review carries its document's sensitivity under.
const SENSITIVITY_SCOPE_KEY: &str = "sensitivity";

/// The claim scope key a review of a private document carries.
const PRIVATE_SCOPE_KEY: &str = "private";

/// How a submit reads its output: a blob or code output on the vault alone,
/// a CLAIM or document revision on the run's read lane.
pub(super) struct OutputReader<'v> {
    vault: &'v Vault,
    /// The run's read key, and the hold on every result body a lane read in
    /// an open transaction may find; only a CLAIM or document output has one.
    lane: Option<(ScopedReadActorKey, ResultBodyPin)>,
}

impl<'v> OutputReader<'v> {
    /// The reader for `output`; `key` is asked only for a CLAIM or document
    /// output.
    pub(super) fn new(
        vault: &'v Vault,
        output: OutputRevision,
        key: impl FnOnce() -> ScopedReadActorKey,
    ) -> Self {
        let lane = match output {
            OutputRevision::Claim { .. } | OutputRevision::Document { .. } => {
                Some((key(), vault.pin_all_result_bodies()))
            }
            OutputRevision::Blob { .. } | OutputRevision::Code { .. } => None,
        };
        Self { vault, lane }
    }

    /// A fresh lane for one transaction, its grant clock prepared: taken
    /// before that transaction opens. `None` for a blob or code output.
    pub(super) fn lane(&self) -> Result<Option<ScopedRead<'v>>> {
        let Some((key, _)) = &self.lane else {
            return Ok(None);
        };
        let lane = self
            .vault
            .scoped_read(key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        lane.persist_grant_clock()?;
        Ok(Some(lane))
    }
}

/// The scope a review of the CLAIM `entity` at `revision` stands in: the
/// revision's own world, relationships, scope, facet and project. The
/// CLAIM's initial ClaimOf weight is its own birth fact, so the review does
/// not carry it.
pub(super) fn claim_revision_scope_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    lane: &ScopedRead<'_>,
    entity: EntityId,
    revision: RevisionRef,
) -> Result<Read<OutputScope>> {
    let live = crate::vault::live_entity_row_in_txn(&vault.store, txn, &entity)?;
    if live.live_type() != Some(ENTITY_TYPE_CLAIM) {
        return Ok(Err(OUTPUT_MISSING));
    }
    let Some((kind, body)) = revision_in_txn(txn, lane, entity, revision)? else {
        return Ok(Err(OUTPUT_MISSING));
    };
    if kind != ENTITY_TYPE_CLAIM {
        return Ok(Err(OUTPUT_MISSING));
    }
    let Ok(body) = crate::claim::decode_claim_body(&body, true) else {
        return Ok(Err(OUTPUT_MISSING));
    };
    Ok(Ok(OutputScope {
        world: body.world,
        rel: body.rel,
        scope: crate::claim::without_initial_weight(body.scope),
        facet: body.scope_facet,
        project: body.scope_project,
    }))
}

/// The scope a review of the common document of `entity` at `revision`
/// stands in: the owning record's position, read in `txn`.
pub(super) fn document_revision_scope_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    lane: &ScopedRead<'_>,
    entity: EntityId,
    revision: RevisionRef,
) -> Result<Read<OutputScope>> {
    let LiveEntityRow::Live { entity_type, body } =
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &entity)?
    else {
        return Ok(Err(OUTPUT_MISSING));
    };
    if !matches!(
        entity_type,
        ENTITY_TYPE_NOTE | ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SUMMARY
    ) || !crate::vault::entity_revision::common_document_retains_in_txn(
        &vault.store,
        txn,
        &entity,
        revision,
    )? {
        return Ok(Err(OUTPUT_MISSING));
    }
    // The lane's exact read comes first: an output it does not read is
    // missing, whatever else is true of it, so a refusal never tells a
    // reader the lane denies that the record or its revision exists.
    match revision_in_txn(txn, lane, entity, revision)? {
        Some((kind, _)) if kind == entity_type => {}
        _ => return Ok(Err(OUTPUT_MISSING)),
    }
    if entity_type == ENTITY_TYPE_NOTE
        && !crate::note::note_vault_readable_in_txn(&vault.store, txn, &entity, &body)?
    {
        return Ok(Err(OUTPUT_UNSCOPED));
    }
    record_position_in_txn(vault, txn, entity, entity_type, &body)
}

/// The type and body of `entity` at `revision`, once `lane` reads it there
/// with the exact revision reader. `None` for a revision the store does not
/// hold, or one the lane does not read.
fn revision_in_txn(
    txn: &RoTxn<'_>,
    lane: &ScopedRead<'_>,
    entity: EntityId,
    revision: RevisionRef,
) -> Result<Option<(u8, Vec<u8>)>> {
    let read = lane.get_entities_parts_with_mode_in_txn(
        txn,
        std::slice::from_ref(&entity),
        ReadMode::Pinned(revision),
    );
    match read {
        Ok(mut parts) => Ok(parts.pop().flatten().map(|(kind, _, body)| (kind, body))),
        Err(Error::EntityNotFound | Error::Artifact(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The review scope of the live record `entity` of `kind`, with body
/// `body`: its stored position, which the review must carry whole, and the
/// relationships and privacy a relationship read judges the record by.
fn record_position_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: EntityId,
    kind: u8,
    body: &[u8],
) -> Result<Read<OutputScope>> {
    let Some(position) = crate::federation::record_scope::disclosure_scope_for_stored_row(
        &vault.store,
        txn,
        entity,
        kind,
        body,
    )?
    else {
        return Ok(Err(OUTPUT_UNSCOPED));
    };
    let (Some(world), Some(facet), Some(project), SensitivityCeiling::AtMost(sensitivity)) = (
        single(&position.worlds),
        single(&position.facets),
        single(&position.audience),
        position.sensitivity,
    ) else {
        return Ok(Err(OUTPUT_UNSCOPED));
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &entity)?
    else {
        return Ok(Err(OUTPUT_MISSING));
    };
    let (rel, private) = match crate::claim::relationship_read(&vault.store, txn, &entity, &raw)? {
        RelationshipRead::Decided(true) => (None, false),
        RelationshipRead::Decided(false) => return Ok(Err(OUTPUT_UNSCOPED)),
        RelationshipRead::Gated { space, private, .. } => (space, private),
    };
    let mut scope = vec![(
        Value::from(SENSITIVITY_SCOPE_KEY),
        Value::from(sensitivity.as_str()),
    )];
    if private {
        scope.push((Value::from(PRIVATE_SCOPE_KEY), Value::Boolean(true)));
    }
    Ok(Ok(OutputScope {
        world: Some(world).filter(|world| *world != crate::claim::base_world_id()),
        rel,
        scope: Some(Value::Map(scope)),
        facet,
        project,
    }))
}

/// The one member of `axis`; `None` for several, none, or every member.
fn single(axis: &ScopeAxis<ScopeId>) -> Option<EntityId> {
    match axis {
        ScopeAxis::Some(members) if members.len() == 1 => members.first().map(|member| member.0),
        _ => None,
    }
}
