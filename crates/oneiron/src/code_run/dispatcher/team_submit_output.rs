//! The output a `self.team.submit` names (OF-540), as one snapshot reads it:
//! proven to exist as pinned, and the scope the review of it stands in. A
//! blob or code output's scope is the one its own recorded claim carries:
//! the exact blob version's `blob.version` claim, or the code revision's
//! provenance claim. A CLAIM or document revision's (FIX 2783) is read by
//! [`super::team_submit_entity`]. The review copies that scope, so it is
//! never wider than the output; an output with no scope the review can carry
//! is refused, and the vault's default scope never stands in for it. A
//! scope whose relationship is no longer a live RELATIONSHIP is refused in
//! the review's writer.

use heed::RoTxn;
use rmpv::Value;

use super::team_submit_entity::{claim_revision_scope_in_txn, document_revision_scope_in_txn};
use crate::claim::ScopedRead;
use crate::code_revision::CodeRevisionKind;
use crate::code_run::team_submit::OutputRevision;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_RELATIONSHIP};
use crate::vault::RevisionRef;
use crate::{ClaimBody, ClaimCandidate, EntityId, Vault};

/// The output is not there as pinned.
pub(super) const OUTPUT_MISSING: &str = "team_submit_output_missing";

/// The output has no scope the review can carry: no recorded claim to take
/// it from, a claim that cannot be read, or a record position the review
/// cannot stand in whole.
pub(super) const OUTPUT_UNSCOPED: &str = "team_submit_output_unscoped";

/// The output's recorded claim names a relationship that is no longer a
/// live RELATIONSHIP, so no review can stand in its scope.
const SCOPE_STALE: &str = "team_submit_scope_stale";

/// A read of the output, or the guest's failure code.
pub(super) type Read<T> = std::result::Result<T, &'static str>;

/// Where a submitted output's scope was read from.
#[derive(Debug, PartialEq)]
enum ScopeSource {
    /// The output's own recorded claim: the exact blob version's
    /// `blob.version` claim, or the code revision's provenance claim.
    RecordedClaim(EntityId),
    /// The submitted CLAIM revision's own scope fields.
    ClaimRevision(RevisionRef),
    /// The position of the record that owns the submitted document version.
    DocumentRecord(RevisionRef),
}

/// The scope a review of one output stands in.
pub(super) struct OutputScope {
    pub(super) world: Option<EntityId>,
    pub(super) rel: crate::claim::RelationshipScope,
    pub(super) scope: Option<Value>,
    pub(super) facet: EntityId,
    pub(super) project: EntityId,
}

/// A submitted output: the entity the review is about, and the scope the
/// review stands in.
#[derive(Debug, PartialEq)]
pub(super) struct OutputDescriptor {
    subject: EntityId,
    /// Where the scope below was read from.
    source: ScopeSource,
    world: Option<EntityId>,
    rel: crate::claim::RelationshipScope,
    scope: Option<Value>,
    facet: EntityId,
    project: EntityId,
}

impl OutputDescriptor {
    /// The entity the review is about: the blob artifact, the code
    /// revision, the CLAIM, or the record that owns the document.
    pub(super) const fn subject(&self) -> EntityId {
        self.subject
    }

    /// `candidate` in the output's scope: its facet and project, its world,
    /// its relationship and its scope restrictions.
    pub(super) fn scoped(&self, candidate: ClaimCandidate) -> ClaimCandidate {
        let mut candidate = candidate.with_scope_stamps(self.facet, self.project);
        if let Some(world) = self.world {
            candidate = candidate.with_world(world);
        }
        candidate = candidate.with_relationships(self.rel.clone());
        if let Some(scope) = &self.scope {
            candidate = candidate.with_scope(scope.clone());
        }
        candidate
    }

    /// Whether `body` stands in exactly the output's scope.
    pub(super) fn scopes(&self, body: &ClaimBody) -> bool {
        body.world == self.world
            && body.rel == self.rel
            && body.scope == self.scope
            && body.scope_facet == self.facet
            && body.scope_project == self.project
    }

    /// Whether the output's scope still stands in `txn`: every relationship
    /// it names must still be a live RELATIONSHIP, as the review's own write
    /// requires. A refusal is the guest's failure code.
    pub(super) fn scope_stands_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Read<()>> {
        for rel in self.rel.iter().flatten() {
            let found = crate::vault::live_entity_row_in_txn(&vault.store, txn, rel)?.live_type();
            if found != Some(ENTITY_TYPE_RELATIONSHIP) {
                return Ok(Err(SCOPE_STALE));
            }
        }
        Ok(Ok(()))
    }
}

/// Reads `output` in `txn`: proves it exists as pinned, then reads the scope
/// the review of it stands in. A CLAIM or document revision is read on
/// `lane`, the run's read lane. A refusal is the guest's failure code.
pub(super) fn output_descriptor_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    lane: Option<&ScopedRead<'_>>,
    output: OutputRevision,
) -> Result<Read<OutputDescriptor>> {
    let unlaned = || Error::InvariantViolation("team submit entity output read without a lane");
    let read = match output {
        OutputRevision::Blob { artifact, version } => {
            let scope_claim = blob_scope_claim_in_txn(vault, txn, artifact, version)?;
            recorded_claim_scope_in_txn(vault, txn, scope_claim)?
        }
        OutputRevision::Code { revision } => {
            let scope_claim = code_scope_claim_in_txn(vault, txn, revision)?;
            recorded_claim_scope_in_txn(vault, txn, scope_claim)?
        }
        OutputRevision::Claim { entity, revision } => {
            let lane = lane.ok_or_else(unlaned)?;
            claim_revision_scope_in_txn(vault, txn, lane, entity, revision)?
                .map(|scope| (ScopeSource::ClaimRevision(revision), scope))
        }
        OutputRevision::Document { entity, revision } => {
            let lane = lane.ok_or_else(unlaned)?;
            document_revision_scope_in_txn(vault, txn, lane, entity, revision)?
                .map(|scope| (ScopeSource::DocumentRecord(revision), scope))
        }
    };
    Ok(read.map(|(source, scope)| OutputDescriptor {
        subject: output.subject(),
        source,
        world: scope.world,
        rel: scope.rel,
        scope: scope.scope,
        facet: scope.facet,
        project: scope.project,
    }))
}

/// The scope the output's recorded claim `scope_claim` carries; a refusal
/// reading that claim's id passes through.
fn recorded_claim_scope_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    scope_claim: Read<EntityId>,
) -> Result<Read<(ScopeSource, OutputScope)>> {
    let scope_claim = match scope_claim {
        Ok(id) => id,
        Err(code) => return Ok(Err(code)),
    };
    let Some(body) = vault.get_claim_in_txn(txn, &scope_claim).ok().flatten() else {
        return Ok(Err(OUTPUT_UNSCOPED));
    };
    Ok(Ok((
        ScopeSource::RecordedClaim(scope_claim),
        OutputScope {
            world: body.world,
            rel: body.rel,
            scope: body.scope,
            facet: body.scope_facet,
            project: body.scope_project,
        },
    )))
}

/// The exact version's `blob.version` claim, once the artifact, the
/// version's record bound to that claim, and the stored bytes its content
/// hash names are all there. A head is never read in its place.
fn blob_scope_claim_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: EntityId,
    version: u64,
) -> Result<Read<EntityId>> {
    match vault.get_blob_artifact_in_txn(txn, &artifact) {
        Ok(Some(_)) => {}
        Ok(None) | Err(Error::Artifact(_)) => return Ok(Err(OUTPUT_MISSING)),
        Err(error) => return Err(error),
    }
    let Some(record) = vault.blob_artifact_version_metadata_in_txn(txn, &artifact, version)? else {
        return Ok(Err(OUTPUT_MISSING));
    };
    match vault.read_blob_artifact_version_in_txn(txn, &artifact, version) {
        Ok(Some(_)) => Ok(Ok(record.claim_id)),
        Ok(None) | Err(Error::EntityNotFound) => Ok(Err(OUTPUT_MISSING)),
        Err(error) => Err(error),
    }
}

/// The code revision's provenance claim, once the revision is a
/// CODE_ARTIFACT entity and the verified reader answers it finalized as a
/// commit or a revert. A bare finalized bit is no proof.
fn code_scope_claim_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    revision: EntityId,
) -> Result<Read<EntityId>> {
    let is_code_artifact =
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &revision)?
            .is_some_and(|row| row.entity_type == ENTITY_TYPE_CODE_ARTIFACT);
    if !is_code_artifact {
        return Ok(Err(OUTPUT_MISSING));
    }
    let finalized = match vault.get_code_revision_in_txn(txn, &revision) {
        Ok(found) => found.filter(|record| {
            matches!(
                record.kind,
                CodeRevisionKind::Commit | CodeRevisionKind::Revert
            )
        }),
        Err(Error::Artifact(_) | Error::EntityNotFound) => None,
        Err(error) => return Err(error),
    };
    let Some(finalized) = finalized else {
        return Ok(Err(OUTPUT_MISSING));
    };
    Ok(finalized.provenance_claim_id.ok_or(OUTPUT_UNSCOPED))
}
