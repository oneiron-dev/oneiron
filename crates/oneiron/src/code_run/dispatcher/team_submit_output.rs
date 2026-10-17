//! The output a `self.team.submit` names (OF-540), as one snapshot reads it:
//! proven to exist as pinned, and the scope its own recorded claim carries.
//! That claim is the exact blob version's `blob.version` claim, or the code
//! revision's provenance claim. The review copies its scope, so it is never
//! wider than the output; an output with no such claim is refused, and the
//! vault's default scope never stands in for it. A scope whose relationship
//! is no longer a live RELATIONSHIP is refused in the review's writer.

use heed::RoTxn;
use rmpv::Value;

use crate::code_revision::CodeRevisionKind;
use crate::code_run::team_submit::OutputRevision;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_RELATIONSHIP};
use crate::{ClaimBody, ClaimCandidate, EntityId, Vault};

/// The output is not there as pinned.
const OUTPUT_MISSING: &str = "team_submit_output_missing";

/// The output has no recorded claim to take its scope from, or that claim
/// cannot be read.
const OUTPUT_UNSCOPED: &str = "team_submit_output_unscoped";

/// The output's recorded claim names a relationship that is no longer a
/// live RELATIONSHIP, so no review can stand in its scope.
const SCOPE_STALE: &str = "team_submit_scope_stale";

/// A read of the output, or the guest's failure code.
type Read<T> = std::result::Result<T, &'static str>;

/// A submitted output: the entity the review is about, and the scope its
/// recorded claim stands in.
#[derive(Debug, PartialEq)]
pub(super) struct OutputDescriptor {
    subject: EntityId,
    /// The output's own recorded claim its scope is read from.
    scope_claim: EntityId,
    world: Option<EntityId>,
    rel: Option<EntityId>,
    scope: Option<Value>,
    facet: EntityId,
    project: EntityId,
}

impl OutputDescriptor {
    /// The entity the review is about: the blob artifact, or the code
    /// revision.
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
        if let Some(rel) = self.rel {
            candidate = candidate.with_relationship(rel);
        }
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

    /// Whether the output's scope still stands in `txn`: the relationship it
    /// names, if any, must still be a live RELATIONSHIP, as the review's own
    /// write requires. A refusal is the guest's failure code.
    pub(super) fn scope_stands_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Read<()>> {
        let Some(rel) = self.rel else {
            return Ok(Ok(()));
        };
        let found = crate::vault::live_entity_row_in_txn(&vault.store, txn, &rel)?.live_type();
        Ok(if found == Some(ENTITY_TYPE_RELATIONSHIP) {
            Ok(())
        } else {
            Err(SCOPE_STALE)
        })
    }
}

/// Reads `output` in `txn`: proves it exists as pinned, then reads the scope
/// its recorded claim carries. A refusal is the guest's failure code.
pub(super) fn output_descriptor_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    output: OutputRevision,
) -> Result<Read<OutputDescriptor>> {
    let scope_claim = match output {
        OutputRevision::Blob { artifact, version } => {
            blob_scope_claim_in_txn(vault, txn, artifact, version)?
        }
        OutputRevision::Code { revision } => code_scope_claim_in_txn(vault, txn, revision)?,
    };
    let scope_claim = match scope_claim {
        Ok(id) => id,
        Err(code) => return Ok(Err(code)),
    };
    let Some(body) = vault.get_claim_in_txn(txn, &scope_claim).ok().flatten() else {
        return Ok(Err(OUTPUT_UNSCOPED));
    };
    Ok(Ok(OutputDescriptor {
        subject: output.subject(),
        scope_claim,
        world: body.world,
        rel: body.rel,
        scope: body.scope,
        facet: body.scope_facet,
        project: body.scope_project,
    }))
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
