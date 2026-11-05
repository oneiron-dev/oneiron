//! Core half of `origin::export_parent`: its store-layer items live in `oneiron_store::origin::export_parent` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::export_parent::*;

use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::store::code_revision_record::CodeRevision;
use crate::{EntityId, Vault};

impl Vault {
    /// The Git parents `revision`'s projection takes, or `None` when it is
    /// neither an import-bound tested revision nor an unbound one whose
    /// seal consumed a push completely. Runs under the export's repository
    /// writer.
    ///
    /// # Errors
    /// A mapped projection whose parent this chain does not allow, an
    /// ancestor projection that does not reach the admitted commit, a chain
    /// past its depth bound, or a store or object store failure.
    pub(crate) fn resolve_import_export_parents(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        revision: &CodeRevision,
    ) -> Result<Option<Vec<GitOid>>> {
        if revision.tested_queue.is_none() {
            return Ok(None);
        }
        let Some(manifest) = self.resolve_code_revision_import_anchor(revision.revision_id)? else {
            return Ok(push_boundary(revision)?.map(|tip| vec![tip]));
        };
        let source = GitOid::parse_hex(manifest.anchor.source_commit)?;
        let mut allowed = vec![source.clone()];
        // The nearest original boundary: an engine projection, or the
        // incoming tip of a push a verified seal consumed completely (G4
        // PR2), the revision's own first. Its original commits are kept.
        let mut nearest = push_boundary(revision)?;
        allowed.extend(nearest.clone());
        let mut next = revision.parent_revision_id;
        for _ in 0..crate::limits::MAX_ANCESTOR_DEPTH {
            let Some(id) = next else {
                return self.import_projection_parents(
                    git,
                    repo,
                    revision.revision_id,
                    &source,
                    nearest,
                    &allowed,
                );
            };
            if let Some(mapped) = self.exported_engine_commit(repo, id)? {
                nearest.get_or_insert_with(|| mapped.clone());
                allowed.push(mapped);
            }
            let ancestor = self.get_code_revision(&id)?.ok_or(Error::EntityNotFound)?;
            if let Some(boundary) = push_boundary(&ancestor)? {
                nearest.get_or_insert_with(|| boundary.clone());
                allowed.push(boundary);
            }
            next = ancestor.parent_revision_id;
        }
        Err(Error::IndexOverflow("tested queue revision chain"))
    }

    /// The stored projection's own parents when `revision` is mapped, each
    /// one this chain allows; otherwise the nearest mapped ancestor, whose
    /// history must reach `source`, or `source` itself.
    fn import_projection_parents(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        revision: EntityId,
        source: &GitOid,
        nearest: Option<GitOid>,
        allowed: &[GitOid],
    ) -> Result<Option<Vec<GitOid>>> {
        if let Some(mapped) = self.exported_engine_commit(repo, revision)? {
            let parents = commit_parents(&git.read_object(repo, &mapped)?)?;
            if parents.is_empty() || parents.iter().any(|parent| !allowed.contains(parent)) {
                return Err(Error::InvariantViolation(
                    "a mapped projection's parent is not one its import chain allows",
                ));
            }
            return Ok(Some(parents));
        }
        let parent = nearest.unwrap_or_else(|| source.clone());
        if parent != *source
            && !git
                .merge_base(repo, source.as_str(), parent.as_str())
                .is_ok_and(|base| base == *source)
        {
            return Err(Error::InvariantViolation(
                "an exported engine ancestor does not descend from the admitted commit",
            ));
        }
        Ok(Some(vec![parent]))
    }
}

/// The incoming tip of the last push `revision`'s seal consumed
/// completely, if any: its checked tree is that tip's own.
fn push_boundary(revision: &CodeRevision) -> Result<Option<GitOid>> {
    // A masked copy's submitted tip is a COPY commit, never a canonical
    // parent: only the last ordinary push names the boundary (FIX 7608).
    match revision.tested_queue.as_ref().and_then(|tested| {
        tested
            .received_pushes
            .iter()
            .rev()
            .find(|link| link.projection.is_none())
    }) {
        Some(link) => Ok(Some(GitOid::parse_hex(link.new_commit.clone())?)),
        None => Ok(None),
    }
}
