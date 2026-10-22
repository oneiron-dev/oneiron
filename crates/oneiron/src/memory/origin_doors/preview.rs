//! The exact export preview doors (FIX 6869, G4 PR3):
//! `vault.code.export.preview` and `vault.code.export.preview.read`.
//!
//! CALL N `require_exact_preview_sources` (owner-or-Granted-agent): the
//! answer is the complete sealed tree, or one typed hold naming every
//! blocking source and what clears it, never a partial exact payload. Two
//! callers, as the exact publish doors admit them:
//! - every live Owner, co-Owners included, from any linked surface: the
//!   owner's own proof naming this handle's own human actor, judged again
//!   in the release snapshot. Operator root alone admits nobody;
//! - this handle's own actor under ONE live Grant whose repo bounds admit
//!   the anchor and ref and whose Scope covers `vault.code.export.preview`,
//!   judged by G1's read seam before anything the request names resolves,
//!   then over every path of both trees, and again at release. Its source
//!   is its OWN live materialized checkout of the served store.
//!
//! Neither borrows the other's proof, and no request field names a caller.
//! Under a Grant the hold names only the sources the caller may see; every
//! other source folds into one "outside your Grant" line with no id, path,
//! hash or count. These reads write nothing, and the ordinary export, its
//! queue twin and every push keep their own admission unchanged.
use std::collections::BTreeSet;

use super::*;
use crate::federation::repo_access::RepoMembership;
use crate::federation::{
    AgentGrantStanding, RepoAccessBounds, RepoAccessIntent, RepoAccessRefusal, RepoTarget,
};
use crate::git_wire::{GitOid, GitRefName, GitWireRepo};
use crate::memory::repo_doors::refusal_error;
use crate::origin::export_preview::{
    CodeExportBlockingSource, CodeExportFileReadAnswer, CodeExportFileReadRequest,
    CodeExportPreviewAnswer, CodeExportPreviewBlockReason, CodeExportPreviewBlocker,
    CodeExportPreviewHold, CodeExportPreviewRequest, CodeExportSide, PinnedExportPreview,
    PinnedLeaf,
};
use crate::origin::publication::OriginPublicationStatus;
use crate::origin::secret_projection::repo_mark_preview_blockers_in_txn;
use crate::origin::smart_http::push_queue_key;
use crate::secret_custody::{SecretSight, sighted_bytes_in_txn};

/// The Scope verb a Grant lists for both preview rows.
const PREVIEW_GRANT_VERB: &str = "vault.code.export.preview";

/// Who calls a preview door, as its host bound it.
#[derive(Debug, Clone)]
pub enum CodeExportPreviewProof {
    /// A live Owner's proof, naming this handle's own human actor.
    Owner(AuthenticatedOwner),
    /// This handle's own actor, admitted by one live Grant in the door's
    /// snapshots. It carries no actor, Grant id or authority.
    Grant,
}

/// What a preview door may release: the complete pinned preview, or the
/// hold as this caller reads it.
enum PreviewRelease {
    Ready(PinnedExportPreview),
    Held(CodeExportPreviewHold),
}

impl Memory<'_> {
    /// An embedded handle's preview caller: the vault owner's proof when the
    /// handle is the embedded owner's, else the handle's own actor.
    pub fn code_export_preview_proof(&self, verb: &str) -> CodeExportPreviewProof {
        self.embedded_owner(verb)
            .map_or(CodeExportPreviewProof::Grant, CodeExportPreviewProof::Owner)
    }

    /// `vault.code.export.preview`: the complete raw-byte and Git-mode
    /// delta of one explicit sealed revision against one explicit ref
    /// expectation, or the typed hold.
    pub fn code_export_preview_as(
        &self,
        proof: &CodeExportPreviewProof,
        input: CodeExportPreviewRequest,
    ) -> MemoryResult<CodeExportPreviewAnswer> {
        Ok(match self.release_export_preview(proof, &input)? {
            PreviewRelease::Ready(pinned) => CodeExportPreviewAnswer::Ready {
                preview: pinned.preview.ok_or(crate::Error::InvariantViolation(
                    "a released export preview has no answer",
                ))?,
            },
            PreviewRelease::Held(hold) => CodeExportPreviewAnswer::Held { hold },
        })
    }

    /// `vault.code.export.preview.read`: the exact bytes and mode of one
    /// changed side of the preview `input.preview` names again, by its
    /// recomputed handle, or the same typed hold.
    pub fn code_export_preview_read_as(
        &self,
        proof: &CodeExportPreviewProof,
        input: CodeExportFileReadRequest,
    ) -> MemoryResult<CodeExportFileReadAnswer> {
        Ok(match self.release_export_preview(proof, &input.preview)? {
            PreviewRelease::Ready(pinned) => match pinned.read_leaf(&input.handle)? {
                Ok(file) => CodeExportFileReadAnswer::Ready { file },
                Err(reason) => return Err(MemoryError::bad_request(reason)),
            },
            PreviewRelease::Held(hold) => CodeExportFileReadAnswer::Held { hold },
        })
    }

    /// CALL N: admits the caller before anything named resolves, resolves
    /// the source and the pinned preview, then judges the caller, every
    /// source, its secret sight and its Grant's path scope in the release
    /// snapshot. Every blocker is gathered before anything is released.
    fn release_export_preview(
        &self,
        proof: &CodeExportPreviewProof,
        request: &CodeExportPreviewRequest,
    ) -> MemoryResult<PreviewRelease> {
        let first = match proof {
            CodeExportPreviewProof::Owner(owner) => {
                self.origin_owner(owner)?;
                None
            }
            CodeExportPreviewProof::Grant => Some(self.preview_grant(request)?),
        };
        let owner = first.is_none();
        let Some(served) = self.workbench_repo(request.code_repo)? else {
            return Err(MemoryError::not_found(
                "the served code repository is absent or withheld",
            ));
        };
        let wire = self.origin_door_wire(&request.endpoint)?;
        let export = export_request(request);
        let repo = match proof {
            CodeExportPreviewProof::Owner(owner) => {
                self.origin_export_source(owner, &wire, &export)?
            }
            CodeExportPreviewProof::Grant => self.preview_caller_source(&wire, &export)?,
        };
        if served.store != repo.identity().as_hex() {
            return Err(MemoryError::bad_request(
                "code_repo is another object store's anchor than the served repository's",
            ));
        }
        self.origin_export_authority(&request.repo)?;
        if !self.preview_reads(request.revision, owner)? {
            if !owner {
                return Ok(PreviewRelease::Held(CodeExportPreviewHold::of(vec![
                    CodeExportPreviewBlocker::outside_grant(),
                ])));
            }
            if self.vault.get_entity_type(&request.revision)?.is_none() {
                return Err(MemoryError::not_found("code revision not found"));
            }
            return Ok(PreviewRelease::Held(CodeExportPreviewHold::of(vec![
                withheld_record(request.revision),
            ])));
        }
        let base_published = self.preview_base_published(&repo, request)?;
        let mut pinned =
            self.vault
                .preview_engine_commit_export(&wire, &repo, request, base_published)?;
        let mut blockers = std::mem::take(&mut pinned.blockers);
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let bounds = match (proof, first) {
            (CodeExportPreviewProof::Owner(owner), _) => {
                self.origin_owner_in_txn(owner, &txn)?;
                None
            }
            (CodeExportPreviewProof::Grant, Some(first)) => Some(self.preview_grant_release(
                &txn,
                request,
                pinned.paths(),
                &first,
                &mut blockers,
            )?),
            (CodeExportPreviewProof::Grant, None) => {
                return Err(crate::Error::InvariantViolation(
                    "a Grant preview resolved no admitting Grant",
                )
                .into());
            }
        };
        for source in &pinned.sources {
            if !self.preview_reads(source.entity, owner)?
                && (source.required || self.vault.get_entity_type(&source.entity)?.is_some())
            {
                blockers.push(withheld_record(source.entity));
            }
        }
        // A Granted agent's preview of a blob a repo mark covers is held as
        // masked, before any generic sight is read; the owner's stays exact
        // (FIX 7608, CALL N).
        if !owner {
            blockers.extend(repo_mark_preview_blockers_in_txn(
                self.vault,
                &txn,
                &served.store,
                &pinned.before,
                &pinned.after,
            )?);
        }
        let sight = self.secret_sight_in_txn(&txn)?;
        if sight == SecretSight::Masked {
            for (side, leaves) in [
                (CodeExportSide::Before, &pinned.before),
                (CodeExportSide::After, &pinned.after),
            ] {
                for (path, leaf) in leaves {
                    if let Some(blocker) = sight_blocker(self.vault, &txn, side, path, leaf, sight)?
                    {
                        blockers.push(blocker);
                    }
                }
            }
        }
        drop(txn);
        if blockers.is_empty() {
            if pinned.preview.is_none() {
                return Err(crate::Error::InvariantViolation(
                    "an unblocked export preview resolved no answer",
                )
                .into());
            }
            return Ok(PreviewRelease::Ready(pinned));
        }
        let blockers = match bounds {
            None => blockers,
            Some(bounds) => self.grant_visible_blockers(blockers, &bounds)?,
        };
        Ok(PreviewRelease::Held(CodeExportPreviewHold::of(blockers)))
    }

    /// CALL N's Grant arm before anything named resolves: one live Grant
    /// admitting this handle's own actor to the anchor and ref, covering
    /// the preview verb. A refusal is the read seam's typed code.
    fn preview_grant(&self, request: &CodeExportPreviewRequest) -> MemoryResult<RepoMembership> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        match self.preview_grant_in_txn(&txn, request, BTreeSet::new(), None)? {
            Ok(membership) => Ok(membership),
            Err(Some(refused)) => Err(refusal_error(refused)),
            Err(None) => Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "preview_not_granted: no single Grant that admits this read covers \
                 vault.code.export.preview",
                &[
                    "Ask an Owner for a Grant whose Scope lists vault.code.export.preview on \
                     this repository and ref, or have an Owner read this preview.",
                ],
            )),
        }
    }

    /// The Grant arm in the release snapshot: the first Grant whose bounds
    /// admit every path of both trees AND covers the preview verb, so an
    /// earlier narrower Grant never masks a later covering one. With none,
    /// the paths fold into the one outside line and the admitting Grant
    /// must still stand. Its bounds decide what the hold may name.
    fn preview_grant_release(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &CodeExportPreviewRequest,
        paths: BTreeSet<String>,
        first: &RepoMembership,
        blockers: &mut Vec<CodeExportPreviewBlocker>,
    ) -> MemoryResult<RepoAccessBounds> {
        if let Ok(covering) = self.preview_grant_in_txn(txn, request, paths, None)? {
            return Ok(covering.bounds);
        }
        blockers.push(CodeExportPreviewBlocker::outside_grant());
        match self.preview_grant_in_txn(txn, request, BTreeSet::new(), Some(first.grant))? {
            Ok(standing) => Ok(standing.bounds),
            Err(refused) => Err(refusal_error(
                refused.unwrap_or(RepoAccessRefusal::NoMembership),
            )),
        }
    }

    /// G1's read seam over `paths` of the request's anchor and ref, passing
    /// only a Grant whose Scope covers the preview verb (`ScopeAxis::All`
    /// covers it; a named set must hold that exact verb) and, with `bound`,
    /// only that very Grant.
    fn preview_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &CodeExportPreviewRequest,
        paths: BTreeSet<String>,
        bound: Option<EntityId>,
    ) -> MemoryResult<std::result::Result<RepoMembership, Option<RepoAccessRefusal>>> {
        let target = RepoTarget {
            repo: request.code_repo,
            git_ref: request.ref_name.clone(),
            paths,
        };
        let verb = PREVIEW_GRANT_VERB.to_owned();
        let covers = |standing: &AgentGrantStanding| {
            standing.grant.authority_scope.verbs.contains(&verb)
                && bound.is_none_or(|id| id == standing.id)
        };
        Ok(self.vault.admit_repo_read_passing_in_txn(
            txn,
            self.actor,
            self.actor_class,
            request.code_repo,
            &target,
            covers,
        )?)
    }

    /// The Grant arm's source: a live checkout lease THIS handle's own
    /// actor holds on the served repository, already materialized, whose
    /// object store is the served one. No owner's lease stands in.
    fn preview_caller_source(
        &self,
        wire: &GitWire<'_>,
        input: &CodeExportRequest,
    ) -> MemoryResult<GitWireRepo> {
        let repo_dir = origin_repo_dir(self.vault, &input.repo)?;
        let served = RepoRef::LocalFolder {
            path: repo_dir.to_string_lossy().into_owned(),
            commit: "0".repeat(crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN),
        };
        let ticket = format!("{}.{}", input.checkout, input.epoch);
        let lease = crate::credential_door::require_checkout_lease(
            self.vault,
            &ticket,
            &self.actor.to_hex(),
            &served,
        )
        .map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("checkout lease refused: {error}"),
                &["Name a live lease you hold on this served repository, at its epoch."],
            )
        })?;
        let tree = wire
            .checkout_worktree_path(&lease)
            .map_err(checkout_refusal)?;
        if !tree.is_dir() {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the checkout is not materialized",
                &["Bind it first with vault.repo.checkout.bind."],
            ));
        }
        let repo = wire.open_repo(lease.repo_ref.clone(), &tree)?;
        if repo.common_dir() != push_queue_key(self.vault, &input.repo)?.as_path() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the checkout does not share the served repository's object store",
                &[],
            ));
        }
        Ok(repo)
    }

    /// Whether a Published publication of the expected commit on this full
    /// ref and store exists, by the export's own lookup. An absent
    /// expectation needs none.
    fn preview_base_published(
        &self,
        repo: &GitWireRepo,
        request: &CodeExportPreviewRequest,
    ) -> MemoryResult<bool> {
        let Some(expected) = &request.expected_old_oid else {
            return Ok(false);
        };
        let ref_name = GitRefName::parse_full(request.ref_name.clone())?;
        let commit = GitOid::parse_hex(expected.clone())?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        Ok(self
            .origin_matching_publications(repo_id, &ref_name, &commit)?
            .iter()
            .any(|record| matches!(record.status, OriginPublicationStatus::Published)))
    }

    /// Whether the caller's credential reads the record `id`. An owner's
    /// read lists the row either way; a Grant holder's lists only a row it
    /// reads, so no hidden id rides the answer's listing.
    fn preview_reads(&self, id: EntityId, list_hidden: bool) -> MemoryResult<bool> {
        let readable = self.get_entity(&id.to_hex())?.value.is_some();
        if readable || list_hidden {
            self.produced_from([id]);
        }
        Ok(readable)
    }

    /// The hold as a Grant holder reads it, and ONE outside line for every
    /// source outside its Grant scope (L02, CALL N). A Grant reading the
    /// whole repo (`**`) names each source its credential reads as an
    /// Owner sees it, objects and evidence included. A narrower one names
    /// only a record its credential reads or a path its read globs admit,
    /// under a fixed explanation, and folds every object and evidence link.
    fn grant_visible_blockers(
        &self,
        blockers: Vec<CodeExportPreviewBlocker>,
        bounds: &RepoAccessBounds,
    ) -> MemoryResult<Vec<CodeExportPreviewBlocker>> {
        let whole_repo = bounds.readable.contains("**");
        let mut visible = Vec::new();
        let mut outside = false;
        for blocker in blockers {
            let named = match &blocker.source {
                CodeExportBlockingSource::Entity { entity } => {
                    self.preview_reads(*entity, false)?
                }
                CodeExportBlockingSource::File { path, entity, .. } => {
                    bounds.admits_path(RepoAccessIntent::Read, path)
                        && match entity {
                            Some(entity) => self.preview_reads(*entity, false)?,
                            None => true,
                        }
                }
                CodeExportBlockingSource::Object { .. }
                | CodeExportBlockingSource::Evidence { .. } => whole_repo,
                CodeExportBlockingSource::OutsideGrant => false,
            };
            if !named {
                outside = true;
            } else if whole_repo {
                visible.push(blocker);
            } else {
                visible.push(CodeExportPreviewBlocker {
                    message: blocker.reason.grant_message().to_owned(),
                    ..blocker
                });
            }
        }
        if outside {
            visible.push(CodeExportPreviewBlocker::outside_grant());
        }
        Ok(visible)
    }
}

/// The ordinary export request the preview's pins name: its `code_repo`
/// selector dropped.
fn export_request(request: &CodeExportPreviewRequest) -> CodeExportRequest {
    CodeExportRequest {
        repo: request.repo.clone(),
        checkout: request.checkout.clone(),
        epoch: request.epoch,
        revision: request.revision,
        ref_name: request.ref_name.clone(),
        expected_old_oid: request.expected_old_oid.clone(),
        endpoint: request.endpoint.clone(),
    }
}

/// A record the caller's credential does not read.
fn withheld_record(entity: EntityId) -> CodeExportPreviewBlocker {
    CodeExportPreviewBlocker::new(
        CodeExportBlockingSource::Entity { entity },
        CodeExportPreviewBlockReason::Withheld,
        "this record is absent or withheld from your credential",
        "Read with a credential whose scope reads this record, or ask an Owner to restore it.",
    )
}

/// What `sight` would release of one pinned leaf: nothing blocks when its
/// copy is its exact bytes; a changed copy is masked; a file the release
/// refuses is withheld. Granted sight stands only on its own read receipt.
fn sight_blocker(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    side: CodeExportSide,
    path: &str,
    leaf: &PinnedLeaf,
    sight: SecretSight,
) -> MemoryResult<Option<CodeExportPreviewBlocker>> {
    let (reason, message, way_out) =
        match sighted_bytes_in_txn(&vault.store, txn, leaf.bytes.clone(), sight) {
            Ok(copy) if copy == leaf.bytes => return Ok(None),
            Ok(_) => (
                CodeExportPreviewBlockReason::Masked,
                "your credential reads a masked copy of this file, not its exact bytes",
                "Have an Owner read this preview, or obtain a secret read grant covering this \
                 file's keys; a masked copy is never released as exact.",
            ),
            Err(crate::Error::Secret(_) | crate::Error::InvariantViolation(_)) => (
                CodeExportPreviewBlockReason::Withheld,
                "the release withholds this file from your credential",
                "Have an Owner read this preview; a sealed or unreadable file is released to \
                 an Owner or a granted reader only.",
            ),
            Err(error) => return Err(error.into()),
        };
    Ok(Some(CodeExportPreviewBlocker::new(
        CodeExportBlockingSource::File {
            side,
            path: path.to_owned(),
            entity: None,
        },
        reason,
        message,
        way_out,
    )))
}
