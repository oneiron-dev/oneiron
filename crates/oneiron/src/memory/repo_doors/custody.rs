//! `self.code.checkout.bind` and `self.code.export` (FIX 6867, G1 PR3b): a
//! leased run binds its own checkout lease of a served repo the Grant
//! admits, and exports one finalized, promoted revision from it.
//!
//! These are the PR2 run doors' two custody rows, not another exporter: the
//! checkout is materialized through the unchanged GitWire port and the
//! export goes through the unchanged `export_engine_commit`, each behind the
//! run's own admission. No owner proof is read and no owner door is called.
//! The run names its repo anchor, its ref, its lease and its revision; the
//! served store is the anchor's stored repo, the holder is the run's actor,
//! the TASK is the run's, and no tree, actor or remote credential is taken
//! from the input.
//!
//! An export also needs the publication policy (L02, FIX 6866): one Grant
//! that admits the ref over every path the revision holds and lists
//! `publish`. With none the run gets the typed hold
//! [`REPO_PUBLICATION_POLICY_REQUIRED`]; a `git_push` Grant never implies an
//! export, a promotion or a mirror release.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{RepoRunAnswer, RepoRunBinding, refusal_error, repo_target};
use crate::EntityId;
use crate::checkout::lease::{CheckoutLeaseAct, CheckoutRepoOps};
use crate::codebase::RepoRef;
use crate::federation::{RepoAccessIntent, RepoAccessRefusal, RepoTarget};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::memory::origin_doors::OriginPublicationState;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::origin::export::EngineCommitExport;
use crate::origin::publication::OriginPublicationStatus;
use crate::origin::residence::{OriginAuthorityLease, OriginHostAuthority};
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::origin::secret_projection::checkout_recipient::record_run_checkout_recipient;
use crate::origin::smart_http::{
    ORIGIN_REPO_DIR_SUFFIX, origin_repo_dir, origin_serving_root, push_queue_key,
};

/// The hold a run's export answers while no Grant both admits its ref over
/// the revision's paths and lists `publish` (L02's publication policy). The
/// revision stays as it was; nothing is exported.
pub const REPO_PUBLICATION_POLICY_REQUIRED: &str = "repo_publication_policy_required";

/// `self.code.checkout.bind`: materializes the run's own live checkout
/// lease of the admitted repo's served store, through the unchanged GitWire
/// port. The lease is one the run's actor holds for the run's TASK; no
/// lease is minted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckoutBindInput {
    /// The CODE anchor the run's Grant admits; its stored repo is the
    /// served store.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The door base the checkout's remote points at, ending in `/git`:
    /// HTTPS, or HTTP on loopback only. It grants nothing and selects no
    /// object store; with none the worktree gets no remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// `self.code.checkout.bind`'s answer. No host path is shown.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckoutBindOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub checkout: String,
    pub epoch: u64,
    /// `<endpoint>/lease/<checkout>.<epoch>/<repo>.git`, the worktree's
    /// fetch and push URL, when an endpoint was named. It holds a
    /// redemption right only; every request still needs the holder's
    /// credential and the run's Grant.
    pub remote_url: Option<String>,
}

/// `self.code.export`: one finalized, promoted CodeRevision exported from
/// the run's own materialized checkout through the unchanged engine export
/// and origin publication protocol. The engine regenerates every byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoExportInput {
    pub repo: EntityId,
    /// The full ref to advance, such as `refs/heads/main`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub checkout: String,
    pub epoch: u64,
    /// The finalized, promoted CodeRevision.
    pub revision: EntityId,
    /// The value the advance is decided against; `None` means the ref must
    /// not exist yet. It is never discovered for the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_old_oid: Option<String>,
}

/// `self.code.export`'s answer: what the publication protocol decided.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoExportOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub revision: EntityId,
    pub git_commit: String,
    /// The publication id.
    pub receipt: EntityId,
    pub status: OriginPublicationState,
    /// The one Grant the publication policy admitted the export under.
    pub grant: EntityId,
    pub ref_was_already_applied: bool,
    pub wire_replayed: bool,
    pub wire_rejected: bool,
}

/// The run's own checkout of a served repo, as admitted and read.
struct RunCheckout {
    served: String,
    lease: CheckoutLeaseAct,
    /// The PROJECT the run's admission bound its anchor in.
    project: EntityId,
}

impl Memory<'_> {
    /// `self.code.checkout.bind` for a run: the run is admitted to edit the
    /// ref, the lease is the run's own on the anchor's served store, and the
    /// unchanged GitWire port materializes it.
    pub fn repo_checkout_bind_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoCheckoutBindInput,
    ) -> MemoryResult<RepoRunAnswer<RepoCheckoutBindOutput>> {
        let own = self.repo_run_checkout(
            binding,
            input.repo,
            &input.git_ref,
            &input.checkout,
            input.epoch,
            BTreeSet::new(),
        )?;
        let wire = match input.endpoint.as_deref() {
            Some(endpoint) => GitWire::new(self.vault)?.with_checkout_door(endpoint)?,
            None => GitWire::new(self.vault)?,
        };
        // A run reads masked (ASK 1): on a marked store its lease is bound
        // to the masked copy once, and the port materializes that copy.
        wire.select_projected_checkout(&own.lease, true)
            .map_err(checkout_refusal)?;
        // FIX 10271/9328: the run's proven agent, PROJECT and run, kept
        // beside the copy's binding for its later Git exchanges.
        if binding.actor.actor_class() == crate::EdgeActorClass::Agent {
            let recipient = RepoRevealRecipient::proven_agent(binding.actor.entity_ref())
                .in_project(Some(own.project))
                .for_run(Some(binding.executor_run.to_hex()));
            record_run_checkout_recipient(self.vault, &own.lease, input.repo, &recipient);
        }
        wire.materialize(&own.lease).map_err(checkout_refusal)?;
        let checkout = own.lease.checkout_id.to_string();
        let remote_url = input.endpoint.as_deref().map(|endpoint| {
            format!(
                "{endpoint}/lease/{checkout}.{}/{}.git",
                own.lease.epoch, own.served
            )
        });
        Ok(RepoRunAnswer {
            rows: vec![input.repo],
            output: RepoCheckoutBindOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                checkout,
                epoch: own.lease.epoch,
                remote_url,
            },
        })
    }

    /// `self.code.export` for a run: the revision is one the run's lane
    /// reads, the run's checkout is materialized on the served store, and
    /// L02's publication policy admits the ref over every path the revision
    /// holds, judged again just before the engine export and inside its
    /// writers (FIX 7179); a ref move that rewrites history needs that Grant
    /// to list publish_rewrite too.
    pub fn repo_export_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoExportInput,
    ) -> MemoryResult<RepoRunAnswer<RepoExportOutput>> {
        let revision = self
            .vault
            .get_code_revision(&input.revision)?
            .ok_or_else(|| refusal_error(RepoAccessRefusal::NoMembership))?;
        self.repo_lane_reads(binding, &[revision.revision_id, revision.session_id])?;
        // Every path the revision's tree holds: its documents and its
        // untouched blobs (FIX 7346), so the Grant covers the whole export.
        let paths: BTreeSet<String> = revision
            .file_frontiers
            .values()
            .map(|frontier| frontier.path.clone())
            .chain(revision.blob_frontiers.keys().cloned())
            .collect();
        let own = self.repo_run_checkout(
            binding,
            input.repo,
            &input.git_ref,
            &input.checkout,
            input.epoch,
            paths.clone(),
        )?;
        let grant =
            self.repo_publication_grant(binding, input.repo, &input.git_ref, &paths, false)?;
        let wire = GitWire::new(self.vault)?;
        let source = self.repo_checkout_source(&wire, &own)?;
        let request = EngineCommitExport {
            revision_id: revision.revision_id,
            ref_name: GitRefName::parse_full(input.git_ref.clone())?,
            expected_old_oid: input
                .expected_old_oid
                .clone()
                .map(GitOid::parse_hex)
                .transpose()?,
        };
        let authority = self.repo_export_authority(&own.served)?;
        let target = repo_target(input.repo, &input.git_ref, &paths);
        // The run and its publication Grant, judged once more in the
        // snapshot just before the export makes any Git object.
        self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        if self.repo_publication_grant(binding, input.repo, &input.git_ref, &paths, false)? != grant
        {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        // The exact ref move is classified once its projection is known: a
        // move whose new commit does not descend from `expected_old_oid` is a
        // history rewrite, and needs a Grant that also lists publish_rewrite
        // (FIX 8800); without one it is the typed publication hold.
        let held = std::cell::Cell::new((grant, false));
        let receipt = self.vault.export_engine_commit_checked(
            &wire,
            &source,
            &request,
            authority.as_ref(),
            |new_oid| {
                let Some(old) = &request.expected_old_oid else {
                    return Ok(Ok(()));
                };
                // A move this store cannot prove descends is a rewrite.
                let descends = wire
                    .commits_reachable_from(
                        &source,
                        std::slice::from_ref(old),
                        std::slice::from_ref(new_oid),
                    )
                    .unwrap_or(false);
                if descends {
                    return Ok(Ok(()));
                }
                Ok(self
                    .repo_publication_grant(binding, input.repo, &input.git_ref, &paths, true)
                    .map(|rewrite| held.set((rewrite, true))))
            },
            // The run and the Grant it publishes under, judged again as the
            // first act of each writer before the publication, so a revoke
            // that lands before them publishes nothing (FIX 7179).
            |txn| {
                let (grant, rewrite) = held.get();
                match self.vault.admit_repo_run_in_txn(
                    txn,
                    binding,
                    &target,
                    RepoAccessIntent::Read,
                )? {
                    Ok(_) => {}
                    Err(refused) => return Ok(Err(refusal_error(refused))),
                }
                Ok(
                    match self.repo_publication_grant_in_txn(txn, binding, &target, rewrite)? {
                        Ok(again) if again == grant => Ok(()),
                        Ok(_) => Err(refusal_error(RepoAccessRefusal::StaleLease)),
                        Err(hold) => Err(hold),
                    },
                )
            },
        )??;
        let (grant, _) = held.get();
        Ok(RepoRunAnswer {
            rows: vec![input.repo, revision.revision_id],
            output: RepoExportOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                revision: revision.revision_id,
                git_commit: receipt.record.new_oid.as_str().to_owned(),
                receipt: receipt.record.publication_id,
                status: match receipt.record.status {
                    OriginPublicationStatus::Prepared => OriginPublicationState::Prepared,
                    OriginPublicationStatus::Published => OriginPublicationState::Published,
                    OriginPublicationStatus::Failed => OriginPublicationState::Failed,
                    OriginPublicationStatus::Conflicted => OriginPublicationState::Conflicted,
                },
                grant,
                ref_was_already_applied: receipt.ref_was_already_applied,
                wire_replayed: receipt.wire_replayed(),
                wire_rejected: receipt.wire_rejection().is_some(),
            },
        })
    }

    /// The run admitted to edit `git_ref` of `repo` over `paths`, and the
    /// run's own live lease `checkout`.`epoch` on the anchor's served store:
    /// held by the run's actor, for the run's TASK, at the vault's time.
    fn repo_run_checkout(
        &self,
        binding: &RepoRunBinding,
        repo: EntityId,
        git_ref: &str,
        checkout: &str,
        epoch: u64,
        paths: BTreeSet<String>,
    ) -> MemoryResult<RunCheckout> {
        let target = repo_target(repo, git_ref, paths);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Edit)?;
        let served = served_repo_name(self.vault, &admitted.membership.repo_ref)
            .ok_or_else(|| refusal_error(RepoAccessRefusal::WrongRepo))?;
        let repo_dir = origin_repo_dir(self.vault, &served)?;
        let store = RepoRef::LocalFolder {
            path: repo_dir.to_string_lossy().into_owned(),
            commit: "0".repeat(crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN),
        };
        let holder = binding.actor.entity_ref().to_hex();
        let ticket = format!("{checkout}.{epoch}");
        let lease =
            crate::credential_door::require_checkout_lease(self.vault, &ticket, &holder, &store)
                .map_err(|_| refusal_error(RepoAccessRefusal::StaleLease))?;
        if lease.task_ref != binding.task {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        Ok(RunCheckout {
            served,
            lease,
            project: admitted.membership.bounds.project,
        })
    }

    /// The run's materialized checkout as the export's source: its tree
    /// exists and shares the served store's object store.
    fn repo_checkout_source(
        &self,
        wire: &GitWire<'_>,
        own: &RunCheckout,
    ) -> MemoryResult<GitWireRepo> {
        let tree = wire
            .checkout_worktree_path(&own.lease)
            .map_err(checkout_refusal)?;
        if !tree.is_dir() {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the run's checkout is not materialized",
                &["Bind it first with self.code.checkout.bind."],
            ));
        }
        // A masked copy's checkout exports from the canonical ORIGINAL
        // store, never the copy's (FIX 7608 2b-ii-B2).
        let source = if wire
            .projected_checkout_binding(&own.lease)
            .map_err(checkout_refusal)?
            .is_some()
        {
            let RepoRef::LocalFolder { path, .. } = &own.lease.repo_ref else {
                return Err(refusal_error(RepoAccessRefusal::WrongRepo));
            };
            PathBuf::from(path)
        } else {
            tree
        };
        let repo = wire.open_repo(own.lease.repo_ref.clone(), &source)?;
        if repo.common_dir() != push_queue_key(self.vault, &own.served)?.as_path() {
            return Err(refusal_error(RepoAccessRefusal::WrongRepo));
        }
        Ok(repo)
    }

    /// L02's publication policy for the run: the one Grant that admits
    /// `git_ref` of `repo` over every one of `paths` and lists `publish`,
    /// and `publish_rewrite` too for a `rewrite`, read in one snapshot.
    /// None is the typed hold.
    fn repo_publication_grant(
        &self,
        binding: &RepoRunBinding,
        repo: EntityId,
        git_ref: &str,
        paths: &BTreeSet<String>,
        rewrite: bool,
    ) -> MemoryResult<EntityId> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.repo_publication_grant_in_txn(
            &txn,
            binding,
            &repo_target(repo, git_ref, paths),
            rewrite,
        )?
    }

    /// [`Self::repo_publication_grant`] over `target`, read in `txn`: the
    /// Grant, or the typed publication hold.
    ///
    /// # Errors
    /// A store, fold or clock failure.
    fn repo_publication_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        target: &RepoTarget,
        rewrite: bool,
    ) -> crate::Result<MemoryResult<EntityId>> {
        let admitted = self.vault.admit_origin_publish_grant_in_txn(
            txn,
            binding.actor.entity_ref(),
            binding.actor.actor_class(),
            target,
            rewrite,
            None,
        )?;
        Ok(match admitted {
            Ok(grant) => Ok(grant.grant),
            Err(denial) => Err(MemoryError::new(
                REPO_PUBLICATION_POLICY_REQUIRED,
                format!("{}: {}", denial.code, denial.message),
                &["The owner grants publish on this repo; git_push never implies an export."],
            )),
        })
    }

    /// The host authority the export publishes under, read as the owner's
    /// export reads it: a held epoch passes its lease, an unconfigured
    /// origin passes none, and any other host's authority refuses.
    fn repo_export_authority(&self, served: &str) -> MemoryResult<Option<OriginAuthorityLease>> {
        match self.vault.origin_host_authority(served)? {
            OriginHostAuthority::Unconfigured => Ok(None),
            OriginHostAuthority::Held(lease) => Ok(Some(lease)),
            OriginHostAuthority::Mirror(_)
            | OriginHostAuthority::Elsewhere(_)
            | OriginHostAuthority::WriterErased(_) => Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "this host does not hold the served repository's origin authority",
                &[],
            )),
        }
    }
}

/// The served name of the store `anchor` names: a local folder directly
/// under this vault's serving root, `<name>.git`, that is the very
/// directory the name serves. `None` for anything else, an imported working
/// folder included.
fn served_repo_name(vault: &crate::Vault, anchor: &RepoRef) -> Option<String> {
    let RepoRef::LocalFolder { path, .. } = anchor else {
        return None;
    };
    let dir: PathBuf = Path::new(path).canonicalize().ok()?;
    if dir.parent()? != origin_serving_root(vault).ok()?.as_path() {
        return None;
    }
    let name = dir
        .file_name()?
        .to_str()?
        .strip_suffix(ORIGIN_REPO_DIR_SUFFIX)?
        .to_owned();
    let served = origin_repo_dir(vault, &name).ok()?.canonicalize().ok()?;
    (served == dir).then_some(name)
}

/// A checkout port refusal, as the run reads it.
fn checkout_refusal(error: crate::checkout::lease::CheckoutError) -> MemoryError {
    crate::memory::checkout_doors::refusal(error)
}
