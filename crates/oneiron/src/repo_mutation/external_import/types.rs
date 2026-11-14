//! The outside import's wire types (FIX 6871, G7 PR1) and the one
//! normalization every request passes before anything reads it.
//!
//! A request names the served repository, its CODE anchor, the exact base
//! revision, the outside source (an https repository, one full ref, an
//! optional asserted pull request number, and the exact base and head
//! commits), an optional custody binding and the door route. It never names
//! an actor, a principal class, a token, a host path, argv, a file list, a
//! verdict or an implicit HEAD. Answers carry ids, refs and commits only.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::git_wire::{GitOid, GitRefName};
use crate::memory::merge_queue_doors::MergeQueueCheckWorkView;
use crate::memory::origin_doors::CodePushIngressView;

/// One exact outside source: what is fetched and pushed, frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalImportSource {
    /// The repository's https origin (`https://host[:port]`); a bare host
    /// is read as its https origin. An assertion of where, never of who.
    pub host: String,
    /// The canonical https Git repository URL, with no userinfo, query or
    /// fragment.
    pub repository: String,
    /// The full outside ref fetched (`refs/heads/...`, `refs/pull/N/head`).
    pub source_ref: String,
    /// The asserted pull request number; the ref and commits decide bytes.
    pub pull_request: Option<u64>,
    /// The exact base commit, 40 lower-hex.
    pub base_commit: String,
    /// The exact head commit, 40 lower-hex.
    pub head_commit: String,
}

#[doc(hidden)]
pub(crate) use oneiron_verb_wire::repo_mutation::external_import::types::Malformed;
#[doc(hidden)]
use oneiron_verb_wire::repo_mutation::external_import::types::canonical_repository;
#[doc(hidden)]
pub use oneiron_verb_wire::repo_mutation::external_import::types::{
    ExternalImportDoor, ExternalImportLfsRoute, ExternalImportLfsTransfer, ExternalImportLookup,
    ExternalImportPhase,
};

/// `vault.code.imports.create`'s request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalImportRequest {
    /// The served repository's name, with no `.git` suffix.
    pub repo: String,
    /// The served repository's CODE anchor.
    pub code_repo: EntityId,
    /// The exact tested revision the outside change proposes against.
    pub base_revision: EntityId,
    /// The full `refs/imported/...` ref to push to. Absent: the engine
    /// derives `refs/imported/<host>/<owner>/<repo>/<ref-or-pr-N>` and
    /// answers it (CALL S).
    pub imported_ref: Option<String>,
    pub source: ExternalImportSource,
    /// A custody secret holding one complete `Authorization` header for
    /// the source host. Absent: an anonymous fetch, never a fallback.
    pub source_binding: Option<String>,
    pub door: ExternalImportDoor,
}

/// An import's immutable identity and the receive links known so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExternalImportReceipt {
    /// The `repo.external_import_source` claim id.
    pub import: EntityId,
    pub repo: String,
    pub code_repo: EntityId,
    /// The frozen source, its requested head included.
    pub source: ExternalImportSource,
    pub imported_ref: String,
    pub base_revision: EntityId,
    /// The authenticated importer; `None` once erased.
    pub importer: Option<EntityId>,
    /// The publication of the exact base seed, when one was received.
    pub seed_publication: Option<EntityId>,
    /// The receive-pack provenance of the exact base to head update.
    pub receive_provenance: Option<EntityId>,
    /// That update's Published publication.
    pub publication: Option<EntityId>,
    /// How the newest attempt that set out to fetch the source's Git-LFS
    /// objects carried them (FIX 19876), from its saved facts. `None` when
    /// no attempt fetched any. Not whether the objects arrived; the door
    /// judges that.
    pub lfs_transfer: Option<ExternalImportLfsTransfer>,
}

/// `vault.code.imports.get`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalImportStatus {
    pub receipt: ExternalImportReceipt,
    pub phase: ExternalImportPhase,
    /// A stable reason code, never a child's diagnostics.
    pub reason: Option<String>,
    /// The received head update and its candidate, once received.
    pub ingress: Option<CodePushIngressView>,
    /// The candidate's linked checker work, in saved order.
    pub checks: Vec<MergeQueueCheckWorkView>,
}

/// A request's source after normalization: the canonical values every
/// identity, fetch and push reads, and nothing the caller did not name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedSource {
    pub(crate) source: ExternalImportSource,
    pub(crate) base: GitOid,
    pub(crate) head: GitOid,
}

impl ExternalImportSource {
    /// The canonical form: the https origin and repository URL spelled once
    /// (lowercase scheme and host, no trailing slash), the full ref
    /// validated and both commits as 40 lower-hex.
    pub(crate) fn normalized(&self) -> std::result::Result<NormalizedSource, Malformed> {
        let (origin, repository) = canonical_repository(&self.repository)?;
        let host = self.host.trim().to_ascii_lowercase();
        let host = if host.starts_with("https://") {
            host.trim_end_matches('/').to_owned()
        } else {
            format!("https://{}", host.trim_end_matches('/'))
        };
        if host != origin {
            return Err((
                "source_host_mismatch",
                format!("host {host} is not the repository's https origin {origin}"),
            ));
        }
        let source_ref = GitRefName::parse_full(self.source_ref.trim()).map_err(|_| {
            (
                "source_ref_invalid",
                "source_ref must be one full refs/ name".to_owned(),
            )
        })?;
        let commit = |value: &str, field: &str| {
            GitOid::parse_hex(value.trim().to_ascii_lowercase())
                .map_err(|_| ("commit_invalid", format!("{field} must be a 40-hex commit")))
        };
        let base = commit(&self.base_commit, "base_commit")?;
        let head = commit(&self.head_commit, "head_commit")?;
        Ok(NormalizedSource {
            source: Self {
                host: origin,
                repository,
                source_ref: source_ref.as_str().to_owned(),
                pull_request: self.pull_request,
                base_commit: base.as_str().to_owned(),
                head_commit: head.as_str().to_owned(),
            },
            base,
            head,
        })
    }
}
