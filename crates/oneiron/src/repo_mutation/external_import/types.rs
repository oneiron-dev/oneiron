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

/// Which authenticated door route the stock push takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalImportDoor {
    /// The ordinary `/git` route, admitted by the caller's own standing.
    Raw,
    /// The checkout-lease route of a live checkout at its epoch.
    Checkout { checkout: String, epoch: u64 },
}

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

/// `vault.code.imports.get`'s request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalImportLookup {
    pub repo: String,
    pub code_repo: EntityId,
    /// The import's source claim id.
    pub import: EntityId,
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
}

/// Where an import stands, derived from its saved facts and the door's
/// own receive records; never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalImportPhase {
    /// Nothing decided yet, or the seed landed and the head awaits a send.
    Pending,
    /// The outside fetch or its proof refused.
    FetchRefused,
    /// The outside ref names another commit than the frozen head.
    SourceMoved,
    /// No exact base, an ambiguous one, or an imported ref holding another
    /// commit: this import alone is held.
    HeldBase,
    /// The door refused a send (lease, admission or scan).
    DoorRefused,
    /// A send was dispatched and no receive record proves its outcome yet.
    TransportUnknown,
    /// The door received the exact base to head update.
    Received,
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

/// Why a request does not normalize: a stable code and a safe detail.
pub(crate) type Malformed = (&'static str, String);

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

impl ExternalImportDoor {
    /// The checkout-lease ticket this route redeems, once well formed.
    pub(crate) fn ticket(&self) -> std::result::Result<Option<String>, Malformed> {
        match self {
            Self::Raw => Ok(None),
            Self::Checkout { checkout, epoch } => {
                if checkout.len() != 32
                    || !checkout
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || *epoch == 0
                {
                    return Err((
                        "checkout_lease_invalid",
                        "a checkout door names a 32 lower-hex checkout and a positive epoch"
                            .to_owned(),
                    ));
                }
                Ok(Some(format!("{checkout}.{epoch}")))
            }
        }
    }
}

/// The https origin and canonical URL of an outside repository.
fn canonical_repository(url: &str) -> std::result::Result<(String, String), Malformed> {
    let url = url.trim();
    let malformed = || {
        (
            "source_repository_invalid",
            "repository must be an https Git URL with a host and a path, and no userinfo, \
             query or fragment"
                .to_owned(),
        )
    };
    let Some(rest) = url
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .and_then(|_| url.get(8..))
    else {
        return Err(malformed());
    };
    let (authority, path) = rest.split_once('/').ok_or_else(malformed)?;
    let path = path.trim_end_matches('/');
    if authority.is_empty()
        || path.is_empty()
        || url.contains(['@', '?', '#', '\\', ' '])
        || url.bytes().any(|byte| byte.is_ascii_control())
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(malformed());
    }
    let origin = format!("https://{}", authority.to_ascii_lowercase());
    Ok((origin.clone(), format!("{origin}/{path}")))
}
