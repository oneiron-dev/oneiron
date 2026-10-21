//! The shapes of one exact publish request (FIX 6866): what it names, the
//! review it carries, where it stands and the refusal that ended it. The
//! stored row is the answer every publish verb gives.

use serde::{Deserialize, Serialize};

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// What the mirror's branch held when the request was made, read with the
/// mirror's own credential. The push is leased on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OriginPublishRemote {
    /// The mirror held no such branch: the push may only create it.
    Absent,
    /// The branch stood at this commit, 40 lower-hex characters.
    At { commit: String },
}

/// How the pushed commit may stand to the mirror's tip (CALLS "FIX 6866
/// push shape").
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublishForce {
    /// Create the branch, or move it forward: the mirror's tip must be an
    /// ancestor of the commit, proven here before anything goes out.
    #[default]
    FastForward,
    /// Replace a tip the commit does not descend from: a history rewrite.
    /// Only the owner, or a Grant that also lists `publish_rewrite`, asks,
    /// approves or executes it. The mirror's own branch protection stands.
    Rewrite,
}

/// Where one request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublishState {
    /// Reviewed and recorded; waiting for an approval of its digest.
    Pending,
    /// Its reviewed tuple is approved; waiting for its one dispatch.
    Approved,
    /// Its one push was claimed. It is never sent again: it settles from
    /// what the mirror is observed to hold.
    Dispatching,
    /// The mirror took the commit at the branch.
    Published,
    /// The mirror was observed holding the commit at the branch, without a
    /// push acknowledgement from this request.
    ObservedPublished,
    /// The request ended without publishing; `refusal` names why.
    Refused,
    /// Cancelled before its dispatch.
    Cancelled,
    /// Its caller's expiry passed before its dispatch.
    Expired,
}

impl OriginPublishState {
    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Approved | Self::Dispatching)
    }
}

/// The class an actor acted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublishActorClass {
    Human,
    Agent,
    System,
}

impl From<EdgeActorClass> for OriginPublishActorClass {
    fn from(class: EdgeActorClass) -> Self {
        match class {
            EdgeActorClass::Human => Self::Human,
            EdgeActorClass::Agent => Self::Agent,
            EdgeActorClass::System => Self::System,
        }
    }
}

impl From<OriginPublishActorClass> for EdgeActorClass {
    fn from(class: OriginPublishActorClass) -> Self {
        match class {
            OriginPublishActorClass::Human => Self::Human,
            OriginPublishActorClass::Agent => Self::Agent,
            OriginPublishActorClass::System => Self::System,
        }
    }
}

/// What one act stood on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OriginPublishAuthority {
    /// The vault's live owner, from any linked surface.
    Owner,
    /// One live agent Grant, bound here and checked again at dispatch.
    Grant { grant: EntityId },
}

/// One act on a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishAct {
    /// Who acted; `None` once erased.
    pub actor: Option<EntityId>,
    pub class: OriginPublishActorClass,
    pub authority: OriginPublishAuthority,
    /// Seconds, on the vault clock.
    pub at: u64,
}

/// The mirror a request is bound to, as its row stood when the request was
/// made. A dispatch finding any field changed refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishDestination {
    pub url: String,
    pub user: String,
    /// The custody record of the push token; never its value.
    pub secret_ref: String,
    /// The mirror's generation id; `None` only for a mirror row stored
    /// before generations.
    pub target_generation: Option<EntityId>,
}

/// Git-LFS bytes the push carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublishLfsBytes {
    /// None: a pointer the review names is not verified at the mirror.
    NotSent,
}

/// The full-ancestry review a request carries (CALLS "FIX 6866 review
/// scope"). Its pages are read with `vault.code.origin.publish.review`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishReview {
    /// BLAKE3, 64 lower hex, over the tuple's commit and base and every
    /// item of every page in order. An approval names it.
    pub digest: String,
    /// The mirror tip whose history the review leaves out; `None` when it
    /// covers the commit's whole history (the branch was absent, or its tip
    /// is not held here).
    pub subtracted: Option<String>,
    pub commits: u64,
    /// Path entries across every commit.
    pub entries: u64,
    /// Distinct paths.
    pub paths: u64,
    pub pages: u64,
    pub lfs_bytes: OriginPublishLfsBytes,
}

/// Why a request ended without publishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublishRefusalReason {
    /// The mirror's URL, user, custody record or generation changed, or it
    /// was cleared.
    DestinationChanged,
    /// The mirror's branch holds neither the leased tip nor the commit.
    RemoteMoved,
    /// The mirror refused the update (a stale lease, a protected branch).
    Rejected,
    /// The push's outcome could not be proven and the mirror does not hold
    /// the commit: it is never sent again.
    OutcomeUnknown,
    /// The approval's owner or Grant no longer stands.
    AuthorityChanged,
    /// The commit is no longer held here.
    ObjectsMissing,
}

/// The typed refusal that ended a request, with safe fields only: never a
/// credential or git's own text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishRefusal {
    pub reason: OriginPublishRefusalReason,
    /// The branch as the last authenticated read saw it; `None` when no
    /// read was made or none could be.
    pub observed: Option<OriginPublishRemote>,
    /// The destination fields that changed, for `destination_changed`.
    pub changed_fields: Vec<String>,
    /// The redacted cause: an operation, a class and an exit code.
    pub detail: Option<String>,
}

/// One exact publish request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishRequestView {
    pub request_id: EntityId,
    /// The served name.
    pub repo: String,
    /// The object-store-derived repository id.
    pub repo_id: EntityId,
    pub destination: OriginPublishDestination,
    /// The full branch ref, `refs/heads/...`.
    pub ref_name: String,
    /// The exact commit, 40 lower hex.
    pub commit: String,
    pub expected_remote: OriginPublishRemote,
    pub force: OriginPublishForce,
    /// The repo handle (a CODE anchor) a Grant holder's acts are bounded by.
    pub code_repo: Option<EntityId>,
    pub idempotency_key: Option<String>,
    /// Seconds; an undispatched request expires then. `None`: never.
    pub expires_at: Option<u64>,
    pub review: OriginPublishReview,
    pub state: OriginPublishState,
    pub requested: OriginPublishAct,
    pub approved: Option<OriginPublishAct>,
    pub dispatched: Option<OriginPublishAct>,
    pub refusal: Option<OriginPublishRefusal>,
    pub created_at: u64,
    pub finished_at: Option<u64>,
}

/// One item of a review page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OriginPublishReviewItem {
    /// A commit the push would expose, with every parent.
    Commit {
        commit: String,
        parents: Vec<String>,
    },
    /// A path the commit before it introduces against one of its parents.
    Path {
        /// `A`, `M`, `T` or `D`.
        status: String,
        mode: String,
        /// `None` for a deletion.
        object: Option<String>,
        /// Lossy UTF-8 of the stored path bytes; the digest reads the bytes.
        path: String,
    },
    /// An object a whole ref names on its way to what it points at (FIX
    /// 6866 part 2; an automatic mirror push only): an annotated tag, with
    /// the object it names and its tag name, or a tree or blob the ref names
    /// directly. The digest reads a tag's raw bytes, message included.
    Object {
        /// `tag`, `tree` or `blob`.
        object_type: String,
        object: String,
        /// What a tag names; `None` for a tree or blob.
        target: Option<String>,
        /// A tag's name; `None` for a tree or blob.
        name: Option<String>,
    },
}

/// One stored page of a review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishReviewPage {
    pub items: Vec<OriginPublishReviewItem>,
}
