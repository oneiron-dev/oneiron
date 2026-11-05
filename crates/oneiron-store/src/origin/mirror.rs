//! Outbound mirror pushing (ARCH-0068 RA8).
//!
//! The owner names one https mirror per served repository: its URL, the
//! custody record holding its push token and a cadence. The repository's
//! origin pushes its published refs, and only those, to the mirror on that
//! cadence, forced, and deletes there the refs it pushed before that are no
//! longer published. The cadence is the repository's real RPO. A host that
//! is not the repository's origin (a mirror, or another host's epoch) never
//! pushes.
//!
//! The token leaves custody only through [`Vault::inject_secret_at_door`]
//! bound to [`ORIGIN_MIRROR_PUSH_EFFECTOR`], and reaches git only as this
//! push's `Authorization` header, never config or disk.
//!
//! Mirror-main stays read-only. Mirror-side work comes back inbound through
//! the door as `refs/imported/<source>/<branch>`, which the change index
//! stamps `mirror_import`; merges happen at origin and push outward. Imported
//! refs are never pushed back out.
//!
//! Refs pushed are not readiness. A mirror clone must build without this
//! vault (ARCH-0068), and the push sends no Git-LFS bytes, so each run that
//! lands records an [`OriginMirrorReadiness`]: `Ready` only when the pushed
//! refs' whole history names no LFS object, else `NotReady`, naming the
//! objects nothing has verified at the mirror. The census behind it
//! (`mirror_census`) reads histories of any size in pages and never fails or
//! holds back the push.
//!
//! Each mirror carries a sync strategy (FIX 6866, `mirror_strategy`): a
//! `schedule` mirror is pushed on its cadence or by a push-now; a
//! `full_auto` mirror as soon as its published refs move, green heads only
//! (`mirror_auto`). An `ask_me` mirror, the default, sends nothing whole:
//! its push-now refuses with `publish_request_required`, and exact reviewed
//! commits go out through `origin::publish` instead. Every automatic push
//! freezes a reviewed plan before egress, leases each ref on the tip it
//! read and reconciles before any resend (`mirror_run`, `origin::publish`).
//! A mirror whose audience is public or unstated never takes history that
//! holds a marked live key (FIX 7608 slice 9, `secret_publication`).

use serde::{Deserialize, Serialize};

use crate::code_snapshot::repo_ref::RepoRef;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::mirror_auto::OriginMirrorAutomation;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use crate::origin::mirror_strategy::PublishRequestRequired;
use crate::origin::publication::publication_types::OriginPublicationStatus;
use crate::origin::secret_publication::RepoDestinationAudience;
use crate::origin::secret_publication::RepoDestinationVisibility;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The effector a mirror's push token is bound to in custody.
pub const ORIGIN_MIRROR_PUSH_EFFECTOR: &str = "origin:mirror-push";

/// The shortest cadence the owner may set, in seconds: the lifecycle tick.
pub const ORIGIN_MIRROR_MIN_EVERY_SECS: u64 = 60;

/// The basic-auth user a token goes with when the owner names none.
pub const ORIGIN_MIRROR_DEFAULT_USER: &str = "x-access-token";

/// Refs that came in from a mirror; they never go back out.
pub const ORIGIN_MIRROR_IMPORTED_PREFIX: &str = "refs/imported/";

/// The Git-LFS objects a not-ready run names; the census counts the rest and
/// still reads every one.
pub const ORIGIN_MIRROR_NAMED_LFS_OBJECTS: usize = 8;

const MAX_URL_BYTES: usize = 2048;
pub const MAX_USER_BYTES: usize = 128;

/// The owner's outbound mirror of one served repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorTarget {
    /// The served name the owner configured it under.
    pub repo: String,
    /// The mirror's https URL. It carries no credential, query or fragment.
    pub url: String,
    /// The custody record whose value is the mirror's push token.
    pub secret_ref: String,
    /// The basic-auth user the token goes with.
    pub user: String,
    /// Seconds between pushes: the repository's real RPO.
    pub every_secs: u64,
    /// The last push, whatever its outcome.
    pub last: Option<OriginMirrorRun>,
    /// The refs the mirror took from this vault's last successful push. A
    /// ref that leaves the published set is deleted there on the next push.
    pub pushed: Vec<String>,
    /// How the mirror sends what this vault publishes; a row that names
    /// none is `ask_me`.
    #[serde(default)]
    pub sync_strategy: OriginMirrorSyncStrategy,
    /// Moves by one each time the strategy changes.
    #[serde(default)]
    pub strategy_revision: u64,
    /// A fresh id each time the URL, user, custody record or served name
    /// changes, so no incarnation, across a clear and a new setup, ever
    /// repeats one; an exact publish request is bound to the one it was made
    /// at. `None` only on a row stored before generations.
    #[serde(default)]
    pub target_generation: Option<EntityId>,
    /// What the automatic pushes last did beyond `last` (FIX 6866): their
    /// newest plan, a run held before egress, a reconcile read that keeps
    /// failing, and full-auto heads waiting for checks.
    #[serde(default)]
    pub automation: Option<OriginMirrorAutomation>,
    /// Who can read the mirror, as the owner stated it (C3): `unknown` when
    /// unstated, held as public. A public or unknown mirror never takes
    /// history that holds a marked live key (`secret_publication`).
    pub audience: RepoDestinationAudience,
}

/// One push to a mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorRun {
    /// Seconds, on the vault clock.
    pub at: u64,
    /// Refs pushed.
    pub refs: u64,
    /// Refs deleted at the mirror.
    pub deleted: u64,
    /// `None` when the push landed; its redacted cause otherwise.
    pub failure: Option<String>,
    /// Whether a clone of the mirror could stand without this vault once
    /// these refs landed. Refs pushed are not readiness. `None` when the push
    /// failed: `failure` names why.
    pub readiness: Option<OriginMirrorReadiness>,
}

/// Whether a mirror holds what its pushed refs need beyond Git objects: the
/// Git-LFS objects their history names (ARCH-0068: a mirror clone builds
/// without vault access).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OriginMirrorReadiness {
    /// The pushed refs' whole history names no Git-LFS object.
    Ready,
    /// The mirror is not known to hold every Git-LFS object the pushed refs'
    /// history names.
    NotReady {
        /// Why it is not ready.
        reason: OriginMirrorNotReadyReason,
        /// The first distinct objects the census met, at most
        /// `ORIGIN_MIRROR_NAMED_LFS_OBJECTS` (8).
        objects: Vec<OriginMirrorLfsObject>,
        /// The further distinct objects the census counted but did not name.
        omitted_objects: u64,
    },
}

/// Why a mirror run is not ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorNotReadyReason {
    /// The pushed refs' history names Git-LFS objects whose bytes this push
    /// did not get to the mirror: refused, failed, unverified or not held
    /// by this vault.
    LfsObjectsNotVerified,
    /// The census of the pushed refs' Git-LFS pointers could not finish: an
    /// object was missing or a read failed. It names what it met before.
    LfsInventoryIncomplete,
}

/// One Git-LFS object a pushed ref's history names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorLfsObject {
    /// Its SHA-256, lower hex.
    pub oid: String,
    /// The byte length its pointer declares.
    pub size: u64,
}

/// What the owner sets.
#[derive(Debug, Clone)]
pub struct OriginMirrorTargetInput {
    /// The mirror's https URL.
    pub url: String,
    /// The custody record of the push token, bound to
    /// [`ORIGIN_MIRROR_PUSH_EFFECTOR`].
    pub secret_ref: String,
    /// [`ORIGIN_MIRROR_DEFAULT_USER`] when absent.
    pub user: Option<String>,
    /// Seconds between pushes, at least [`ORIGIN_MIRROR_MIN_EVERY_SECS`].
    pub every_secs: u64,
    /// The strategy; when absent the same URL keeps its own and a new one
    /// starts at `ask_me`.
    pub sync_strategy: Option<OriginMirrorSyncStrategy>,
    /// Who can read the mirror, as the owner states it; when absent the
    /// same URL keeps its own and a new one is `unknown`, held as public.
    pub visibility: Option<RepoDestinationVisibility>,
}

/// What one scheduled pass over the mirror targets did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OriginMirrorPushes {
    /// Targets configured.
    pub targets: u64,
    /// Pushes that landed.
    pub pushed: u64,
    /// Targets not due, not this host's to push, or left for the next pass.
    pub skipped: u64,
    /// Pushes that failed; each target's row names its cause.
    pub failed: u64,
}

/// Refuses a whole-ref push of a mirror whose strategy asks first.
pub fn require_whole_ref_strategy(repo_name: &str, target: &OriginMirrorTarget) -> Result<()> {
    if target.sync_strategy.pushes_whole_refs() {
        return Ok(());
    }
    Err(PublishRequestRequired {
        repo: repo_name.to_owned(),
        strategy: target.sync_strategy,
    }
    .into())
}

/// An https URL with a host, and no credential, query, fragment, space or
/// control byte.
pub fn validate_mirror_url(url: &str) -> Result<()> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(invalid("mirror URL must be https"));
    };
    let host = rest.split('/').next().unwrap_or("");
    if url.len() > MAX_URL_BYTES
        || host.is_empty()
        || host.contains('@')
        || rest.len() == host.len()
        || url
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '\\'))
    {
        return Err(invalid(
            "mirror URL must name a host and a path, with no credential, query or fragment",
        ));
    }
    Ok(())
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
