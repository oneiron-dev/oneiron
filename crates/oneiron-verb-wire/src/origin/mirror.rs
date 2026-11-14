//! Moved from `crates/oneiron/src/origin/mirror.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::origin::mirror_auto::OriginMirrorAutomation;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BrokerIsolation;
use oneiron_store::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron_store::origin::secret_publication::RepoDestinationAudience;
use serde::Deserialize;
use serde::Serialize;

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
    /// How this run's Git-LFS upload went out, apart from the git pushes'
    /// own broker isolation. `None` when the run sent no LFS object: the
    /// push failed, the census did not finish, or it met none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lfs_transfer: Option<OriginMirrorLfsTransfer>,
}

/// How one mirror run's Git-LFS upload went out (FIX 19876): the route its
/// batch calls and object actions took, and on the broker's route its
/// isolation and how many credential echoes it rewrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorLfsTransfer {
    /// Who sent the requests.
    pub route: OriginMirrorLfsRoute,
    /// How the credential broker is kept apart from the daemon, once an
    /// exchange reached it; `None` on the daemon's route, or when no
    /// exchange reached the broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_isolation: Option<BrokerIsolation>,
    /// How many action header values of the batch replies the broker
    /// rewrote to its placeholder, each the mirror's credential handed back
    /// for an action; the broker installed it again only on an action at
    /// the mirror's own origin. A count, never a value; zero on the daemon's
    /// route.
    #[serde(default)]
    pub credential_rewrites: u64,
}

/// Who sent a mirror run's Git-LFS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorLfsRoute {
    /// The served host's credential broker, which alone installed the
    /// mirror's credential.
    Broker,
    /// This daemon's own HTTPS client, the mirror's credential in its
    /// memory: a vault opened with no host.
    Daemon,
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
