//! What blocks one pending owner work request, as its executor observes it
//! (FIX 4686, 4784, 4785, 4786, 4787): an owner's read that reports and
//! decides nothing.
//!
//! - A world's key work in Reassert mode lists, per key id its executor's own
//!   records name, what blocks the key there: its pad, a record or counted
//!   wrap that opens it, or a frontier one record cannot name. The checks are
//!   the holder's own read (`super::super::reassert`'s holder), never its
//!   writer; whether one record names a key's frontier is the writer's own
//!   read-only plan of that key's missing wraps for this request, on this
//!   install's durable state, so a restart changes no answer (FIX 5552).
//!   Keys the fold holds that no record of the executor's own names are
//!   listed as unknown history: the census reads its own records alone. A
//!   world with many keys pages; nothing is cut. The ensure step that
//!   follows, the world's current key or the first key it would mint, is
//!   reported the same way, and so is an Ensure request's (FIX 5552).
//! - A bundle publication reports whether its home keeps sealed copies by
//!   its known profile, what this install's relay last saw when it tried to
//!   reach that home and of the home's newest generation's outer capsules,
//!   and the exact attempt it persisted and has not resolved.
//!
//! Only the executor observes its own work: any other install answers that
//! the executor's observation is unavailable here. Pending and progress stay
//! as they are (CALLS WORLD_KEY_REASSERT_INCOMPLETE, BUNDLE_PUBLISH_EXECUTOR
//! unchanged). Ids, counts and closed reasons only, and a sealed bundle's
//! ciphertext digest: never a secret, a key or a digest of plaintext.

use serde::Serialize;

use crate::authority::{
    AuthorityEntryHash, AuthorityFold, OwnerWorkBody, OwnerWorkKind, WorldKeyId, WorldKeyMode,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

mod key_plan;

/// How many keys one page of a re-assertion's diagnostics lists. A page
/// boundary, never a cap: `next_offset` names the rest.
const REASSERT_DIAGNOSTICS_PAGE: usize = 256;

/// Why a bundle publication's home may keep no sealed copy, as its profile
/// stands here (FIX 4786). The request stays pending as it was; this only
/// says why.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleHomeWarning {
    /// The home's profile is a phone's: its own doors keep no sealed copy
    /// (DEC-0005, SEALED_BUNDLE_DEVICE_POLICY), so no publisher's upload
    /// lands there.
    HomeDoesNotKeepSealedBundles,
    /// No live profile of the home is known here: whether it keeps sealed
    /// copies is unknown.
    HomeProfileUnknown,
}

impl BundleHomeWarning {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::HomeDoesNotKeepSealedBundles => {
                "the home is a phone, which keeps no sealed copy; the request stays pending until \
                 you ask for a home that keeps one"
            }
            Self::HomeProfileUnknown => {
                "no profile of the home is known here, so whether it keeps sealed copies is unknown"
            }
        }
    }
}

/// The warning a publication to `home` carries, from the home's trusted
/// profile, else its live roster profile (FIX 4786): `None` when that
/// profile's class keeps sealed copies.
#[cfg(feature = "sync")]
pub(super) fn bundle_home_warning(
    fold: &AuthorityFold,
    home: EntityId,
) -> Option<BundleHomeWarning> {
    let class = match fold.trusted_machine(home) {
        Some(trusted) => Some(trusted.profile.device_class),
        None => fold
            .machine(home)
            .and_then(|folded| folded.roster.as_ref())
            .filter(|roster| roster.is_live())
            .map(|roster| roster.profile.device_class),
    };
    match class {
        None => Some(BundleHomeWarning::HomeProfileUnknown),
        Some(class) if !crate::sync::residence::holds_sealed_bundle(class) => {
            Some(BundleHomeWarning::HomeDoesNotKeepSealedBundles)
        }
        Some(_) => None,
    }
}

/// Without the sync relay no home keeps a bundle here, and none is judged.
#[cfg(not(feature = "sync"))]
pub(super) fn bundle_home_warning(
    _fold: &AuthorityFold,
    _home: EntityId,
) -> Option<BundleHomeWarning> {
    None
}

/// What blocks one key of a re-assertion on its executor (FIX 4686).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReassertKeyState {
    /// Every recipient the settings allow holds a counted wrap of it.
    Wrapped,
    /// It opens here and `missing` recipients lack a counted wrap: the next
    /// pickup wraps them, unless the world's frontier proves too wide.
    WrapsPending { missing: usize },
    /// No pad of it is here.
    MissingPad,
    /// No record of this install's own, and no counted wrap to it, opens it
    /// here.
    NoOpeningRecordOrWrap,
    /// It opens here, but a record wrapping it to the recipients that lack a
    /// wrap would name more rows than one record may (OF-520), by the
    /// writer's own plan of this key for this request on this install's
    /// durable state (FIX 5552): the world's settings need merging from one
    /// machine that sees every edit.
    FrontierNeedsSplit,
    /// Counted records named other bytes or another owner for it: the
    /// re-assertion leaves it as it is.
    Conflicted,
    /// The fold holds it, but no record of this install's own names it here:
    /// the re-assertion does not reach it from this install, and whether this
    /// install wrapped it before is not known here.
    UnknownHistory,
}

/// One key of a re-assertion and its state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReassertKey {
    pub key: WorldKeyId,
    #[serde(flatten)]
    pub state: ReassertKeyState,
}

/// Why the executor's read checks could not run here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReassertUnread {
    /// This install's machine secret does not load: the pickup leaves the
    /// work pending for the same reason.
    NoMachineSecret,
    /// This install is no eligible reader mine here under its install key,
    /// or its identity or key changed: its next pickup answers the request.
    NotMineReader,
}

/// The world's current key on the executor, as the ensure step finds it
/// (FIX 5552): the step that follows once every key of a re-assertion is
/// wrapped again, and all an Ensure request does. Recomputed from this
/// install's durable state on every read; nothing is minted or wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnsureView {
    /// The world's current key here. `None` when it has none here and the
    /// ensure mints its first key: then `WrapsPending` counts every recipient
    /// its first records wrap to, and `FrontierNeedsSplit` says one record
    /// cannot name them all, so its record wraps to this install and the
    /// pinned root alone and the other readers wait for the world's settings
    /// to merge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<WorldKeyId>,
    #[serde(flatten)]
    pub state: ReassertKeyState,
}

/// One page of a re-assertion's keys on its executor (FIX 4686).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReassertDiagnostics {
    pub world: EntityId,
    /// Why the read checks did not run; `None` when they did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<ReassertUnread>,
    /// The world reads everywhere: it counts no key, and nothing blocks the
    /// re-assertion.
    pub reads_everywhere: bool,
    /// A door on this handle raised OF-520's question for this world since
    /// the handle opened: history. Each key's own state says whether its
    /// frontier still needs a split (FIX 5552).
    pub question_raised: bool,
    /// Every key in this page, ascending by id: the keys this install's own
    /// records name, with the keys of unknown history among them.
    pub keys: Vec<ReassertKey>,
    /// Where the next page starts; `None` on the last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// The ensure step after every key is wrapped again (FIX 5552); `None`
    /// when the read checks did not run or the world reads everywhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensure: Option<EnsureView>,
}

impl ReassertDiagnostics {
    fn empty(world: EntityId, question_raised: bool) -> Self {
        Self {
            world,
            unread: None,
            reads_everywhere: false,
            question_raised,
            keys: Vec::new(),
            next_offset: None,
            ensure: None,
        }
    }
}

/// A world's key work in Ensure mode on its executor (FIX 5552).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnsureDiagnostics {
    pub world: EntityId,
    /// Why the read checks did not run; `None` when they did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<ReassertUnread>,
    /// The world reads everywhere: it counts no key, and nothing blocks the
    /// ensure.
    pub reads_everywhere: bool,
    /// A door on this handle raised OF-520's question for this world since
    /// the handle opened: history, as a re-assertion's.
    pub question_raised: bool,
    /// The world's current key, or the first one the ensure would mint;
    /// `None` when the read checks did not run or the world reads everywhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensure: Option<EnsureView>,
}

/// What a relay pass found when it went for a publication's home (FIX
/// 4784). It never decides who executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishReach {
    /// The pass reached the home the request names, its proof standing here.
    Reached,
    /// The pass reached another home: this install's relay syncs with a home
    /// the request does not name.
    OtherHome,
    /// The pass reached a home whose proof does not stand here.
    HomeUnproven,
    /// The pass reached no home: offline, or the connection did not come up.
    Offline,
    /// The home refused the pass's bind, or answered in a shape it did not
    /// take.
    Refused,
}

/// How one outer capsule of the home's newest generation opened here (FIX
/// 4785).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleRead {
    /// A capsule sealed to this machine opens it.
    Opens,
    /// No capsule opens with this machine's key: it is not among the
    /// object's outer readers, so it can neither carry the generation nor
    /// see a lost acknowledgement in it.
    NoCapsuleHere,
    /// No capsule opens with this machine's key, and the publication grant
    /// the object carries for the request this install publishes for does:
    /// it carries that one generation and publishes on top of it, with no
    /// world key and no later generation by it.
    PublicationGrant,
    /// It opened, or failed, for another reason: a publisher this install
    /// does not take, or another error. Not a capsule question.
    Refused,
}

impl CapsuleRead {
    /// How `opened` went.
    #[cfg(feature = "sync")]
    pub(crate) fn of<T>(opened: &Result<T>) -> Self {
        match opened {
            Ok(_) => Self::Opens,
            Err(crate::Error::Secret(crate::error::SecretError::SealedBundleNoCapsule)) => {
                Self::NoCapsuleHere
            }
            Err(_) => Self::Refused,
        }
    }
}

/// The home's newest generation as a relay pass read it (FIX 4785).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum LatestRead {
    /// The pass did not read it: it did not reach the home, or stopped first.
    NotRead,
    /// The home keeps no generation: there is nothing to open, and the
    /// executor publishes to the empty home.
    NoneKept,
    /// How the generation's two outer capsules opened here.
    Read {
        bundle: CapsuleRead,
        pads: CapsuleRead,
    },
}

/// What one relay pass on this install observed for a publication (FIX
/// 4784, 4785), kept in memory until the handle closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PublishObserved {
    /// The vault second of the pass.
    pub at: u64,
    /// The home the pass reached, when its proof stands here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<EntityId>,
    pub reach: PublishReach,
    pub latest: LatestRead,
}

/// The exact attempt an executor persisted before its commit and has not
/// resolved (FIX 4787): the generation and the sealed bundle's ciphertext
/// digest, each in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishAttemptView {
    pub generation: String,
    pub bundle_digest: String,
}

/// What this install's relay observed for a publication (FIX 4784).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RelayObservation {
    /// No relay pass on this install observed it since this handle opened:
    /// the relay may not run here, or has not run yet. Never read as
    /// "unreachable".
    Unknown,
    /// What each pass last saw, by the home it reached.
    Observed { passes: Vec<PublishObserved> },
}

/// A bundle publication on its executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicationDiagnostics {
    pub home: EntityId,
    /// As the receipt's: why the home may keep no sealed copy (FIX 4786).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_warning: Option<BundleHomeWarning>,
    /// What this install's relay observed of the home and the newest
    /// generation, or that it is unknown.
    pub relay: RelayObservation,
    /// The exact attempt this install persisted and has not resolved; `None`
    /// with none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt: Option<PublishAttemptView>,
}

/// What the install a diagnostics read runs on observes of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "observation")]
pub enum ExecutorObservation {
    /// Another install is the executor: only it observes its own blockers.
    Unavailable,
    /// The request has its result here: nothing blocks it.
    Answered,
    /// A world's key work in Reassert mode.
    Reassert(ReassertDiagnostics),
    /// A world's key work in Ensure mode (FIX 5552).
    Ensure(EnsureDiagnostics),
    /// A bundle publication.
    BundlePublication(PublicationDiagnostics),
    /// Work of another kind or mode: no executor diagnostics are kept.
    NotReported,
}

impl ExecutorObservation {
    /// The words a surface shows.
    #[must_use]
    pub fn text(&self) -> &'static str {
        match self {
            Self::Unavailable => "executor observation unavailable on this install",
            Self::Answered => "answered by its executor",
            Self::Reassert(_) => {
                "the executor's own records name these keys; keys of unknown history are listed \
                 as such"
            }
            Self::Ensure(_) => {
                "the world's current key on the executor, or the first key it would mint, and \
                 what blocks wrapping it to every reader"
            }
            Self::BundlePublication(_) => {
                "what the executor's relay last saw here; unknown until a pass observes it"
            }
            Self::NotReported => "no executor diagnostics are kept for this work",
        }
    }
}

/// One request's executor diagnostics, as this install observes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerWorkDiagnostics {
    /// The request's signed entry, in hex.
    pub request: String,
    pub kind: OwnerWorkKind,
    /// The install that is to do it; `None` for the owner's kit push (FIX
    /// 6053), which no machine executes.
    pub executor: Option<EntityId>,
    #[serde(flatten)]
    pub observation: ExecutorObservation,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Vault {
    /// What blocks the owner work request signed as entry `request`, as
    /// this install observes it: its executor's own observation when this
    /// install is the executor, else that it is unavailable here. A
    /// re-assertion's keys page from `offset`. An owner's read: the proof is
    /// revalidated. `None` when this install folds no such request. Reads
    /// only: no request, pickup or relay changes.
    pub fn owner_work_diagnostics(
        &self,
        owner: &AuthenticatedOwner,
        request: AuthorityEntryHash,
        offset: usize,
    ) -> Result<Option<OwnerWorkDiagnostics>> {
        let (asked, me, answered) = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let Some(asked) = fold.owner_work_request(&request).cloned() else {
                return Ok(None);
            };
            let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
            (asked, me, fold.owner_work_result(&request).is_some())
        };
        // A kit custody request (FIX 6053) names no machine as executor.
        let executor = asked.executor_machine();
        let observation = if executor.is_none() || me != executor {
            ExecutorObservation::Unavailable
        } else if answered {
            ExecutorObservation::Answered
        } else {
            match asked.work {
                OwnerWorkBody::WorldKey {
                    mode: WorldKeyMode::Reassert,
                } => ExecutorObservation::Reassert(self.reassert_diagnostics(
                    request,
                    asked.act.target,
                    offset,
                )?),
                OwnerWorkBody::WorldKey {
                    mode: WorldKeyMode::Ensure,
                } => {
                    ExecutorObservation::Ensure(self.ensure_diagnostics(request, asked.act.target)?)
                }
                OwnerWorkBody::PublishBundle { home } => ExecutorObservation::BundlePublication(
                    self.publication_diagnostics(request, home)?,
                ),
                OwnerWorkBody::Root { .. }
                | OwnerWorkBody::Custody { .. }
                | OwnerWorkBody::ExportSecret(_) => ExecutorObservation::NotReported,
            }
        };
        Ok(Some(OwnerWorkDiagnostics {
            request: hex(&request),
            kind: asked.kind(),
            executor,
            observation,
        }))
    }

    /// A publication to `home` as this install's relay observed it.
    fn publication_diagnostics(
        &self,
        request: AuthorityEntryHash,
        home: EntityId,
    ) -> Result<PublicationDiagnostics> {
        let home_warning = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            bundle_home_warning(&fold, home)
        };
        let passes: Vec<PublishObserved> = self
            .world_keys
            .publications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|((asked, _), _)| *asked == request)
            .map(|(_, observed)| *observed)
            .collect();
        let relay = if passes.is_empty() {
            RelayObservation::Unknown
        } else {
            RelayObservation::Observed { passes }
        };
        #[cfg(feature = "sync")]
        let attempt = self
            .unresolved_bundle_attempt(request)?
            .map(|attempt| PublishAttemptView {
                generation: hex(&attempt.generation.to_bytes()),
                bundle_digest: hex(&attempt.bundle_digest),
            });
        #[cfg(not(feature = "sync"))]
        let attempt = None;
        Ok(PublicationDiagnostics {
            home,
            home_warning,
            relay,
            attempt,
        })
    }
}

#[cfg(feature = "sync")]
impl Vault {
    /// Keeps what a relay pass observed for the publication `request`, by
    /// the home it reached (FIX 4784, 4785). In memory only.
    pub(crate) fn observe_bundle_publication(
        &self,
        request: AuthorityEntryHash,
        observed: PublishObserved,
    ) {
        self.world_keys
            .publications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((request, observed.home), observed);
    }

    /// Forgets the observations of every publication not in `pending`, the
    /// ones still naming this install with no result.
    pub(crate) fn keep_bundle_publication_observations(
        &self,
        pending: &[(AuthorityEntryHash, EntityId)],
    ) {
        self.world_keys
            .publications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(request, _), _| pending.iter().any(|(asked, _)| asked == request));
    }
}
