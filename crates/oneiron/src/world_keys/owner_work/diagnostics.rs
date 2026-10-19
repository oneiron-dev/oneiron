//! What blocks one pending owner work request, as its executor observes it
//! (FIX 4686, 4784, 4785, 4786, 4787): an owner's read that reports and
//! decides nothing.
//!
//! - A world's key work in Reassert mode lists, per key id its executor's own
//!   records name, what blocks the key there: its pad, a record or counted
//!   wrap that opens it, or a frontier one record cannot name. The checks are
//!   the holder's own read (`super::super::reassert`'s holder), never its
//!   writer. Keys the fold holds that no record of the executor's own names
//!   are listed as unknown history: the census reads its own records alone.
//!   A world with many keys pages; nothing is cut.
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

use super::super::reassert::HeldKey;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, OwnerWorkBody, OwnerWorkKind, WorldKeyId, WorldKeyMode,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// How many keys one page of a re-assertion's diagnostics lists. A page
/// boundary, never a cap: `next_offset` names the rest.
const REASSERT_DIAGNOSTICS_PAGE: usize = 256;

/// Why a bundle publication's home may keep no sealed copy, as its profile
/// stands here (FIX 4786). The request stays pending as it was; this only
/// says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
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
    /// It opens here, but a record wrapping it would name more rows than one
    /// record may (OF-520, raised on this handle): the world's settings need
    /// merging from one machine that sees every edit.
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
    /// Every key in this page, ascending by id: the keys this install's own
    /// records name, with the keys of unknown history among them.
    pub keys: Vec<ReassertKey>,
    /// Where the next page starts; `None` on the last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

impl ReassertDiagnostics {
    fn empty(world: EntityId) -> Self {
        Self {
            world,
            unread: None,
            reads_everywhere: false,
            keys: Vec::new(),
            next_offset: None,
        }
    }
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
    pub executor: EntityId,
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
        let observation = if me != Some(asked.executor) {
            ExecutorObservation::Unavailable
        } else if answered {
            ExecutorObservation::Answered
        } else {
            match asked.work {
                OwnerWorkBody::WorldKey {
                    mode: WorldKeyMode::Reassert,
                } => ExecutorObservation::Reassert(
                    self.reassert_diagnostics(asked.act.target, offset)?,
                ),
                OwnerWorkBody::PublishBundle { home } => ExecutorObservation::BundlePublication(
                    self.publication_diagnostics(request, home)?,
                ),
                OwnerWorkBody::WorldKey {
                    mode: WorldKeyMode::Ensure,
                }
                | OwnerWorkBody::Root { .. }
                | OwnerWorkBody::Custody { .. } => ExecutorObservation::NotReported,
            }
        };
        Ok(Some(OwnerWorkDiagnostics {
            request: hex(&request),
            kind: asked.kind(),
            executor: asked.executor,
            observation,
        }))
    }

    /// One page of `world`'s keys from `offset`, through the holder's own
    /// read checks: the ids its records name, then the fold's other keys of
    /// the world as unknown history, ascending by id.
    fn reassert_diagnostics(&self, world: EntityId, offset: usize) -> Result<ReassertDiagnostics> {
        let mut out = ReassertDiagnostics::empty(world);
        let Ok(secret) = self.machine_secret_outside_txn() else {
            out.unread = Some(ReassertUnread::NoMachineSecret);
            return Ok(out);
        };
        let txn = self.store.env.read_txn()?;
        let read = match self.holder_read_in_txn(&txn, world, &secret) {
            Ok(Some(read)) => read,
            Ok(None) => {
                out.reads_everywhere = true;
                return Ok(out);
            }
            Err(crate::Error::Secret(crate::error::SecretError::WorldKeyRefused(_))) => {
                out.unread = Some(ReassertUnread::NotMineReader);
                return Ok(out);
            }
            Err(error) => return Err(error),
        };
        let mut every: Vec<WorldKeyId> = read
            .fold
            .all_world_keys()
            .map(|key| key.id)
            .filter(|id| id.world == world)
            .chain(read.ids.iter().copied())
            .collect();
        every.sort_unstable();
        every.dedup();
        let wide = self.world_keys.frontier_raised(world);
        for id in every.iter().skip(offset).take(REASSERT_DIAGNOSTICS_PAGE) {
            let state = if !read.ids.contains(id) {
                ReassertKeyState::UnknownHistory
            } else {
                match read.check(&self.store, &txn, *id, &secret)? {
                    HeldKey::Conflicted => ReassertKeyState::Conflicted,
                    HeldKey::MissingPad => ReassertKeyState::MissingPad,
                    HeldKey::NoOpening => ReassertKeyState::NoOpeningRecordOrWrap,
                    HeldKey::Opened { missing, .. } if missing.is_empty() => {
                        ReassertKeyState::Wrapped
                    }
                    HeldKey::Opened { .. } if wide => ReassertKeyState::FrontierNeedsSplit,
                    HeldKey::Opened { missing, .. } => ReassertKeyState::WrapsPending {
                        missing: missing.len(),
                    },
                }
            };
            out.keys.push(ReassertKey { key: *id, state });
        }
        let end = offset.saturating_add(REASSERT_DIAGNOSTICS_PAGE);
        out.next_offset = (end < every.len()).then_some(end);
        Ok(out)
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
