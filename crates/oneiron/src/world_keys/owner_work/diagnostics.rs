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
//!   the worlds whose authority capsule there awaits a reader to seal it to
//!   the root pinned now (FIX 4496), and the exact attempt it persisted and
//!   has not resolved. Pending or answered, it also reports the last upload
//!   this install assembled for that home when the upload carries a readable
//!   section unchanged because it did not open, decode or merge here (FIX
//!   19525), as the upkeep reports it: the request's result does not hide
//!   what the owner repairs.
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
use crate::world_keys::UnmergedSection;
use crate::{EntityId, Vault};

use super::DeviceSyncStart;

mod key_plan;

/// How many keys one page of a re-assertion's diagnostics lists. A page
/// boundary, never a cap: `next_offset` names the rest.
const REASSERT_DIAGNOSTICS_PAGE: usize = 256;

#[doc(hidden)]
pub use oneiron_verb_wire::world_keys::owner_work::diagnostics::BundleHomeWarning;

/// The warning a publication to `home` carries, from the home's trusted
/// profile, else its live roster profile (FIX 4786); for a home whose
/// profile's class keeps sealed copies, the worlds of `awaiting_reader`, read
/// from the home's newest generation (FIX 4496), else `None`.
#[cfg(feature = "sync")]
pub(super) fn bundle_home_warning(
    fold: &AuthorityFold,
    home: EntityId,
    awaiting_reader: &[EntityId],
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
        Some(_) if !awaiting_reader.is_empty() => Some(BundleHomeWarning::AwaitingReader {
            worlds: awaiting_reader.to_vec(),
        }),
        Some(_) => None,
    }
}

/// Without the sync relay no home keeps a bundle here, and none is judged.
#[cfg(not(feature = "sync"))]
pub(super) fn bundle_home_warning(
    _fold: &AuthorityFold,
    _home: EntityId,
    _awaiting_reader: &[EntityId],
) -> Option<BundleHomeWarning> {
    None
}

#[doc(hidden)]
pub use oneiron_records::world_keys::owner_work::diagnostics::{
    EnsureDiagnostics, EnsureView, PublishAttemptView, PublishReach, ReassertKey, ReassertKeyState,
    ReassertUnread, UnmergedUploadView,
};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        /// The worlds whose authority capsule the generation files sealed to
        /// no recovery root pinned here then (FIX 4496); empty when the
        /// bundle did not open here or no root is pinned.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        awaiting_reader: Vec<EntityId>,
    },
}

/// What one relay pass on this install observed for a publication (FIX
/// 4784, 4785), kept in memory until the handle closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishObserved {
    /// The vault second of the pass.
    pub at: u64,
    /// The home the pass reached, when its proof stands here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<EntityId>,
    pub reach: PublishReach,
    pub latest: LatestRead,
    /// Each world whose capsule this pass's upload did not seal fresh because
    /// its merged authority history was incomplete (FIX 4497): owners warn
    /// members of exactly these worlds, not only of an empty capsule (FIX
    /// 12417). Empty when the pass assembled no upload or sealed every world.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub incomplete_authority: Vec<EntityId>,
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
    /// As the receipt's: why the home may keep no sealed copy (FIX 4786);
    /// else the worlds its newest generation, as the relay last read it,
    /// leaves to a reader (FIX 4496).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_warning: Option<BundleHomeWarning>,
    /// What this install's relay observed of the home and the newest
    /// generation, or that it is unknown.
    pub relay: RelayObservation,
    /// The last device-sync start outcome observed on this open vault session,
    /// shared by its clones. `None` means no outcome was recorded, not that
    /// sync is unconfigured. This is historical, never current worker health.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_sync_start: Option<DeviceSyncStart>,
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
    /// A bundle publication's, on its executor, pending or answered: the
    /// last upload this install assembled for its home when that upload
    /// carries a readable section unchanged (FIX 19525). `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmerged_upload: Option<UnmergedUploadView>,
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
            // The fold's shared body, never a copy of its permits (FIX 12138).
            let Some(asked) = fold.shared_owner_work_request(&request) else {
                return Ok(None);
            };
            let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
            (asked, me, fold.owner_work_result(&request).is_some())
        };
        // A kit custody request (FIX 6053) names no machine as executor.
        let executor = asked.executor_machine();
        // What the last upload for a publication's home carries unmerged,
        // shown whether the request has its result or not (FIX 19525).
        let unmerged_upload = if let OwnerWorkBody::PublishBundle { home } = asked.work {
            executor
                .filter(|executor| me == Some(*executor))
                .and_then(|executor| unmerged_upload_view(executor, home))
        } else {
            None
        };
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
            unmerged_upload,
        }))
    }

    /// A publication to `home` as this install's relay observed it.
    fn publication_diagnostics(
        &self,
        request: AuthorityEntryHash,
        home: EntityId,
    ) -> Result<PublicationDiagnostics> {
        let passes: Vec<PublishObserved> = self
            .world_keys
            .publications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|((asked, _), _)| *asked == request)
            .map(|(_, observed)| observed.clone())
            .collect();
        let awaiting_reader = passes
            .iter()
            .filter(|observed| observed.home == Some(home))
            .find_map(|observed| match &observed.latest {
                LatestRead::Read {
                    awaiting_reader, ..
                } => Some(&awaiting_reader[..]),
                LatestRead::NotRead | LatestRead::NoneKept => None,
            })
            .unwrap_or_default();
        let home_warning = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            bundle_home_warning(&fold, home, awaiting_reader)
        };
        let relay = if passes.is_empty() {
            RelayObservation::Unknown
        } else {
            RelayObservation::Observed { passes }
        };
        let device_sync_start = *self
            .world_keys
            .device_sync_start
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            device_sync_start,
            attempt,
        })
    }
}

/// The last upload `machine`, this install, assembled for `home`, as the
/// relay observation keeps it, when it carries a readable section unchanged
/// (FIX 19525).
#[cfg(feature = "sync")]
fn unmerged_upload_view(machine: EntityId, home: EntityId) -> Option<UnmergedUploadView> {
    let mut observation = crate::sync::client::sealed_bundle_relay_observation(&machine)?;
    let upload = observation.uploads.remove(&Some(home))?;
    if upload.sections.is_empty() {
        return None;
    }
    Some(UnmergedUploadView {
        at: upload.at,
        generation: hex(&upload.generation.to_bytes()),
        unmerged_sections: upload.sections,
    })
}

/// Without the sync relay no upload is assembled here.
#[cfg(not(feature = "sync"))]
fn unmerged_upload_view(_machine: EntityId, _home: EntityId) -> Option<UnmergedUploadView> {
    None
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
