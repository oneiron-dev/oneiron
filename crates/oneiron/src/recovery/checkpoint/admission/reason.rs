//! Why a cold managed restore refused (LC FIX 5384/5385; the contract is
//! lanes/l14/t3/restore-contract.md): a typed reason named at the branch
//! that refused, carried beside the error today's restore paths return,
//! which stays the same error, message and order. A reason names the check,
//! never a byte of what it checked. A failure no branch names stays
//! `storage_io`, `codec_invalid` or `startup_failed`, with the phase it
//! happened in: never a guessed precise cause.

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ArtifactError;

/// Why a cold managed restore refused; its wire spelling is snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreAdmissionReason {
    SourceIdentityMismatch,
    DataKeyMismatch,
    ArtifactIdentityMismatch,
    ArtifactKindMismatch,
    SignerUntrusted,
    SignatureInvalid,
    ArtifactIntegrityInvalid,
    CodecInvalid,
    BackupRegistryBindingMismatch,
    CustodyRequirementInvalid,
    CustodyLineageMismatch,
    CustodyHeadInvalid,
    AnchorUnavailable,
    AnchorMissing,
    AnchorInvalid,
    CustodyLogIncomplete,
    CustodyDiverged,
    CustodyHeadTooOld,
    CustodyKeyMissing,
    CustodyOwnerKeyRequired,
    BodyCustodyUnavailable,
    ClaimReceiptInvalid,
    AnchorMoved,
    CustodyLandingFailed,
    ManagedDekMacMismatch,
    DerivationOwnerMismatch,
    PageCustodyInvalid,
    RecipientBindingInvalid,
    RecipientReused,
    LastWrap,
    RetirementAuthorityInvalid,
    StorageIo,
    StartupFailed,
}

/// The step of a cold managed restore a refusal came from; snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePhase {
    /// The delivered key, the artifact's identity and its signed commitment.
    SourceCheck,
    /// The artifact opened whole: its manifest, frames, image and digests.
    ArtifactOpen,
    /// The custody head, its anchor and log, admitted and landed.
    CustodyAdmission,
    /// The image's rows and bodies landed and the vault reopened.
    RowsLanding,
    /// The caller's checks before the takeover fence.
    Finish,
    /// The anchor's advance to the takeover writer epoch.
    TakeoverFence,
    /// The fresh escrow wraps and the released recipients' retirement.
    Recipients,
    /// The restored vault's page-seal custody read back.
    PageCustody,
    /// The caller's step after every keep (the commit marker).
    CommitMarker,
}

/// What a refused cold managed restore left at its destination; snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreDestinationState {
    /// Nothing was kept: the destination, its custody and its mirror went.
    Removed,
    /// The restore was kept and is not serving: the destination and its
    /// custody stay, never rolled back.
    CommittedNotServing,
    /// Whether the last step happened is not known: the destination stays,
    /// never opened as ordinary or overwritten.
    Uncertain,
}

/// A cold managed restore's refusal: its reason, the phase, what the
/// destination holds, and the error today's paths return for it.
#[derive(Debug)]
pub struct RestoreAdmissionError {
    pub reason: RestoreAdmissionReason,
    pub phase: RestorePhase,
    pub destination: RestoreDestinationState,
    error: Error,
}

impl RestoreAdmissionError {
    /// A refusal the caller names: its own checks in the restore's `finish`
    /// and after-keep steps (a DEK MAC, a derivation owner, the marker).
    pub fn new(
        reason: RestoreAdmissionReason,
        phase: RestorePhase,
        destination: RestoreDestinationState,
        error: Error,
    ) -> Self {
        Self {
            reason,
            phase,
            destination,
            error,
        }
    }

    /// The error the refusal carries, as today's paths return it.
    pub fn error(&self) -> &Error {
        &self.error
    }

    pub fn into_error(self) -> Error {
        self.error
    }

    /// The same refusal after every keep: the destination stays, committed
    /// and not serving unless the caller said uncertain.
    pub(super) fn committed(mut self) -> Self {
        if self.destination == RestoreDestinationState::Removed {
            self.destination = RestoreDestinationState::CommittedNotServing;
        }
        self
    }
}

impl std::fmt::Display for RestoreAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} in {:?}: {}", self.reason, self.phase, self.error)
    }
}

impl std::error::Error for RestoreAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The branch-typed carrier the restore steps return: the error today's
/// paths return, unchanged, and the reason its branch names. Today's paths
/// take the error back with `?`.
#[derive(Debug)]
pub(crate) struct Rejected {
    reason: RestoreAdmissionReason,
    error: Error,
}

impl Rejected {
    pub(crate) fn new(reason: RestoreAdmissionReason, error: Error) -> Self {
        Self { reason, error }
    }

    /// The refusal in `phase`, before anything was kept.
    pub(crate) fn at(self, phase: RestorePhase) -> RestoreAdmissionError {
        RestoreAdmissionError::new(
            self.reason,
            phase,
            RestoreDestinationState::Removed,
            self.error,
        )
    }

    /// A body landing's error (FIX 6474): a frame its envelope reader
    /// refused, which reaches here inside the I/O error that reader's `Read`
    /// returns, is `codec_invalid`; any other is typed by its kind, raw I/O
    /// `storage_io`. The error stays as it came.
    pub(crate) fn landing(error: Error) -> Self {
        let reason = if frame_refused(&error) {
            RestoreAdmissionReason::CodecInvalid
        } else {
            by_kind(&error)
        };
        Self::new(reason, error)
    }

    /// A claim-bound receipt's read (FIX 6474): one that does not decode or
    /// open under its key is `claim_receipt_invalid`; a storage failure, or
    /// any other, is typed by its kind.
    pub(crate) fn receipt(error: Error) -> Self {
        match error {
            Error::CorruptedIndex(_) | Error::InvalidKey => {
                Self::new(RestoreAdmissionReason::ClaimReceiptInvalid, error)
            }
            error => Self::from(error),
        }
    }
}

/// Whether `error` is, or carries inside the I/O errors a `Read` wraps it
/// in, an undecodable record: a frame that failed its check.
fn frame_refused(error: &Error) -> bool {
    let mut at = error;
    loop {
        match at {
            Error::CorruptedIndex(_) | Error::InvalidKey => return true,
            Error::Io(io) => match io.get_ref().and_then(|inner| inner.downcast_ref::<Error>()) {
                Some(inner) => at = inner,
                None => return false,
            },
            _ => return false,
        }
    }
}

/// Names `reason` on an error of a branch that refused for it.
pub(crate) fn because(reason: RestoreAdmissionReason) -> impl FnOnce(Error) -> Rejected {
    move |error| Rejected::new(reason, error)
}

impl From<Error> for Rejected {
    /// An error no branch named: typed by its kind alone.
    fn from(error: Error) -> Self {
        Self::new(by_kind(&error), error)
    }
}

impl From<Rejected> for Error {
    fn from(rejected: Rejected) -> Self {
        rejected.error
    }
}

/// The reason an error's own type names: a disk or storage failure, an
/// undecodable record, the two custody refusals whose variants are typed
/// already (KS-2A, KS-3), and anything else a startup failure.
fn by_kind(error: &Error) -> RestoreAdmissionReason {
    use RestoreAdmissionReason as R;
    match error {
        Error::Io(_) | Error::Storage(_) | Error::MapFull => R::StorageIo,
        Error::CorruptedIndex(_) | Error::InvalidKey => R::CodecInvalid,
        Error::Artifact(ArtifactError::BodyKeyCustodyUnavailable { .. }) => {
            R::BodyCustodyUnavailable
        }
        Error::Artifact(ArtifactError::KnownValueHistoryUnavailable { .. }) => R::CustodyKeyMissing,
        _ => R::StartupFailed,
    }
}
