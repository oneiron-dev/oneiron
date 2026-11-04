//! Door constants, floor names and prefixes, error type, and small naming helpers.

use crate::store::code_snapshot::RepoRef;

// The one-shot lifetime ceiling and the floor-name predicate are defined in
// `oneiron-authority`: the authority log's slip checks apply the same bounds.
pub(crate) use oneiron_authority::credential_door::names_a_floor;

/// The pre-receive scan is unconditional. Not a dial, not a policy row, not a
/// slip caveat: a catastrophe-class guard has no "off".
pub(super) const DOOR_SCAN_ALWAYS_ON: bool = true;

/// The lease ceiling this door holds while no holder policy row names one,
/// in seconds: a default, never a limit on what the holder may choose
/// (FIX 9777).
pub(super) const DOOR_MAX_LEASE_TTL_SECS: u64 = 3600;

pub(crate) use crate::receive_scan::DOOR_RECEIVE_PACK_EFFECTOR;

/// Every effector this door knows how to be. The dial may narrow this set to
/// a subset; a row naming anything outside it is a widen and fails closed.
pub(super) const DOOR_EFFECTORS: [&str; 1] = [DOOR_RECEIVE_PACK_EFFECTOR];

/// Verb: push objects through the door.
pub(super) const DOOR_VERB_RECEIVE_PACK: &str = "receive-pack";

const _: () = assert!(DOOR_SCAN_ALWAYS_ON);

/// Longest pushed-blob path the seam accepts before calling the input
/// unusable (a scanner failure, never a pass).
pub(super) const DOOR_MAX_PATH_BYTES: usize = 4096;

/// Longest object id the seam accepts. Git object ids are hex; anything else
/// is unusable seam input.
pub(super) const DOOR_MAX_OID_BYTES: usize = 64;

/// What an error names when the path itself is the malformed field. The raw
/// bytes never reach a message.
pub(super) const UNUSABLE_PATH: &str = "<unusable-path>";

/// A landed storage/custody refusal, as a door error.
pub(super) fn custody<E: Into<crate::error::Error>>(err: E) -> CredentialDoorError {
    CredentialDoorError::Custody(err.into())
}

/// Any failure to READ the authority log is the same answer: the door cannot
/// witness a single-use caveat, so it refuses one.
pub(crate) fn log_unreachable<E>(_err: E) -> CredentialDoorError {
    CredentialDoorError::AuthorityLogUnreachable
}

/// The door's typed refusals. Module-local by claim: the core error enum is
/// not extended for this seam.
///
/// No variant carries a secret value, an added line, or token material — the
/// door's whole job is to keep those out of anything printable.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialDoorError {
    /// Default-deny: absent, expired, revoked, parent-revoked, unverified, or
    /// insufficient credential. Loopback does not change this outcome.
    #[error("credential door refused the principal: {reason:?}")]
    UnauthorizedPrincipal {
        /// Which arm of the one evaluator call refused.
        reason: DoorDenyReason,
    },
    /// The scan could not run (unusable seam input, or the scanner itself
    /// failed). Fail-closed: a scan that did not happen is a rejection.
    #[error("credential door scan failed for {path}: {reason}")]
    ScanFailure {
        /// The pushed blob's path, or a placeholder when the path itself is
        /// the malformed field (its raw bytes never reach a message).
        path: String,
        /// Why the scan could not run.
        reason: &'static str,
    },
    /// A `secret.door.*` row is malformed, duplicated, or tries to widen.
    /// A present-but-unreadable declaration never falls back to the default.
    #[error("credential door policy row {key} is invalid: {reason}")]
    InvalidDoorPolicy {
        /// The offending policy key.
        key: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },
    /// Something inside the lattice named a floor.
    #[error("credential door floor named from {site}: {name}")]
    FloorNamed {
        /// Where the naming attempt came from.
        site: &'static str,
        /// The offending token.
        name: String,
    },
    /// The requested effector scope is empty, not a door effector, or has
    /// been narrowed away. There is no unscoped lease.
    #[error("credential door refused the lease scope {effector:?}: {reason}")]
    LeaseScopeRefused {
        /// The requested effector.
        effector: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// The authority log could not be read, so a single-use caveat cannot be
    /// witnessed. A verifier that cannot reach the log refuses the caveat.
    #[error("credential door could not reach the authority log")]
    AuthorityLogUnreachable,
    /// Signed authority does not admit this mint, handle, or use.
    #[error("credential door authority refused the operation")]
    AuthorityRejected,
    /// Third outcome: scope is valid but the verb needs an owner grant.
    #[error("credential door asks for verb-class consent")]
    Ask {
        reason: DoorDenyReason,
        effect: Box<crate::consent::ComposedEffect>,
    },
    /// A landed custody/vault refusal, passed through unchanged.
    #[error(transparent)]
    Custody(#[from] crate::error::Error),
}

/// The door's result alias.
pub(crate) type DoorResult<T> = Result<T, CredentialDoorError>;

/// Which arm of the one evaluator call refused. Not a credential kind: the
/// door has exactly one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoorDenyReason {
    /// No credential was presented at all.
    CredentialAbsent,
    /// The holder view carries no identity, so nothing was verified.
    HolderUnverified,
    /// Now is outside `[issued_at, expires_at)`.
    Expired,
    /// `verb ∈ slip` failed.
    VerbNotInSlip,
    /// `record ⊑ slip` failed.
    RecordOutsideSlip,
    /// `record ⊑ channel` failed.
    ChannelOutsideSlip,
}

pub(crate) use crate::receive_scan::{PushedBlob, ReceiveBlobKind, ReceiveScanHit};

/// What the ONE disposition does with a push's hits (FIX 7608, owner
/// ruling SECRETS-IN-REPOS = A). It is chosen in exactly one statement of
/// `binary_scan::resolve_receive_scan_hits`, never by a flag, a dial, a
/// caller or a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiveScanDisposition {
    /// The refusal with lift advice (the default before the FIX 7608 flip).
    #[allow(
        dead_code,
        reason = "FIX 7608 flip: the one statement chooses AdmitMarked; this arm stays its alternative"
    )]
    Refuse,
    /// Admit the push with each hit marked in its intent's transaction.
    AdmitMarked,
}

pub(crate) use crate::origin::receive_scan_verdict::{CheckoutSecretLiftProposal, DoorScanVerdict};

/// The repo identity a slip binds, WITHOUT the commit: a push door authorizes
/// against the repository, not against one revision of it.
pub(super) fn repo_record(repo: &RepoRef) -> String {
    match repo {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { owner, repo, .. } => format!("github:{owner}/{repo}"),
    }
}

/// A lease-TTL ceiling in seconds, as a MEET-SEMILATTICE value rather than a
/// number somebody may assign.
///
/// `None` is "no row declared one", the TOP of this lattice; the holder's
/// declared rows meet (minimum) among themselves, so packs compose to the
/// same answer in any order. The door reads [`DOOR_MAX_LEASE_TTL_SECS`] only
/// while nothing was declared (FIX 9777).
///
/// `Copy` on purpose: a ceiling is a BOUND, not custody of anything, and
/// copying a bound cannot duplicate authority. [`DoorCredential`] itself stays
/// non-`Clone`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TtlCeiling(Option<u64>);

impl TtlCeiling {
    /// The ceiling a holder's declaration of `secs` sets.
    pub(super) fn at_most(secs: u64) -> Self {
        Self(Some(secs))
    }

    /// The lattice meet: the tighter of two ceilings. Commutative,
    /// associative and idempotent; an undeclared side leaves the other.
    pub(super) fn meet(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(left), Some(right)) => Self(Some(left.min(right))),
            (declared, None) | (None, declared) => Self(declared),
        }
    }

    /// The ceiling in force: the holder's, or the door's default.
    pub(super) fn secs(self) -> u64 {
        self.0.unwrap_or(DOOR_MAX_LEASE_TTL_SECS)
    }
}
