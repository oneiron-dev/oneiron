//! Door constants, floor names and prefixes, error type, and small naming helpers.

use crate::codebase::RepoRef;

/// The pre-receive scan is unconditional. Not a dial, not a policy row, not a
/// slip caveat: a catastrophe-class guard has no "off".
pub(super) const DOOR_SCAN_ALWAYS_ON: bool = true;

/// The hard ceiling on any lease this door issues, in seconds. A dial may
/// narrow it; nothing may raise it.
pub(super) const DOOR_MAX_LEASE_TTL_SECS: u64 = 3600;

/// The hard ceiling on a one-shot credential's lifetime, in seconds.
pub(super) const DOOR_ONE_SHOT_MAX_LIFETIME_SECS: u64 = 300;

/// The receive-pack door's effector — the scope every door-issued lease and
/// door injection is bound to by default.
pub(crate) const DOOR_RECEIVE_PACK_EFFECTOR: &str = "door:receive-pack";

/// Every effector this door knows how to be. The dial may narrow this set to
/// a subset; a row naming anything outside it is a widen and fails closed.
pub(super) const DOOR_EFFECTORS: [&str; 1] = [DOOR_RECEIVE_PACK_EFFECTOR];

/// Verb: push objects through the door.
pub(super) const DOOR_VERB_RECEIVE_PACK: &str = "receive-pack";

/// Verb: use a secret at the door without ever holding it.
pub(super) const DOOR_VERB_INJECT: &str = "inject";

/// Verb: mint a T1 lease ticket over a named secret.
pub(super) const DOOR_VERB_LEASE: &str = "lease";

/// Verb: redeem a one-shot credential into its named lease scope.
pub(super) const DOOR_VERB_REDEEM: &str = "redeem";

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

/// Floor names, lowercased. A policy row, verb, record, or channel that names
/// one of these is trying to reach a floor from inside the lattice.
const DOOR_FLOOR_NAMES: [&str; 3] = [
    "door_scan_always_on",
    "door_max_lease_ttl_secs",
    "door_one_shot_max_lifetime_secs",
];

/// Reserved policy-key prefixes, lowercased: the floor namespace and the scan
/// namespace are not dial space.
const DOOR_FLOOR_KEY_PREFIXES: [&str; 2] = ["secret.door.floor.", "secret.door.scan"];

/// True when `token` names a catastrophe floor.
pub(super) fn names_a_floor(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let mut names = DOOR_FLOOR_NAMES.iter();
    let mut prefixes = DOOR_FLOOR_KEY_PREFIXES.iter();
    names.any(|name| lower.contains(name)) || prefixes.any(|p| lower.starts_with(p))
}

/// A landed storage/custody refusal, as a door error.
pub(super) fn custody<E: Into<crate::error::Error>>(err: E) -> CredentialDoorError {
    CredentialDoorError::Custody(err.into())
}

/// Any failure to READ the authority log is the same answer: the door cannot
/// witness a single-use caveat, so it refuses one.
pub(super) fn log_unreachable<E>(_err: E) -> CredentialDoorError {
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
    /// A pushed blob carries a NUL byte or invalid UTF-8. Rejected regardless
    /// of entropy, magic bytes, or size: unscannable bytes have no pass path.
    #[error("credential door rejected binary content at {path}")]
    BinaryContentRejected {
        /// The pushed blob's path.
        path: String,
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
    /// The requested TTL is zero or above the effective ceiling.
    #[error("credential door denied a {requested_secs}s lease (ceiling {ceiling_secs}s)")]
    LeaseTtlDenied {
        /// What the caller asked for.
        requested_secs: u64,
        /// The effective ceiling (floor ∧ policy ∧ slip attenuation).
        ceiling_secs: u64,
    },
    /// The dial the STAMPING transaction resolved is not the dial the door
    /// admitted under.
    ///
    /// Raised by [`AdmittedLease::reaffirm_in_txn`] for any disagreement its
    /// two substantive arms did not already name. A dial that moved between the
    /// door's read and the stamp is a dial whose intent this materialization
    /// cannot know it is honouring, so it refuses rather than committing a row
    /// under a reading that is no longer true. Carries the door's own effector
    /// CONSTANT, never a caller-supplied string.
    #[error("credential door dial moved under the stamp for {effector}")]
    DialMovedUnderStamp {
        /// The door effector the admission was taken for.
        effector: &'static str,
    },
    /// A one-shot credential's lifetime exceeds the hard cap.
    #[error("credential door denied a {lifetime_secs}s one-shot (ceiling {ceiling_secs}s)")]
    OneShotLifetimeDenied {
        /// The credential's declared lifetime.
        lifetime_secs: u64,
        /// [`DOOR_ONE_SHOT_MAX_LIFETIME_SECS`].
        ceiling_secs: u64,
    },
    /// The authority log could not be read, so a single-use caveat cannot be
    /// witnessed. A verifier that cannot reach the log refuses the caveat.
    #[error("credential door could not reach the authority log")]
    AuthorityLogUnreachable,
    /// No landed authority-log surface admits slip-mint bodies, and this
    /// ticket may not invent one. The mint arm stops here, honestly, instead
    /// of growing a private ledger.
    #[error("credential door cannot mint: no landed authority-log mint surface")]
    MintUnavailable,
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
    /// The slip itself is revoked.
    Revoked,
    /// A parent slip is revoked, so every derived slip dies with it.
    ParentRevoked,
    /// `verb ∈ slip` failed.
    VerbNotInSlip,
    /// `record ⊑ slip` failed.
    RecordOutsideSlip,
    /// `record ⊑ channel` failed.
    ChannelOutsideSlip,
    /// The single-use caveat this operation requires is absent.
    SingleUseCaveatAbsent,
}

/// Lifecycle of a presented credential. Mirrors the landed lease-status
/// idiom: only `Active` admits use.
///
/// The three states are ORDERED by death — `Active ⊏ ParentRevoked ⊏ Revoked`
/// — and every transition this module admits is a join UP that order. That is
/// why there is no status setter: a setter's whole shape is "assign a status",
/// and the one assignment a revocation model must never admit,
/// `Revoked -> Active`, is precisely the one a setter cannot refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DoorCredentialStatus {
    /// Live within its lifetime.
    Active,
    /// Revoked directly.
    Revoked,
    /// Revoked by cascade from a revoked parent.
    ParentRevoked,
}

impl DoorCredentialStatus {
    /// Position in the death order. Higher is deader, and a DIRECT revocation
    /// outranks a cascaded one so a slip revoked in its own right is never
    /// downgraded to merely having inherited its parent's death.
    fn rank(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::ParentRevoked => 1,
            Self::Revoked => 2,
        }
    }

    /// The lattice join: the deader of the two. Idempotent, commutative,
    /// associative and monotone, which is exactly what makes `Revoked`
    /// terminal no matter what arrives afterwards or in what order.
    pub(super) fn join(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// One pushed blob as the transport hands it to the door. A data seam: the
/// quarantine extraction that fills it belongs to the transport owner.
///
/// `Debug` redacts `added_lines` — those bytes are exactly the ones that may
/// be secret-shaped, and a diagnostic print is not a place for them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PushedBlob {
    /// Repository-relative path of the blob.
    pub(crate) path: String,
    /// The blob's object id (hex).
    pub(crate) oid: String,
    /// Diff-ADDED lines only, as raw bytes. Context and removed lines are not
    /// the door's business; added bytes are what a push makes durable.
    pub(crate) added_lines: Vec<Vec<u8>>,
}

impl std::fmt::Debug for PushedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedBlob")
            .field("path", &self.path)
            .field("oid", &self.oid)
            .field(
                "added_lines",
                &format_args!("<redacted {} added lines>", self.added_lines.len()),
            )
            .finish()
    }
}

/// The verdict of a pre-receive scan. A verdict is a scan OUTCOME: an
/// unscannable blob is not a verdict, it is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DoorScanVerdict {
    /// Every added line scanned, nothing matched.
    Clean,
    /// The push is refused; each proposal names one offending path.
    Rejected {
        /// One proposal per offending blob.
        proposals: Vec<SecretLiftProposal>,
    },
}

/// "Lift this into the vault instead" — the door's advice when a push carries
/// secret-shaped bytes.
///
/// Path, detector reason, and a suggested NAME. Never the matched line, never
/// the token, never any value bytes: the proposal travels back to whoever
/// pushed, and it must be safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretLiftProposal {
    /// The offending blob's path.
    pub(crate) path: String,
    /// The detector's reason code (e.g. `gate.secret_scan.github_token`).
    pub(crate) reason: &'static str,
    /// A suggested custody name for the lifted secret, derived from the repo
    /// and path only.
    pub(crate) suggested_secret_name: String,
}

impl SecretLiftProposal {
    /// Builds a proposal from non-secret addressing data only.
    pub(super) fn new(repo: &RepoRef, path: &str, reason: &'static str) -> Self {
        Self {
            path: path.to_owned(),
            reason,
            suggested_secret_name: format!("{}.{}", repo_slug(repo), path_slug(path)),
        }
    }
}

/// The repo identity a slip binds, WITHOUT the commit: a push door authorizes
/// against the repository, not against one revision of it.
pub(super) fn repo_record(repo: &RepoRef) -> String {
    match repo {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { owner, repo, .. } => format!("github:{owner}/{repo}"),
    }
}

/// A short, name-shaped slug for the repository.
fn repo_slug(repo: &RepoRef) -> String {
    match repo {
        RepoRef::LocalFolder { path, .. } => path_slug(path.rsplit('/').next().unwrap_or(path)),
        RepoRef::GitHubAtCommit { owner, repo, .. } => {
            format!("{}_{}", path_slug(owner), path_slug(repo))
        }
    }
}

/// Lowercases and folds everything that is not `[a-z0-9]` into `_` so a
/// suggested name is a name and carries no path punctuation.
fn path_slug(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unnamed".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// A lease-TTL ceiling in seconds, as a MEET-SEMILATTICE value rather than a
/// number somebody may assign.
///
/// [`DOOR_MAX_LEASE_TTL_SECS`] is the TOP of this lattice, not a check applied
/// somewhere downstream of it. Every way in clamps against that floor, and the
/// only way to combine two ceilings is `meet` (minimum), so a `TtlCeiling`
/// above the floor is not a value this type can hold and no sequence of
/// caveats, dial rows, clock readings, or call orders can construct one. That
/// is the whole difference from the `Option<u64>` this replaced, where the
/// invariant lived in whoever remembered to take the `min` last and an
/// un-narrowed slip was spelled the same as a slip with no opinion.
///
/// `Copy` on purpose: a ceiling is a BOUND, not custody of anything, and
/// copying a bound cannot duplicate authority. [`DoorCredential`] itself stays
/// non-`Clone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TtlCeiling(u64);

impl Default for TtlCeiling {
    /// The safe default IS the floor: a slip nobody narrowed sits at the
    /// widest ceiling the door has, never wider and never unbounded.
    fn default() -> Self {
        Self::FLOOR
    }
}

impl TtlCeiling {
    /// The catastrophe floor — the widest ceiling that can exist here.
    pub(super) const FLOOR: Self = Self(DOOR_MAX_LEASE_TTL_SECS);

    /// The ceiling a declaration of `secs` buys. Never above the floor: a
    /// value that would widen is clamped rather than refused, because this is
    /// the NARROWING side of the seam. The refusals that must be loud — a dial
    /// row that tries to widen the ceiling — are raised where the row is
    /// decoded ([`decode_floors_row`]), so clamping here cannot hide one.
    pub(super) fn at_most(secs: u64) -> Self {
        Self(secs.min(Self::FLOOR.0))
    }

    /// The lattice meet: the tighter of two ceilings. Commutative,
    /// associative and idempotent, so ceilings compose to the same answer in
    /// any order and no composition can ever raise one.
    pub(super) fn meet(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// [`Self::meet`] against a bound that arrives as raw seconds.
    pub(super) fn meet_secs(self, secs: u64) -> Self {
        self.meet(Self::at_most(secs))
    }

    /// The ceiling in seconds, for the refusal that has to report it.
    pub(super) fn secs(self) -> u64 {
        self.0
    }

    /// Whether a REQUESTED TTL is admitted: positive, and at or below the
    /// ceiling. Zero is not a lease, it is an empty ticket.
    pub(super) fn admits(self, requested_secs: u64) -> bool {
        requested_secs != 0 && requested_secs <= self.0
    }
}
