//! ARCH-0068 RC4 — the credential door (CSTDY-02).
//!
//! One organ owns what a repository push has to survive before anything it
//! carries becomes durable, and what a credential may buy at that boundary:
//!
//! 1. **T0 remote-at-door injection** — the value is resolved and handed to
//!    the egress INSIDE [`Vault::inject_secret_at_door`]; the caller receives
//!    a [`DoorInjectionReceipt`] and never the bytes.
//! 2. **T1 lease tickets** — the landed bounded materialization is the ONE
//!    materializing call (it writes the lease row and its receipt before the
//!    value returns, and clamps the lease against the credential's absolute
//!    expiry using the same instant that authorized it); this module composes
//!    over it and never mints a second, unmarked materialization path.
//! 3. **A catastrophe-class dial** — `secret.door.*` rows in the vault's
//!    POLICY_MANIFEST bodies, resolved locally with the same fail-closed,
//!    most-restrictive-wins idiom [`crate::secret_custody::SecretCustodyFloor`]
//!    uses. The dial NARROWS ONLY, it covers EVERY door effector including
//!    receive-pack itself, and it fails closed on any indexed declaration this
//!    door cannot read.
//! 4. **A pre-receive secret-shaped diff verdict** — every added line of every
//!    pushed blob goes through [`scan_file_content`] (the detector stays
//!    single-homed in `batch::secret_scan`; this door is a read-only consumer).
//! 5. **Authenticated receive-pack** — loopback is a network fact, never an
//!    identity, so the credential checks run unconditionally, under the same
//!    resolved effector dial every other door operation answers to.
//! 6. **A one-shot redemption hatch** — consumed by move, single-use caveat,
//!    lifetime capped, named secret and named effector only.
//!
//! # Floors are constants, not dials
//!
//! [`DOOR_SCAN_ALWAYS_ON`], [`DOOR_MAX_LEASE_TTL_SECS`] and
//! [`DOOR_ONE_SHOT_MAX_LIFETIME_SECS`] sit OUTSIDE the policy lattice. No
//! policy row, verb, caveat, attenuation, or scope may name or disable one:
//! naming a floor from inside the lattice is itself a fail-closed refusal
//! ([`CredentialDoorError::FloorNamed`]), because the only thing a "floor
//! switch" can ever be is an off switch for a catastrophe guard.
//!
//! # The clock is the vault's, not the caller's
//!
//! No door operation takes a `now`. Every one of them reads a
//! [`VaultInstant`] from [`CredentialDoorService::door_instant`] — the vault's
//! authority-plane observation clock — and that single reading answers the
//! credential's lifetime, sizes its remaining validity, bounds the ticket it
//! may buy, and stamps the lease.
//!
//! A caller-supplied `now: u64` was an authorization input wearing a
//! timestamp's clothes: whoever passed it decided whether the presented slip
//! was inside its own window and how much of that window was left. `now =
//! issued_at` revives a credential that died an hour ago and hands it a
//! full-length ticket, and no amount of default-deny elsewhere in the
//! evaluator can refuse it, because by then the lie has already been told.
//! [`VaultInstant`] has no `From<u64>` and no public constructor, so that
//! argument is not merely absent from these signatures — it cannot be
//! reintroduced by a caller at all.
//!
//! # Admission is a VALUE, taken inside the transaction that stamps
//!
//! The dial is not a bag of numbers this module reads twice. What resolving it
//! yields is [`PolicyFloors`] — the dial-narrowable catastrophe floors, each in
//! its lattice form — and an [`EffectorDial`], a subset of [`DOOR_EFFECTORS`]
//! BY CONSTRUCTION, because a [`DoorEffector`] cannot be built from a name that
//! is not one of this door's own constants. What the scope check PRODUCES is an
//! [`AdmittedScope`]: proof that one named effector was admitted, carrying the
//! resolved dial it was admitted under and the single [`VaultInstant`] the
//! operation authorized at. Sizing a ticket against that proof yields an
//! [`AdmittedLease`], and that ONE value is the entire argument list of
//! [`Vault::materialize_admitted_lease`]. No raw `max_lease_ttl_secs: u64` and
//! no caller-supplied effector set survives anywhere on the path to a stamp, so
//! there is exactly one admission shape and no second way to reach the mint.
//!
//! The gap that closes is not a type error, it is a TIME-OF-CHECK gap. The door
//! used to resolve the dial in one read transaction while the vault stamped the
//! lease in a different write transaction, so the dial that ADMITTED a request
//! was never the dial the row COMMITTED under: a dial narrowed — emptied, even
//! — in between still minted a ticket at the stale wide reading, and the one
//! row an operator reaches for in a catastrophe lost every race it was in.
//! [`AdmittedLease::reaffirm_in_txn`] re-resolves the dial INSIDE the write
//! transaction that stamps, refuses on any disagreement with the admission, and
//! is the FIRST thing that transaction does — before the record is read, before
//! the custody floor is resolved, and long before a value byte is touched.
//!
//! The witnessed instant is the one thing threaded IN rather than re-derived
//! there. A second reading inside the write transaction could disagree with the
//! lifetime check that already passed, which would put the credential's window
//! and the lease's dates back on two different clocks — exactly the split the
//! typed instant exists to prevent. So the proof carries the reading, and the
//! lifetime check, the ceiling, the absolute bound and `granted_at` stay one
//! observation.
//!
//! # What this module deliberately does NOT do
//!
//! It owns the VERDICT, never the transport. There is no receive-pack
//! protocol code, no hook implementation, no git invocation, and no server
//! adapter here; the wire side consumes this seam later (ONE-1908). The
//! quarantine extraction that fills a [`PushedBlob`] is likewise the
//! transport owner's work — [`PushedBlob`] is the seam boundary, not the
//! mechanism.
//!
//! # The credential
//!
//! One credential = one presented capability slip. This tree carries no slip
//! struct yet, so [`DoorCredential`] is the smallest honest holder-view the
//! crate-private seam needs: non-secret identifiers plus the verbs, records,
//! channels and lifetime the holder's slip bounds. It carries NO token
//! material, it is not `Clone` (single-use redemption is consumption by
//! move), and it is not constructible from a caller-supplied string: the
//! constructor's contract is that holder proof was already verified by the
//! verifier that produced the view. The production verifier arrives with the
//! transport adapter; this module ships the seam and its fail-closed
//! evaluation.
//!
//! # The one-shot mint STOP
//!
//! There is no landed authority-log surface that admits slip-mint bodies, and
//! inventing an `AuthorityOp` variant or a door-local ledger is forbidden. So
//! [`CredentialDoorService::mint_one_shot`] exists for API closure and fails
//! closed with [`CredentialDoorError::MintUnavailable`]. Redemption is the
//! landed half: it consumes the credential by move, refuses a single-use
//! caveat it cannot witness against the authority log, and writes no ledger
//! of its own.
// The door is created before its first production consumer: the transport
// adapter that calls these surfaces is a later ticket, and until it lands the
// module's own tests are what exercise them.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use rmpv::Value;

use crate::batch::secret_scan::scan_file_content;
use crate::codebase::RepoRef;
use crate::secret_custody::{
    PolicyManifestWalkError, policy_manifest_bodies_strict, policy_manifest_body_map,
};
use crate::secret_lease::{DoorInjectionReceipt, SecretLeaseMaterialization, VaultInstant};
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Catastrophe floors (outside the lattice) and door vocabulary
// ---------------------------------------------------------------------------

/// The pre-receive scan is unconditional. Not a dial, not a policy row, not a
/// slip caveat: a catastrophe-class guard has no "off".
pub(crate) const DOOR_SCAN_ALWAYS_ON: bool = true;

/// The hard ceiling on any lease this door issues, in seconds. A dial may
/// narrow it; nothing may raise it.
pub(crate) const DOOR_MAX_LEASE_TTL_SECS: u64 = 3600;

/// The hard ceiling on a one-shot credential's lifetime, in seconds.
pub(crate) const DOOR_ONE_SHOT_MAX_LIFETIME_SECS: u64 = 300;

/// The receive-pack door's effector — the scope every door-issued lease and
/// door injection is bound to by default.
pub(crate) const DOOR_RECEIVE_PACK_EFFECTOR: &str = "door:receive-pack";

/// Every effector this door knows how to be. The dial may narrow this set to
/// a subset; a row naming anything outside it is a widen and fails closed.
pub(crate) const DOOR_EFFECTORS: [&str; 1] = [DOOR_RECEIVE_PACK_EFFECTOR];

/// Verb: push objects through the door.
pub(crate) const DOOR_VERB_RECEIVE_PACK: &str = "receive-pack";
/// Verb: use a secret at the door without ever holding it.
pub(crate) const DOOR_VERB_INJECT: &str = "inject";
/// Verb: mint a T1 lease ticket over a named secret.
pub(crate) const DOOR_VERB_LEASE: &str = "lease";
/// Verb: redeem a one-shot credential into its named lease scope.
pub(crate) const DOOR_VERB_REDEEM: &str = "redeem";

// The scan floor is a constant the build itself checks: if anyone ever turns
// `DOOR_SCAN_ALWAYS_ON` into something that can be false, this fails to
// compile rather than opening a silent pass path.
const _: () = assert!(DOOR_SCAN_ALWAYS_ON);

/// Longest pushed-blob path the seam accepts before calling the input
/// unusable (a scanner failure, never a pass).
const DOOR_MAX_PATH_BYTES: usize = 4096;
/// Longest object id the seam accepts. Git object ids are hex; anything else
/// is unusable seam input.
const DOOR_MAX_OID_BYTES: usize = 64;
/// What an error names when the path itself is the malformed field. The raw
/// bytes never reach a message.
const UNUSABLE_PATH: &str = "<unusable-path>";

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
fn names_a_floor(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let mut names = DOOR_FLOOR_NAMES.iter();
    let mut prefixes = DOOR_FLOOR_KEY_PREFIXES.iter();
    names.any(|name| lower.contains(name)) || prefixes.any(|p| lower.starts_with(p))
}

/// A landed storage/custody refusal, as a door error.
fn custody<E: Into<crate::error::Error>>(err: E) -> CredentialDoorError {
    CredentialDoorError::Custody(err.into())
}

/// Any failure to READ the authority log is the same answer: the door cannot
/// witness a single-use caveat, so it refuses one.
fn log_unreachable<E>(_err: E) -> CredentialDoorError {
    CredentialDoorError::AuthorityLogUnreachable
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

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
pub(crate) enum DoorCredentialStatus {
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
    fn join(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

// ---------------------------------------------------------------------------
// Pushed blobs, verdicts, lift proposals
// ---------------------------------------------------------------------------

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
    fn new(repo: &RepoRef, path: &str, reason: &'static str) -> Self {
        Self {
            path: path.to_owned(),
            reason,
            suggested_secret_name: format!("{}.{}", repo_slug(repo), path_slug(path)),
        }
    }
}

/// The repo identity a slip binds, WITHOUT the commit: a push door authorizes
/// against the repository, not against one revision of it.
fn repo_record(repo: &RepoRef) -> String {
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

// ---------------------------------------------------------------------------
// The TTL ceiling lattice
// ---------------------------------------------------------------------------

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
pub(crate) struct TtlCeiling(u64);

impl Default for TtlCeiling {
    /// The safe default IS the floor: a slip nobody narrowed sits at the
    /// widest ceiling the door has, never wider and never unbounded.
    fn default() -> Self {
        Self::FLOOR
    }
}

impl TtlCeiling {
    /// The catastrophe floor — the widest ceiling that can exist here.
    const FLOOR: Self = Self(DOOR_MAX_LEASE_TTL_SECS);

    /// The ceiling a declaration of `secs` buys. Never above the floor: a
    /// value that would widen is clamped rather than refused, because this is
    /// the NARROWING side of the seam. The refusals that must be loud — a dial
    /// row that tries to widen the ceiling — are raised where the row is
    /// decoded ([`decode_floors_row`]), so clamping here cannot hide one.
    fn at_most(secs: u64) -> Self {
        Self(secs.min(Self::FLOOR.0))
    }

    /// The lattice meet: the tighter of two ceilings. Commutative,
    /// associative and idempotent, so ceilings compose to the same answer in
    /// any order and no composition can ever raise one.
    fn meet(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// [`Self::meet`] against a bound that arrives as raw seconds.
    fn meet_secs(self, secs: u64) -> Self {
        self.meet(Self::at_most(secs))
    }

    /// The ceiling in seconds, for the refusal that has to report it.
    fn secs(self) -> u64 {
        self.0
    }

    /// Whether a REQUESTED TTL is admitted: positive, and at or below the
    /// ceiling. Zero is not a lease, it is an empty ticket.
    fn admits(self, requested_secs: u64) -> bool {
        requested_secs != 0 && requested_secs <= self.0
    }
}

// ---------------------------------------------------------------------------
// The presented credential
// ---------------------------------------------------------------------------

/// One presented capability slip, as the door sees it.
///
/// Deliberately NOT `Clone`: a one-shot is consumed by move, and a type that
/// can be duplicated cannot carry that guarantee. Deliberately without token
/// material: identifiers and bounds only, so `Debug` is safe by construction.
///
/// Every field is private and the constructor is the only door in. The
/// constructor does NOT verify anything — it records that verification
/// already happened upstream. A blank holder view therefore fails closed at
/// evaluation instead of pretending a caller-supplied string is proof.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DoorCredential {
    slip_id: String,
    holder_ref: String,
    verbs: BTreeSet<String>,
    records: BTreeSet<String>,
    channels: BTreeSet<String>,
    issued_at: u64,
    expires_at: u64,
    status: DoorCredentialStatus,
    single_use: bool,
    ttl_cap: TtlCeiling,
}

impl DoorCredential {
    /// The holder view of a slip whose proof the caller has ALREADY verified.
    ///
    /// Fail-closed defaults: no verbs, no records, no channels, no caveat, and
    /// a TTL ceiling sitting at the floor ([`TtlCeiling::default`]) rather than
    /// unbounded. A credential built and never narrowed authorizes nothing.
    pub(crate) fn verified(
        slip_id: impl Into<String>,
        holder_ref: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            slip_id: slip_id.into(),
            holder_ref: holder_ref.into(),
            verbs: BTreeSet::new(),
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            issued_at,
            expires_at,
            status: DoorCredentialStatus::Active,
            single_use: false,
            ttl_cap: TtlCeiling::default(),
        }
    }

    /// Verbs the slip grants.
    pub(crate) fn with_verbs<I, S>(mut self, verbs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.verbs = verbs.into_iter().map(Into::into).collect();
        self
    }

    /// Records (repositories, secret names) the slip bounds.
    pub(crate) fn with_records<I, S>(mut self, records: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.records = records.into_iter().map(Into::into).collect();
        self
    }

    /// Channels (door effectors) the slip bounds.
    pub(crate) fn with_channels<I, S>(mut self, channels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.channels = channels.into_iter().map(Into::into).collect();
        self
    }

    /// Records a DIRECT revocation.
    ///
    /// Monotone by construction: revocation is a join up the status order
    /// ([`DoorCredentialStatus::join`]), so it is idempotent, it survives any
    /// cascade that arrives later, and it has no inverse. There is deliberately
    /// no way back — `Revoked -> Active` is not an operation this type offers,
    /// so it is not a state machine the caller can be talked into.
    pub(crate) fn revoked(mut self) -> Self {
        self.status = self.status.join(DoorCredentialStatus::Revoked);
        self
    }

    /// Records a PARENT slip's revocation cascading down.
    ///
    /// The same join, one rank lower: it kills a live slip, and it leaves an
    /// already directly-revoked slip exactly as revoked as it was rather than
    /// rewriting the reason it died.
    pub(crate) fn parent_revoked(mut self) -> Self {
        self.status = self.status.join(DoorCredentialStatus::ParentRevoked);
        self
    }

    /// Attaches the single-use caveat.
    pub(crate) fn with_single_use_caveat(mut self) -> Self {
        self.single_use = true;
        self
    }

    /// Slip-side attenuation of the lease TTL. Narrowing only: the effective
    /// ceiling is a minimum, so a slip asking for more than the floor gets the
    /// floor, never more.
    ///
    /// Attenuation is also narrowing with respect to ITSELF. A verifier may
    /// apply one TTL caveat per slip in the chain, and the caveats arrive in
    /// whatever order the chain is walked; storing the new value would let a
    /// later, looser caveat restore authority an earlier one had already
    /// given up. So the caveat is merged by [`TtlCeiling::meet`] — the lattice
    /// minimum — which makes repeated attenuation idempotent, monotone, and
    /// independent of caveat order, and leaves the tightest caveat in the
    /// chain standing however late the loosest one arrives.
    pub(crate) fn attenuate_lease_ttl(mut self, secs: u64) -> Self {
        self.ttl_cap = self.ttl_cap.meet_secs(secs);
        self
    }

    /// The non-secret slip identifier.
    pub(crate) fn slip_id(&self) -> &str {
        &self.slip_id
    }

    /// The non-secret holder reference.
    pub(crate) fn holder_ref(&self) -> &str {
        &self.holder_ref
    }

    /// Whether the single-use caveat is present.
    pub(crate) fn is_single_use(&self) -> bool {
        self.single_use
    }

    /// The credential's declared lifetime in seconds.
    fn lifetime_secs(&self) -> u64 {
        self.expires_at.saturating_sub(self.issued_at)
    }

    /// How much of the credential's validity is LEFT at `now`, in seconds.
    ///
    /// This is the bound every ticket the credential buys sits under: a lease
    /// that outlives the slip that bought it turns the slip's expiry into a
    /// suggestion, and a half-spent slip would otherwise buy a full-length
    /// ticket. `now` is the same vault-witnessed instant [`Self::evaluate`]
    /// admits against — the credential's `expires_at` is an external wire
    /// fact, and it is compared against the vault's reading rather than
    /// against anything the presenter chose.
    ///
    /// A DURATION is only half the bound, and it is deliberately the half that
    /// answers "may this be asked for". The absolute half — "when does the
    /// ticket die" — travels with the materialization request, derived from
    /// this same instant; see
    /// [`CredentialDoorService::issue_lease_ticket`].
    fn remaining_secs(&self, now: VaultInstant) -> u64 {
        self.expires_at.saturating_sub(now.secs())
    }

    /// The ONE evaluator call: `verb ∈ slip ∧ record ⊑ slip ∧ record ⊑ channel`,
    /// under the slip's lifetime and revocation state.
    ///
    /// Nothing about the caller's network position enters here. That is the
    /// point: "localhost" is a route, not a principal.
    ///
    /// Nothing about the caller's CLOCK enters here either, for the same
    /// reason. `now` is a [`VaultInstant`] — a reading the vault took — so the
    /// lifetime arm below is a comparison of the slip's declared window
    /// against the engine's own observation, not against a number the
    /// presenter handed in alongside the slip.
    fn evaluate(
        &self,
        verb: &str,
        record: &str,
        channel: &str,
        now: VaultInstant,
    ) -> DoorResult<()> {
        self.reject_floor_naming()?;
        let deny = |reason| Err(CredentialDoorError::UnauthorizedPrincipal { reason });

        if self.slip_id.is_empty() || self.holder_ref.is_empty() {
            return deny(DoorDenyReason::HolderUnverified);
        }
        match self.status {
            DoorCredentialStatus::Revoked => return deny(DoorDenyReason::Revoked),
            DoorCredentialStatus::ParentRevoked => return deny(DoorDenyReason::ParentRevoked),
            DoorCredentialStatus::Active => {}
        }
        let now_secs = now.secs();
        if now_secs < self.issued_at || now_secs >= self.expires_at {
            return deny(DoorDenyReason::Expired);
        }
        if !self.verbs.contains(verb) {
            return deny(DoorDenyReason::VerbNotInSlip);
        }
        if record.is_empty() || !self.records.contains(record) {
            return deny(DoorDenyReason::RecordOutsideSlip);
        }
        if channel.is_empty() || !self.channels.contains(channel) {
            return deny(DoorDenyReason::ChannelOutsideSlip);
        }
        Ok(())
    }

    /// A slip may not reach a floor either. Verbs, records and channels are
    /// lattice tokens; floors are not in the lattice.
    fn reject_floor_naming(&self) -> DoorResult<()> {
        let tokens = self
            .verbs
            .iter()
            .chain(self.records.iter())
            .chain(self.channels.iter());
        for token in tokens {
            if names_a_floor(token) {
                return Err(CredentialDoorError::FloorNamed {
                    site: "credential",
                    name: token.clone(),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The door dial: `secret.door.*` policy-manifest rows
// ---------------------------------------------------------------------------

/// MessagePack keys this door reads out of POLICY_MANIFEST bodies.
mod door_policy_keys {
    /// Narrowed TTL ceiling, in seconds.
    pub(crate) const MAX_LEASE_TTL_SECS: &str = "secret.door.max_lease_ttl_secs";
    /// Narrowed effector set.
    pub(crate) const ALLOWED_EFFECTORS: &str = "secret.door.allowed_effectors";
    /// What an error names when the malformed field is the BODY that would
    /// carry the door rows rather than one row inside it.
    pub(crate) const NAMESPACE: &str = "secret.door.*";
    /// What an error names when the corruption is in the INDEXED MANIFEST
    /// PLANE itself — the type-index entry, the entity row it points at, or
    /// that row's metadata header — rather than in any body this door reads.
    /// A safe, constant label: no entity id, no key bytes, no body bytes.
    pub(crate) const MANIFEST_PLANE: &str = "policy_manifest.index";
}

/// MessagePack key-map helpers local to this module (the per-module idiom the
/// custody floor and the gate each keep their own copy of).
enum MapValue<'a> {
    Missing,
    Duplicate,
    Present(&'a Value),
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

/// The refusal a strict POLICY_MANIFEST walk hands this door, mapped into the
/// door's own module-local surface.
///
/// A storage failure stays the landed custody refusal it already was. Every
/// other refusal names a SAFE CONSTANT label and a safe constant reason — the
/// index-plane label when the corruption is in the indexed manifest plane
/// itself, the door's namespace when a body is present but unreadable — and
/// never an id, a key byte, or a byte of any body.
fn manifest_refusal(err: PolicyManifestWalkError) -> CredentialDoorError {
    match err {
        PolicyManifestWalkError::Storage(err) => CredentialDoorError::Custody(err),
        PolicyManifestWalkError::IndexPlane(reason) => CredentialDoorError::InvalidDoorPolicy {
            key: door_policy_keys::MANIFEST_PLANE,
            reason,
        },
        PolicyManifestWalkError::UnreadableBody(reason) => CredentialDoorError::InvalidDoorPolicy {
            key: door_policy_keys::NAMESPACE,
            reason,
        },
    }
}

/// ONE door effector, PROVED a member of [`DOOR_EFFECTORS`].
///
/// The payload is a `&'static str` borrowed from [`DOOR_EFFECTORS`] itself and
/// the field is private, so a value of this type IS one of the door's own
/// effector constants — not a string that happened to compare equal to one at
/// some earlier moment, in some other transaction. That is the difference from
/// the bare `&str` this replaces at the authorization site: a name becomes
/// authority only by passing [`DoorEffector::parse`], and what comes out the
/// other side carries the CONSTANT rather than the caller's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DoorEffector(&'static str);

impl DoorEffector {
    /// Every effector this door knows, as proved values. The one place a
    /// `DoorEffector` is built without a membership test, because this IS the
    /// membership set.
    fn all() -> impl Iterator<Item = Self> {
        DOOR_EFFECTORS.iter().copied().map(Self)
    }

    /// The membership test that is the only OTHER way in. An empty name, a
    /// foreign connector, and a near-miss spelling all fail it, so "there is no
    /// unscoped door operation" becomes a fact about the type instead of a
    /// check every call site has to remember to repeat.
    fn parse(name: &str) -> Option<Self> {
        Self::all().find(|effector| effector.0 == name)
    }

    /// The effector's constant name, for the rows, receipts and evaluator
    /// arguments that still spell it out.
    pub(crate) fn as_str(self) -> &'static str {
        self.0
    }
}

/// The dial's effector set: a SUBSET of [`DOOR_EFFECTORS`] by construction.
///
/// A `BTreeSet<DoorEffector>` cannot hold a name this door does not know,
/// because [`DoorEffector`] cannot hold one — so "a dial may only narrow the
/// door's effectors" is enforced by the ELEMENT TYPE rather than by a
/// membership check at each use. The `BTreeSet<String>` this replaces could
/// hold anything at all; the widen refusal lived in whoever remembered to test
/// membership before trusting the set, and a set that reached a mint untested
/// was indistinguishable from one that had been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectorDial(BTreeSet<DoorEffector>);

impl Default for EffectorDial {
    /// The safe default IS the widest a dial may ever be: the door's whole
    /// effector set. A dial nobody narrowed narrows nothing, and there is no
    /// spelling here for "unbounded".
    fn default() -> Self {
        Self(DoorEffector::all().collect())
    }
}

impl EffectorDial {
    /// The lattice meet: the intersection, i.e. the more restrictive of two
    /// dials. Commutative, associative, idempotent, and incapable of widening,
    /// so packs compose to the same answer in any order.
    fn meet(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    /// Whether this dial still admits a PROVED effector. There is no overload
    /// taking a `&str`: proving membership of [`DOOR_EFFECTORS`] happens once,
    /// at [`DoorEffector::parse`], and never again by accident here.
    fn admits(&self, effector: DoorEffector) -> bool {
        self.0.contains(&effector)
    }

    /// How many effectors survive the dial — for the regressions that prove an
    /// emptied dial is a shut door.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// The dial-narrowable catastrophe floors, RESOLVED — a snapshot, never a
/// second resolver.
///
/// Every floor a `secret.door.*` row may narrow lives here, and lives in its
/// LATTICE form ([`TtlCeiling`]) rather than as a number. That is why there is
/// no `max_lease_ttl_secs: u64` field any more: a raw `u64` can hold a ceiling
/// above [`DOOR_MAX_LEASE_TTL_SECS`], can be assigned from anywhere, and puts
/// the floor back in the hands of whoever remembers to `min` against it last.
///
/// [`DOOR_SCAN_ALWAYS_ON`] and [`DOOR_ONE_SHOT_MAX_LIFETIME_SECS`] are
/// deliberately NOT here. They are not dial space at all, and a field on a
/// resolved snapshot is exactly the shape that would suggest some row could
/// move them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyFloors {
    lease_ttl: TtlCeiling,
}

impl PolicyFloors {
    /// The floors a declaration of `secs` buys. Narrowing only by construction:
    /// [`TtlCeiling::at_most`] clamps at the hard floor on the way in.
    fn at_most_lease_ttl(secs: u64) -> Self {
        Self {
            lease_ttl: TtlCeiling::at_most(secs),
        }
    }

    /// The lattice meet, per floor: the tighter of two snapshots.
    fn meet(self, other: Self) -> Self {
        Self {
            lease_ttl: self.lease_ttl.meet(other.lease_ttl),
        }
    }

    /// The resolved lease-TTL ceiling.
    pub(crate) fn lease_ttl(self) -> TtlCeiling {
        self.lease_ttl
    }
}

/// The resolved door dial: the floors it narrows and the effectors it leaves
/// open. Narrow-only by construction — every field starts at its widest safe
/// value and merges toward the most restrictive declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DoorPolicy {
    floors: PolicyFloors,
    dial: EffectorDial,
}

impl DoorPolicy {
    /// Narrows `self` against `other`, most-restrictive per field. Only meets
    /// compose here, so no order of packs can raise anything.
    fn merge(&mut self, other: &DoorPolicy) {
        self.floors = self.floors.meet(other.floors);
        self.dial = self.dial.meet(&other.dial);
    }

    /// The effector set this dial resolved to.
    pub(crate) fn dial(&self) -> &EffectorDial {
        &self.dial
    }

    /// The resolved lease-TTL ceiling in seconds, for the refusals and
    /// assertions that have to report a number.
    pub(crate) fn lease_ttl_ceiling_secs(&self) -> u64 {
        self.floors.lease_ttl.secs()
    }

    /// Whether this dial still admits `effector` as a door scope. An empty
    /// effector is never admitted: there is no unscoped door operation, and
    /// [`DoorEffector::parse`] is the single place that is decided.
    pub(crate) fn admits_effector(&self, effector: &str) -> bool {
        DoorEffector::parse(effector).is_some_and(|proved| self.dial.admits(proved))
    }

    /// The effective lease ceiling: the hard floor, narrowed by the dial,
    /// narrowed again by the slip's own attenuation (itself already a minimum
    /// over every caveat applied), and narrowed last by what is LEFT of the
    /// slip's validity at `now`. Only minima compose here, so no combination
    /// of dial, slip, caveat order, and witnessed instant can ever raise it.
    ///
    /// This is the ceiling on what may be REQUESTED. What the issued ticket
    /// actually expires at is clamped once more, by the absolute credential
    /// expiry, inside the transaction that stamps it.
    ///
    /// Every term is ALREADY a lattice value or enters through
    /// [`TtlCeiling::at_most`], so the hard floor is applied by CONSTRUCTION
    /// rather than by a `min` this function has to remember; the rest is
    /// `meet`, which cannot raise anything. The dial's own term needs no clamp
    /// at all now — [`PolicyFloors`] cannot hold a ceiling above the floor.
    fn effective_ttl_ceiling(&self, credential: &DoorCredential, now: VaultInstant) -> TtlCeiling {
        let dial_ceiling = self.floors.lease_ttl;
        dial_ceiling
            .meet(credential.ttl_cap)
            .meet_secs(credential.remaining_secs(now))
    }

    /// The same effective ceiling, in seconds.
    pub(crate) fn effective_lease_ttl_ceiling(
        &self,
        credential: &DoorCredential,
        now: VaultInstant,
    ) -> u64 {
        self.effective_ttl_ceiling(credential, now).secs()
    }

    /// Resolves the dial from every POLICY_MANIFEST body in the vault,
    /// most-restrictive wins.
    ///
    /// An ABSENT row means "this pack declares no door dial" and takes the
    /// safe default. A row that is PRESENT but unreadable, duplicated, or
    /// widening is an ERROR: defaulting it would silently restore the
    /// permissive posture the declaration existed to narrow.
    ///
    /// The same reasoning governs the INDEX PLANE the bodies are reached
    /// through, and it is why this door consumes the STRICT shared walk
    /// ([`policy_manifest_bodies_strict`]) instead of the diagnostics-collecting
    /// resolver [`crate::gate`] owns. A manifest the door cannot read is
    /// indistinguishable, from here, from a manifest that narrowed the dial to
    /// nothing: an unusable type-index key, an entry whose entity row is gone,
    /// an entity whose metadata header will not parse, an entry that names a
    /// row of some other type, and a body that will not canonically decode are
    /// all "a declaration was indexed and this door cannot see it". Skipping
    /// any of them hands back the FULL effector set and the FULL TTL ceiling,
    /// so deleting one entity row would be enough to re-open a door a dial had
    /// shut. Every one of them fails closed instead, through
    /// [`manifest_refusal`], naming only a constant label and a constant
    /// reason — never an id, a key, or a byte of any body.
    pub(crate) fn resolve(store: &Store, txn: &heed::RoTxn<'_>) -> DoorResult<Self> {
        let mut policy = DoorPolicy::default();
        for entries in policy_manifest_bodies_strict(store, txn).map_err(manifest_refusal)? {
            policy.merge(&decode_door_policy_rows(&entries)?);
        }
        Ok(policy)
    }
}

/// Decodes the `secret.door.*` rows of ONE policy-manifest body.
///
/// `Ok(None)` means only "this body canonically decodes to something that is
/// not a map, so it carries no door rows" — the body schema itself belongs to
/// the gate. A body that does not canonically decode at all fails closed
/// instead (see [`policy_manifest_body_map`], the shared canonical-body
/// boundary this door and the custody floor both read through).
pub(crate) fn decode_door_policy_keys(body: &[u8]) -> DoorResult<Option<DoorPolicy>> {
    let Some(entries) = policy_manifest_body_map(body).map_err(manifest_refusal)? else {
        return Ok(None);
    };
    decode_door_policy_rows(&entries).map(Some)
}

/// Decodes the `secret.door.*` rows of one canonically-decoded manifest body.
///
/// An ABSENT effector row means "this pack declares no effector narrowing" and
/// takes the widest safe dial; a PRESENT one is decoded straight into typed
/// members, so a widening name never becomes a set element in the first place.
fn decode_door_policy_rows(entries: &[(Value, Value)]) -> DoorResult<DoorPolicy> {
    reject_floor_naming_rows(entries)?;

    Ok(DoorPolicy {
        floors: decode_floors_row(entries)?,
        dial: decode_effector_row(entries)?.unwrap_or_default(),
    })
}

/// No policy row may name a floor — not to set it, not to read it, not to
/// turn it off.
fn reject_floor_naming_rows(entries: &[(Value, Value)]) -> DoorResult<()> {
    for (key, _) in entries {
        let Some(name) = key.as_str() else {
            continue;
        };
        if names_a_floor(name) {
            return Err(CredentialDoorError::FloorNamed {
                site: "policy manifest row",
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// Decodes the dial-narrowable floors out of one body.
///
/// The refusals are unchanged and stay LOUD: a non-integer ceiling, a
/// duplicated row, and a row that tries to RAISE the ceiling above
/// [`DOOR_MAX_LEASE_TTL_SECS`] each fail closed here rather than being clamped
/// silently by [`TtlCeiling::at_most`] downstream. Only a declaration that
/// genuinely narrows becomes a [`PolicyFloors`].
fn decode_floors_row(entries: &[(Value, Value)]) -> DoorResult<PolicyFloors> {
    let key = door_policy_keys::MAX_LEASE_TTL_SECS;
    let invalid = |reason| CredentialDoorError::InvalidDoorPolicy { key, reason };
    match single_map_value(entries, key) {
        MapValue::Missing => Ok(PolicyFloors::default()),
        MapValue::Present(value) => {
            let Some(secs) = as_u64(value) else {
                return Err(invalid("TTL ceiling must be an unsigned integer"));
            };
            if secs > DOOR_MAX_LEASE_TTL_SECS {
                return Err(invalid("a dial may only narrow the TTL ceiling"));
            }
            Ok(PolicyFloors::at_most_lease_ttl(secs))
        }
        MapValue::Duplicate => Err(invalid("duplicated row leaves the ceiling ambiguous")),
    }
}

/// Decodes the declared effector narrowing out of one body.
///
/// The widen refusal is the SAME predicate the typed effector is built from:
/// [`DoorEffector::parse`] fails exactly when the old `DOOR_EFFECTORS.contains`
/// check failed, and refusing there is what keeps a foreign name out of the
/// resulting [`EffectorDial`] rather than merely out of a later comparison.
fn decode_effector_row(entries: &[(Value, Value)]) -> DoorResult<Option<EffectorDial>> {
    let key = door_policy_keys::ALLOWED_EFFECTORS;
    let invalid = |reason| CredentialDoorError::InvalidDoorPolicy { key, reason };
    match single_map_value(entries, key) {
        MapValue::Missing => Ok(None),
        MapValue::Present(Value::Array(items)) => {
            let mut allowed = BTreeSet::new();
            for item in items {
                let name = item
                    .as_str()
                    .ok_or_else(|| invalid("effector entries must be strings"))?;
                let Some(effector) = DoorEffector::parse(name) else {
                    return Err(invalid("a door dial may only narrow the door's effectors"));
                };
                allowed.insert(effector);
            }
            Ok(Some(EffectorDial(allowed)))
        }
        MapValue::Present(_) => Err(invalid("allowed effectors must be an array")),
        MapValue::Duplicate => Err(invalid("duplicated row leaves the set ambiguous")),
    }
}

// ---------------------------------------------------------------------------
// The admission proof: what the scope check produces, what the stamp consumes
// ---------------------------------------------------------------------------

/// Why the re-admission taken INSIDE the stamping transaction refused a scope
/// the door had already admitted at its own read.
///
/// A named constant because the two refusals are otherwise spelled the same:
/// the regression that proves this check runs in the write transaction, and not
/// merely at the door, has to be able to tell which one answered.
pub(crate) const STAMP_SCOPE_REFUSAL: &str =
    "the stamping transaction's dial no longer admits this scope";

/// PROOF that one door effector was admitted, and the authority it was admitted
/// under.
///
/// The door's scope check PRODUCES this; everything after it CONSUMES it. The
/// evaluator takes its channel argument from here rather than from the caller's
/// string, the TTL ceiling is computed from the floors recorded here, the
/// absolute bound is derived from the instant recorded here, and the stamping
/// transaction re-derives the dial to compare against the one recorded here.
///
/// Fields are private and [`AdmittedScope::admit`] is the only constructor, so
/// an admission cannot be assembled after the fact out of a dial, an effector
/// and an instant that never met — which is precisely what the three loose
/// arguments this replaces allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedScope {
    effector: DoorEffector,
    policy: DoorPolicy,
    at: VaultInstant,
}

impl AdmittedScope {
    /// The door's scope check, and the ONLY way to obtain the proof: the
    /// effector must be one this door knows AND one the resolved dial still
    /// admits. An empty effector fails the first half, so there is no unscoped
    /// door operation to construct.
    fn admit(policy: DoorPolicy, effector: &str, at: VaultInstant) -> DoorResult<Self> {
        let admitted = DoorEffector::parse(effector)
            .filter(|proved| policy.dial.admits(*proved))
            .ok_or_else(|| CredentialDoorError::LeaseScopeRefused {
                effector: effector.to_owned(),
                reason: "not a door effector the resolved dial admits",
            })?;
        Ok(Self {
            effector: admitted,
            policy,
            at,
        })
    }

    /// The PROVED effector. Door operations bind their scope to this, never to
    /// the string the caller handed in.
    pub(crate) fn effector(&self) -> DoorEffector {
        self.effector
    }

    /// The single vault reading this operation authorizes and stamps under.
    pub(crate) fn instant(&self) -> VaultInstant {
        self.at
    }

    /// The floors the scope was admitted under.
    pub(crate) fn floors(&self) -> PolicyFloors {
        self.policy.floors
    }

    /// The effective lease ceiling under THIS admission — the floors, the
    /// slip's attenuation and its remaining validity, all against the one
    /// instant the proof carries. There is no way to compute a ceiling from a
    /// dial and an instant that were not admitted together.
    fn effective_ttl_ceiling(&self, credential: &DoorCredential) -> TtlCeiling {
        self.policy.effective_ttl_ceiling(credential, self.at)
    }

    /// Sizes a lease against this scope, yielding the ONE admission shape that
    /// reaches the stamping operation. Consumes the scope by value: a proof
    /// spends into exactly one ticket.
    fn into_lease(self, secret_ref: &str, ttl_secs: u64, not_after: VaultInstant) -> AdmittedLease {
        AdmittedLease {
            scope: self,
            secret_ref: secret_ref.to_owned(),
            ttl_secs,
            not_after,
        }
    }
}

/// The ONE admission shape that reaches the stamping operation.
///
/// [`Vault::materialize_admitted_lease`] takes this and nothing else — no raw
/// `max_lease_ttl_secs`, no caller-supplied effector string, no loose `now`,
/// and no separately-computed bound. Everything the stamp needs travelled
/// together, was admitted together, and can be checked together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedLease {
    scope: AdmittedScope,
    secret_ref: String,
    ttl_secs: u64,
    not_after: VaultInstant,
}

impl AdmittedLease {
    /// The named secret the credential was evaluated against.
    pub(crate) fn secret_ref(&self) -> &str {
        &self.secret_ref
    }

    /// The admitted scope's effector CONSTANT.
    pub(crate) fn effector(&self) -> &'static str {
        self.scope.effector.as_str()
    }

    /// The requested TTL the ceiling admitted.
    pub(crate) fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// The witnessed instant this lease authorizes and stamps under.
    pub(crate) fn instant(&self) -> VaultInstant {
        self.scope.at
    }

    /// The absolute instant the authority that bought this lease dies at.
    pub(crate) fn not_after(&self) -> VaultInstant {
        self.not_after
    }

    /// The admission, taken AGAIN inside the transaction that is about to
    /// stamp — the whole point of this step.
    ///
    /// The door resolves the dial in a read transaction, and the lease commits
    /// in a write transaction opened afterwards. Between the two, a manifest
    /// row can land: the dial that admitted the request is then not the dial
    /// the row commits under, and the single row an operator reaches for in a
    /// catastrophe — an emptied effector set — loses to whatever was already
    /// in flight. Re-resolving HERE, under the transaction that writes, closes
    /// that window: the check and the commit are the same atomic act.
    ///
    /// Three arms, all denials, in order of how specifically they can name what
    /// went wrong:
    ///
    /// 1. the live dial no longer admits the scope — the emptied-dial case, and
    ///    the reason it carries is [`STAMP_SCOPE_REFUSAL`] rather than the
    ///    door's own, so a test can tell which side answered;
    /// 2. the live floors no longer admit the requested TTL — a dial that
    ///    narrowed the ceiling under a ticket already sized at the wider one;
    /// 3. any OTHER disagreement, including a dial that WIDENED. A widening is
    ///    harmless to mint under, but it is still evidence that the reading
    ///    this admission rests on is stale, and a stale reading is not
    ///    something a stamp gets to shrug at.
    ///
    /// Deliberately NO clock reading happens here. The instant is threaded in
    /// through the proof, because a second reading could disagree with the
    /// lifetime check that already passed and put the credential's window and
    /// the lease's dates on two different observations.
    pub(crate) fn reaffirm_in_txn(&self, store: &Store, txn: &heed::RoTxn<'_>) -> DoorResult<()> {
        let live = DoorPolicy::resolve(store, txn)?;
        if !live.dial.admits(self.scope.effector) {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: self.scope.effector.as_str().to_owned(),
                reason: STAMP_SCOPE_REFUSAL,
            });
        }
        let ceiling = live.floors.lease_ttl;
        if !ceiling.admits(self.ttl_secs) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: self.ttl_secs,
                ceiling_secs: ceiling.secs(),
            });
        }
        if live != self.scope.policy {
            return Err(CredentialDoorError::DialMovedUnderStamp {
                effector: self.scope.effector.as_str(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The door service
// ---------------------------------------------------------------------------

/// The credential door over one landed vault.
///
/// It holds no secret state of its own: the vault owns custody, the authority
/// log owns grants, and the detector owns detection. What lives here is the
/// composition and its refusals.
pub(crate) struct CredentialDoorService {
    vault: Arc<Vault>,
}

/// Compatibility alias for the door's shorter name. One principal noun, two
/// spellings — never two organs.
pub(crate) type CredentialDoor = CredentialDoorService;

impl CredentialDoorService {
    /// Binds the door to a vault.
    pub(crate) fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// The vault this door composes over.
    pub(crate) fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// Resolves the door dial from the live vault, in a READ transaction.
    ///
    /// This is the door's admission-time reading, and it is deliberately no
    /// longer the last word. A read transaction cannot hold anything still for
    /// the write transaction that stamps a lease later, so what this resolves
    /// is re-resolved there and compared
    /// ([`AdmittedLease::reaffirm_in_txn`]). Treating this answer as final is
    /// exactly the gap that let a dial narrowed after the read still mint.
    pub(crate) fn door_policy(&self) -> DoorResult<DoorPolicy> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        DoorPolicy::resolve(&self.vault.store, &rtxn)
    }

    /// The ONE instant a door operation authorizes and stamps under.
    ///
    /// Read from the vault's own seam ([`Vault::instant_in_txn`]) inside a
    /// read transaction — the authority plane's persisted-floor monotone
    /// observation, the same clock the fold makes widen-maturity decisions on.
    /// It is not a parameter, it is not a trait a caller may implement, and it
    /// is not the raw wall clock.
    ///
    /// Every door operation calls this EXACTLY once and threads the reading
    /// through: the lifetime check, the remaining-validity ceiling, the
    /// absolute lease bound, and the stamped `granted_at` are then all one
    /// observation. Reading twice would reintroduce, inside this module, the
    /// very gap removing the caller's `now` closed.
    fn door_instant(&self) -> DoorResult<VaultInstant> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        self.vault.instant_in_txn(&rtxn).map_err(custody)
    }

    /// Authenticates a receive-pack attempt.
    ///
    /// `peer_addr` is transport context the caller already has; it is
    /// deliberately NOT an authorization input, and the leading underscore is
    /// the proof that no branch reads it. A loopback push authenticates
    /// exactly like any other push, because "localhost" describes a route and
    /// never a principal.
    ///
    /// The catastrophe dial applies HERE too. Receive-pack is a door effector
    /// like any other, so the resolved dial is admitted before the push
    /// authenticates: a manifest that narrows `secret.door.allowed_effectors`
    /// away from [`DOOR_RECEIVE_PACK_EFFECTOR`] shuts the receive-pack door
    /// itself, not merely the leases and injections taken through it. Without
    /// that check the one row an operator would reach for in a catastrophe —
    /// an empty effector set — would leave the push path wide open while
    /// closing everything downstream of it. The credential is still evaluated
    /// unconditionally; the dial only ever narrows.
    pub(crate) fn authenticate_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        repo: &RepoRef,
        _peer_addr: IpAddr,
    ) -> DoorResult<()> {
        let Some(credential) = presented else {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::CredentialAbsent,
            });
        };
        let now = self.door_instant()?;
        let admitted = self.admit_scope(DOOR_RECEIVE_PACK_EFFECTOR, now)?;
        self.witness_single_use(credential)?;
        credential.evaluate(
            DOOR_VERB_RECEIVE_PACK,
            &repo_record(repo),
            admitted.effector().as_str(),
            admitted.instant(),
        )
    }

    /// The pre-receive verdict over a push's added lines.
    ///
    /// Unconditional ([`DOOR_SCAN_ALWAYS_ON`]): there is no credential, dial,
    /// or caveat argument that could turn it off, because none is accepted.
    /// Unscannable input never passes — binary content and scanner failure
    /// both leave through the error surface, not through a verdict.
    pub(crate) fn pre_receive_scan(
        &self,
        repo: &RepoRef,
        blobs: &[PushedBlob],
    ) -> DoorResult<DoorScanVerdict> {
        let mut proposals = Vec::new();
        for blob in blobs {
            if let Some(reason) = scan_one_blob(blob)? {
                proposals.push(SecretLiftProposal::new(repo, &blob.path, reason));
            }
        }
        if proposals.is_empty() {
            Ok(DoorScanVerdict::Clean)
        } else {
            Ok(DoorScanVerdict::Rejected { proposals })
        }
    }

    /// T0: use a secret at the door without anyone workspace-side holding it.
    ///
    /// `apply` runs INSIDE [`Vault::inject_secret_at_door`] and can only
    /// return `()`, so the value cannot come back out through it. The caller
    /// gets the receipt; the bytes stay at the door.
    pub(crate) fn inject_secret_at_door(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> crate::error::Result<()>,
    ) -> DoorResult<DoorInjectionReceipt> {
        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        self.witness_single_use(presented)?;
        presented.evaluate(
            DOOR_VERB_INJECT,
            secret_ref,
            admitted.effector().as_str(),
            admitted.instant(),
        )?;
        let vault = &self.vault;
        // T0 stamps no lease, so there is no lease-stamping transaction for an
        // admission to move inside of. The landed injection keeps its
        // drop-then-apply shape exactly: the write txn is released BEFORE the
        // caller's closure runs, because no caller code may execute inside an
        // LMDB write transaction.
        vault
            .inject_secret_at_door(secret_ref, admitted.effector().as_str(), apply)
            .map_err(custody)
    }

    /// T1: issue a lease ticket over a named secret, in an exact door scope.
    ///
    /// The composition is thin on purpose: the landed materialization writes
    /// the lease row and its receipt BEFORE the value returns, so the door
    /// adds no second, unmarked materializing path and no receipt family of
    /// its own.
    ///
    /// The ticket is bounded by the credential's REMAINING validity as well as
    /// by floor, dial and attenuation: a slip may not sell more time than it
    /// still has.
    ///
    /// That bound is handed to the materialization as the credential's
    /// ABSOLUTE expiry, not only as a duration: a duration alone would let a
    /// slip at its exact remaining bound — which is precisely where redemption
    /// and a maximal request both land — buy a ticket that outlives it.
    ///
    /// Both halves of the bound, and the lifetime check they rest on, are
    /// computed from the SAME [`VaultInstant`] this call read at its start,
    /// and that instant is what
    /// [`Vault::materialize_admitted_lease`] stamps `granted_at` from. So the
    /// absolute expiry travels as `now.after(remaining)` — which IS
    /// `presented.expires_at`, exactly, because the evaluator has already
    /// proved `now < expires_at` — rather than as the credential's raw wire
    /// number. There is no second clock reading anywhere in the path for a
    /// delay to open a gap in, and no way for a caller to name the instant any
    /// of it happens at.
    ///
    /// What the ticket carries into the vault is the [`AdmittedLease`] — the
    /// admitted scope, the secret, the admitted TTL and the absolute bound, as
    /// one value — and the transaction that stamps it takes the door's
    /// admission AGAIN under itself before writing a row. A dial narrowed
    /// between the read above and that write denies rather than minting under
    /// this now-stale reading.
    pub(crate) fn issue_lease_ticket(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
    ) -> DoorResult<SecretLeaseMaterialization> {
        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        self.witness_single_use(presented)?;
        presented.evaluate(
            DOOR_VERB_LEASE,
            secret_ref,
            admitted.effector().as_str(),
            now,
        )?;

        let ceiling = admitted.effective_ttl_ceiling(presented);
        if !ceiling.admits(ttl_secs) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: ttl_secs,
                ceiling_secs: ceiling.secs(),
            });
        }
        let not_after = now.after(presented.remaining_secs(now));
        let vault = &self.vault;
        vault.materialize_admitted_lease(&admitted.into_lease(secret_ref, ttl_secs, not_after))
    }

    /// Redeems a one-shot credential, consuming it BY MOVE.
    ///
    /// Single use is structural here: `one_shot` is moved in and dropped
    /// before this returns, and [`DoorCredential`] is not `Clone`, so a second
    /// redemption of the same credential cannot be written. That is the whole
    /// enforcement — there is no door-local burn ledger, no token registry,
    /// and no new authority-log entry, because no landed surface licenses one.
    /// What the door CAN do it does: it refuses a single-use caveat it cannot
    /// witness against the authority log, and it never hands back a ticket
    /// that outlives the one-shot it was redeemed from.
    pub(crate) fn redeem_one_shot(
        &self,
        one_shot: DoorCredential,
    ) -> DoorResult<SecretLeaseMaterialization> {
        if !one_shot.single_use {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::SingleUseCaveatAbsent,
            });
        }
        self.witness_single_use(&one_shot)?;

        let lifetime = one_shot.lifetime_secs();
        if lifetime == 0 || lifetime > DOOR_ONE_SHOT_MAX_LIFETIME_SECS {
            return Err(CredentialDoorError::OneShotLifetimeDenied {
                lifetime_secs: lifetime,
                ceiling_secs: DOOR_ONE_SHOT_MAX_LIFETIME_SECS,
            });
        }
        // A one-shot names EXACTLY one secret and EXACTLY one effector. Any
        // other shape is a wildcard wearing a caveat.
        let (Some(secret_ref), 1) = (one_shot.records.first(), one_shot.records.len()) else {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: String::new(),
                reason: "a one-shot must name exactly one secret",
            });
        };
        let (Some(effector), 1) = (one_shot.channels.first(), one_shot.channels.len()) else {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: String::new(),
                reason: "a one-shot must name exactly one effector",
            });
        };

        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        one_shot.evaluate(
            DOOR_VERB_REDEEM,
            secret_ref,
            admitted.effector().as_str(),
            now,
        )?;

        // The declared lifetime is the CAP the one-shot was written under; the
        // ceiling carries what is left of it at `now`, so a one-shot redeemed
        // late buys only the time it still has.
        let ceiling = admitted.effective_ttl_ceiling(&one_shot);
        let ttl = lifetime.min(ceiling.secs());
        if !ceiling.admits(ttl) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: lifetime,
                ceiling_secs: ceiling.secs(),
            });
        }
        let vault = &self.vault;
        // The one-shot's own absolute expiry rides along, for the same reason
        // `issue_lease_ticket` sends the slip's, and derived the same way: the
        // redemption arm always asks for its whole remaining bound, so the
        // absolute instant is what keeps a redeemed ticket from outliving the
        // one-shot it was redeemed from.
        let not_after = now.after(one_shot.remaining_secs(now));
        vault.materialize_admitted_lease(&admitted.into_lease(secret_ref, ttl, not_after))
        // `one_shot` drops here: the credential is spent.
    }

    /// The one-shot MINT arm — a recorded stop, not a feature.
    ///
    /// Minting a slip is an authority-log act, and this tree exposes no landed
    /// append surface that admits slip-mint bodies. Inventing an operation
    /// variant, a door-local ledger, or a hash-at-rest token store to fake one
    /// is exactly the shortcut that must not be taken, so this fails closed
    /// and says why. Redemption above works today with a verified one-shot the
    /// verifier hands over.
    ///
    /// `_now` survives the typed-instant migration deliberately: this arm
    /// authorizes nothing and reads nothing, so it has no clock seam to move
    /// onto. When the mint surface lands it will read its instant the same way
    /// every other door operation does.
    pub(crate) fn mint_one_shot(
        &self,
        _secret_ref: &str,
        _effector: &str,
        _lifetime_secs: u64,
        _now: u64,
    ) -> DoorResult<DoorCredential> {
        Err(CredentialDoorError::MintUnavailable)
    }

    /// A door operation is always scoped, and the scope check is where the
    /// operation's AUTHORITY becomes a value.
    ///
    /// One resolved dial, one proved effector, one witnessed instant, one
    /// [`AdmittedScope`]. Everything downstream reads that proof instead of
    /// re-deriving any part of it: the evaluator's channel argument, the TTL
    /// ceiling, the absolute bound, and the re-admission the stamping
    /// transaction takes. The `()` this used to return left the dial, the
    /// effector and the instant lying around as three separate values that
    /// nothing tied together — which is how they came apart.
    fn admit_scope(&self, effector: &str, at: VaultInstant) -> DoorResult<AdmittedScope> {
        AdmittedScope::admit(self.door_policy()?, effector, at)
    }

    /// A single-use caveat is only meaningful against the log that records
    /// mints and revocations. A verifier that cannot READ that log refuses the
    /// caveat rather than assuming the credential is still live.
    ///
    /// Read-only: the fold is taken through the landed read-side face inside a
    /// read transaction, and nothing is appended here or anywhere else in this
    /// module.
    fn witness_single_use(&self, credential: &DoorCredential) -> DoorResult<()> {
        if !credential.single_use {
            return Ok(());
        }
        #[cfg(test)]
        {
            if authority_log_fault_hook::take_log_unreachable() {
                return Err(CredentialDoorError::AuthorityLogUnreachable);
            }
        }
        let vault = &self.vault;
        let rtxn = vault.store.env.read_txn().map_err(log_unreachable)?;
        vault
            .authority_fold_readonly_in_txn(&rtxn)
            .map_err(log_unreachable)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scanning one blob
// ---------------------------------------------------------------------------

/// Scans one blob's added lines, returning the detector reason on a hit.
///
/// Order is load-bearing: seam validation, then the binary check over EVERY
/// added line, and only then the detector. The landed scanner is
/// intentionally lossy (it classifies over `from_utf8_lossy`), so asking it
/// about binary bytes would be asking a question it cannot answer — the door
/// answers it first, and the answer is always rejection.
fn scan_one_blob(blob: &PushedBlob) -> DoorResult<Option<&'static str>> {
    validate_seam_fields(blob)?;
    #[cfg(test)]
    {
        if scan_fault_hook::take_scanner_failure() {
            return Err(CredentialDoorError::ScanFailure {
                path: blob.path.clone(),
                reason: "scanner unavailable",
            });
        }
    }
    for line in &blob.added_lines {
        reject_unscannable(&blob.path, line)?;
    }
    for line in &blob.added_lines {
        if let Some(reason) = scan_file_content(&blob.path, line) {
            return Ok(Some(reason));
        }
    }
    Ok(None)
}

/// Binary is rejected, never skipped: a NUL byte or invalid UTF-8 anywhere in
/// the added bytes ends the push. Entropy, magic bytes, and size do not enter
/// — there is no allowlist to be wrong about.
fn reject_unscannable(path: &str, line: &[u8]) -> DoorResult<()> {
    if line.contains(&0) || std::str::from_utf8(line).is_err() {
        return Err(CredentialDoorError::BinaryContentRejected {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Seam input the door cannot use is a scanner failure, which is a rejection.
/// An unnamed or unaddressable blob must never become a quiet pass.
fn validate_seam_fields(blob: &PushedBlob) -> DoorResult<()> {
    if blob.path.is_empty()
        || blob.path.len() > DOOR_MAX_PATH_BYTES
        || blob.path.chars().any(char::is_control)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: UNUSABLE_PATH.to_owned(),
            reason: "pushed blob path is empty, oversized, or carries control bytes",
        });
    }
    if blob.oid.is_empty()
        || blob.oid.len() > DOOR_MAX_OID_BYTES
        || !blob.oid.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: blob.path.clone(),
            reason: "pushed blob oid is empty, oversized, or not hexadecimal",
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test-only fault hooks (the landed one-shot thread-local idiom)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod scan_fault_hook {
    //! One-shot test-only fault injection on the scan, proving the
    //! fail-closed arm: a scan that could not run is a rejection, never a
    //! pass.

    use std::cell::Cell;

    thread_local! {
        static SCANNER_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot scanner failure on the current thread.
    pub(crate) fn arm_scanner_failure() {
        SCANNER_FAILURE.with(|cell| cell.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_scanner_failure() -> bool {
        SCANNER_FAILURE.with(|cell| cell.replace(false))
    }
}

#[cfg(test)]
pub(crate) mod authority_log_fault_hook {
    //! One-shot test-only fault injection on the single-use witness, proving
    //! that a verifier which cannot reach the authority log refuses the
    //! caveat instead of assuming it holds.

    use std::cell::Cell;

    thread_local! {
        static LOG_UNREACHABLE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot unreachable authority log on the current thread.
    pub(crate) fn arm_log_unreachable() {
        LOG_UNREACHABLE.with(|cell| cell.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_log_unreachable() -> bool {
        LOG_UNREACHABLE.with(|cell| cell.replace(false))
    }
}

#[cfg(test)]
mod tests;
