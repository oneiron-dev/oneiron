//! ARCH-0068 RC4 — the credential door (CSTDY-02).
//!
//! One organ owns what a repository push has to survive before anything it
//! carries becomes durable, and what a credential may buy at that boundary:
//!
//! 1. **T0 remote-at-door injection** — the value is resolved and handed to
//!    the egress INSIDE [`Vault::inject_secret_at_door`]; the caller receives
//!    a [`DoorInjectionReceipt`] and never the bytes.
//! 2. **T1 lease tickets** — [`Vault::materialize_secret_lease_bounded`] is
//!    the ONE materializing call (it writes the lease row and its receipt
//!    before the value returns, and clamps the lease against the credential's
//!    absolute expiry using the same clock that stamps it); this module
//!    composes over it and never mints a second, unmarked materialization
//!    path.
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
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;

use rmpv::Value;

use crate::batch::secret_scan::scan_file_content;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::codebase::RepoRef;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::secret_lease::{DoorInjectionReceipt, SecretLeaseMaterialization};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoorCredentialStatus {
    /// Live within its lifetime.
    Active,
    /// Revoked directly.
    Revoked,
    /// Revoked by cascade from a revoked parent.
    ParentRevoked,
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
    max_lease_ttl_secs: Option<u64>,
}

impl DoorCredential {
    /// The holder view of a slip whose proof the caller has ALREADY verified.
    ///
    /// Fail-closed defaults: no verbs, no records, no channels, no caveat, no
    /// attenuation. A credential built and never narrowed authorizes nothing.
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
            max_lease_ttl_secs: None,
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

    /// Sets the lifecycle status (revocation, including parent cascade).
    pub(crate) fn with_status(mut self, status: DoorCredentialStatus) -> Self {
        self.status = status;
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
    /// given up. So the stored value is the MINIMUM of what is there and what
    /// arrives, which makes repeated attenuation idempotent in each direction
    /// and independent of caveat order.
    pub(crate) fn attenuate_lease_ttl(mut self, secs: u64) -> Self {
        let narrowed = self
            .max_lease_ttl_secs
            .map_or(secs, |prior| prior.min(secs));
        self.max_lease_ttl_secs = Some(narrowed);
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
    /// ticket. `now` is the same witnessed instant [`Self::evaluate`] admits
    /// against.
    ///
    /// A DURATION is only half the bound, and it is deliberately the half
    /// that answers "may this be asked for". It cannot answer "when does the
    /// ticket die", because the landed materialization stamps `granted_at`
    /// from its OWN clock: at the remaining boundary, a single second between
    /// this call and that stamp would place `granted_at + ttl` past
    /// [`Self::expires_at`]. The absolute half of the bound travels with the
    /// materialization request instead — see
    /// [`CredentialDoorService::issue_lease_ticket`].
    fn remaining_secs(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }

    /// The ONE evaluator call: `verb ∈ slip ∧ record ⊑ slip ∧ record ⊑ channel`,
    /// under the slip's lifetime and revocation state.
    ///
    /// Nothing about the caller's network position enters here. That is the
    /// point: "localhost" is a route, not a principal.
    fn evaluate(&self, verb: &str, record: &str, channel: &str, now: u64) -> DoorResult<()> {
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
        if now < self.issued_at || now >= self.expires_at {
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

/// Extracts the trailing [`EntityId`] from a type-index key (the local copy of
/// the same idiom the custody floor keeps; those helpers are private to their
/// modules).
fn type_index_entity_id(key: &[u8], entity_type: u8) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != entity_type {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}

/// The resolved door dial. Narrow-only by construction: every field starts at
/// the floor and merges toward the most restrictive declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoorPolicy {
    /// The TTL ceiling this dial allows. Never above
    /// [`DOOR_MAX_LEASE_TTL_SECS`].
    pub(crate) max_lease_ttl_secs: u64,
    /// The effectors this dial allows. Always a subset of [`DOOR_EFFECTORS`].
    pub(crate) allowed_effectors: BTreeSet<String>,
}

/// The door's full effector set as owned strings — the widest a dial may
/// ever be.
fn default_effectors() -> BTreeSet<String> {
    let effectors = DOOR_EFFECTORS.iter();
    effectors.copied().map(String::from).collect()
}

impl Default for DoorPolicy {
    fn default() -> Self {
        Self {
            max_lease_ttl_secs: DOOR_MAX_LEASE_TTL_SECS,
            allowed_effectors: default_effectors(),
        }
    }
}

impl DoorPolicy {
    /// Narrows `self` against `other`, most-restrictive per field.
    fn merge(&mut self, other: DoorPolicy) {
        self.max_lease_ttl_secs = self.max_lease_ttl_secs.min(other.max_lease_ttl_secs);
        self.allowed_effectors = self
            .allowed_effectors
            .intersection(&other.allowed_effectors)
            .cloned()
            .collect();
    }

    /// Whether this dial still admits `effector` as a door scope. An empty
    /// effector is never admitted: there is no unscoped door operation.
    pub(crate) fn admits_effector(&self, effector: &str) -> bool {
        !effector.is_empty()
            && DOOR_EFFECTORS.contains(&effector)
            && self.allowed_effectors.contains(effector)
    }

    /// The effective lease ceiling: the hard floor, narrowed by the dial,
    /// narrowed again by the slip's own attenuation (itself already a minimum
    /// over every caveat applied), and narrowed last by what is LEFT of the
    /// slip's validity at `now`. Only minima compose here, so no combination
    /// of dial, slip, caveat order, and witnessed clock can ever raise it.
    ///
    /// This is the ceiling on what may be REQUESTED. What the issued ticket
    /// actually expires at is clamped once more, by the absolute credential
    /// expiry, inside the transaction that stamps it.
    pub(crate) fn effective_lease_ttl_ceiling(&self, credential: &DoorCredential, now: u64) -> u64 {
        let mut ceiling = DOOR_MAX_LEASE_TTL_SECS.min(self.max_lease_ttl_secs);
        if let Some(attenuated) = credential.max_lease_ttl_secs {
            ceiling = ceiling.min(attenuated);
        }
        ceiling.min(credential.remaining_secs(now))
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
    /// through, and it is the reason this resolver does not skip a broken
    /// entry the way a diagnostics-collecting resolver may. A manifest the
    /// door cannot read is indistinguishable, from here, from a manifest that
    /// narrowed the dial to nothing: an unusable type-index key, an entry
    /// whose entity row is gone, an entity whose metadata header will not
    /// parse, and an entry that names a row of some other type are all
    /// "a declaration was indexed and this door cannot see it". Skipping any
    /// of them hands back the FULL effector set and the FULL TTL ceiling, so
    /// deleting one entity row would be enough to re-open a door a dial had
    /// shut. Every one of them fails closed instead, naming only the constant
    /// [`door_policy_keys::MANIFEST_PLANE`] label and a constant reason —
    /// never an id, a key, or a byte of any body.
    pub(crate) fn resolve(store: &Store, txn: &heed::RoTxn<'_>) -> DoorResult<Self> {
        let corrupt = |reason| CredentialDoorError::InvalidDoorPolicy {
            key: door_policy_keys::MANIFEST_PLANE,
            reason,
        };
        let mut policy = DoorPolicy::default();
        for index_entry in store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])
            .map_err(custody)?
        {
            let (key, _) = index_entry.map_err(custody)?;
            let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_POLICY_MANIFEST) else {
                return Err(corrupt("policy-manifest type-index key is unusable"));
            };
            let Some(raw) = store.entities.get(txn, id.as_bytes()).map_err(custody)? else {
                return Err(corrupt("policy-manifest index entry has no entity row"));
            };
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(corrupt("policy-manifest entity metadata header is invalid"));
            };
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(corrupt("policy-manifest entry names another entity type"));
            }
            if let Some(partial) = decode_door_policy_keys(&raw[ENTITY_METADATA_HEADER_LEN..])? {
                policy.merge(partial);
            }
        }
        Ok(policy)
    }
}

/// Reads a policy-manifest body as the CANONICAL single MessagePack value the
/// manifest contract defines — exactly one value, covering exactly the whole
/// body, which is the same shape [`crate::gate`]'s canonical decoder requires
/// of the bodies it owns.
///
/// The two answers are separated by READABILITY, not by shape:
///
/// * A body that canonically decodes to a value which is not a map is a plane
///   this door does not read: `Ok(None)`, the landed
///   [`crate::secret_custody::SecretCustodyFloor`] idiom. The manifest body
///   SCHEMA belongs to the gate, and an unrelated plane is not this door's to
///   reject.
/// * A body that does not canonically decode AT ALL — empty, truncated,
///   corrupt, or carrying bytes left over past its value — is UNREADABLE.
///   The door cannot see what such a body declared, and it is exactly a
///   restrictive declaration that corruption would erase, so defaulting it
///   would silently restore the permissive posture the declaration existed to
///   narrow. That fails closed, like every other present-but-unreadable
///   declaration in this plane.
fn door_policy_map(body: &[u8]) -> DoorResult<Option<Vec<(Value, Value)>>> {
    let unreadable = |reason| CredentialDoorError::InvalidDoorPolicy {
        key: door_policy_keys::NAMESPACE,
        reason,
    };
    let mut cursor = Cursor::new(body);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Err(unreadable("policy manifest body does not decode"));
    };
    if cursor.position() != body.len() as u64 {
        return Err(unreadable("policy manifest body has bytes past its value"));
    }
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    Ok(Some(entries))
}

/// Decodes the `secret.door.*` rows of ONE policy-manifest body.
///
/// `Ok(None)` means only "this body canonically decodes to something that is
/// not a map, so it carries no door rows" — the body schema itself belongs to
/// the gate. A body that does not canonically decode at all fails closed
/// instead (see [`door_policy_map`]).
pub(crate) fn decode_door_policy_keys(body: &[u8]) -> DoorResult<Option<DoorPolicy>> {
    let Some(entries) = door_policy_map(body)? else {
        return Ok(None);
    };
    reject_floor_naming_rows(&entries)?;

    let ttl_ceiling = decode_ttl_row(&entries)?;
    let declared_effectors = decode_effector_row(&entries)?;
    Ok(Some(DoorPolicy {
        max_lease_ttl_secs: ttl_ceiling,
        allowed_effectors: declared_effectors.unwrap_or_else(default_effectors),
    }))
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

fn decode_ttl_row(entries: &[(Value, Value)]) -> DoorResult<u64> {
    let key = door_policy_keys::MAX_LEASE_TTL_SECS;
    let invalid = |reason| CredentialDoorError::InvalidDoorPolicy { key, reason };
    match single_map_value(entries, key) {
        MapValue::Missing => Ok(DOOR_MAX_LEASE_TTL_SECS),
        MapValue::Present(value) => {
            let Some(secs) = as_u64(value) else {
                return Err(invalid("TTL ceiling must be an unsigned integer"));
            };
            if secs > DOOR_MAX_LEASE_TTL_SECS {
                return Err(invalid("a dial may only narrow the TTL ceiling"));
            }
            Ok(secs)
        }
        MapValue::Duplicate => Err(invalid("duplicated row leaves the ceiling ambiguous")),
    }
}

fn decode_effector_row(entries: &[(Value, Value)]) -> DoorResult<Option<BTreeSet<String>>> {
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
                if !DOOR_EFFECTORS.contains(&name) {
                    return Err(invalid("a door dial may only narrow the door's effectors"));
                }
                allowed.insert(name.to_owned());
            }
            Ok(Some(allowed))
        }
        MapValue::Present(_) => Err(invalid("allowed effectors must be an array")),
        MapValue::Duplicate => Err(invalid("duplicated row leaves the set ambiguous")),
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

    /// Resolves the door dial from the live vault.
    pub(crate) fn door_policy(&self) -> DoorResult<DoorPolicy> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        DoorPolicy::resolve(&self.vault.store, &rtxn)
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
        now: u64,
    ) -> DoorResult<()> {
        let Some(credential) = presented else {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::CredentialAbsent,
            });
        };
        let policy = self.door_policy()?;
        self.admit_scope(&policy, DOOR_RECEIVE_PACK_EFFECTOR)?;
        self.witness_single_use(credential)?;
        credential.evaluate(
            DOOR_VERB_RECEIVE_PACK,
            &repo_record(repo),
            DOOR_RECEIVE_PACK_EFFECTOR,
            now,
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
        now: u64,
        apply: &mut dyn FnMut(&[u8]) -> crate::error::Result<()>,
    ) -> DoorResult<DoorInjectionReceipt> {
        let policy = self.door_policy()?;
        self.admit_scope(&policy, effector)?;
        self.witness_single_use(presented)?;
        presented.evaluate(DOOR_VERB_INJECT, secret_ref, effector, now)?;
        let vault = &self.vault;
        vault
            .inject_secret_at_door(secret_ref, effector, apply)
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
    /// ABSOLUTE expiry, not only as a duration. The duration is computed
    /// against the witnessed `now` this call authorizes at, while the landed
    /// materialization stamps `granted_at` from its own transaction clock; if
    /// only the duration crossed, a request that took a second to reach
    /// persistence — or a redemption of a slip at its exact remaining bound —
    /// would mint a lease that outlives the credential by however far the
    /// clock had moved. Passing the instant lets the write transaction clamp
    /// against the reading it actually stamps
    /// ([`Vault::materialize_secret_lease_bounded`]), so no delay can widen
    /// the ticket and no ticket can outlive the slip that bought it.
    pub(crate) fn issue_lease_ticket(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
        now: u64,
    ) -> DoorResult<SecretLeaseMaterialization> {
        let policy = self.door_policy()?;
        self.admit_scope(&policy, effector)?;
        self.witness_single_use(presented)?;
        presented.evaluate(DOOR_VERB_LEASE, secret_ref, effector, now)?;

        let ceiling = policy.effective_lease_ttl_ceiling(presented, now);
        if ttl_secs == 0 || ttl_secs > ceiling {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: ttl_secs,
                ceiling_secs: ceiling,
            });
        }
        let vault = &self.vault;
        vault
            .materialize_secret_lease_bounded(
                secret_ref,
                effector,
                ttl_secs,
                Some(presented.expires_at),
            )
            .map_err(custody)
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
        now: u64,
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

        let policy = self.door_policy()?;
        self.admit_scope(&policy, effector)?;
        one_shot.evaluate(DOOR_VERB_REDEEM, secret_ref, effector, now)?;

        // The declared lifetime is the CAP the one-shot was written under; the
        // ceiling carries what is left of it at `now`, so a one-shot redeemed
        // late buys only the time it still has.
        let ceiling = policy.effective_lease_ttl_ceiling(&one_shot, now);
        let ttl = lifetime.min(ceiling);
        if ttl == 0 {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: lifetime,
                ceiling_secs: ceiling,
            });
        }
        let vault = &self.vault;
        // The one-shot's own absolute expiry rides along, for the same reason
        // `issue_lease_ticket` sends the slip's: the redeemed ticket is
        // clamped by the clock that stamps it, so a redemption that reaches
        // persistence late cannot hand back time the one-shot no longer had.
        let expires_at = one_shot.expires_at;
        vault
            .materialize_secret_lease_bounded(secret_ref, effector, ttl, Some(expires_at))
            .map_err(custody)
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
    pub(crate) fn mint_one_shot(
        &self,
        _secret_ref: &str,
        _effector: &str,
        _lifetime_secs: u64,
        _now: u64,
    ) -> DoorResult<DoorCredential> {
        Err(CredentialDoorError::MintUnavailable)
    }

    /// A door operation is always scoped: the effector must be one this door
    /// knows and one the dial still admits.
    fn admit_scope(&self, policy: &DoorPolicy, effector: &str) -> DoorResult<()> {
        if policy.admits_effector(effector) {
            return Ok(());
        }
        Err(CredentialDoorError::LeaseScopeRefused {
            effector: effector.to_owned(),
            reason: "not a door effector the resolved dial admits",
        })
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
