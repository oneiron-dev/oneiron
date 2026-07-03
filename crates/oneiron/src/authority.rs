//! AUTHORITY_LOG record substrate.
//!
//! Type 122 is a fold-verified maintenance log. Replay doors validate the
//! record shape and embedded origin signature only; authority semantics stay in
//! [`fold_authority_log`], where the roster is derived from peer-signed log
//! entries rather than from a server-issued registry.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rmpv::Value;

use crate::error::{Error, Result};

/// Current AUTHORITY_LOG body schema version.
pub const AUTHORITY_LOG_SCHEMA_VERSION: u64 = 1;

/// Domain-separated signature transcript for authority-log self-mutations.
pub const AUTHORITY_TRANSCRIPT_DOMAIN: &[u8] = b"oneiron/authority/v1";

/// BLAKE3 authority entry hash length.
pub const AUTHORITY_HASH_LEN: usize = 32;

/// Owner role bit.
pub const ROLE_OWNER: u16 = 0x0001;
/// Admin role bit.
pub const ROLE_ADMIN: u16 = 0x0002;
/// Agent/member role bit.
pub const ROLE_AGENT: u16 = 0x0004;
/// Cloud-worker/member role bit. Cloud is a member, never root.
pub const ROLE_CLOUD: u16 = 0x0008;
/// Recovery-participant role bit.
pub const ROLE_RECOVERY: u16 = 0x0010;
const ROLE_DEFINED_MASK: u16 = ROLE_OWNER | ROLE_ADMIN | ROLE_AGENT | ROLE_CLOUD | ROLE_RECOVERY;

/// Owner-facing alarm kind emitted when AUTH-5 detects key equivocation.
pub const AUTHORITY_FORK_ALARM_KIND: &str = "AUTHORITY FORK DETECTED";

/// Content hash of a canonical authority entry.
pub type AuthorityEntryHash = [u8; AUTHORITY_HASH_LEN];

/// Vault id derived from the canonical signed genesis entry.
pub type AuthorityVaultId = [u8; AUTHORITY_HASH_LEN];

const AUTHORITY_ENTRY_KEYS: [&str; 8] = [
    "schema_version",
    "vault_id",
    "seq",
    "parent_hashes",
    "op",
    "signer",
    "cosigns",
    "ts",
];
const KEY_SCHEMA_VERSION: &str = AUTHORITY_ENTRY_KEYS[0];
const KEY_VAULT_ID: &str = AUTHORITY_ENTRY_KEYS[1];
const KEY_SEQ: &str = AUTHORITY_ENTRY_KEYS[2];
const KEY_PARENT_HASHES: &str = AUTHORITY_ENTRY_KEYS[3];
const KEY_OP: &str = AUTHORITY_ENTRY_KEYS[4];
const KEY_SIGNER: &str = AUTHORITY_ENTRY_KEYS[5];
const KEY_COSIGNS: &str = AUTHORITY_ENTRY_KEYS[6];
const KEY_TS: &str = AUTHORITY_ENTRY_KEYS[7];

const SIGNATURE_KEYS: [&str; 3] = ["suite", "public_key", "signature"];
const KEY_SUITE: &str = SIGNATURE_KEYS[0];
const KEY_PUBLIC_KEY: &str = SIGNATURE_KEYS[1];
const KEY_SIGNATURE: &str = SIGNATURE_KEYS[2];

const ATTESTATION_KEYS: [&str; 2] = ["kind", "evidence"];
const KEY_ATTEST_KIND: &str = ATTESTATION_KEYS[0];
const KEY_ATTEST_EVIDENCE: &str = ATTESTATION_KEYS[1];

const OP_KEY_KIND: &str = "kind";
const OP_KIND_GENESIS: &str = "genesis";
const OP_KIND_ENROLL_DEVICE: &str = "enroll_device";
const OP_KIND_REVOKE_DEVICE: &str = "revoke_device";
const OP_KIND_SET_CEILING: &str = "set_ceiling";
const OP_KIND_ROTATE_KEY: &str = "rotate_key";
const OP_KIND_SET_TIER_FLOOR: &str = "set_tier_floor";
const OP_KIND_RECOVERY_REBOOT: &str = "recovery_reboot";
const OP_KIND_FEDERATION_CONFIRM: &str = "federation_confirm";
const OP_KIND_VETO_PENDING_WIDEN: &str = "veto_pending_widen";

const CONFIRM_KIND_ACCEPT: &str = "accept";
const CONFIRM_KIND_RESCOPE: &str = "rescope";
const CONFIRM_KIND_A2A_CONNECT: &str = "a2a_connect";
const CONFIRM_KIND_REVOKE: &str = "revoke";

const MAX_PARENTS: usize = 32;
const MAX_COSIGNS: usize = 8;
const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 4096;
const MAX_ACTOR_CLASS_BYTES: usize = 64;

/// Lower bound for the default software-tier pending-widen delay (24h).
pub const MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 24 * 60 * 60;
/// Upper bound for the default software-tier pending-widen delay (48h).
pub const MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 48 * 60 * 60;
/// Default local seen-time delay for software-tier widens.
pub const DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS;
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS >= MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS);
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS <= MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS);

/// Signature suite carried by an authority signature envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthoritySignatureSuite {
    /// Ed25519 signature, used by software-tier authority keys.
    Ed25519,
    /// P-256 ECDSA signature, used by Secure Enclave / hardware authority keys.
    P256,
}

impl AuthoritySignatureSuite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ed25519" => Some(Self::Ed25519),
            "p256" => Some(Self::P256),
            _ => None,
        }
    }
}

/// Authority public key material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityKey {
    /// 32-byte Ed25519 verifying key.
    Ed25519([u8; 32]),
    /// Canonical compressed SEC1-encoded P-256 verifying key.
    P256(Vec<u8>),
}

impl AuthorityKey {
    /// Returns the matching signature suite for this key.
    #[must_use]
    pub const fn suite(&self) -> AuthoritySignatureSuite {
        match self {
            Self::Ed25519(_) => AuthoritySignatureSuite::Ed25519,
            Self::P256(_) => AuthoritySignatureSuite::P256,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Ed25519(bytes) => VerifyingKey::from_bytes(bytes)
                .map(|_| ())
                .map_err(|_| invalid_authority()),
            Self::P256(bytes) => {
                if canonical_p256_key_bytes(bytes)? != *bytes {
                    return Err(invalid_authority());
                }
                Ok(())
            }
        }
    }
}

/// Hardware/software attestation envelope for an enrolled authority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityAttestation {
    /// Pinned attestation kind string.
    pub kind: String,
    /// Opaque attestation evidence bytes.
    pub evidence: Vec<u8>,
}

impl AuthorityAttestation {
    fn validate(&self) -> Result<()> {
        if self.kind.is_empty()
            || self.kind.len() > 64
            || self.evidence.len() > MAX_ATTESTATION_EVIDENCE_BYTES
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Authority assurance tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityTier {
    /// Passphrase-derived or otherwise software-held authority key.
    Software,
    /// Hardware-backed authority key.
    Hardware,
    /// Explicit custodial cloud authority key, never default root.
    CloudCustodial,
}

impl AuthorityTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
            Self::CloudCustodial => "cloud_custodial",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "software" => Some(Self::Software),
            "hardware" => Some(Self::Hardware),
            "cloud_custodial" => Some(Self::CloudCustodial),
            _ => None,
        }
    }
}

/// Signature envelope over [`authority_transcript`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySignature {
    /// Signature algorithm.
    pub suite: AuthoritySignatureSuite,
    /// Authority public key that verifies the signature.
    pub public_key: AuthorityKey,
    /// Raw signature bytes: 64 bytes for Ed25519 and fixed-width P-256 ECDSA.
    pub signature: Vec<u8>,
}

impl AuthoritySignature {
    fn validate(&self) -> Result<()> {
        if self.suite != self.public_key.suite() {
            return Err(invalid_authority());
        }
        match self.suite {
            AuthoritySignatureSuite::Ed25519 if self.signature.len() == 64 => {}
            AuthoritySignatureSuite::P256 if self.signature.len() == 64 => {}
            _ => return Err(invalid_authority()),
        }
        self.public_key.validate()?;
        if self.suite == AuthoritySignatureSuite::P256 {
            let signature =
                P256Signature::from_slice(&self.signature).map_err(|_| invalid_authority())?;
            if signature.normalize_s().is_some() {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }
}

/// Federation confirm action recorded in the authority log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityConfirmKind {
    /// Connection accept.
    Accept,
    /// Re-scope or epoch bump.
    Rescope,
    /// Foreign A2A connect.
    A2aConnect,
    /// Revocation confirm.
    Revoke,
}

impl AuthorityConfirmKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accept => CONFIRM_KIND_ACCEPT,
            Self::Rescope => CONFIRM_KIND_RESCOPE,
            Self::A2aConnect => CONFIRM_KIND_A2A_CONNECT,
            Self::Revoke => CONFIRM_KIND_REVOKE,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            CONFIRM_KIND_ACCEPT => Some(Self::Accept),
            CONFIRM_KIND_RESCOPE => Some(Self::Rescope),
            CONFIRM_KIND_A2A_CONNECT => Some(Self::A2aConnect),
            CONFIRM_KIND_REVOKE => Some(Self::Revoke),
            _ => None,
        }
    }
}

/// Fold-verified federation confirm payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfirmAction {
    /// Confirm kind.
    pub kind: AuthorityConfirmKind,
    /// Connection/grant identifier.
    pub confirm_id: [u8; 32],
    /// Peer vault id.
    pub peer_vault_id: AuthorityVaultId,
    /// Consent epoch.
    pub epoch: u64,
    /// Device-bound nonce.
    pub nonce: [u8; 16],
}

/// Device authority material carried by genesis/enroll/rotate/recovery ops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthority {
    /// Authority key.
    pub key: AuthorityKey,
    /// Transport key binding; all-zero for genesis when unavailable.
    pub transport_key_binding: [u8; 32],
    /// Attestation envelope.
    pub attestation: AuthorityAttestation,
    /// Assurance tier.
    pub tier: AuthorityTier,
    /// Role bits.
    pub roles: u16,
}

impl DeviceAuthority {
    fn validate(&self) -> Result<()> {
        if self.roles == 0 {
            return Err(invalid_authority());
        }
        if (self.roles & !ROLE_DEFINED_MASK) != 0 {
            return Err(invalid_authority());
        }
        if (self.roles & ROLE_CLOUD) != 0 && (self.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0 {
            return Err(invalid_authority());
        }
        if self.tier == AuthorityTier::CloudCustodial
            && (self.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
        {
            return Err(invalid_authority());
        }
        self.key.validate()?;
        self.attestation.validate()
    }

    fn can_authority_consent(&self) -> bool {
        (self.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
            && (self.roles & ROLE_CLOUD) == 0
            && self.tier != AuthorityTier::CloudCustodial
    }
}

/// Pinned operation vocabulary for type-122.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOp {
    /// Vault genesis. `vault_id` is `None` on the containing entry and is
    /// derived as BLAKE3(canonical signed genesis).
    Genesis {
        device: DeviceAuthority,
        genesis_nonce: [u8; 32],
        tier_floor: AuthorityTier,
        pending_widen_delay_secs: u64,
    },
    /// Enrolls a new authority key.
    EnrollDevice { device: DeviceAuthority },
    /// Revokes an authority key.
    RevokeDevice { revoked_key: AuthorityKey },
    /// Binds an authority key to an actor-class ceiling.
    SetCeiling {
        authority_key: AuthorityKey,
        actor_class: String,
        ceiling: u8,
    },
    /// Rotates one authority key to another.
    RotateKey {
        old_key: AuthorityKey,
        new_device: DeviceAuthority,
    },
    /// Sets the vault tier floor.
    SetTierFloor { tier_floor: AuthorityTier },
    /// Rebootstraps authority after recovery.
    RecoveryReboot {
        new_genesis_nonce: [u8; 32],
        new_device: DeviceAuthority,
        tier_floor: AuthorityTier,
    },
    /// Federation confirm that travels with authority fold verification.
    FederationConfirm(AuthorityConfirmAction),
    /// Owner veto for a software-tier widen that is still pending.
    VetoPendingWiden {
        /// Target authority entry hash to suppress under most-restrictive-wins.
        pending_widen_hash: AuthorityEntryHash,
    },
}

/// A canonical, signed AUTHORITY_LOG entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityLogEntry {
    /// Schema version.
    pub schema_version: u64,
    /// `None` for genesis; `Some(genesis_vault_id)` for all other entries.
    pub vault_id: Option<AuthorityVaultId>,
    /// Per-signer strictly monotonic sequence number.
    pub seq: u64,
    /// Parent entry hashes in the authority DAG.
    pub parent_hashes: Vec<AuthorityEntryHash>,
    /// Operation payload.
    pub op: AuthorityOp,
    /// Primary signer.
    pub signer: AuthoritySignature,
    /// Optional quorum co-signatures.
    pub cosigns: Vec<AuthoritySignature>,
    /// Advisory timestamp. Fold semantics must never branch on this value.
    pub ts: u64,
}

impl AuthorityLogEntry {
    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != AUTHORITY_LOG_SCHEMA_VERSION
            || self.parent_hashes.len() > MAX_PARENTS
            || self.cosigns.len() > MAX_COSIGNS
        {
            return Err(invalid_authority());
        }
        let mut parents = self.parent_hashes.clone();
        parents.sort_unstable();
        parents.dedup();
        if parents.len() != self.parent_hashes.len() {
            return Err(invalid_authority());
        }
        match self.op {
            AuthorityOp::Genesis { .. }
                if !self.parent_hashes.is_empty()
                    || self.vault_id.is_some()
                    || !self.cosigns.is_empty() =>
            {
                return Err(invalid_authority());
            }
            AuthorityOp::Genesis { .. } => {}
            _ if self.vault_id.is_none() => return Err(invalid_authority()),
            _ => {}
        }
        validate_op(&self.op)?;
        self.signer.validate()?;
        let mut previous_cosign_key: Option<&AuthorityKey> = None;
        for cosign in &self.cosigns {
            cosign.validate()?;
            if cosign.public_key == self.signer.public_key {
                return Err(invalid_authority());
            }
            if previous_cosign_key.is_some_and(|previous| previous >= &cosign.public_key) {
                return Err(invalid_authority());
            }
            previous_cosign_key = Some(&cosign.public_key);
        }
        Ok(())
    }

    fn signer_key(&self) -> &AuthorityKey {
        &self.signer.public_key
    }
}

/// Folded roster entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedDevice {
    /// Authority key.
    pub key: AuthorityKey,
    /// Assurance tier.
    pub tier: AuthorityTier,
    /// Role bits after most-restrictive conflict folding.
    pub roles: u16,
    /// Whether any valid revocation tombstone removed this key.
    pub revoked: bool,
}

/// Local pending-widen state exposed by the fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPendingWiden {
    /// Pending authority entry.
    pub entry_hash: AuthorityEntryHash,
    /// Local first-seen monotonic timestamp, if the caller supplied one.
    pub first_seen_at_secs: Option<u64>,
    /// Local timestamp at which the entry becomes eligible.
    pub eligible_at_secs: Option<u64>,
    /// Delay window chosen by genesis for this vault.
    pub delay_secs: u64,
}

/// Fold issue retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityFoldIssue {
    /// Entry failed shape or signature verification.
    InvalidEntry(AuthorityEntryHash),
    /// Entry references a missing or invalid parent.
    InvalidAncestry(AuthorityEntryHash),
    /// Entry signer was not valid in its own ancestry.
    SignerNotInAncestry(AuthorityEntryHash),
    /// Entry sequence was not strictly greater than that signer's ancestry high-water mark.
    NonMonotonicSeq(AuthorityEntryHash),
    /// Entry binds the wrong vault id.
    WrongVault(AuthorityEntryHash),
    /// The fold contains more than one independently rooted vault id.
    ConflictingVaultRoot {
        /// Entry folded under a vault id that conflicts with another root.
        entry: AuthorityEntryHash,
        /// Conflicting vault id.
        vault_id: AuthorityVaultId,
    },
    /// Entry lacks an active owner/admin signer or co-signer in its ancestry.
    MissingAuthorityConsent(AuthorityEntryHash),
    /// Entry requires a distinct active co-signer quorum.
    MissingQuorum(AuthorityEntryHash),
    /// One key signed divergent content at the same sequence number.
    EquivocationDetected {
        /// Equivocating authority key.
        signer: AuthorityKey,
        /// Conflicting signer sequence number.
        seq: u64,
    },
}

/// Fold-visible AUTH-5 state for one detected signer fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityForkStatus {
    /// Transient same-pass edge where the fold observes divergent entries and raises the alarm.
    ///
    /// Stable fold output records the immediately following `Quarantined` state.
    Forked,
    /// Forked key is quarantined until a valid quorum revoke folds in.
    Quarantined,
    /// A valid quorum revoke for the forked key has folded in.
    Resolved,
}

/// Queryable fold row for one signer fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFork {
    /// Equivocating authority key.
    pub signer: AuthorityKey,
    /// Conflicting signer sequence number.
    pub seq: u64,
    /// First conflicting entry hash, sorted lexicographically.
    pub first_hash: AuthorityEntryHash,
    /// Second conflicting entry hash, sorted lexicographically.
    pub second_hash: AuthorityEntryHash,
    /// Current deterministic fork state.
    pub status: AuthorityForkStatus,
}

/// Typed owner-facing alarm row for one authority fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityForkAlarm {
    /// Equivocating authority key.
    pub signer: AuthorityKey,
    /// Conflicting signer sequence number.
    pub seq: u64,
    /// First conflicting entry hash, sorted lexicographically.
    pub first_hash: AuthorityEntryHash,
    /// Second conflicting entry hash, sorted lexicographically.
    pub second_hash: AuthorityEntryHash,
}

impl AuthorityForkAlarm {
    /// Stable alarm discriminator for owner-facing surfaces.
    pub const KIND: &'static str = AUTHORITY_FORK_ALARM_KIND;
}

/// Deterministic authority fold output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFold {
    /// Derived vault id.
    pub vault_id: Option<AuthorityVaultId>,
    /// Valid entry hashes.
    pub valid_entries: BTreeSet<AuthorityEntryHash>,
    /// Fold-derived active/revoked roster.
    pub roster: BTreeMap<AuthorityKey, FoldedDevice>,
    /// Most-restrictive tier floor.
    pub tier_floor: Option<AuthorityTier>,
    /// Software-tier widens that are valid but not yet locally eligible.
    pub pending_widens: BTreeMap<AuthorityEntryHash, AuthorityPendingWiden>,
    /// Pending widen hashes killed by a valid owner veto.
    pub vetoed_widens: BTreeSet<AuthorityEntryHash>,
    /// AUTH-5 signer-fork state rows.
    pub authority_forks: Vec<AuthorityFork>,
    /// Owner-facing AUTHORITY FORK alarms, one per detected fork.
    pub fork_alarms: Vec<AuthorityForkAlarm>,
    /// Fold diagnostics.
    pub issues: Vec<AuthorityFoldIssue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FoldState {
    vault_id: AuthorityVaultId,
    roster: BTreeMap<AuthorityKey, FoldedDevice>,
    tier_floor: AuthorityTier,
    pending_widen_delay_secs: u64,
    pending_widens: BTreeMap<AuthorityEntryHash, AuthorityPendingWiden>,
    vetoed_widens: BTreeSet<AuthorityEntryHash>,
    /// Delayed software rotations that revoked old owner/admin keys.
    ///
    /// These keys are retained only to validate vetoes against widens that were
    /// concurrent with, or older than, the delayed rotation that revoked them.
    delayed_rotation_veto_revocations: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    authority_forks: BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    seqs: BTreeMap<AuthorityKey, u64>,
}

/// Encodes an authority entry to canonical MessagePack bytes.
pub fn encode_authority_log_entry_body(entry: &AuthorityLogEntry) -> Result<Vec<u8>> {
    entry.validate_shape()?;
    encode_value(&entry_value(entry, true))
}

/// Decodes a canonical authority entry and verifies the embedded origin signature.
pub fn decode_authority_log_entry_body(bytes: &[u8]) -> Result<AuthorityLogEntry> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_authority())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_authority());
    }
    let entry = decode_entry_value(&value)?;
    entry.validate_shape()?;
    let current_canonical = encode_authority_log_entry_body(&entry)?;
    if current_canonical == bytes && verify_entry_signatures_current(&entry).is_ok() {
        return Ok(entry);
    }
    if let Some(legacy_canonical) = legacy_genesis_signed_entry_bytes(&entry)?
        && legacy_canonical == bytes
        && verify_entry_signatures_legacy_genesis(&entry).is_ok()
    {
        return Ok(entry);
    }
    Err(invalid_authority())
}

/// Validates body bytes for write/replay doors.
pub fn validate_authority_log_entry_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_authority_log_entry_body(bytes).map(|_| ())
}

/// BLAKE3 hash of the canonical signed authority entry.
pub fn authority_entry_hash(entry: &AuthorityLogEntry) -> Result<AuthorityEntryHash> {
    let current_canonical = encode_authority_log_entry_body(entry)?;
    if verify_entry_signatures_current(entry).is_err()
        && verify_entry_signatures_legacy_genesis(entry).is_ok()
        && let Some(legacy_canonical) = legacy_genesis_signed_entry_bytes(entry)?
    {
        return Ok(*blake3::hash(&legacy_canonical).as_bytes());
    }
    Ok(*blake3::hash(&current_canonical).as_bytes())
}

/// BLAKE3 vault id derived from a canonical signed genesis entry.
pub fn genesis_vault_id(entry: &AuthorityLogEntry) -> Result<AuthorityVaultId> {
    if !matches!(entry.op, AuthorityOp::Genesis { .. }) || entry.vault_id.is_some() {
        return Err(invalid_authority());
    }
    authority_entry_hash(entry)
}

/// Domain-separated signature transcript for an authority entry.
pub fn authority_transcript(entry: &AuthorityLogEntry) -> Result<Vec<u8>> {
    authority_transcript_with_genesis_delay(entry, true)
}

fn authority_transcript_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_genesis_delay: bool,
) -> Result<Vec<u8>> {
    let unsigned = encode_value(&transcript_value_with_genesis_delay(
        entry,
        include_genesis_delay,
    ))?;
    let mut transcript = Vec::with_capacity(AUTHORITY_TRANSCRIPT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(AUTHORITY_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

fn transcript_value_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_genesis_delay: bool,
) -> Value {
    Value::Map(vec![
        (
            Value::from("entry"),
            entry_value_with_genesis_delay(entry, false, include_genesis_delay),
        ),
        (Value::from(KEY_SIGNER), key_value(entry.signer_key())),
        (
            Value::from("cosign_keys"),
            Value::Array(
                entry
                    .cosigns
                    .iter()
                    .map(|signature| key_value(&signature.public_key))
                    .collect(),
            ),
        ),
    ])
}

fn canonical_p256_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let key = P256VerifyingKey::from_sec1_bytes(bytes).map_err(|_| invalid_authority())?;
    Ok(key.to_encoded_point(true).as_bytes().to_vec())
}

/// Verifies an authority signature envelope against a transcript.
#[must_use]
pub fn verify_authority_signature(signature: &AuthoritySignature, transcript: &[u8]) -> bool {
    if signature.validate().is_err() {
        return false;
    }
    match (&signature.public_key, signature.suite) {
        (AuthorityKey::Ed25519(public_key), AuthoritySignatureSuite::Ed25519) => {
            let Ok(key) = VerifyingKey::from_bytes(public_key) else {
                return false;
            };
            let Ok(signature_bytes) = signature.signature.as_slice().try_into() else {
                return false;
            };
            let sig = Ed25519Signature::from_bytes(signature_bytes);
            key.verify(transcript, &sig).is_ok()
        }
        (AuthorityKey::P256(public_key), AuthoritySignatureSuite::P256) => {
            let Ok(key) = P256VerifyingKey::from_sec1_bytes(public_key) else {
                return false;
            };
            let Ok(sig) = P256Signature::from_slice(&signature.signature) else {
                return false;
            };
            key.verify(transcript, &sig).is_ok()
        }
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct FoldContext<'a> {
    first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
    vetoed_widens: &'a BTreeSet<AuthorityEntryHash>,
    authority_forks: &'a BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    equivocation_groups: &'a BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>,
    unresolved_equivocation_groups: &'a BTreeSet<(AuthorityKey, u64)>,
    entry_ancestors: Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
}

/// Folds a set of authority entries into a deterministic roster.
///
/// Entries missing local first-seen timestamps remain pending; callers with
/// local seen-time data should use [`fold_authority_log_with_seen_times`].
pub fn fold_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    fold_authority_log_inner(entries, &first_seen_at_secs, Some(0), true)
}

#[cfg(test)]
fn fold_authority_log_without_seen_time_delay(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    fold_authority_log_inner(entries, &first_seen_at_secs, None, false)
}

/// Folds authority entries using local first-seen timestamps for delayed widens.
///
/// `first_seen_at_secs` is keyed by authority entry hash and must be sourced
/// from the local device's monotonic first-observation time. Entries missing a
/// timestamp remain pending until the caller can provide one.
pub fn fold_authority_log_with_seen_times(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
) -> AuthorityFold {
    fold_authority_log_inner(entries, first_seen_at_secs, Some(now_secs), true)
}

pub(crate) fn authority_first_seen_sync_key(hash: &AuthorityEntryHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity("authlog:first_seen:".len() + AUTHORITY_HASH_LEN * 2);
    key.push_str("authlog:first_seen:");
    for byte in hash {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    key
}

pub(crate) fn authority_first_seen_backfill_sync_key() -> &'static str {
    "authlog:first_seen:backfill:v1"
}

pub(crate) fn authority_first_seen_clock_sync_key() -> &'static str {
    "authlog:first_seen:clock_floor"
}

struct AuthorityLocalClock {
    last_instant: Instant,
    last_secs: u64,
}

fn authority_local_clocks() -> &'static Mutex<BTreeMap<usize, AuthorityLocalClock>> {
    static LOCAL_CLOCKS: OnceLock<Mutex<BTreeMap<usize, AuthorityLocalClock>>> = OnceLock::new();
    LOCAL_CLOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn authority_observation_secs_for_domain(
    clock_domain: usize,
    previous_floor: u64,
    candidate_wall_secs: u64,
) -> u64 {
    let now = Instant::now();
    let mut clocks = authority_local_clocks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match clocks.get_mut(&clock_domain) {
        Some(clock) => {
            let elapsed = now.saturating_duration_since(clock.last_instant).as_secs();
            let observed = clock.last_secs.saturating_add(elapsed).max(previous_floor);
            clock.last_secs = observed;
            clock.last_instant = now;
            observed
        }
        None => {
            let observed = candidate_wall_secs.max(previous_floor);
            clocks.insert(
                clock_domain,
                AuthorityLocalClock {
                    last_instant: now,
                    last_secs: observed,
                },
            );
            observed
        }
    }
}

pub(crate) fn release_authority_clock_domain(clock_domain: usize) {
    let mut clocks = authority_local_clocks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clocks.remove(&clock_domain);
}

pub(crate) fn encode_authority_first_seen_secs(secs: u64) -> [u8; 8] {
    secs.to_be_bytes()
}

pub(crate) fn decode_authority_first_seen_secs(raw: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(raw.try_into().ok()?))
}

fn fold_authority_log_inner(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
) -> AuthorityFold {
    let mut vetoed_widens = BTreeSet::new();
    let empty_authority_forks = BTreeMap::new();
    let empty_equivocation_groups = BTreeMap::new();
    let empty_unresolved_equivocation_groups = BTreeSet::new();
    let mut fold = fold_authority_log_once(
        entries,
        FoldContext {
            first_seen_at_secs,
            now_secs,
            enforce_seen_time_delay,
            vetoed_widens: &vetoed_widens,
            authority_forks: &empty_authority_forks,
            equivocation_groups: &empty_equivocation_groups,
            unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
            entry_ancestors: None,
        },
    );
    for _ in 0..=entries.len() {
        if fold.vetoed_widens == vetoed_widens {
            return fold;
        }
        vetoed_widens = fold.vetoed_widens.clone();
        fold = fold_authority_log_once(
            entries,
            FoldContext {
                first_seen_at_secs,
                now_secs,
                enforce_seen_time_delay,
                vetoed_widens: &vetoed_widens,
                authority_forks: &empty_authority_forks,
                equivocation_groups: &empty_equivocation_groups,
                unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
                entry_ancestors: None,
            },
        );
    }
    fold
}

fn fold_authority_log_once(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
) -> AuthorityFold {
    let mut by_hash = BTreeMap::<AuthorityEntryHash, AuthorityLogEntry>::new();
    let mut issues = Vec::new();
    let mut by_signer_seq = BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>::new();
    for entry in entries {
        match authority_entry_hash(entry) {
            Ok(hash) if verify_entry_signatures(entry).is_ok() => {
                by_hash.entry(hash).or_insert_with(|| entry.clone());
                by_signer_seq
                    .entry((entry.signer_key().clone(), entry.seq))
                    .or_default()
                    .insert(hash);
            }
            Ok(hash) => issues.push(AuthorityFoldIssue::InvalidEntry(hash)),
            Err(_) => issues.push(AuthorityFoldIssue::InvalidEntry([0; 32])),
        }
    }
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let mut equivocation_groups =
        BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>::new();
    let mut equivocation_by_hash = BTreeMap::<AuthorityEntryHash, (AuthorityKey, u64)>::new();
    for ((signer, seq), hashes) in by_signer_seq {
        if hashes.len() > 1 {
            if restore_prefix_divergence(&hashes, &by_hash, &entry_ancestors) {
                continue;
            }
            for hash in &hashes {
                equivocation_by_hash.insert(*hash, (signer.clone(), seq));
            }
            equivocation_groups.insert((signer.clone(), seq), hashes);
        }
    }
    let mut authority_forks = BTreeMap::<(AuthorityKey, u64), AuthorityFork>::new();
    let mut unresolved_equivocation_groups =
        BTreeSet::<(AuthorityKey, u64)>::from_iter(equivocation_groups.keys().cloned());

    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash.keys().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let hashes: Vec<_> = pending.iter().copied().collect();
        for hash in hashes {
            let entry = &by_hash[&hash];
            if let Some(group_key) = equivocation_by_hash.get(&hash) {
                let group_key = group_key.clone();
                let group = &equivocation_groups[&group_key];
                let fold_context = FoldContext {
                    authority_forks: &authority_forks,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(&entry_ancestors),
                    ..context
                };
                match resolve_equivocation_group(
                    &group_key,
                    group,
                    &by_hash,
                    &states,
                    &pending,
                    fold_context,
                ) {
                    EquivocationResolution::Waiting => continue,
                    EquivocationResolution::Resolved {
                        winner,
                        issues: group_issues,
                    } => {
                        unresolved_equivocation_groups.remove(&group_key);
                        if let Some((winner_hash, state)) = winner {
                            issues.push(AuthorityFoldIssue::EquivocationDetected {
                                signer: group_key.0.clone(),
                                seq: group_key.1,
                            });
                            if let Some(fork) = state.authority_forks.get(&group_key).cloned() {
                                authority_forks.insert(group_key.clone(), fork);
                            }
                            states.insert(winner_hash, *state);
                        }
                        issues.extend(group_issues);
                        for group_hash in group {
                            pending.remove(group_hash);
                        }
                        progressed = true;
                        continue;
                    }
                }
            }
            let fold_context = FoldContext {
                authority_forks: &authority_forks,
                equivocation_groups: &equivocation_groups,
                unresolved_equivocation_groups: &unresolved_equivocation_groups,
                entry_ancestors: Some(&entry_ancestors),
                ..context
            };
            match fold_entry_state(entry, hash, &states, fold_context) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(issue) => {
                    issues.push(issue);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
            }
        }
    }
    for hash in pending {
        issues.push(AuthorityFoldIssue::InvalidAncestry(hash));
    }

    let mut vault_ids = BTreeSet::new();
    for state in states.values() {
        vault_ids.insert(state.vault_id);
    }
    if vault_ids.len() > 1 {
        for (hash, state) in &states {
            issues.push(AuthorityFoldIssue::ConflictingVaultRoot {
                entry: *hash,
                vault_id: state.vault_id,
            });
        }
        return AuthorityFold {
            vault_id: None,
            valid_entries: BTreeSet::new(),
            roster: BTreeMap::new(),
            tier_floor: None,
            pending_widens: BTreeMap::new(),
            vetoed_widens: BTreeSet::new(),
            authority_forks: Vec::new(),
            fork_alarms: Vec::new(),
            issues,
        };
    }

    let mut merged: Option<FoldState> = None;
    let mut valid_entries = BTreeSet::new();
    for (hash, state) in &states {
        valid_entries.insert(*hash);
        merged = Some(match merged {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }

    let authority_forks: Vec<_> = merged.as_ref().map_or_else(Vec::new, |state| {
        state.authority_forks.values().cloned().collect()
    });
    let fork_alarms = authority_forks
        .iter()
        .map(|fork| AuthorityForkAlarm {
            signer: fork.signer.clone(),
            seq: fork.seq,
            first_hash: fork.first_hash,
            second_hash: fork.second_hash,
        })
        .collect();

    AuthorityFold {
        vault_id: merged.as_ref().map(|state| state.vault_id),
        valid_entries,
        roster: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.roster.clone()),
        tier_floor: merged.as_ref().map(|state| state.tier_floor),
        pending_widens: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.pending_widens.clone()),
        vetoed_widens: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.vetoed_widens.clone()),
        authority_forks,
        fork_alarms,
        issues,
    }
}

enum EntryFold {
    Ready(FoldState),
    Waiting,
    Invalid(AuthorityFoldIssue),
}

enum EquivocationResolution {
    Resolved {
        winner: Option<(AuthorityEntryHash, Box<FoldState>)>,
        issues: Vec<AuthorityFoldIssue>,
    },
    Waiting,
}

fn resolve_equivocation_group(
    group_key: &(AuthorityKey, u64),
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> EquivocationResolution {
    let mut ready = Vec::<(AuthorityEntryHash, FoldState, FoldState)>::new();
    let mut issues = Vec::new();
    for hash in group {
        let entry = &by_hash[hash];
        match fold_entry_state(entry, *hash, states, context) {
            EntryFold::Ready(state) => {
                let rank_state = equivocation_rank_state(entry, *hash, &state);
                ready.push((*hash, state, rank_state));
            }
            EntryFold::Invalid(issue) => issues.push(issue),
            EntryFold::Waiting
                if entry_waits_on_pending_parent_outside_group(entry, states, pending, group) =>
            {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting if entry_waits_on_unresolved_equivocation(entry, *hash, context) => {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting => issues.push(AuthorityFoldIssue::InvalidAncestry(*hash)),
        }
    }

    if ready.is_empty() {
        return EquivocationResolution::Resolved {
            winner: None,
            issues,
        };
    }

    ready.sort_by(compare_fork_rank);
    let mut ready = ready.into_iter();
    let mut winner = None;
    for (candidate_hash, mut candidate_state, _) in ready.by_ref() {
        record_authority_fork(&mut candidate_state, &group_key.0, group_key.1, group);
        if matches!(
            &by_hash[&candidate_hash].op,
            AuthorityOp::RevokeDevice { revoked_key } if revoked_key == &group_key.0
        ) {
            resolve_recorded_authority_fork(&mut candidate_state, &group_key.0, group_key.1);
        }
        if let Some(issue) = fork_winner_revoke_post_quarantine_issue(
            &candidate_state,
            context,
            candidate_hash,
            &by_hash[&candidate_hash].op,
            &group_key.0,
        ) {
            issues.push(issue);
            continue;
        }
        winner = Some((candidate_hash, Box::new(candidate_state)));
        break;
    }
    for (loser, _, _) in ready {
        issues.push(AuthorityFoldIssue::InvalidEntry(loser));
    }
    EquivocationResolution::Resolved { winner, issues }
}

fn record_authority_fork(
    state: &mut FoldState,
    signer: &AuthorityKey,
    seq: u64,
    group: &BTreeSet<AuthorityEntryHash>,
) {
    let Some(fork) = authority_fork_from_group(signer, seq, group) else {
        return;
    };
    state.authority_forks.insert((signer.clone(), seq), fork);
}

fn resolve_recorded_authority_fork(state: &mut FoldState, signer: &AuthorityKey, seq: u64) {
    if let Some(fork) = state.authority_forks.get_mut(&(signer.clone(), seq)) {
        fork.status = AuthorityForkStatus::Resolved;
    }
}

fn fork_winner_revoke_post_quarantine_issue(
    state: &FoldState,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    op: &AuthorityOp,
    forked_key: &AuthorityKey,
) -> Option<AuthorityFoldIssue> {
    if !matches!(op, AuthorityOp::RevokeDevice { .. }) {
        return None;
    }
    if active_roster_count_after_fork_quarantine(state, context, hash, forked_key) < 2 {
        return Some(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if !state_has_authority_consent_after_fork_quarantine(state, context, hash, forked_key) {
        return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    None
}

fn active_roster_count_after_fork_quarantine(
    state: &FoldState,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    forked_key: &AuthorityKey,
) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            *key != forked_key
                && !device.revoked
                && device.roles != 0
                && !key_is_quarantined_for_entry(state, context, key, hash)
        })
        .count()
}

fn state_has_authority_consent_after_fork_quarantine(
    state: &FoldState,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    forked_key: &AuthorityKey,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        key != forked_key
            && folded_device_can_authority_consent(device)
            && !key_is_quarantined_for_entry(state, context, key, hash)
    })
}

fn authority_fork_from_group(
    signer: &AuthorityKey,
    seq: u64,
    group: &BTreeSet<AuthorityEntryHash>,
) -> Option<AuthorityFork> {
    let first_hash = group.iter().next().copied()?;
    let second_hash = group.iter().next_back().copied()?;
    if first_hash == second_hash {
        return None;
    };
    let forked = AuthorityFork {
        signer: signer.clone(),
        seq,
        first_hash,
        second_hash,
        status: AuthorityForkStatus::Forked,
    };
    Some(AuthorityFork {
        status: AuthorityForkStatus::Quarantined,
        ..forked
    })
}

fn resolve_global_forks_for_revoke(
    state: &mut FoldState,
    context: FoldContext<'_>,
    revoked_key: &AuthorityKey,
) {
    for (key, fork) in context.authority_forks {
        if &key.0 == revoked_key {
            state
                .authority_forks
                .entry(key.clone())
                .and_modify(|existing| existing.status = AuthorityForkStatus::Resolved)
                .or_insert_with(|| AuthorityFork {
                    status: AuthorityForkStatus::Resolved,
                    ..fork.clone()
                });
        }
    }
}

fn resolve_global_forks_for_recovery_reboot(state: &mut FoldState, context: FoldContext<'_>) {
    for (key, fork) in context.authority_forks {
        if state
            .roster
            .get(&fork.signer)
            .is_some_and(|device| device.revoked)
        {
            state
                .authority_forks
                .entry(key.clone())
                .and_modify(|existing| existing.status = AuthorityForkStatus::Resolved)
                .or_insert_with(|| AuthorityFork {
                    status: AuthorityForkStatus::Resolved,
                    ..fork.clone()
                });
        }
    }
}

fn key_is_quarantined_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    key: &AuthorityKey,
    entry_hash: AuthorityEntryHash,
) -> bool {
    state
        .authority_forks
        .values()
        .chain(context.authority_forks.values())
        .any(|fork| {
            fork.signer == *key
                && fork.status == AuthorityForkStatus::Quarantined
                && !fork_resolved_in_state(state, key, fork.seq)
                && !entry_is_prefork_or_fork_candidate(context, key, fork.seq, entry_hash)
        })
}

fn fork_resolved_in_state(state: &FoldState, key: &AuthorityKey, seq: u64) -> bool {
    state
        .authority_forks
        .get(&(key.clone(), seq))
        .is_some_and(|fork| fork.status == AuthorityForkStatus::Resolved)
}

fn entry_is_prefork_or_fork_candidate(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    if group.contains(&entry_hash) {
        return true;
    }
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    group.iter().any(|fork_hash| {
        ancestors
            .get(fork_hash)
            .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

fn entry_waits_on_unresolved_equivocation(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let signer = entry.signer_key();
    context
        .unresolved_equivocation_groups
        .iter()
        .any(|(fork_key, fork_seq)| {
            if entry_is_prefork_or_fork_candidate(context, fork_key, *fork_seq, hash) {
                return false;
            }
            (fork_key == signer && *fork_seq < entry.seq)
                || entry
                    .cosigns
                    .iter()
                    .any(|signature| signature.public_key == *fork_key)
                || matches!(&entry.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == fork_key)
        })
}

fn entry_waits_on_pending_parent_outside_group(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    group: &BTreeSet<AuthorityEntryHash>,
) -> bool {
    entry.parent_hashes.iter().any(|parent| {
        !states.contains_key(parent) && pending.contains(parent) && !group.contains(parent)
    })
}

fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>> {
    let mut index = BTreeMap::new();
    for hash in by_hash.keys().copied() {
        let mut ancestors = BTreeSet::new();
        let mut stack = by_hash[&hash].parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(hash, ancestors);
    }
    index
}

fn restore_prefix_divergence(
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> bool {
    if group.len() != 2 {
        return false;
    }
    let mut hashes = group.iter().copied();
    let left = hashes.next().expect("len checked");
    let right = hashes.next().expect("len checked");
    let Some(left_ancestors) = ancestors.get(&left) else {
        return false;
    };
    let Some(right_ancestors) = ancestors.get(&right) else {
        return false;
    };
    if left_ancestors.is_subset(right_ancestors) && left_ancestors != right_ancestors {
        return branch_divergent_suffix_has_restore_marker(
            right,
            left_ancestors,
            by_hash,
            ancestors,
        );
    }
    if right_ancestors.is_subset(left_ancestors) && right_ancestors != left_ancestors {
        return branch_divergent_suffix_has_restore_marker(
            left,
            right_ancestors,
            by_hash,
            ancestors,
        );
    }
    false
}

fn branch_divergent_suffix_has_restore_marker(
    longer_hash: AuthorityEntryHash,
    shorter_ancestors: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> bool {
    restore_marker_is_fold_admissible(longer_hash, by_hash, ancestors)
        || ancestors.get(&longer_hash).is_some_and(|branch_ancestors| {
            branch_ancestors
                .iter()
                .filter(|ancestor| !shorter_ancestors.contains(*ancestor))
                .any(|ancestor| restore_marker_is_fold_admissible(*ancestor, by_hash, ancestors))
        })
}

fn restore_marker_is_fold_admissible(
    hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> bool {
    let Some(entry) = by_hash.get(&hash) else {
        return false;
    };
    if !matches!(entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    entry_folds_on_available_ancestry(hash, by_hash, ancestors)
}

fn entry_folds_on_available_ancestry(
    target_hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> bool {
    let Some(target_ancestors) = ancestors.get(&target_hash) else {
        return false;
    };
    if target_ancestors
        .iter()
        .any(|ancestor| !by_hash.contains_key(ancestor))
    {
        return false;
    }
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending = target_ancestors.clone();
    pending.insert(target_hash);

    for _ in 0..=pending.len() {
        if states.contains_key(&target_hash) {
            return true;
        }
        let hashes: Vec<_> = pending.iter().copied().collect();
        let mut progressed = false;
        for hash in hashes {
            let Some(entry) = by_hash.get(&hash) else {
                return false;
            };
            match fold_entry_state(
                entry,
                hash,
                &states,
                FoldContext {
                    first_seen_at_secs: &first_seen_at_secs,
                    now_secs: None,
                    enforce_seen_time_delay: false,
                    vetoed_widens: &vetoed_widens,
                    authority_forks: &authority_forks,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(ancestors),
                },
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
                EntryFold::Invalid(_) => return false,
            }
        }
        if !progressed {
            return false;
        }
    }
    false
}

fn equivocation_rank_state(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    state: &FoldState,
) -> FoldState {
    let mut rank_state = state.clone();
    if rank_state.pending_widens.contains_key(&hash) {
        rank_state.pending_widens.remove(&hash);
        apply_op(&mut rank_state, &entry.op, hash, true);
    }
    rank_state
}

fn compare_fork_rank(
    (left_hash, _, left_rank): &(AuthorityEntryHash, FoldState, FoldState),
    (right_hash, _, right_rank): &(AuthorityEntryHash, FoldState, FoldState),
) -> Ordering {
    fork_rank(left_rank, *left_hash).cmp(&fork_rank(right_rank, *right_hash))
}

fn fork_rank(
    state: &FoldState,
    terminal_hash: AuthorityEntryHash,
) -> (usize, u32, u8, AuthorityEntryHash) {
    let mut active_devices = 0;
    let mut active_role_bits = 0;
    for device in state.roster.values() {
        if !device.revoked && device.roles != 0 {
            active_devices += 1;
            active_role_bits += device.roles.count_ones();
        }
    }
    let tier_floor = match state.tier_floor {
        AuthorityTier::CloudCustodial => 0,
        AuthorityTier::Hardware => 1,
        AuthorityTier::Software => 2,
    };
    (active_devices, active_role_bits, tier_floor, terminal_hash)
}

fn fold_entry_state(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
) -> EntryFold {
    if entry.validate_shape().is_err() || verify_entry_signatures(entry).is_err() {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }

    if let AuthorityOp::Genesis {
        device,
        tier_floor,
        pending_widen_delay_secs,
        ..
    } = &entry.op
    {
        if *entry.signer_key() != device.key || entry.seq != 0 {
            return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
        }
        let Ok(vault_id) = genesis_vault_id(entry) else {
            return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
        };
        let mut state = FoldState {
            vault_id,
            roster: BTreeMap::new(),
            tier_floor: *tier_floor,
            pending_widen_delay_secs: *pending_widen_delay_secs,
            pending_widens: BTreeMap::new(),
            vetoed_widens: context.vetoed_widens.clone(),
            delayed_rotation_veto_revocations: BTreeMap::new(),
            authority_forks: BTreeMap::new(),
            seqs: BTreeMap::new(),
        };
        upsert_device(&mut state, device);
        state.seqs.insert(device.key.clone(), 0);
        return EntryFold::Ready(state);
    }

    let mut parent_state: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) = states.get(parent) else {
            return EntryFold::Waiting;
        };
        if parent_state
            .as_ref()
            .is_some_and(|current| current.vault_id != state.vault_id)
        {
            return EntryFold::Invalid(AuthorityFoldIssue::WrongVault(hash));
        }
        parent_state = Some(match parent_state {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }
    let Some(mut state) = parent_state else {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidAncestry(hash));
    };

    if entry.vault_id != Some(state.vault_id) {
        return EntryFold::Invalid(AuthorityFoldIssue::WrongVault(hash));
    }
    let signer = entry.signer_key().clone();
    if entry_waits_on_unresolved_equivocation(entry, hash, context) {
        return EntryFold::Waiting;
    }
    if let AuthorityOp::VetoPendingWiden { pending_widen_hash } = &entry.op {
        if !context.vetoed_widens.contains(pending_widen_hash) {
            let Some(target_state) = states.get(pending_widen_hash) else {
                return EntryFold::Waiting;
            };
            if !target_state.pending_widens.contains_key(pending_widen_hash) {
                return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
            }
        }
        let participants =
            match veto_participant_keys(&state, entry, hash, *pending_widen_hash, context) {
                Ok(participants) => participants,
                Err(issue) => return EntryFold::Invalid(issue),
            };
        if !has_veto_authority_consent(&state, &participants, *pending_widen_hash, context) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        if let Some(prior_seq) = state.seqs.get(&signer).copied()
            && entry.seq <= prior_seq
        {
            return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
        }
        state.vetoed_widens.insert(*pending_widen_hash);
        state.pending_widens.remove(pending_widen_hash);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if context.enforce_seen_time_delay && !state.pending_widens.is_empty() {
        return EntryFold::Waiting;
    }
    if state
        .roster
        .get(&signer)
        .is_none_or(|device| device.revoked)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    let participants = match active_participant_keys(&state, entry, hash, context) {
        Ok(participants) => participants,
        Err(issue) => return EntryFold::Invalid(issue),
    };
    if !has_authority_consent(&state, &participants) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if entry_requires_peer_cosign(entry)
        && active_roster_count_for_entry(&state, context, hash) >= 2
        && participants.len() < 2
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if revoke_would_break_quorum(&state, entry, &participants, hash, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if let Some(prior_seq) = state.seqs.get(&signer).copied()
        && entry.seq <= prior_seq
    {
        return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if op_reuses_existing_device_key(&state, &entry.op) {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if context.vetoed_widens.contains(&hash)
        && op_is_delayable_widen(&state, &entry.op, &participants)
    {
        state.pending_widens.remove(&hash);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if let Some(pending_widen) =
        pending_widen_for_entry(&state, entry, hash, &participants, context)
    {
        let mut eventual_state = state.clone();
        apply_op(&mut eventual_state, &entry.op, hash, true);
        if !state_has_authority_consent_for_entry(&eventual_state, context, hash) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        state.pending_widens.insert(hash, pending_widen);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    let applied_delayed_widen =
        context.enforce_seen_time_delay && op_is_delayable_widen(&state, &entry.op, &participants);
    apply_op(&mut state, &entry.op, hash, applied_delayed_widen);
    match &entry.op {
        AuthorityOp::RevokeDevice { revoked_key } => {
            resolve_global_forks_for_revoke(&mut state, context, revoked_key);
        }
        AuthorityOp::RecoveryReboot { .. } => {
            resolve_global_forks_for_recovery_reboot(&mut state, context);
        }
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. } => {}
    }
    if !state_has_authority_consent_for_entry(&state, context, hash) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    state.seqs.insert(signer, entry.seq);
    EntryFold::Ready(state)
}

fn veto_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        let active_member = state
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles != 0);
        if key_is_quarantined_for_entry(state, context, key, hash)
            || (!active_member
                && !delayed_rotation_veto_allowed(state, key, pending_widen_hash, context))
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
}

fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
            || key_is_quarantined_for_entry(state, context, key, hash)
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
}

fn has_authority_consent(state: &FoldState, participants: &BTreeSet<AuthorityKey>) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(folded_device_can_authority_consent)
    })
}

fn has_veto_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(folded_device_can_owner_veto)
            || delayed_rotation_veto_allowed(state, key, pending_widen_hash, context)
    })
}

fn delayed_rotation_veto_allowed(
    state: &FoldState,
    key: &AuthorityKey,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let Some(revocations) = state.delayed_rotation_veto_revocations.get(key) else {
        return false;
    };
    let Some(entry_ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(target_ancestors) = entry_ancestors.get(&pending_widen_hash) else {
        return false;
    };

    revocations
        .iter()
        .all(|revocation| !target_ancestors.contains(revocation))
}

fn state_has_authority_consent_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        folded_device_can_authority_consent(device)
            && !key_is_quarantined_for_entry(state, context, key, hash)
    })
}

fn folded_device_can_authority_consent(device: &FoldedDevice) -> bool {
    !device.revoked
        && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
        && (device.roles & ROLE_CLOUD) == 0
        && device.tier != AuthorityTier::CloudCustodial
}

fn folded_device_can_owner_veto(device: &FoldedDevice) -> bool {
    !device.revoked
        && (device.roles & ROLE_OWNER) != 0
        && (device.roles & ROLE_CLOUD) == 0
        && device.tier != AuthorityTier::CloudCustodial
}

fn pending_widen_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> Option<AuthorityPendingWiden> {
    if !context.enforce_seen_time_delay || !op_is_delayable_widen(state, &entry.op, participants) {
        return None;
    }

    let first_seen_at_secs = context.first_seen_at_secs.get(&hash).copied();
    let eligible_at_secs =
        first_seen_at_secs.and_then(|seen_at| seen_at.checked_add(state.pending_widen_delay_secs));
    if let (Some(now_secs), Some(eligible_at_secs)) = (context.now_secs, eligible_at_secs)
        && now_secs >= eligible_at_secs
    {
        return None;
    }

    Some(AuthorityPendingWiden {
        entry_hash: hash,
        first_seen_at_secs,
        eligible_at_secs,
        delay_secs: state.pending_widen_delay_secs,
    })
}

fn op_has_instant_widen_authority(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    if matches!(op, AuthorityOp::RecoveryReboot { .. }) {
        return true;
    }
    participants.iter().any(|key| {
        state.roster.get(key).is_some_and(|device| {
            folded_device_can_authority_consent(device) && device.tier == AuthorityTier::Hardware
        })
    })
}

fn op_is_delayable_widen(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    op_can_be_pending_widen(state, op) && !op_has_instant_widen_authority(state, op, participants)
}

fn op_can_be_pending_widen(state: &FoldState, op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device } => state
            .roster
            .get(&device.key)
            .is_none_or(|folded| folded.revoked),
        AuthorityOp::RotateKey { .. } => true,
        AuthorityOp::SetTierFloor { tier_floor } => *tier_floor < state.tier_floor,
        AuthorityOp::RecoveryReboot { .. } => true,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. } => false,
    }
}

fn op_reuses_existing_device_key(state: &FoldState, op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::RecoveryReboot {
            new_device: device, ..
        } => state.roster.contains_key(&device.key),
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. } => false,
    }
}

fn entry_requires_peer_cosign(entry: &AuthorityLogEntry) -> bool {
    !matches!(
        entry.op,
        AuthorityOp::Genesis { .. } | AuthorityOp::VetoPendingWiden { .. }
    )
}

fn revoke_would_break_quorum(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    participants: &BTreeSet<AuthorityKey>,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
        return false;
    };
    let active_before = active_roster_count_for_entry(state, context, hash);
    let revoked_was_active = state.roster.get(revoked_key).is_some_and(|device| {
        !device.revoked
            && device.roles != 0
            && !key_is_quarantined_for_entry(state, context, revoked_key, hash)
    });
    let active_after = active_before.saturating_sub(usize::from(revoked_was_active));
    participants.len() < 2 || active_after < 2
}

fn active_roster_count_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            !device.revoked
                && device.roles != 0
                && !key_is_quarantined_for_entry(state, context, key, hash)
        })
        .count()
}

fn merge_states(left: &FoldState, right: &FoldState) -> FoldState {
    debug_assert_eq!(left.vault_id, right.vault_id);
    let mut merged = left.clone();
    merged.tier_floor = most_restrictive_tier_floor(left.tier_floor, right.tier_floor);
    merged.pending_widen_delay_secs = left
        .pending_widen_delay_secs
        .max(right.pending_widen_delay_secs);
    merged.pending_widens.extend(
        right
            .pending_widens
            .iter()
            .map(|(hash, pending)| (*hash, pending.clone())),
    );
    merged
        .vetoed_widens
        .extend(right.vetoed_widens.iter().copied());
    for (key, revocations) in &right.delayed_rotation_veto_revocations {
        merged
            .delayed_rotation_veto_revocations
            .entry(key.clone())
            .or_default()
            .extend(revocations.iter().copied());
    }
    for (key, fork) in &right.authority_forks {
        merged
            .authority_forks
            .entry(key.clone())
            .and_modify(|existing| {
                if fork.status == AuthorityForkStatus::Resolved {
                    existing.status = AuthorityForkStatus::Resolved;
                }
            })
            .or_insert_with(|| fork.clone());
    }
    for vetoed in &merged.vetoed_widens {
        merged.pending_widens.remove(vetoed);
    }
    for (key, device) in &right.roster {
        match merged.roster.get_mut(key) {
            Some(existing) => {
                existing.revoked |= device.revoked;
                existing.roles &= device.roles;
                existing.tier = most_restrictive_device_tier(existing.tier, device.tier);
            }
            None => {
                merged.roster.insert(key.clone(), device.clone());
            }
        }
    }
    for (key, seq) in &right.seqs {
        merged
            .seqs
            .entry(key.clone())
            .and_modify(|current| *current = (*current).max(*seq))
            .or_insert(*seq);
    }
    merged
}

fn apply_op(
    state: &mut FoldState,
    op: &AuthorityOp,
    entry_hash: AuthorityEntryHash,
    applied_delayed_widen: bool,
) {
    match op {
        AuthorityOp::Genesis { .. } => {}
        AuthorityOp::EnrollDevice { device } => upsert_device(state, device),
        AuthorityOp::RevokeDevice { revoked_key } => {
            revoke_key(state, revoked_key);
            for fork in state.authority_forks.values_mut() {
                if fork.signer == *revoked_key && fork.status == AuthorityForkStatus::Quarantined {
                    fork.status = AuthorityForkStatus::Resolved;
                }
            }
        }
        AuthorityOp::SetCeiling { .. } | AuthorityOp::FederationConfirm(_) => {}
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => {
            // Vetoes signed during a delayed rotation can be parented after the
            // pending rotation entry; keep the old key as veto-only authority
            // once that delayed rotation lands and revokes it.
            if applied_delayed_widen
                && state
                    .roster
                    .get(old_key)
                    .is_some_and(folded_device_can_owner_veto)
            {
                state
                    .delayed_rotation_veto_revocations
                    .entry(old_key.clone())
                    .or_default()
                    .insert(entry_hash);
            }
            revoke_key(state, old_key);
            upsert_device(state, new_device);
        }
        AuthorityOp::SetTierFloor { tier_floor } => {
            state.tier_floor = most_restrictive_tier_floor(state.tier_floor, *tier_floor);
        }
        AuthorityOp::RecoveryReboot {
            new_device,
            tier_floor,
            ..
        } => {
            let revoked_keys: BTreeSet<_> = state.roster.keys().cloned().collect();
            for device in state.roster.values_mut() {
                device.revoked = true;
            }
            state.tier_floor = most_restrictive_tier_floor(state.tier_floor, *tier_floor);
            upsert_device(state, new_device);
            for fork in state.authority_forks.values_mut() {
                if fork.status == AuthorityForkStatus::Quarantined
                    && revoked_keys.contains(&fork.signer)
                {
                    fork.status = AuthorityForkStatus::Resolved;
                }
            }
        }
        AuthorityOp::VetoPendingWiden { .. } => {}
    }
}

fn upsert_device(state: &mut FoldState, device: &DeviceAuthority) {
    let folded = FoldedDevice {
        key: device.key.clone(),
        tier: device.tier,
        roles: device.roles,
        revoked: false,
    };
    match state.roster.get_mut(&device.key) {
        Some(existing) => {
            if !existing.revoked {
                existing.roles &= folded.roles;
                existing.tier = most_restrictive_device_tier(existing.tier, folded.tier);
            }
        }
        None => {
            state.roster.insert(device.key.clone(), folded);
        }
    }
}

fn revoke_key(state: &mut FoldState, key: &AuthorityKey) {
    state
        .roster
        .entry(key.clone())
        .and_modify(|device| device.revoked = true)
        .or_insert(FoldedDevice {
            key: key.clone(),
            tier: AuthorityTier::Software,
            roles: 0,
            revoked: true,
        });
}

fn most_restrictive_device_tier(left: AuthorityTier, right: AuthorityTier) -> AuthorityTier {
    left.min(right)
}

fn most_restrictive_tier_floor(left: AuthorityTier, right: AuthorityTier) -> AuthorityTier {
    left.max(right)
}

fn verify_entry_signatures(entry: &AuthorityLogEntry) -> Result<()> {
    if verify_entry_signatures_current(entry).is_ok()
        || verify_entry_signatures_legacy_genesis(entry).is_ok()
    {
        return Ok(());
    }
    Err(invalid_authority())
}

fn verify_entry_signatures_current(entry: &AuthorityLogEntry) -> Result<()> {
    let transcript = authority_transcript(entry)?;
    if verify_entry_signatures_with_transcript(entry, &transcript) {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}

fn verify_entry_signatures_legacy_genesis(entry: &AuthorityLogEntry) -> Result<()> {
    if !legacy_genesis_encoding_candidate(entry) {
        return Err(invalid_authority());
    }
    let transcript = authority_transcript_with_genesis_delay(entry, false)?;
    if verify_entry_signatures_with_transcript(entry, &transcript) {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}

fn verify_entry_signatures_with_transcript(entry: &AuthorityLogEntry, transcript: &[u8]) -> bool {
    verify_authority_signature(&entry.signer, transcript)
        && entry
            .cosigns
            .iter()
            .all(|cosign| verify_authority_signature(cosign, transcript))
}

fn validate_op(op: &AuthorityOp) -> Result<()> {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            pending_widen_delay_secs,
            ..
        } => {
            if genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            validate_pending_widen_delay_secs(*pending_widen_delay_secs)?;
            device.validate()?;
            if !device.can_authority_consent() {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::EnrollDevice { device } => device.validate(),
        AuthorityOp::RevokeDevice { revoked_key } => revoked_key.validate(),
        AuthorityOp::SetCeiling {
            authority_key,
            actor_class,
            ..
        } => {
            if actor_class.is_empty() || actor_class.len() > MAX_ACTOR_CLASS_BYTES {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => {
            old_key.validate()?;
            new_device.validate()?;
            if old_key == &new_device.key {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::SetTierFloor { .. } | AuthorityOp::FederationConfirm(_) => Ok(()),
        AuthorityOp::RecoveryReboot {
            new_genesis_nonce,
            new_device,
            ..
        } => {
            if new_genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            new_device.validate()?;
            if !new_device.can_authority_consent() {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::VetoPendingWiden { pending_widen_hash } => {
            if pending_widen_hash.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            Ok(())
        }
    }
}

fn validate_pending_widen_delay_secs(delay_secs: u64) -> Result<()> {
    if (MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS..=MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS)
        .contains(&delay_secs)
    {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}

fn entry_value(entry: &AuthorityLogEntry, include_signatures: bool) -> Value {
    entry_value_with_genesis_delay(entry, include_signatures, true)
}

fn entry_value_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_signatures: bool,
    include_genesis_delay: bool,
) -> Value {
    let mut fields = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(entry.schema_version),
        ),
        (Value::from(KEY_VAULT_ID), option_hash_value(entry.vault_id)),
        (Value::from(KEY_SEQ), Value::from(entry.seq)),
        (
            Value::from(KEY_PARENT_HASHES),
            Value::Array(
                sorted_hashes(&entry.parent_hashes)
                    .into_iter()
                    .map(binary_value)
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_OP),
            op_value_with_genesis_delay(&entry.op, include_genesis_delay),
        ),
    ];
    if include_signatures {
        fields.push((Value::from(KEY_SIGNER), signature_value(&entry.signer)));
        fields.push((
            Value::from(KEY_COSIGNS),
            Value::Array(entry.cosigns.iter().map(signature_value).collect()),
        ));
    }
    fields.push((Value::from(KEY_TS), Value::from(entry.ts)));
    Value::Map(fields)
}

fn op_value_with_genesis_delay(op: &AuthorityOp, include_genesis_delay: bool) -> Value {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            tier_floor,
            pending_widen_delay_secs,
        } => {
            let mut fields = vec![
                (Value::from(OP_KEY_KIND), Value::from(OP_KIND_GENESIS)),
                (Value::from("device"), device_value(device)),
                (Value::from("genesis_nonce"), binary_value(*genesis_nonce)),
                (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
            ];
            if include_genesis_delay {
                fields.push((
                    Value::from("pending_widen_delay_secs"),
                    Value::from(*pending_widen_delay_secs),
                ));
            }
            Value::Map(fields)
        }
        AuthorityOp::EnrollDevice { device } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ENROLL_DEVICE)),
            (Value::from("device"), device_value(device)),
        ]),
        AuthorityOp::RevokeDevice { revoked_key } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_REVOKE_DEVICE)),
            (Value::from("revoked_key"), key_value(revoked_key)),
        ]),
        AuthorityOp::SetCeiling {
            authority_key,
            actor_class,
            ceiling,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_SET_CEILING)),
            (Value::from("authority_key"), key_value(authority_key)),
            (
                Value::from("actor_class"),
                Value::from(actor_class.as_str()),
            ),
            (Value::from("ceiling"), Value::from(*ceiling)),
        ]),
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ROTATE_KEY)),
            (Value::from("old_key"), key_value(old_key)),
            (Value::from("new_device"), device_value(new_device)),
        ]),
        AuthorityOp::SetTierFloor { tier_floor } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_SET_TIER_FLOOR),
            ),
            (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
        ]),
        AuthorityOp::RecoveryReboot {
            new_genesis_nonce,
            new_device,
            tier_floor,
        } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_RECOVERY_REBOOT),
            ),
            (
                Value::from("new_genesis_nonce"),
                binary_value(*new_genesis_nonce),
            ),
            (Value::from("new_device"), device_value(new_device)),
            (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
        ]),
        AuthorityOp::FederationConfirm(action) => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_FEDERATION_CONFIRM),
            ),
            (
                Value::from("confirm_kind"),
                Value::from(action.kind.as_str()),
            ),
            (Value::from("confirm_id"), binary_value(action.confirm_id)),
            (
                Value::from("peer_vault_id"),
                binary_value(action.peer_vault_id),
            ),
            (Value::from("epoch"), Value::from(action.epoch)),
            (Value::from("nonce"), binary_value_16(action.nonce)),
        ]),
        AuthorityOp::VetoPendingWiden { pending_widen_hash } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_VETO_PENDING_WIDEN),
            ),
            (
                Value::from("pending_widen_hash"),
                binary_value(*pending_widen_hash),
            ),
        ]),
    }
}

fn legacy_genesis_encoding_candidate(entry: &AuthorityLogEntry) -> bool {
    matches!(
        &entry.op,
        AuthorityOp::Genesis {
            pending_widen_delay_secs,
            ..
        } if *pending_widen_delay_secs == DEFAULT_PENDING_WIDEN_DELAY_SECS
    )
}

fn legacy_genesis_signed_entry_bytes(entry: &AuthorityLogEntry) -> Result<Option<Vec<u8>>> {
    if legacy_genesis_encoding_candidate(entry) {
        encode_value(&entry_value_with_genesis_delay(entry, true, false)).map(Some)
    } else {
        Ok(None)
    }
}

fn device_value(device: &DeviceAuthority) -> Value {
    Value::Map(vec![
        (Value::from("key"), key_value(&device.key)),
        (
            Value::from("transport_key_binding"),
            binary_value(device.transport_key_binding),
        ),
        (
            Value::from("attestation"),
            attestation_value(&device.attestation),
        ),
        (Value::from("tier"), Value::from(device.tier.as_str())),
        (Value::from("roles"), Value::from(u64::from(device.roles))),
    ])
}

fn key_value(key: &AuthorityKey) -> Value {
    match key {
        AuthorityKey::Ed25519(bytes) => Value::Map(vec![
            (Value::from(KEY_SUITE), Value::from("ed25519")),
            (Value::from(KEY_PUBLIC_KEY), binary_value(*bytes)),
        ]),
        AuthorityKey::P256(bytes) => Value::Map(vec![
            (Value::from(KEY_SUITE), Value::from("p256")),
            (Value::from(KEY_PUBLIC_KEY), Value::Binary(bytes.clone())),
        ]),
    }
}

fn signature_value(signature: &AuthoritySignature) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SUITE),
            Value::from(signature.suite.as_str()),
        ),
        (
            Value::from(KEY_PUBLIC_KEY),
            key_bytes_value(&signature.public_key),
        ),
        (
            Value::from(KEY_SIGNATURE),
            Value::Binary(signature.signature.clone()),
        ),
    ])
}

fn key_bytes_value(key: &AuthorityKey) -> Value {
    match key {
        AuthorityKey::Ed25519(bytes) => binary_value(*bytes),
        AuthorityKey::P256(bytes) => Value::Binary(bytes.clone()),
    }
}

fn attestation_value(attestation: &AuthorityAttestation) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_ATTEST_KIND),
            Value::from(attestation.kind.as_str()),
        ),
        (
            Value::from(KEY_ATTEST_EVIDENCE),
            Value::Binary(attestation.evidence.clone()),
        ),
    ])
}

fn option_hash_value(value: Option<[u8; 32]>) -> Value {
    value.map_or(Value::Nil, binary_value)
}

fn binary_value(value: [u8; 32]) -> Value {
    Value::Binary(value.to_vec())
}

fn binary_value_16(value: [u8; 16]) -> Value {
    Value::Binary(value.to_vec())
}

fn sorted_hashes(values: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("authority log body MessagePack encode failed"))?;
    Ok(out)
}

fn decode_entry_value(value: &Value) -> Result<AuthorityLogEntry> {
    let entries = map_entries(value)?;
    validate_keys(entries, &AUTHORITY_ENTRY_KEYS)?;
    let schema_version = required(entries, KEY_SCHEMA_VERSION)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let vault_id = decode_optional_hash(required(entries, KEY_VAULT_ID)?)?;
    let seq = required(entries, KEY_SEQ)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let parent_hashes = decode_hash_array(required(entries, KEY_PARENT_HASHES)?)?;
    let op = decode_op(required(entries, KEY_OP)?)?;
    let signer = decode_signature(required(entries, KEY_SIGNER)?)?;
    let cosigns = decode_signature_array(required(entries, KEY_COSIGNS)?)?;
    let ts = required(entries, KEY_TS)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    Ok(AuthorityLogEntry {
        schema_version,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer,
        cosigns,
        ts,
    })
}

fn decode_op(value: &Value) -> Result<AuthorityOp> {
    let entries = map_entries(value)?;
    let kind = required(entries, OP_KEY_KIND)?
        .as_str()
        .ok_or_else(invalid_authority)?;
    match kind {
        OP_KIND_GENESIS => {
            let pending_widen_delay = optional(entries, "pending_widen_delay_secs");
            if pending_widen_delay.is_some() {
                validate_keys(
                    entries,
                    &[
                        OP_KEY_KIND,
                        "device",
                        "genesis_nonce",
                        "tier_floor",
                        "pending_widen_delay_secs",
                    ],
                )?;
            } else {
                validate_keys(
                    entries,
                    &[OP_KEY_KIND, "device", "genesis_nonce", "tier_floor"],
                )?;
            }
            Ok(AuthorityOp::Genesis {
                device: decode_device(required(entries, "device")?)?,
                genesis_nonce: decode_hash(required(entries, "genesis_nonce")?)?,
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
                pending_widen_delay_secs: pending_widen_delay
                    .map(|value| value.as_u64().ok_or_else(invalid_authority))
                    .transpose()?
                    .unwrap_or(DEFAULT_PENDING_WIDEN_DELAY_SECS),
            })
        }
        OP_KIND_ENROLL_DEVICE => {
            validate_keys(entries, &[OP_KEY_KIND, "device"])?;
            Ok(AuthorityOp::EnrollDevice {
                device: decode_device(required(entries, "device")?)?,
            })
        }
        OP_KIND_REVOKE_DEVICE => {
            validate_keys(entries, &[OP_KEY_KIND, "revoked_key"])?;
            Ok(AuthorityOp::RevokeDevice {
                revoked_key: decode_key(required(entries, "revoked_key")?)?,
            })
        }
        OP_KIND_SET_CEILING => {
            validate_keys(
                entries,
                &[OP_KEY_KIND, "authority_key", "actor_class", "ceiling"],
            )?;
            let ceiling_u64 = required(entries, "ceiling")?
                .as_u64()
                .ok_or_else(invalid_authority)?;
            let ceiling = u8::try_from(ceiling_u64).map_err(|_| invalid_authority())?;
            Ok(AuthorityOp::SetCeiling {
                authority_key: decode_key(required(entries, "authority_key")?)?,
                actor_class: required(entries, "actor_class")?
                    .as_str()
                    .ok_or_else(invalid_authority)?
                    .to_owned(),
                ceiling,
            })
        }
        OP_KIND_ROTATE_KEY => {
            validate_keys(entries, &[OP_KEY_KIND, "old_key", "new_device"])?;
            Ok(AuthorityOp::RotateKey {
                old_key: decode_key(required(entries, "old_key")?)?,
                new_device: decode_device(required(entries, "new_device")?)?,
            })
        }
        OP_KIND_SET_TIER_FLOOR => {
            validate_keys(entries, &[OP_KEY_KIND, "tier_floor"])?;
            Ok(AuthorityOp::SetTierFloor {
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
            })
        }
        OP_KIND_RECOVERY_REBOOT => {
            validate_keys(
                entries,
                &[OP_KEY_KIND, "new_genesis_nonce", "new_device", "tier_floor"],
            )?;
            Ok(AuthorityOp::RecoveryReboot {
                new_genesis_nonce: decode_hash(required(entries, "new_genesis_nonce")?)?,
                new_device: decode_device(required(entries, "new_device")?)?,
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
            })
        }
        OP_KIND_FEDERATION_CONFIRM => {
            validate_keys(
                entries,
                &[
                    OP_KEY_KIND,
                    "confirm_kind",
                    "confirm_id",
                    "peer_vault_id",
                    "epoch",
                    "nonce",
                ],
            )?;
            let confirm_kind = required(entries, "confirm_kind")?
                .as_str()
                .and_then(AuthorityConfirmKind::parse)
                .ok_or_else(invalid_authority)?;
            Ok(AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: confirm_kind,
                confirm_id: decode_hash(required(entries, "confirm_id")?)?,
                peer_vault_id: decode_hash(required(entries, "peer_vault_id")?)?,
                epoch: required(entries, "epoch")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                nonce: decode_16(required(entries, "nonce")?)?,
            }))
        }
        OP_KIND_VETO_PENDING_WIDEN => {
            validate_keys(entries, &[OP_KEY_KIND, "pending_widen_hash"])?;
            Ok(AuthorityOp::VetoPendingWiden {
                pending_widen_hash: decode_hash(required(entries, "pending_widen_hash")?)?,
            })
        }
        _ => Err(invalid_authority()),
    }
}

fn decode_device(value: &Value) -> Result<DeviceAuthority> {
    let entries = map_entries(value)?;
    validate_keys(
        entries,
        &[
            "key",
            "transport_key_binding",
            "attestation",
            "tier",
            "roles",
        ],
    )?;
    let roles_u64 = required(entries, "roles")?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let roles = u16::try_from(roles_u64).map_err(|_| invalid_authority())?;
    Ok(DeviceAuthority {
        key: decode_key(required(entries, "key")?)?,
        transport_key_binding: decode_hash(required(entries, "transport_key_binding")?)?,
        attestation: decode_attestation(required(entries, "attestation")?)?,
        tier: decode_tier(required(entries, "tier")?)?,
        roles,
    })
}

fn decode_key(value: &Value) -> Result<AuthorityKey> {
    let entries = map_entries(value)?;
    validate_keys(entries, &[KEY_SUITE, KEY_PUBLIC_KEY])?;
    let suite = required(entries, KEY_SUITE)?
        .as_str()
        .and_then(AuthoritySignatureSuite::parse)
        .ok_or_else(invalid_authority)?;
    let raw = bytes(required(entries, KEY_PUBLIC_KEY)?)?;
    match suite {
        AuthoritySignatureSuite::Ed25519 => Ok(AuthorityKey::Ed25519(
            raw.try_into().map_err(|_| invalid_authority())?,
        )),
        AuthoritySignatureSuite::P256 => Ok(AuthorityKey::P256(canonical_p256_key_bytes(raw)?)),
    }
}

fn decode_signature(value: &Value) -> Result<AuthoritySignature> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SIGNATURE_KEYS)?;
    let suite = required(entries, KEY_SUITE)?
        .as_str()
        .and_then(AuthoritySignatureSuite::parse)
        .ok_or_else(invalid_authority)?;
    let raw_key = bytes(required(entries, KEY_PUBLIC_KEY)?)?;
    let public_key = match suite {
        AuthoritySignatureSuite::Ed25519 => {
            AuthorityKey::Ed25519(raw_key.try_into().map_err(|_| invalid_authority())?)
        }
        AuthoritySignatureSuite::P256 => AuthorityKey::P256(canonical_p256_key_bytes(raw_key)?),
    };
    Ok(AuthoritySignature {
        suite,
        public_key,
        signature: bytes(required(entries, KEY_SIGNATURE)?)?.to_vec(),
    })
}

fn decode_signature_array(value: &Value) -> Result<Vec<AuthoritySignature>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    values.iter().map(decode_signature).collect()
}

fn decode_attestation(value: &Value) -> Result<AuthorityAttestation> {
    let entries = map_entries(value)?;
    validate_keys(entries, &ATTESTATION_KEYS)?;
    Ok(AuthorityAttestation {
        kind: required(entries, KEY_ATTEST_KIND)?
            .as_str()
            .ok_or_else(invalid_authority)?
            .to_owned(),
        evidence: bytes(required(entries, KEY_ATTEST_EVIDENCE)?)?.to_vec(),
    })
}

fn decode_tier(value: &Value) -> Result<AuthorityTier> {
    value
        .as_str()
        .and_then(AuthorityTier::parse)
        .ok_or_else(invalid_authority)
}

fn decode_optional_hash(value: &Value) -> Result<Option<[u8; 32]>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_hash(value).map(Some)
    }
}

fn decode_hash_array(value: &Value) -> Result<Vec<[u8; 32]>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    values.iter().map(decode_hash).collect()
}

fn decode_hash(value: &Value) -> Result<[u8; 32]> {
    bytes(value)?.try_into().map_err(|_| invalid_authority())
}

fn decode_16(value: &Value) -> Result<[u8; 16]> {
    bytes(value)?.try_into().map_err(|_| invalid_authority())
}

fn map_entries(value: &Value) -> Result<&[(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_authority());
    };
    Ok(entries)
}

fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    let mut seen = vec![false; expected.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_authority)?;
        let Some(index) = expected.iter().position(|known| *known == key) else {
            return Err(invalid_authority());
        };
        if seen[index] {
            return Err(invalid_authority());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}

fn required<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
        .ok_or_else(invalid_authority)
}

fn optional<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

fn bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Binary(bytes) => Ok(bytes),
        _ => Err(invalid_authority()),
    }
}

fn invalid_authority() -> Error {
    Error::InvalidAuthorityLogBody("body failed validation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn ed_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn authority_key_from_ed(key: &SigningKey) -> AuthorityKey {
        AuthorityKey::Ed25519(key.verifying_key().to_bytes())
    }

    fn p256_key(seed: u8) -> P256SigningKey {
        let mut rng = StdRng::from_seed([seed; 32]);
        P256SigningKey::random(&mut rng)
    }

    fn authority_key_from_p256(key: &P256SigningKey) -> AuthorityKey {
        let point = key.verifying_key().to_encoded_point(true);
        AuthorityKey::P256(point.as_bytes().to_vec())
    }

    fn attestation(kind: &str) -> AuthorityAttestation {
        AuthorityAttestation {
            kind: kind.to_owned(),
            evidence: vec![1, 2, 3],
        }
    }

    fn device(key: AuthorityKey, roles: u16, tier: AuthorityTier) -> DeviceAuthority {
        DeviceAuthority {
            key,
            transport_key_binding: [7; 32],
            attestation: attestation("SoftwareArgon2id"),
            tier,
            roles,
        }
    }

    fn unsigned_entry(
        vault_id: Option<AuthorityVaultId>,
        seq: u64,
        parent_hashes: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
        signer_key: AuthorityKey,
        ts: u64,
    ) -> AuthorityLogEntry {
        AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id,
            seq,
            parent_hashes,
            op,
            signer: AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts,
        }
    }

    fn sign_ed(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
        let transcript = authority_transcript(&entry).unwrap();
        entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
        entry
    }

    fn sign_ed_legacy_genesis(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
        let transcript = authority_transcript_with_genesis_delay(&entry, false).unwrap();
        entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
        entry
    }

    fn sign_p256(mut entry: AuthorityLogEntry, key: &P256SigningKey) -> AuthorityLogEntry {
        let transcript = authority_transcript(&entry).unwrap();
        let mut signature: P256Signature = key.sign(&transcript);
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }
        entry.signer.signature = signature.to_bytes().to_vec();
        entry
    }

    fn cosign_ed(
        mut entry: AuthorityLogEntry,
        signer: &SigningKey,
        cosigner: &SigningKey,
    ) -> AuthorityLogEntry {
        let cosigner_key = authority_key_from_ed(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner_key.suite(),
            public_key: cosigner_key,
            signature: vec![0; 64],
        });
        entry.cosigns.sort_by(|left, right| {
            left.public_key
                .cmp(&right.public_key)
                .then_with(|| left.signature.cmp(&right.signature))
        });
        let transcript = authority_transcript(&entry).unwrap();
        entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
        let cosigner_key = authority_key_from_ed(cosigner);
        for cosign in &mut entry.cosigns {
            if cosign.public_key == cosigner_key {
                cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
            }
        }
        entry
    }

    fn genesis_entry(seed: u8, pending_widen_delay_secs: u64, ts: u64) -> AuthorityLogEntry {
        let signing = ed_key(seed);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::Genesis {
            device: device(
                key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs,
        };
        sign_ed(unsigned_entry(None, 0, Vec::new(), op, key, ts), &signing)
    }

    struct EnrollSpec {
        seed: u8,
        roles: u16,
        tier: AuthorityTier,
        seq: u64,
        ts: u64,
    }

    fn enroll_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        new_key_seed: u8,
        seq: u64,
        ts: u64,
    ) -> AuthorityLogEntry {
        enroll_device_entry(
            vault_id,
            parent,
            signer,
            EnrollSpec {
                seed: new_key_seed,
                roles: ROLE_AGENT | ROLE_CLOUD,
                tier: AuthorityTier::Software,
                seq,
                ts,
            },
        )
    }

    fn enroll_device_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        spec: EnrollSpec,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        let new = ed_key(spec.seed);
        let op = AuthorityOp::EnrollDevice {
            device: device(authority_key_from_ed(&new), spec.roles, spec.tier),
        };
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                spec.seq,
                vec![authority_entry_hash(parent).unwrap()],
                op,
                signer_key,
                spec.ts,
            ),
            signer,
        )
    }

    fn revoke_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        revoked: AuthorityKey,
        seq: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::RevokeDevice {
                    revoked_key: revoked,
                },
                signer_key,
                777,
            ),
            signer,
        )
    }

    fn set_tier_floor_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        seq: u64,
        tier_floor: AuthorityTier,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::SetTierFloor { tier_floor },
                signer_key,
                888,
            ),
            signer,
        )
    }

    fn set_ceiling_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        seq: u64,
        ts: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::SetCeiling {
                    authority_key: signer_key.clone(),
                    actor_class: "agent".to_string(),
                    ceiling: 1,
                },
                signer_key,
                ts,
            ),
            signer,
        )
    }

    fn rotate_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        old_key: AuthorityKey,
        new_seed: u8,
        seq: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        let new = ed_key(new_seed);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::RotateKey {
                    old_key,
                    new_device: device(
                        authority_key_from_ed(&new),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                },
                signer_key,
                889,
            ),
            signer,
        )
    }

    fn recovery_reboot_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        new_seed: u8,
        seq: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        let new = ed_key(new_seed);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::RecoveryReboot {
                    new_genesis_nonce: [new_seed; 32],
                    new_device: device(
                        authority_key_from_ed(&new),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                    tier_floor: AuthorityTier::Software,
                },
                signer_key,
                890,
            ),
            signer,
        )
    }

    fn veto_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        pending_widen_hash: AuthorityEntryHash,
        seq: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                AuthorityOp::VetoPendingWiden { pending_widen_hash },
                signer_key,
                999,
            ),
            signer,
        )
    }

    fn fold_entry_state_for_test(
        entry: &AuthorityLogEntry,
        hash: AuthorityEntryHash,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) -> EntryFold {
        let first_seen_at_secs = BTreeMap::new();
        let vetoed_widens = BTreeSet::new();
        let authority_forks = BTreeMap::new();
        let equivocation_groups = BTreeMap::new();
        let unresolved_equivocation_groups = BTreeSet::new();
        fold_entry_state(
            entry,
            hash,
            states,
            FoldContext {
                first_seen_at_secs: &first_seen_at_secs,
                now_secs: None,
                enforce_seen_time_delay: false,
                vetoed_widens: &vetoed_widens,
                authority_forks: &authority_forks,
                equivocation_groups: &equivocation_groups,
                unresolved_equivocation_groups: &unresolved_equivocation_groups,
                entry_ancestors: None,
            },
        )
    }

    #[test]
    fn authority_genesis_golden_vector_is_canonical() {
        let genesis = genesis_entry(1, 86_400, 123);
        let encoded = encode_authority_log_entry_body(&genesis).unwrap();
        let vault_id = genesis_vault_id(&genesis).unwrap();

        assert_eq!(
            hex(&encoded),
            "88ae736368656d615f76657273696f6e01a87661756c745f6964c0a373657100ad706172656e745f68617368657390a26f7085a46b696e64a767656e65736973a664657669636585a36b657982a57375697465a765643235353139aa7075626c69635f6b6579c4208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cb57472616e73706f72745f6b65795f62696e64696e67c4200707070707070707070707070707070707070707070707070707070707070707ab6174746573746174696f6e82a46b696e64b0536f6674776172654172676f6e326964a865766964656e6365c403010203a474696572a8736f667477617265a5726f6c657303ad67656e657369735f6e6f6e6365c4200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0baa746965725f666c6f6f72a8736f667477617265b870656e64696e675f776964656e5f64656c61795f73656373ce00015180a67369676e657283a57375697465a765643235353139aa7075626c69635f6b6579c4208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5ca97369676e6174757265c4408131cde03c78cec247140fe8fc1c3b97b4bce2f52ea4564e15a459badddbe8e0f204047d0e2dbc2cad8490ca48eb8488f842dc4b49b13fd59f5bdb6f75f45e0ba7636f7369676e7390a274737b"
        );
        assert_eq!(
            hex(&vault_id),
            "c9328f916e5290288757fc622aba9f87f7226d33590ac6652f1c7c7ad7f0dc12"
        );
        assert_eq!(decode_authority_log_entry_body(&encoded).unwrap(), genesis);
    }

    #[test]
    fn legacy_genesis_without_pending_delay_decodes_with_default_and_old_hash() {
        let signing = ed_key(79);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::Genesis {
            device: device(
                key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
            genesis_nonce: [79; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        };
        let legacy =
            sign_ed_legacy_genesis(unsigned_entry(None, 0, Vec::new(), op, key, 1), &signing);
        let legacy_encoded =
            encode_value(&entry_value_with_genesis_delay(&legacy, true, false)).unwrap();
        let current_encoded = encode_authority_log_entry_body(&legacy).unwrap();
        let legacy_hash = *blake3::hash(&legacy_encoded).as_bytes();

        assert_ne!(legacy_encoded, current_encoded);
        let decoded = decode_authority_log_entry_body(&legacy_encoded).unwrap();
        assert_eq!(decoded, legacy);
        assert_eq!(
            authority_entry_hash(&decoded).unwrap(),
            legacy_hash,
            "legacy genesis hash must stay tied to the legacy signed bytes"
        );
        assert_eq!(genesis_vault_id(&decoded).unwrap(), legacy_hash);
    }

    #[test]
    fn genesis_rejects_pending_widen_delay_outside_ceremony_band() {
        let signing = ed_key(80);
        let key = authority_key_from_ed(&signing);
        for pending_widen_delay_secs in [
            0,
            MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS - 1,
            MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS + 1,
        ] {
            let op = AuthorityOp::Genesis {
                device: device(key.clone(), ROLE_OWNER, AuthorityTier::Software),
                genesis_nonce: [80; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs,
            };
            let entry = unsigned_entry(None, 0, Vec::new(), op, key.clone(), 1);
            assert!(
                encode_authority_log_entry_body(&entry).is_err(),
                "delay {pending_widen_delay_secs} must be rejected"
            );
        }
    }

    #[test]
    fn persisted_seen_time_ignores_forward_wall_clock_jumps_after_first_observation() {
        let domain = 0x1325_0001;
        let first = authority_observation_secs_for_domain(domain, 0, 1_000);
        let jumped = authority_observation_secs_for_domain(domain, first, 1_000_000);

        assert_eq!(first, 1_000);
        assert_eq!(
            jumped, first,
            "wall-clock jumps after first observation must not skip the local delay"
        );
        release_authority_clock_domain(domain);
    }

    #[test]
    fn reopened_authority_clock_advances_wall_time_past_stored_floor() {
        let domain = 0x1325_0002;
        let observed = authority_observation_secs_for_domain(domain, 1_000, 2_500);
        let backward = authority_observation_secs_for_domain(domain, observed, 10);

        assert_eq!(observed, 2_500);
        assert_eq!(
            backward, observed,
            "wall-clock rollback after reopening must not move the floor backward"
        );
        release_authority_clock_domain(domain);
    }

    #[test]
    fn authority_clock_domain_release_drops_process_local_state() {
        let domain = 0x1325_0003;
        let first = authority_observation_secs_for_domain(domain, 0, 5_000);
        let clamped = authority_observation_secs_for_domain(domain, 0, 10);

        assert_eq!(first, 5_000);
        assert_eq!(
            clamped, first,
            "active clock domains must keep their monotonic local floor"
        );

        release_authority_clock_domain(domain);
        let reset = authority_observation_secs_for_domain(domain, 0, 10);

        assert_eq!(
            reset, 10,
            "released clock domains must not keep process-local state"
        );
        release_authority_clock_domain(domain);
    }

    #[test]
    fn authority_signature_suite_verifies_ed25519_and_p256() {
        let ed = genesis_entry(2, 172_800, 1);
        assert!(verify_authority_signature(
            &ed.signer,
            &authority_transcript(&ed).unwrap()
        ));

        let p256 = p256_key(3);
        let key = authority_key_from_p256(&p256);
        let op = AuthorityOp::Genesis {
            device: device(key.clone(), ROLE_OWNER, AuthorityTier::Hardware),
            genesis_nonce: [44; 32],
            tier_floor: AuthorityTier::Hardware,
            pending_widen_delay_secs: 86_400,
        };
        let entry = sign_p256(unsigned_entry(None, 0, Vec::new(), op, key, 2), &p256);
        assert!(verify_authority_signature(
            &entry.signer,
            &authority_transcript(&entry).unwrap()
        ));
        assert!(
            decode_authority_log_entry_body(&encode_authority_log_entry_body(&entry).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn authority_body_validation_rejects_bad_origin_signature() {
        let mut genesis = genesis_entry(3, 86_400, 3);
        genesis.signer.signature[0] ^= 0xff;
        let encoded = encode_value(&entry_value(&genesis, true)).unwrap();
        let err = validate_authority_log_entry_body_bytes(&encoded)
            .expect_err("tampered origin signature must fail closed");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn p256_authority_identity_requires_canonical_compressed_sec1() {
        let signing = p256_key(22);
        let uncompressed = signing.verifying_key().to_encoded_point(false);
        let key = AuthorityKey::P256(uncompressed.as_bytes().to_vec());
        let op = AuthorityOp::Genesis {
            device: device(key.clone(), ROLE_OWNER, AuthorityTier::Hardware),
            genesis_nonce: [22; 32],
            tier_floor: AuthorityTier::Hardware,
            pending_widen_delay_secs: 86_400,
        };
        let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("uncompressed P-256 key must not be canonical authority identity");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn authority_transcript_binds_cosigner_key_set() {
        let owner = ed_key(23);
        let second = ed_key(24);
        let genesis = genesis_entry(23, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 24, 1, 2);
        let signed = cosign_ed(
            unsigned_entry(
                Some(vault_id),
                2,
                vec![authority_entry_hash(&enroll).unwrap()],
                AuthorityOp::SetTierFloor {
                    tier_floor: AuthorityTier::Hardware,
                },
                authority_key_from_ed(&owner),
                3,
            ),
            &owner,
            &second,
        );
        let mut stripped = signed.clone();
        stripped.cosigns.clear();

        assert!(
            decode_authority_log_entry_body(&encode_value(&entry_value(&stripped, true)).unwrap())
                .is_err()
        );
        assert!(
            decode_authority_log_entry_body(&encode_authority_log_entry_body(&signed).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn cloud_devices_cannot_hold_authority_consent_roles() {
        let signing = ed_key(25);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::Genesis {
            device: device(
                key.clone(),
                ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
            genesis_nonce: [25; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        };
        let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("cloud/custodial authority roots must fail closed");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn device_authority_roles_reject_unknown_bits() {
        let signing = ed_key(31);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::Genesis {
            device: device(key.clone(), ROLE_OWNER | 0x8000, AuthorityTier::Hardware),
            genesis_nonce: [31; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        };
        let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("unknown authority role bits must fail closed");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn genesis_requires_owner_or_admin_authority_consent() {
        let signing = ed_key(37);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::Genesis {
            device: device(key.clone(), ROLE_AGENT, AuthorityTier::Software),
            genesis_nonce: [37; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        };
        let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("genesis must establish an owner/admin authority root");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn rotate_key_rejects_self_rotation() {
        let signing = ed_key(38);
        let key = authority_key_from_ed(&signing);
        let op = AuthorityOp::RotateKey {
            old_key: key.clone(),
            new_device: device(key.clone(), ROLE_ADMIN, AuthorityTier::Software),
        };
        let entry = unsigned_entry(Some([38; 32]), 1, vec![[39; 32]], op, key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("self-rotation must fail before fold application");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn invalid_signatures_do_not_poison_equivocation_detection() {
        let valid = genesis_entry(39, 86_400, 1);
        let valid_hash = authority_entry_hash(&valid).unwrap();
        let mut forged = valid.clone();
        forged.ts = 2;
        forged.signer.signature[0] ^= 0xff;
        let forged_hash = authority_entry_hash(&forged).unwrap();

        let fold = fold_authority_log(&[forged, valid]);
        assert!(fold.valid_entries.contains(&valid_hash));
        assert!(!fold.valid_entries.contains(&forged_hash));
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::InvalidEntry(hash) if *hash == forged_hash
        )));
        assert!(
            !fold
                .issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
        );
    }

    #[test]
    fn zero_role_devices_do_not_count_as_quorum_participants() {
        let owner = ed_key(40);
        let zero = ed_key(41);
        let owner_key = authority_key_from_ed(&owner);
        let zero_key = authority_key_from_ed(&zero);
        let state = FoldState {
            vault_id: [40; 32],
            roster: BTreeMap::from([
                (
                    owner_key.clone(),
                    FoldedDevice {
                        key: owner_key.clone(),
                        tier: AuthorityTier::Software,
                        roles: ROLE_ADMIN,
                        revoked: false,
                    },
                ),
                (
                    zero_key.clone(),
                    FoldedDevice {
                        key: zero_key,
                        tier: AuthorityTier::Software,
                        roles: 0,
                        revoked: false,
                    },
                ),
            ]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
            pending_widens: BTreeMap::new(),
            vetoed_widens: BTreeSet::new(),
            delayed_rotation_veto_revocations: BTreeMap::new(),
            authority_forks: BTreeMap::new(),
            seqs: BTreeMap::from([(owner_key.clone(), 0)]),
        };
        let entry = cosign_ed(
            unsigned_entry(
                Some(state.vault_id),
                1,
                vec![[41; 32]],
                AuthorityOp::SetTierFloor {
                    tier_floor: AuthorityTier::Hardware,
                },
                owner_key,
                1,
            ),
            &owner,
            &zero,
        );

        let first_seen_at_secs = BTreeMap::new();
        let vetoed_widens = BTreeSet::new();
        let authority_forks = BTreeMap::new();
        let equivocation_groups = BTreeMap::new();
        let unresolved_equivocation_groups = BTreeSet::new();
        let context = FoldContext {
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: None,
        };
        assert!(
            active_participant_keys(
                &state,
                &entry,
                authority_entry_hash(&entry).unwrap(),
                context
            )
            .is_err()
        );
    }

    fn single_owner_state(seed: u8) -> (SigningKey, AuthorityKey, AuthorityEntryHash, FoldState) {
        let owner = ed_key(seed);
        let owner_key = authority_key_from_ed(&owner);
        let parent = [seed.wrapping_add(90); 32];
        let vault_id = [seed.wrapping_add(91); 32];
        let state = FoldState {
            vault_id,
            roster: BTreeMap::from([(
                owner_key.clone(),
                FoldedDevice {
                    key: owner_key.clone(),
                    tier: AuthorityTier::Software,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    revoked: false,
                },
            )]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
            pending_widens: BTreeMap::new(),
            vetoed_widens: BTreeSet::new(),
            delayed_rotation_veto_revocations: BTreeMap::new(),
            authority_forks: BTreeMap::new(),
            seqs: BTreeMap::from([(owner_key.clone(), 0)]),
        };
        (owner, owner_key, parent, state)
    }

    #[test]
    fn fold_rejects_duplicate_active_enroll_key_before_role_intersection() {
        let (owner, owner_key, parent, state) = single_owner_state(42);
        let entry = sign_ed(
            unsigned_entry(
                Some(state.vault_id),
                1,
                vec![parent],
                AuthorityOp::EnrollDevice {
                    device: device(owner_key.clone(), ROLE_AGENT, AuthorityTier::Software),
                },
                owner_key,
                1,
            ),
            &owner,
        );
        let hash = authority_entry_hash(&entry).unwrap();

        assert!(matches!(
            fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
            EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
                if issue_hash == hash
        ));
    }

    #[test]
    fn fold_rejects_rotation_to_revoked_destination_key() {
        let (owner, owner_key, parent, mut state) = single_owner_state(43);
        let revoked = ed_key(44);
        let revoked_key = authority_key_from_ed(&revoked);
        state.roster.insert(
            revoked_key.clone(),
            FoldedDevice {
                key: revoked_key.clone(),
                tier: AuthorityTier::Software,
                roles: ROLE_ADMIN,
                revoked: true,
            },
        );
        let entry = sign_ed(
            unsigned_entry(
                Some(state.vault_id),
                1,
                vec![parent],
                AuthorityOp::RotateKey {
                    old_key: owner_key.clone(),
                    new_device: device(revoked_key, ROLE_ADMIN, AuthorityTier::Software),
                },
                owner_key,
                1,
            ),
            &owner,
        );
        let hash = authority_entry_hash(&entry).unwrap();

        assert!(matches!(
            fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
            EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
                if issue_hash == hash
        ));
    }

    #[test]
    fn fold_rejects_rotation_that_leaves_no_authority_consent() {
        let (owner, owner_key, parent, state) = single_owner_state(45);
        let agent = ed_key(46);
        let entry = sign_ed(
            unsigned_entry(
                Some(state.vault_id),
                1,
                vec![parent],
                AuthorityOp::RotateKey {
                    old_key: owner_key.clone(),
                    new_device: device(
                        authority_key_from_ed(&agent),
                        ROLE_AGENT,
                        AuthorityTier::Software,
                    ),
                },
                owner_key,
                1,
            ),
            &owner,
        );
        let hash = authority_entry_hash(&entry).unwrap();

        assert!(matches!(
            fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
            EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(issue_hash))
                if issue_hash == hash
        ));
    }

    #[test]
    fn delayed_rotation_that_would_leave_no_authority_consent_is_not_pending() {
        let owner = ed_key(115);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(115, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let genesis_hash = authority_entry_hash(&genesis).unwrap();
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let agent_key = authority_key_from_ed(&ed_key(116));
        let rotate = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![genesis_hash],
                AuthorityOp::RotateKey {
                    old_key: owner_key.clone(),
                    new_device: device(agent_key.clone(), ROLE_AGENT, AuthorityTier::Software),
                },
                owner_key,
                2,
            ),
            &owner,
        );
        let rotate_hash = authority_entry_hash(&rotate).unwrap();
        let first_seen = BTreeMap::from([(rotate_hash, 10)]);

        let fold = fold_authority_log_with_seen_times(&[genesis, rotate], &first_seen, 10);

        assert!(!fold.pending_widens.contains_key(&rotate_hash));
        assert!(!fold.roster.contains_key(&agent_key));
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::MissingAuthorityConsent(issue_hash) if *issue_hash == rotate_hash
        )));
    }

    #[test]
    fn recovery_reboot_requires_consenting_new_device() {
        let owner = ed_key(47);
        let agent = ed_key(48);
        let owner_key = authority_key_from_ed(&owner);
        let op = AuthorityOp::RecoveryReboot {
            new_genesis_nonce: [47; 32],
            new_device: device(
                authority_key_from_ed(&agent),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
            tier_floor: AuthorityTier::Software,
        };
        let entry = unsigned_entry(Some([47; 32]), 1, vec![[48; 32]], op, owner_key, 1);

        let err = encode_authority_log_entry_body(&entry)
            .expect_err("recovery reboot must install a consenting authority");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn fold_rejects_recovery_reboot_reusing_existing_key() {
        let (owner, owner_key, parent, state) = single_owner_state(49);
        let entry = sign_ed(
            unsigned_entry(
                Some(state.vault_id),
                1,
                vec![parent],
                AuthorityOp::RecoveryReboot {
                    new_genesis_nonce: [49; 32],
                    new_device: device(owner_key.clone(), ROLE_OWNER, AuthorityTier::Software),
                    tier_floor: AuthorityTier::Software,
                },
                owner_key,
                1,
            ),
            &owner,
        );
        let hash = authority_entry_hash(&entry).unwrap();

        assert!(matches!(
            fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
            EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
                if issue_hash == hash
        ));
    }

    #[test]
    fn fold_equivocation_dangling_fork_does_not_block_ready_winner() {
        let owner = ed_key(50);
        let genesis = genesis_entry(50, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let ready = set_tier_floor_entry(vault_id, &genesis, &owner, 1, AuthorityTier::Hardware);
        let dangling = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![[0xDA; 32]],
                AuthorityOp::SetTierFloor {
                    tier_floor: AuthorityTier::CloudCustodial,
                },
                authority_key_from_ed(&owner),
                3,
            ),
            &owner,
        );
        let ready_hash = authority_entry_hash(&ready).unwrap();
        let dangling_hash = authority_entry_hash(&dangling).unwrap();

        let fold = fold_authority_log(&[dangling, ready, genesis]);
        assert!(fold.valid_entries.contains(&ready_hash));
        assert!(!fold.valid_entries.contains(&dangling_hash));
        assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::InvalidAncestry(hash) if *hash == dangling_hash
        )));
    }

    #[test]
    fn fold_rejects_entries_signed_by_revoked_key() {
        let owner = ed_key(4);
        let revoked_signer = ed_key(5);
        let cosigner = ed_key(6);
        let genesis = genesis_entry(4, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 5, 1, 2);
        let enroll_cosigner = cosign_ed(
            enroll_entry(vault_id, &enroll, &owner, 6, 2, 3),
            &owner,
            &revoked_signer,
        );
        let revoke = cosign_ed(
            revoke_entry(
                vault_id,
                &enroll_cosigner,
                &owner,
                authority_key_from_ed(&revoked_signer),
                3,
            ),
            &owner,
            &cosigner,
        );
        let invalid_child = enroll_entry(vault_id, &revoke, &revoked_signer, 7, 1, 4);

        let fold = fold_authority_log_without_seen_time_delay(&[
            invalid_child.clone(),
            revoke,
            enroll_cosigner,
            enroll,
            genesis,
        ]);
        assert!(
            !fold
                .valid_entries
                .contains(&authority_entry_hash(&invalid_child).unwrap())
        );
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SignerNotInAncestry(hash)
                if *hash == authority_entry_hash(&invalid_child).unwrap()
        )));
    }

    #[test]
    fn fold_rejects_revoke_without_surviving_quorum() {
        let owner = ed_key(14);
        let revoked_signer = ed_key(15);
        let genesis = genesis_entry(14, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 15, 1, 2);
        let revoke = revoke_entry(
            vault_id,
            &enroll,
            &owner,
            authority_key_from_ed(&revoked_signer),
            2,
        );

        let fold = fold_authority_log_without_seen_time_delay(&[revoke.clone(), enroll, genesis]);
        assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash)
            if *hash == authority_entry_hash(&revoke).unwrap()
        )));
    }

    #[test]
    fn fold_detects_equivocation_by_signer_and_seq() {
        let left = genesis_entry(16, 86_400, 1);
        let right = genesis_entry(16, 86_400, 2);
        let signer = authority_key_from_ed(&ed_key(16));
        let left_hash = authority_entry_hash(&left).unwrap();
        let right_hash = authority_entry_hash(&right).unwrap();
        let winner_hash = left_hash.min(right_hash);
        let winner_vault_id = if winner_hash == left_hash {
            genesis_vault_id(&left).unwrap()
        } else {
            genesis_vault_id(&right).unwrap()
        };

        let fold = fold_authority_log(&[left, right]);
        assert_eq!(fold.vault_id, Some(winner_vault_id));
        assert!(fold.valid_entries.contains(&winner_hash));
        assert_eq!(fold.valid_entries.len(), 1);
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 0 }
                if *key == signer
        )));
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: signer.clone(),
                seq: 0,
                first_hash: left_hash.min(right_hash),
                second_hash: left_hash.max(right_hash),
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer,
                seq: 0,
                first_hash: left_hash.min(right_hash),
                second_hash: left_hash.max(right_hash),
            }]
        );
        assert_eq!(AuthorityForkAlarm::KIND, AUTHORITY_FORK_ALARM_KIND);
    }

    #[test]
    fn multiway_equivocation_alarm_spans_min_and_max_hashes() {
        let owner = ed_key(64);
        let second = ed_key(65);
        let signer = authority_key_from_ed(&owner);
        let genesis = genesis_entry(64, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_entry(vault_id, &genesis, &owner, 65, 1, 2);
        let fork_enroll = cosign_ed(
            enroll_entry(vault_id, &enroll_second, &owner, 66, 2, 3),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
            &owner,
            &second,
        );
        let fork_tier = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let mut hashes = [
            authority_entry_hash(&fork_enroll).unwrap(),
            authority_entry_hash(&fork_ceiling).unwrap(),
            authority_entry_hash(&fork_tier).unwrap(),
        ];
        hashes.sort();

        let fold = fold_authority_log_without_seen_time_delay(&[
            fork_ceiling,
            fork_tier,
            fork_enroll,
            enroll_second,
            genesis,
        ]);

        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: signer.clone(),
                seq: 2,
                first_hash: hashes[0],
                second_hash: hashes[2],
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer,
                seq: 2,
                first_hash: hashes[0],
                second_hash: hashes[2],
            }]
        );
    }

    #[test]
    fn quarantined_key_cannot_widen_enroll_or_set_ceiling_but_prefix_survives() {
        let owner = ed_key(60);
        let second = ed_key(61);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(60, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_entry(vault_id, &genesis, &owner, 61, 1, 2);
        let fork_enroll = cosign_ed(
            enroll_entry(vault_id, &enroll_second, &owner, 62, 2, 3),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
            &owner,
            &second,
        );
        let fork_enroll_hash = authority_entry_hash(&fork_enroll).unwrap();
        let fork_fold = fold_authority_log_without_seen_time_delay(&[
            fork_ceiling.clone(),
            fork_enroll.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        let winner = if fork_fold.valid_entries.contains(&fork_enroll_hash) {
            fork_enroll.clone()
        } else {
            fork_ceiling.clone()
        };
        let child_enroll = cosign_ed(
            enroll_entry(vault_id, &winner, &owner, 63, 3, 5),
            &owner,
            &second,
        );
        let child_widen = cosign_ed(
            set_tier_floor_entry(vault_id, &winner, &owner, 3, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let child_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &winner, &owner, 3, 6),
            &owner,
            &second,
        );
        let child_enroll_hash = authority_entry_hash(&child_enroll).unwrap();
        let child_widen_hash = authority_entry_hash(&child_widen).unwrap();
        let child_ceiling_hash = authority_entry_hash(&child_ceiling).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            child_enroll,
            child_widen,
            child_ceiling,
            fork_enroll,
            fork_ceiling,
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&genesis).unwrap())
        );
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&enroll_second).unwrap())
        );
        assert!(!fold.valid_entries.contains(&child_enroll_hash));
        assert!(!fold.valid_entries.contains(&child_widen_hash));
        assert!(!fold.valid_entries.contains(&child_ceiling_hash));
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        for child_hash in [child_enroll_hash, child_widen_hash, child_ceiling_hash] {
            assert!(fold.issues.iter().any(|issue| matches!(
                issue,
                AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == child_hash
            )));
        }
    }

    #[test]
    fn quarantined_key_cannot_bypass_with_clean_prefix_parent() {
        let owner = ed_key(66);
        let second = ed_key(67);
        let genesis = genesis_entry(66, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_entry(vault_id, &genesis, &owner, 67, 1, 2);
        let fork_enroll = cosign_ed(
            enroll_entry(vault_id, &enroll_second, &owner, 68, 2, 3),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
            &owner,
            &second,
        );
        let clean_prefix_child = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 5),
            &owner,
            &second,
        );
        let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            clean_prefix_child,
            fork_ceiling,
            fork_enroll,
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&genesis).unwrap())
        );
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&enroll_second).unwrap())
        );
        assert!(!fold.valid_entries.contains(&clean_prefix_child_hash));
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == clean_prefix_child_hash
        )));
    }

    #[test]
    fn quorum_revoke_resolves_authority_fork() {
        let owner = ed_key(70);
        let second = ed_key(71);
        let third = ed_key(72);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(70, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 71,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 72,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let fork_restrict = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
            &owner,
            &second,
        );
        let restrict_hash = authority_entry_hash(&fork_restrict).unwrap();
        let fork_fold = fold_authority_log_without_seen_time_delay(&[
            fork_restrict.clone(),
            fork_ceiling.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        let winner = if fork_fold.valid_entries.contains(&restrict_hash) {
            fork_restrict.clone()
        } else {
            fork_ceiling.clone()
        };
        let revoke = cosign_ed(
            revoke_entry(vault_id, &winner, &second, owner_key.clone(), 0),
            &second,
            &third,
        );
        let entries = vec![
            revoke.clone(),
            fork_ceiling.clone(),
            fork_restrict.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let permutations = [
            entries,
            vec![
                genesis,
                enroll_second,
                enroll_third,
                fork_restrict,
                fork_ceiling,
                revoke,
            ],
        ];

        for entries in permutations {
            let fold = fold_authority_log_without_seen_time_delay(&entries);
            assert_eq!(fold.authority_forks.len(), 1);
            assert_eq!(
                fold.authority_forks[0].status,
                AuthorityForkStatus::Resolved
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert!(
                fold.roster
                    .get(&owner_key)
                    .is_some_and(|device| device.revoked)
            );
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(&entries[0]).unwrap())
                    || fold
                        .valid_entries
                        .contains(&authority_entry_hash(&entries[5]).unwrap())
            );
        }
    }

    #[test]
    fn quorum_revoke_on_clean_prefix_resolves_authority_fork() {
        let owner = ed_key(80);
        let second = ed_key(81);
        let third = ed_key(82);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(80, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 81,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 82,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let fork_restrict = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
            &owner,
            &second,
        );
        let revoke = cosign_ed(
            revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
            &second,
            &third,
        );
        let revoke_hash = authority_entry_hash(&revoke).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            revoke,
            fork_ceiling,
            fork_restrict,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert!(fold.valid_entries.contains(&revoke_hash));
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
    }

    #[test]
    fn restore_prefix_divergence_suppresses_authority_fork_alarm() {
        let owner = ed_key(73);
        let second = ed_key(74);
        let genesis = genesis_entry(73, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 74,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let recovery = cosign_ed(
            recovery_reboot_entry(vault_id, &enroll_second, &owner, 75, 2),
            &owner,
            &second,
        );
        let short_branch = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 3),
            &owner,
            &second,
        );
        let restored_branch = cosign_ed(
            set_tier_floor_entry(vault_id, &recovery, &owner, 3, AuthorityTier::Hardware),
            &owner,
            &second,
        );

        for entries in [
            vec![
                restored_branch.clone(),
                short_branch.clone(),
                recovery.clone(),
                enroll_second.clone(),
                genesis.clone(),
            ],
            vec![
                genesis,
                enroll_second,
                recovery,
                short_branch,
                restored_branch,
            ],
        ] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);
            assert!(fold.fork_alarms.is_empty());
            assert!(fold.authority_forks.is_empty());
            assert!(
                !fold.issues.iter().any(|issue| {
                    matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. })
                })
            );
        }
    }

    #[test]
    fn strict_prefix_without_restore_marker_still_quarantines_and_alarms() {
        let owner = ed_key(76);
        let second = ed_key(77);
        let genesis = genesis_entry(76, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 77,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let short_branch = set_ceiling_entry(vault_id, &genesis, &owner, 2, 3);
        let longer_branch = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let fold = fold_authority_log_without_seen_time_delay(&[
            longer_branch,
            short_branch,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert!(fold.issues.iter().any(|issue| {
            matches!(
                issue,
                AuthorityFoldIssue::EquivocationDetected { seq: 2, .. }
            )
        }));
    }

    #[test]
    fn shared_restore_marker_does_not_suppress_later_strict_prefix_fork() {
        let owner = ed_key(83);
        let second = ed_key(84);
        let recovered = ed_key(85);
        let recovered_key = authority_key_from_ed(&recovered);
        let genesis = genesis_entry(83, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 84,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let recovery = cosign_ed(
            recovery_reboot_entry(vault_id, &enroll_second, &owner, 85, 2),
            &owner,
            &second,
        );
        let shared_after_recovery = set_ceiling_entry(vault_id, &recovery, &recovered, 0, 3);
        let short_branch =
            set_tier_floor_entry(vault_id, &recovery, &recovered, 1, AuthorityTier::Hardware);
        let longer_branch = set_ceiling_entry(vault_id, &shared_after_recovery, &recovered, 1, 4);

        let fold = fold_authority_log_without_seen_time_delay(&[
            longer_branch,
            short_branch,
            shared_after_recovery,
            recovery,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, recovered_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
    }

    #[test]
    fn invalid_restore_marker_does_not_suppress_strict_prefix_fork_group() {
        let owner = ed_key(86);
        let second = ed_key(87);
        let genesis = genesis_entry(86, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 87,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let owner_key = authority_key_from_ed(&owner);
        let second_key = authority_key_from_ed(&second);
        let invalid_recovery = cosign_ed(
            unsigned_entry(
                Some(vault_id),
                2,
                vec![authority_entry_hash(&enroll_second).unwrap()],
                AuthorityOp::RecoveryReboot {
                    new_genesis_nonce: [87; 32],
                    new_device: device(
                        second_key,
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                    tier_floor: AuthorityTier::Software,
                },
                owner_key,
                3,
            ),
            &owner,
            &second,
        );
        let short_branch = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
            &owner,
            &second,
        );
        let longer_branch = cosign_ed(
            set_tier_floor_entry(
                vault_id,
                &invalid_recovery,
                &owner,
                3,
                AuthorityTier::Hardware,
            ),
            &owner,
            &second,
        );
        let by_hash = BTreeMap::from_iter([
            (authority_entry_hash(&genesis).unwrap(), genesis),
            (authority_entry_hash(&enroll_second).unwrap(), enroll_second),
            (
                authority_entry_hash(&invalid_recovery).unwrap(),
                invalid_recovery,
            ),
            (authority_entry_hash(&short_branch).unwrap(), short_branch),
            (authority_entry_hash(&longer_branch).unwrap(), longer_branch),
        ]);
        let group = BTreeSet::from_iter([
            *by_hash
                .iter()
                .find_map(|(hash, entry)| {
                    matches!(entry.op, AuthorityOp::SetCeiling { .. }).then_some(hash)
                })
                .expect("short branch present"),
            *by_hash
                .iter()
                .find_map(|(hash, entry)| {
                    matches!(entry.op, AuthorityOp::SetTierFloor { .. }).then_some(hash)
                })
                .expect("longer branch present"),
        ]);
        let ancestors = entry_ancestor_index(&by_hash);

        assert!(
            !restore_prefix_divergence(&group, &by_hash, &ancestors),
            "invalid recovery markers must not route an equivocation group away from fork handling"
        );
    }

    #[test]
    fn group_internal_parent_still_records_authority_fork() {
        let owner = ed_key(88);
        let second = ed_key(89);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(88, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 89,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let first = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
            &owner,
            &second,
        );
        let second_parented_to_first = cosign_ed(
            set_tier_floor_entry(vault_id, &first, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let second_hash = authority_entry_hash(&second_parented_to_first).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            second_parented_to_first,
            first,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::InvalidAncestry(hash) if *hash == second_hash
        )));
    }

    #[test]
    fn all_invalid_same_seq_group_does_not_quarantine_later_valid_entry() {
        let owner = ed_key(96);
        let second = ed_key(97);
        let genesis = genesis_entry(96, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 97,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3);
        let invalid_tier =
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware);
        let valid_later = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
            &owner,
            &second,
        );
        let valid_later_hash = authority_entry_hash(&valid_later).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            valid_later,
            invalid_tier,
            invalid_ceiling,
            enroll_second,
            genesis,
        ]);

        assert!(fold.valid_entries.contains(&valid_later_hash));
        assert!(fold.authority_forks.is_empty());
        assert!(fold.fork_alarms.is_empty());
        assert!(
            !fold
                .issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
        );
    }

    #[test]
    fn all_invalid_same_seq_group_does_not_resolve_clean_prefix_revoke() {
        let owner = ed_key(103);
        let second = ed_key(104);
        let third = ed_key(105);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(103, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 104,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 105,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4);
        let invalid_tier =
            set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware);
        let revoke_owner = cosign_ed(
            revoke_entry(vault_id, &enroll_third, &second, owner_key, 0),
            &second,
            &third,
        );
        let revoke_hash = authority_entry_hash(&revoke_owner).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            revoke_owner,
            invalid_tier,
            invalid_ceiling,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert!(fold.valid_entries.contains(&revoke_hash));
        assert!(fold.authority_forks.is_empty());
        assert!(fold.fork_alarms.is_empty());
        assert!(
            !fold
                .issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
        );
    }

    #[test]
    fn clean_prefix_entry_waits_when_unresolved_fork_key_is_cosigner() {
        let owner = ed_key(109);
        let second = ed_key(110);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(109, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 110,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
            &owner,
            &second,
        );
        let fork_tier = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let clean_prefix_child = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
            &second,
            &owner,
        );
        let fork_ceiling_hash = authority_entry_hash(&fork_ceiling).unwrap();
        let fork_tier_hash = authority_entry_hash(&fork_tier).unwrap();
        let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();
        let by_hash = BTreeMap::from([
            (authority_entry_hash(&genesis).unwrap(), genesis),
            (authority_entry_hash(&enroll_second).unwrap(), enroll_second),
            (fork_ceiling_hash, fork_ceiling),
            (fork_tier_hash, fork_tier),
            (clean_prefix_child_hash, clean_prefix_child.clone()),
        ]);
        let entry_ancestors = entry_ancestor_index(&by_hash);
        let group_key = (owner_key, 2);
        let first_seen_at_secs = BTreeMap::new();
        let vetoed_widens = BTreeSet::new();
        let authority_forks = BTreeMap::new();
        let equivocation_groups = BTreeMap::from([(
            group_key.clone(),
            BTreeSet::from([fork_ceiling_hash, fork_tier_hash]),
        )]);
        let unresolved_equivocation_groups = BTreeSet::from([group_key]);
        let context = FoldContext {
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: Some(&entry_ancestors),
        };

        assert!(entry_waits_on_unresolved_equivocation(
            &clean_prefix_child,
            clean_prefix_child_hash,
            context
        ));
    }

    #[test]
    fn equivocation_group_waits_on_other_unresolved_equivocation() {
        let owner = ed_key(111);
        let second = ed_key(112);
        let owner_key = authority_key_from_ed(&owner);
        let second_key = authority_key_from_ed(&second);
        let genesis = genesis_entry(111, 86_400, 1);
        let genesis_hash = authority_entry_hash(&genesis).unwrap();
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 112,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_second_hash = authority_entry_hash(&enroll_second).unwrap();
        let owner_fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
            &owner,
            &second,
        );
        let owner_fork_tier = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let second_fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
            &second,
            &owner,
        );
        let second_fork_tier = cosign_ed(
            set_tier_floor_entry(
                vault_id,
                &enroll_second,
                &second,
                0,
                AuthorityTier::Hardware,
            ),
            &second,
            &owner,
        );
        let owner_fork_ceiling_hash = authority_entry_hash(&owner_fork_ceiling).unwrap();
        let owner_fork_tier_hash = authority_entry_hash(&owner_fork_tier).unwrap();
        let second_fork_ceiling_hash = authority_entry_hash(&second_fork_ceiling).unwrap();
        let second_fork_tier_hash = authority_entry_hash(&second_fork_tier).unwrap();
        let by_hash = BTreeMap::from([
            (genesis_hash, genesis.clone()),
            (enroll_second_hash, enroll_second.clone()),
            (owner_fork_ceiling_hash, owner_fork_ceiling),
            (owner_fork_tier_hash, owner_fork_tier),
            (second_fork_ceiling_hash, second_fork_ceiling),
            (second_fork_tier_hash, second_fork_tier),
        ]);
        let entry_ancestors = entry_ancestor_index(&by_hash);
        let mut states = BTreeMap::new();
        let genesis_state = match fold_entry_state_for_test(&genesis, genesis_hash, &states) {
            EntryFold::Ready(state) => state,
            _ => panic!("genesis should fold"),
        };
        states.insert(genesis_hash, genesis_state);
        let enroll_state =
            match fold_entry_state_for_test(&enroll_second, enroll_second_hash, &states) {
                EntryFold::Ready(state) => state,
                _ => panic!("enrollment should fold"),
            };
        states.insert(enroll_second_hash, enroll_state);
        let owner_group_key = (owner_key, 2);
        let second_group_key = (second_key, 0);
        let owner_group = BTreeSet::from([owner_fork_ceiling_hash, owner_fork_tier_hash]);
        let second_group = BTreeSet::from([second_fork_ceiling_hash, second_fork_tier_hash]);
        let pending = BTreeSet::from([
            owner_fork_ceiling_hash,
            owner_fork_tier_hash,
            second_fork_ceiling_hash,
            second_fork_tier_hash,
        ]);
        let first_seen_at_secs = BTreeMap::new();
        let vetoed_widens = BTreeSet::new();
        let authority_forks = BTreeMap::new();
        let equivocation_groups = BTreeMap::from([
            (owner_group_key.clone(), owner_group),
            (second_group_key.clone(), second_group.clone()),
        ]);
        let unresolved_equivocation_groups =
            BTreeSet::from([owner_group_key, second_group_key.clone()]);
        let context = FoldContext {
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: Some(&entry_ancestors),
        };

        assert!(matches!(
            resolve_equivocation_group(
                &second_group_key,
                &second_group,
                &by_hash,
                &states,
                &pending,
                context
            ),
            EquivocationResolution::Waiting
        ));
    }

    #[test]
    fn resolved_fork_does_not_mask_unresolved_later_fork_for_same_key() {
        let (_, key, _, mut state) = single_owner_state(98);
        state.authority_forks.insert(
            (key.clone(), 1),
            AuthorityFork {
                signer: key.clone(),
                seq: 1,
                first_hash: [1; 32],
                second_hash: [2; 32],
                status: AuthorityForkStatus::Resolved,
            },
        );
        let authority_forks = BTreeMap::from([(
            (key.clone(), 2),
            AuthorityFork {
                signer: key.clone(),
                seq: 2,
                first_hash: [3; 32],
                second_hash: [4; 32],
                status: AuthorityForkStatus::Quarantined,
            },
        )]);
        let first_seen_at_secs = BTreeMap::new();
        let vetoed_widens = BTreeSet::new();
        let equivocation_groups = BTreeMap::new();
        let unresolved_equivocation_groups = BTreeSet::new();
        let context = FoldContext {
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: None,
        };

        assert!(key_is_quarantined_for_entry(&state, context, &key, [9; 32]));
    }

    #[test]
    fn quarantined_keys_do_not_count_as_revoke_survivors() {
        let owner = ed_key(90);
        let second = ed_key(91);
        let third = ed_key(92);
        let second_key = authority_key_from_ed(&second);
        let genesis = genesis_entry(90, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 91,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &second,
                EnrollSpec {
                    seed: 92,
                    roles: ROLE_AGENT,
                    tier: AuthorityTier::Software,
                    seq: 0,
                    ts: 3,
                },
            ),
            &second,
            &owner,
        );
        let fork_restrict = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_third, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 2, 4),
            &owner,
            &second,
        );
        let fork_fold = fold_authority_log_without_seen_time_delay(&[
            fork_restrict.clone(),
            fork_ceiling.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        let winner = if fork_fold
            .valid_entries
            .contains(&authority_entry_hash(&fork_restrict).unwrap())
        {
            fork_restrict.clone()
        } else {
            fork_ceiling.clone()
        };
        let revoke_second = cosign_ed(
            revoke_entry(vault_id, &winner, &second, second_key, 1),
            &second,
            &third,
        );
        let revoke_hash = authority_entry_hash(&revoke_second).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            revoke_second,
            fork_ceiling,
            fork_restrict,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.authority_forks.len(), 1);
        assert!(!fold.valid_entries.contains(&revoke_hash));
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_hash
        )));
    }

    #[test]
    fn fork_winner_revoke_rechecks_quorum_without_quarantined_signer() {
        let owner = ed_key(106);
        let second = ed_key(107);
        let third = ed_key(108);
        let owner_key = authority_key_from_ed(&owner);
        let second_key = authority_key_from_ed(&second);
        let genesis = genesis_entry(106, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 107,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 108,
                    roles: ROLE_AGENT,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let bad_revoke = cosign_ed(
            revoke_entry(vault_id, &enroll_third, &owner, second_key, 3),
            &owner,
            &third,
        );
        let good_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
            &owner,
            &second,
        );
        let bad_revoke_hash = authority_entry_hash(&bad_revoke).unwrap();
        let good_ceiling_hash = authority_entry_hash(&good_ceiling).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            bad_revoke,
            good_ceiling,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert!(fold.valid_entries.contains(&good_ceiling_hash));
        assert!(!fold.valid_entries.contains(&bad_revoke_hash));
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::MissingQuorum(hash) if *hash == bad_revoke_hash
        )));
    }

    #[test]
    fn winning_self_revoke_marks_authority_fork_resolved() {
        let owner = ed_key(93);
        let second = ed_key(94);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(93, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 94,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 95,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let self_revoke = cosign_ed(
            revoke_entry(vault_id, &enroll_third, &owner, owner_key.clone(), 3),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
            &owner,
            &second,
        );

        let fold = fold_authority_log_without_seen_time_delay(&[
            fork_ceiling,
            self_revoke,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
    }

    #[test]
    fn recovery_reboot_resolves_inherited_authority_fork() {
        let owner = ed_key(100);
        let second = ed_key(101);
        let third = ed_key(102);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(100, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 101,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_third = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_second,
                &owner,
                EnrollSpec {
                    seed: 102,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &second,
        );
        let fork_restrict = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let fork_ceiling = cosign_ed(
            set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
            &owner,
            &second,
        );
        let fork_fold = fold_authority_log_without_seen_time_delay(&[
            fork_restrict.clone(),
            fork_ceiling.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        let winner = if fork_fold
            .valid_entries
            .contains(&authority_entry_hash(&fork_restrict).unwrap())
        {
            fork_restrict.clone()
        } else {
            fork_ceiling.clone()
        };
        let recovery = cosign_ed(
            recovery_reboot_entry(vault_id, &winner, &second, 103, 0),
            &second,
            &third,
        );

        let fold = fold_authority_log_without_seen_time_delay(&[
            recovery,
            fork_ceiling,
            fork_restrict,
            enroll_third,
            enroll_second,
            genesis,
        ]);

        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, owner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
    }

    #[test]
    fn fold_equivocation_fork_rank_prefers_more_restrictive_state_before_hash() {
        let owner = ed_key(34);
        let second = ed_key(35);
        let genesis = genesis_entry(34, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_entry(vault_id, &genesis, &owner, 35, 1, 2);
        let enroll_third = cosign_ed(
            enroll_entry(vault_id, &enroll_second, &owner, 36, 2, 3),
            &owner,
            &second,
        );
        let restrict_floor = cosign_ed(
            set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
            &owner,
            &second,
        );
        let restrict_hash = authority_entry_hash(&restrict_floor).unwrap();
        let grant_hash = authority_entry_hash(&enroll_third).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            enroll_third,
            restrict_floor,
            enroll_second,
            genesis,
        ]);
        assert!(fold.valid_entries.contains(&restrict_hash));
        assert!(!fold.valid_entries.contains(&grant_hash));
        assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 2 }
                if *key == authority_key_from_ed(&owner)
        )));
    }

    #[test]
    fn pending_widen_equivocation_rank_uses_eventual_state() {
        let owner = ed_key(42);
        let genesis = genesis_entry(42, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let mut chosen = None;
        for seed in 43..96 {
            let pending = enroll_device_entry(
                vault_id,
                &genesis,
                &owner,
                EnrollSpec {
                    seed,
                    roles: ROLE_AGENT,
                    tier: AuthorityTier::Software,
                    seq: 1,
                    ts: u64::from(seed),
                },
            );
            let ceiling = set_ceiling_entry(vault_id, &genesis, &owner, 1, u64::from(seed) + 100);
            let pending_hash = authority_entry_hash(&pending).unwrap();
            let ceiling_hash = authority_entry_hash(&ceiling).unwrap();
            if pending_hash < ceiling_hash {
                chosen = Some((pending, pending_hash, ceiling, ceiling_hash));
                break;
            }
        }
        let (pending, pending_hash, ceiling, ceiling_hash) =
            chosen.expect("test seeds must include a pending hash below the ceiling hash");
        let first_seen = BTreeMap::from([(pending_hash, 0)]);

        let fold = fold_authority_log_with_seen_times(
            &[pending, ceiling, genesis],
            &first_seen,
            DEFAULT_PENDING_WIDEN_DELAY_SECS - 1,
        );

        assert!(fold.valid_entries.contains(&ceiling_hash));
        assert!(!fold.valid_entries.contains(&pending_hash));
        assert!(fold.pending_widens.is_empty());
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 1 }
                if *key == authority_key_from_ed(&owner)
        )));
    }

    #[test]
    fn fold_allows_newly_enrolled_signer_to_start_at_seq_zero() {
        let owner = ed_key(32);
        let new_signer = ed_key(33);
        let genesis = genesis_entry(32, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let owner_key = authority_key_from_ed(&owner);
        let new_key = authority_key_from_ed(&new_signer);
        let enroll_admin = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![authority_entry_hash(&genesis).unwrap()],
                AuthorityOp::EnrollDevice {
                    device: device(new_key, ROLE_ADMIN, AuthorityTier::Software),
                },
                owner_key,
                2,
            ),
            &owner,
        );
        let first_new_signer_entry = cosign_ed(
            set_tier_floor_entry(
                vault_id,
                &enroll_admin,
                &new_signer,
                0,
                AuthorityTier::Hardware,
            ),
            &new_signer,
            &owner,
        );
        let first_hash = authority_entry_hash(&first_new_signer_entry).unwrap();

        let fold = fold_authority_log_without_seen_time_delay(&[
            first_new_signer_entry,
            enroll_admin,
            genesis,
        ]);
        assert!(fold.valid_entries.contains(&first_hash));
        assert!(!fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == first_hash
        )));
    }

    #[test]
    fn fold_rejects_cross_vault_root_contamination() {
        let local = genesis_entry(26, 86_400, 1);
        let foreign = genesis_entry(27, 86_400, 1);

        let fold = fold_authority_log(&[local, foreign]);
        assert_eq!(fold.vault_id, None);
        assert!(fold.valid_entries.is_empty());
        assert!(fold.roster.is_empty());
        assert!(
            fold.issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
        );
    }

    #[test]
    fn software_tier_widen_waits_for_local_seen_time_window() {
        let owner = ed_key(60);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(60, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 61,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_hash = authority_entry_hash(&enroll).unwrap();
        let first_seen = BTreeMap::from([(enroll_hash, 10)]);
        let new_key = authority_key_from_ed(&ed_key(61));

        let before = fold_authority_log_with_seen_times(
            &[genesis.clone(), enroll.clone()],
            &first_seen,
            10 + delay - 1,
        );
        assert!(!before.roster.contains_key(&new_key));
        assert_eq!(
            before.pending_widens.get(&enroll_hash),
            Some(&AuthorityPendingWiden {
                entry_hash: enroll_hash,
                first_seen_at_secs: Some(10),
                eligible_at_secs: Some(10 + delay),
                delay_secs: delay,
            })
        );

        let after = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 10 + delay);
        assert!(after.roster.contains_key(&new_key));
        assert!(after.pending_widens.is_empty());
    }

    #[test]
    fn hardware_tier_widen_is_instant() {
        let owner = ed_key(62);
        let owner_key = authority_key_from_ed(&owner);
        let op = AuthorityOp::Genesis {
            device: device(
                owner_key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Hardware,
            ),
            genesis_nonce: [72; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        };
        let genesis = sign_ed(
            unsigned_entry(None, 0, Vec::new(), op, owner_key, 1),
            &owner,
        );
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 63,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_hash = authority_entry_hash(&enroll).unwrap();
        let first_seen = BTreeMap::from([(enroll_hash, 1)]);
        let fold = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 1);

        assert!(
            fold.roster
                .contains_key(&authority_key_from_ed(&ed_key(63)))
        );
        assert!(fold.pending_widens.is_empty());
    }

    #[test]
    fn veto_from_owner_kills_pending_widen_in_every_arrival_order() {
        let owner = ed_key(64);
        let genesis = genesis_entry(64, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 65,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
        let first_seen = BTreeMap::from([(pending_hash, 0)]);
        let permutations = [
            vec![genesis.clone(), pending.clone(), veto.clone()],
            vec![genesis.clone(), veto.clone(), pending.clone()],
            vec![pending.clone(), genesis.clone(), veto.clone()],
            vec![pending.clone(), veto.clone(), genesis.clone()],
            vec![veto.clone(), genesis.clone(), pending.clone()],
            vec![veto, pending, genesis],
        ];

        for entries in permutations {
            let fold = fold_authority_log_with_seen_times(&entries, &first_seen, 200);
            assert!(
                !fold
                    .roster
                    .contains_key(&authority_key_from_ed(&ed_key(65)))
            );
            assert!(fold.vetoed_widens.contains(&pending_hash));
            assert!(fold.pending_widens.is_empty());
        }
    }

    #[test]
    fn veto_after_local_seen_time_window_does_not_revoke_active_widen() {
        let owner = ed_key(95);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(95, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 96,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
        let veto_hash = authority_entry_hash(&veto).unwrap();
        let first_seen = BTreeMap::from([(pending_hash, 0)]);

        let fold =
            fold_authority_log_with_seen_times(&[veto, pending, genesis], &first_seen, delay);

        assert!(
            fold.roster
                .contains_key(&authority_key_from_ed(&ed_key(96)))
        );
        assert!(!fold.valid_entries.contains(&veto_hash));
        assert!(!fold.vetoed_widens.contains(&pending_hash));
    }

    #[test]
    fn admin_without_owner_role_cannot_veto_pending_widen() {
        let owner = ed_key(81);
        let admin = ed_key(82);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(81, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_admin = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 82,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_admin_hash = authority_entry_hash(&enroll_admin).unwrap();
        let pending = cosign_ed(
            enroll_device_entry(
                vault_id,
                &enroll_admin,
                &owner,
                EnrollSpec {
                    seed: 83,
                    roles: ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &admin,
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let veto = veto_entry(vault_id, &pending, &admin, pending_hash, 0);
        let veto_hash = authority_entry_hash(&veto).unwrap();
        let first_seen = BTreeMap::from([(enroll_admin_hash, 0), (pending_hash, delay)]);

        let fold = fold_authority_log_with_seen_times(
            &[veto, pending, enroll_admin, genesis],
            &first_seen,
            delay,
        );

        assert!(!fold.valid_entries.contains(&veto_hash));
        assert!(!fold.vetoed_widens.contains(&pending_hash));
        assert!(fold.pending_widens.contains_key(&pending_hash));
    }

    #[test]
    fn veto_child_of_delayed_rotation_survives_when_old_key_lands_revoked() {
        let owner = ed_key(73);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(73, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key.clone(), 74, 1);
        let rotation_hash = authority_entry_hash(&rotation).unwrap();
        let malicious_widen = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 75,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 2,
            },
        );
        let malicious_hash = authority_entry_hash(&malicious_widen).unwrap();
        let veto = veto_entry(vault_id, &rotation, &owner, malicious_hash, 3);
        let veto_hash = authority_entry_hash(&veto).unwrap();
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let first_seen = BTreeMap::from([(rotation_hash, 0), (malicious_hash, delay)]);

        let fold = fold_authority_log_with_seen_times(
            &[veto, malicious_widen, rotation, genesis],
            &first_seen,
            delay,
        );

        assert!(fold.valid_entries.contains(&veto_hash));
        assert!(fold.vetoed_widens.contains(&malicious_hash));
        assert!(
            !fold
                .roster
                .contains_key(&authority_key_from_ed(&ed_key(75)))
        );
        assert!(
            fold.roster
                .get(&owner_key)
                .is_some_and(|device| device.revoked)
        );
    }

    #[test]
    fn delayed_rotation_veto_key_cannot_veto_descendant_widen() {
        let owner = ed_key(76);
        let owner_key = authority_key_from_ed(&owner);
        let new_owner = ed_key(77);
        let genesis = genesis_entry(76, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key, 77, 1);
        let rotation_hash = authority_entry_hash(&rotation).unwrap();
        let future_widen = enroll_device_entry(
            vault_id,
            &rotation,
            &new_owner,
            EnrollSpec {
                seed: 78,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 0,
                ts: 2,
            },
        );
        let future_hash = authority_entry_hash(&future_widen).unwrap();
        let veto = veto_entry(vault_id, &rotation, &owner, future_hash, 2);
        let veto_hash = authority_entry_hash(&veto).unwrap();
        let first_seen = BTreeMap::from([(rotation_hash, 0), (future_hash, 0)]);

        let fold = fold_authority_log_with_seen_times(
            &[veto, future_widen, rotation, genesis],
            &first_seen,
            DEFAULT_PENDING_WIDEN_DELAY_SECS,
        );

        assert!(!fold.valid_entries.contains(&veto_hash));
        assert!(!fold.vetoed_widens.contains(&future_hash));
        assert!(
            fold.roster
                .contains_key(&authority_key_from_ed(&ed_key(78)))
        );
    }

    #[test]
    fn child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
        let owner = ed_key(97);
        let admin = ed_key(98);
        let child = ed_key(99);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(97, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending_admin = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 98,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending_admin).unwrap();
        let child_widen = cosign_ed(
            enroll_device_entry(
                vault_id,
                &pending_admin,
                &owner,
                EnrollSpec {
                    seed: 99,
                    roles: ROLE_AGENT,
                    tier: AuthorityTier::Software,
                    seq: 2,
                    ts: 3,
                },
            ),
            &owner,
            &admin,
        );
        let child_hash = authority_entry_hash(&child_widen).unwrap();
        let first_seen = BTreeMap::from([(pending_hash, 0), (child_hash, 0)]);

        let before = fold_authority_log_with_seen_times(
            &[child_widen.clone(), pending_admin.clone(), genesis.clone()],
            &first_seen,
            delay - 1,
        );
        assert!(!before.valid_entries.contains(&child_hash));
        assert!(!before.roster.contains_key(&authority_key_from_ed(&child)));

        let after = fold_authority_log_with_seen_times(
            &[child_widen, pending_admin, genesis],
            &first_seen,
            delay,
        );
        assert!(after.valid_entries.contains(&child_hash));
        assert!(after.roster.contains_key(&authority_key_from_ed(&child)));
    }

    #[test]
    fn non_widen_child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
        let owner = ed_key(100);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(100, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending_admin = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 101,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending_admin).unwrap();
        let child_ceiling = set_ceiling_entry(vault_id, &pending_admin, &owner, 2, 3);
        let child_hash = authority_entry_hash(&child_ceiling).unwrap();
        let first_seen = BTreeMap::from([(pending_hash, 0)]);

        let before = fold_authority_log_with_seen_times(
            &[
                child_ceiling.clone(),
                pending_admin.clone(),
                genesis.clone(),
            ],
            &first_seen,
            delay - 1,
        );
        assert!(!before.valid_entries.contains(&child_hash));
        assert!(before.pending_widens.contains_key(&pending_hash));

        let after = fold_authority_log_with_seen_times(
            &[child_ceiling, pending_admin, genesis],
            &first_seen,
            delay,
        );
        assert!(!after.valid_entries.contains(&child_hash));
        assert!(after.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::MissingQuorum(hash) if *hash == child_hash
        )));
    }

    #[test]
    fn devices_with_different_first_seen_times_temporarily_diverge_then_converge() {
        let owner = ed_key(66);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(66, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 67,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let new_key = authority_key_from_ed(&ed_key(67));
        let early_seen = BTreeMap::from([(pending_hash, 0)]);
        let late_seen = BTreeMap::from([(pending_hash, delay - 25)]);

        let early_fold = fold_authority_log_with_seen_times(
            &[genesis.clone(), pending.clone()],
            &early_seen,
            delay + 50,
        );
        let late_fold = fold_authority_log_with_seen_times(
            &[genesis.clone(), pending.clone()],
            &late_seen,
            delay + 50,
        );
        assert!(early_fold.roster.contains_key(&new_key));
        assert!(!late_fold.roster.contains_key(&new_key));
        assert!(late_fold.pending_widens.contains_key(&pending_hash));

        let late_after =
            fold_authority_log_with_seen_times(&[genesis, pending], &late_seen, delay * 2);
        assert_eq!(early_fold.roster, late_after.roster);
        assert!(late_after.pending_widens.is_empty());
    }

    #[test]
    fn concurrent_restriction_beats_pending_widen_after_delay() {
        let owner = ed_key(68);
        let second = ed_key(69);
        let target = ed_key(70);
        let target_key = authority_key_from_ed(&target);
        let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(68, delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_second = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 69,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Hardware,
                seq: 1,
                ts: 2,
            },
        );
        let pending = enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 70,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let revoke = cosign_ed(
            revoke_entry(vault_id, &enroll_second, &second, target_key.clone(), 0),
            &second,
            &owner,
        );
        let first_seen = BTreeMap::from([
            (authority_entry_hash(&enroll_second).unwrap(), 0),
            (pending_hash, delay),
        ]);

        let fold = fold_authority_log_with_seen_times(
            &[pending, revoke, enroll_second, genesis],
            &first_seen,
            delay * 2,
        );
        let folded = fold
            .roster
            .get(&target_key)
            .expect("restriction tombstone should keep the target visible");
        assert!(folded.revoked);
        assert_eq!(folded.roles, 0);
    }

    #[test]
    fn genesis_delay_knob_defaults_within_band_and_custom_delay_is_honored() {
        let owner = ed_key(71);
        let custom_delay = MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS;
        let genesis = genesis_entry(71, custom_delay, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 72,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let first_seen = BTreeMap::from([(pending_hash, 0)]);

        let before = fold_authority_log_with_seen_times(
            &[genesis.clone(), pending.clone()],
            &first_seen,
            custom_delay - 1,
        );
        assert_eq!(
            before.pending_widens[&pending_hash].delay_secs,
            custom_delay
        );
        assert!(
            !before
                .roster
                .contains_key(&authority_key_from_ed(&ed_key(72)))
        );

        let after =
            fold_authority_log_with_seen_times(&[genesis, pending], &first_seen, custom_delay);
        assert!(
            after
                .roster
                .contains_key(&authority_key_from_ed(&ed_key(72)))
        );
    }

    #[test]
    fn timestamp_is_advisory_for_fold_output() {
        let owner = ed_key(7);
        let genesis_a = genesis_entry(7, 86_400, 1);
        let genesis_b = genesis_entry(7, 86_400, 999_999);
        let vault_a = genesis_vault_id(&genesis_a).unwrap();
        let vault_b = genesis_vault_id(&genesis_b).unwrap();
        let enroll_a = enroll_entry(vault_a, &genesis_a, &owner, 8, 1, 2);
        let enroll_b = enroll_entry(vault_b, &genesis_b, &owner, 8, 1, 999_998);

        let fold_a = fold_authority_log(&[genesis_a, enroll_a]);
        let fold_b = fold_authority_log(&[genesis_b, enroll_b]);
        let roles_a: Vec<_> = fold_a
            .roster
            .values()
            .map(|device| (device.roles, device.revoked))
            .collect();
        let roles_b: Vec<_> = fold_b
            .roster
            .values()
            .map(|device| (device.roles, device.revoked))
            .collect();
        assert_eq!(roles_a, roles_b);
    }

    proptest! {
        #[test]
        fn equivocation_alarm_is_permutation_invariant(
            perm in prop::collection::vec(0_usize..4, 4),
        ) {
            let owner = ed_key(90);
            let genesis = genesis_entry(90, 86_400, 1);
            let vault_id = genesis_vault_id(&genesis).unwrap();
            let enroll = enroll_entry(vault_id, &genesis, &owner, 91, 1, 2);
            let left = set_ceiling_entry(vault_id, &enroll, &owner, 2, 3);
            let right = set_tier_floor_entry(vault_id, &enroll, &owner, 2, AuthorityTier::Hardware);
            let entries = vec![genesis, enroll, left, right];
            let baseline = fold_authority_log_without_seen_time_delay(&entries);

            let mut permuted = Vec::new();
            for index in perm {
                if let Some(entry) = entries.get(index % entries.len()) {
                    permuted.push(entry.clone());
                }
            }
            for entry in &entries {
                if !permuted.iter().any(|candidate| candidate == entry) {
                    permuted.push(entry.clone());
                }
            }

            let folded = fold_authority_log_without_seen_time_delay(&permuted);
            prop_assert_eq!(folded.authority_forks, baseline.authority_forks);
            prop_assert_eq!(folded.fork_alarms, baseline.fork_alarms);
            prop_assert_eq!(folded.valid_entries, baseline.valid_entries);
        }

        #[test]
        fn fold_permutation_property_including_pending_widen_delay(
            delay in 86_400_u64..=172_800,
            include_revoke in any::<bool>(),
            perm in prop::collection::vec(0_usize..4, 4),
        ) {
            let owner = ed_key(10);
            let genesis = genesis_entry(10, delay, 11);
            let vault_id = genesis_vault_id(&genesis).unwrap();
            let enroll_a = enroll_entry(vault_id, &genesis, &owner, 11, 1, 12);
            let enroll_b = enroll_entry(vault_id, &genesis, &owner, 12, 2, 13);
            let revoke = revoke_entry(
                vault_id,
                &enroll_a,
                &owner,
                authority_key_from_ed(&ed_key(11)),
                3,
            );
            let mut entries = vec![genesis, enroll_a, enroll_b];
            if include_revoke {
                entries.push(revoke);
            }
            let baseline = fold_authority_log(&entries);

            let mut permuted = Vec::new();
            for index in perm {
                if let Some(entry) = entries.get(index % entries.len()) {
                    permuted.push(entry.clone());
                }
            }
            for entry in &entries {
                if !permuted.iter().any(|candidate| candidate == entry) {
                    permuted.push(entry.clone());
                }
            }
            let folded = fold_authority_log(&permuted);
            prop_assert_eq!(folded.vault_id, baseline.vault_id);
            prop_assert_eq!(folded.roster, baseline.roster);
            prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
        }

        #[test]
        fn fold_seen_time_veto_race_is_permutation_invariant(
            delay in 86_400_u64..=172_800,
            include_veto in any::<bool>(),
            perm in prop::collection::vec(0_usize..3, 3),
        ) {
            let owner = ed_key(20);
            let genesis = genesis_entry(20, delay, 21);
            let vault_id = genesis_vault_id(&genesis).unwrap();
            let pending = enroll_device_entry(
                vault_id,
                &genesis,
                &owner,
                EnrollSpec {
                    seed: 21,
                    roles: ROLE_ADMIN,
                    tier: AuthorityTier::Software,
                    seq: 1,
                    ts: 22,
                },
            );
            let pending_hash = authority_entry_hash(&pending).unwrap();
            let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
            let mut entries = vec![genesis, pending];
            if include_veto {
                entries.push(veto);
            }
            let first_seen = BTreeMap::from([(pending_hash, 0)]);
            let baseline = fold_authority_log_with_seen_times(&entries, &first_seen, delay - 1);

            let mut permuted = Vec::new();
            for index in perm {
                if let Some(entry) = entries.get(index % entries.len()) {
                    permuted.push(entry.clone());
                }
            }
            for entry in &entries {
                if !permuted.iter().any(|candidate| candidate == entry) {
                    permuted.push(entry.clone());
                }
            }
            let folded = fold_authority_log_with_seen_times(&permuted, &first_seen, delay - 1);
            prop_assert_eq!(folded.vault_id, baseline.vault_id);
            prop_assert_eq!(folded.roster, baseline.roster);
            prop_assert_eq!(folded.pending_widens, baseline.pending_widens);
            prop_assert_eq!(folded.vetoed_widens, baseline.vetoed_widens);
            prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
        }
    }
}
