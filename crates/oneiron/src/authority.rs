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
mod tests;
