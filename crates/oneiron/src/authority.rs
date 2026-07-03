//! AUTHORITY_LOG record substrate.
//!
//! Type 122 is a fold-verified maintenance log. Replay doors validate the
//! record shape and embedded origin signature only; authority semantics stay in
//! [`fold_authority_log`], where the roster is derived from peer-signed log
//! entries rather than from a server-issued registry.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

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

const CONFIRM_KIND_ACCEPT: &str = "accept";
const CONFIRM_KIND_RESCOPE: &str = "rescope";
const CONFIRM_KIND_A2A_CONNECT: &str = "a2a_connect";
const CONFIRM_KIND_REVOKE: &str = "revoke";

const MAX_PARENTS: usize = 32;
const MAX_COSIGNS: usize = 8;
const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 4096;
const MAX_ACTOR_CLASS_BYTES: usize = 64;

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
    /// Fold diagnostics.
    pub issues: Vec<AuthorityFoldIssue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FoldState {
    vault_id: AuthorityVaultId,
    roster: BTreeMap<AuthorityKey, FoldedDevice>,
    tier_floor: AuthorityTier,
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
    let canonical = encode_authority_log_entry_body(&entry)?;
    if canonical != bytes {
        return Err(invalid_authority());
    }
    verify_entry_signatures(&entry)?;
    Ok(entry)
}

/// Validates body bytes for write/replay doors.
pub fn validate_authority_log_entry_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_authority_log_entry_body(bytes).map(|_| ())
}

/// BLAKE3 hash of the canonical signed authority entry.
pub fn authority_entry_hash(entry: &AuthorityLogEntry) -> Result<AuthorityEntryHash> {
    Ok(*blake3::hash(&encode_authority_log_entry_body(entry)?).as_bytes())
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
    let unsigned = encode_value(&transcript_value(entry))?;
    let mut transcript = Vec::with_capacity(AUTHORITY_TRANSCRIPT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(AUTHORITY_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

fn transcript_value(entry: &AuthorityLogEntry) -> Value {
    Value::Map(vec![
        (Value::from("entry"), entry_value(entry, false)),
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

/// Folds a set of authority entries into a deterministic roster.
pub fn fold_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
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
    let mut equivocation_groups =
        BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>::new();
    let mut equivocation_by_hash = BTreeMap::<AuthorityEntryHash, (AuthorityKey, u64)>::new();
    for ((signer, seq), hashes) in by_signer_seq {
        if hashes.len() > 1 {
            for hash in &hashes {
                equivocation_by_hash.insert(*hash, (signer.clone(), seq));
            }
            equivocation_groups.insert((signer.clone(), seq), hashes);
            issues.push(AuthorityFoldIssue::EquivocationDetected { signer, seq });
        }
    }

    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash.keys().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let hashes: Vec<_> = pending.iter().copied().collect();
        for hash in hashes {
            let entry = &by_hash[&hash];
            if let Some(group_key) = equivocation_by_hash.get(&hash) {
                let group = &equivocation_groups[group_key];
                match resolve_equivocation_group(group, &by_hash, &states, &pending) {
                    EquivocationResolution::Waiting => continue,
                    EquivocationResolution::Resolved {
                        winner,
                        issues: group_issues,
                    } => {
                        if let Some((winner_hash, state)) = winner {
                            states.insert(winner_hash, state);
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
            match fold_entry_state(entry, hash, &states) {
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

    AuthorityFold {
        vault_id: merged.as_ref().map(|state| state.vault_id),
        valid_entries,
        roster: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.roster.clone()),
        tier_floor: merged.as_ref().map(|state| state.tier_floor),
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
        winner: Option<(AuthorityEntryHash, FoldState)>,
        issues: Vec<AuthorityFoldIssue>,
    },
    Waiting,
}

fn resolve_equivocation_group(
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
) -> EquivocationResolution {
    let mut ready = Vec::<(AuthorityEntryHash, FoldState)>::new();
    let mut issues = Vec::new();
    for hash in group {
        let entry = &by_hash[hash];
        match fold_entry_state(entry, *hash, states) {
            EntryFold::Ready(state) => ready.push((*hash, state)),
            EntryFold::Invalid(issue) => issues.push(issue),
            EntryFold::Waiting if entry_waits_on_pending_parent(entry, states, pending) => {
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
    let winner = ready.remove(0);
    for (loser, _) in ready {
        issues.push(AuthorityFoldIssue::InvalidEntry(loser));
    }
    EquivocationResolution::Resolved {
        winner: Some(winner),
        issues,
    }
}

fn entry_waits_on_pending_parent(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
) -> bool {
    entry
        .parent_hashes
        .iter()
        .any(|parent| !states.contains_key(parent) && pending.contains(parent))
}

fn compare_fork_rank(
    (left_hash, left): &(AuthorityEntryHash, FoldState),
    (right_hash, right): &(AuthorityEntryHash, FoldState),
) -> Ordering {
    fork_rank(left, *left_hash).cmp(&fork_rank(right, *right_hash))
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
) -> EntryFold {
    if entry.validate_shape().is_err() || verify_entry_signatures(entry).is_err() {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }

    if let AuthorityOp::Genesis {
        device, tier_floor, ..
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
    if state
        .roster
        .get(&signer)
        .is_none_or(|device| device.revoked)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    let participants = match active_participant_keys(&state, entry) {
        Ok(participants) => participants,
        Err(issue) => return EntryFold::Invalid(issue),
    };
    if !has_authority_consent(&state, &participants) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if entry_requires_peer_cosign(entry)
        && active_roster_count(&state) >= 2
        && participants.len() < 2
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if revoke_would_break_quorum(&state, entry, &participants) {
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
    apply_op(&mut state, &entry.op);
    if !state_has_authority_consent(&state) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    state.seqs.insert(signer, entry.seq);
    EntryFold::Ready(state)
}

fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
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

fn state_has_authority_consent(state: &FoldState) -> bool {
    state
        .roster
        .values()
        .any(folded_device_can_authority_consent)
}

fn folded_device_can_authority_consent(device: &FoldedDevice) -> bool {
    !device.revoked
        && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
        && (device.roles & ROLE_CLOUD) == 0
        && device.tier != AuthorityTier::CloudCustodial
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
        | AuthorityOp::FederationConfirm(_) => false,
    }
}

fn entry_requires_peer_cosign(entry: &AuthorityLogEntry) -> bool {
    !matches!(entry.op, AuthorityOp::Genesis { .. })
}

fn revoke_would_break_quorum(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
        return false;
    };
    let active_before = active_roster_count(state);
    let active_after = active_before
        - usize::from(
            state
                .roster
                .get(revoked_key)
                .is_some_and(|device| !device.revoked),
        );
    participants.len() < 2 || active_after < 2
}

fn active_roster_count(state: &FoldState) -> usize {
    state
        .roster
        .values()
        .filter(|device| !device.revoked && device.roles != 0)
        .count()
}

fn merge_states(left: &FoldState, right: &FoldState) -> FoldState {
    debug_assert_eq!(left.vault_id, right.vault_id);
    let mut merged = left.clone();
    merged.tier_floor = most_restrictive_tier_floor(left.tier_floor, right.tier_floor);
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

fn apply_op(state: &mut FoldState, op: &AuthorityOp) {
    match op {
        AuthorityOp::Genesis { .. } => {}
        AuthorityOp::EnrollDevice { device } => upsert_device(state, device),
        AuthorityOp::RevokeDevice { revoked_key } => revoke_key(state, revoked_key),
        AuthorityOp::SetCeiling { .. } | AuthorityOp::FederationConfirm(_) => {}
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => {
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
            for device in state.roster.values_mut() {
                device.revoked = true;
            }
            state.tier_floor = most_restrictive_tier_floor(state.tier_floor, *tier_floor);
            upsert_device(state, new_device);
        }
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
    let transcript = authority_transcript(entry)?;
    if !verify_authority_signature(&entry.signer, &transcript) {
        return Err(invalid_authority());
    }
    for cosign in &entry.cosigns {
        if !verify_authority_signature(cosign, &transcript) {
            return Err(invalid_authority());
        }
    }
    Ok(())
}

fn validate_op(op: &AuthorityOp) -> Result<()> {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            ..
        } => {
            if genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
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
    }
}

fn entry_value(entry: &AuthorityLogEntry, include_signatures: bool) -> Value {
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
        (Value::from(KEY_OP), op_value(&entry.op)),
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

fn op_value(op: &AuthorityOp) -> Value {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            tier_floor,
            pending_widen_delay_secs,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_GENESIS)),
            (Value::from("device"), device_value(device)),
            (Value::from("genesis_nonce"), binary_value(*genesis_nonce)),
            (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
            (
                Value::from("pending_widen_delay_secs"),
                Value::from(*pending_widen_delay_secs),
            ),
        ]),
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
            Ok(AuthorityOp::Genesis {
                device: decode_device(required(entries, "device")?)?,
                genesis_nonce: decode_hash(required(entries, "genesis_nonce")?)?,
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
                pending_widen_delay_secs: required(entries, "pending_widen_delay_secs")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
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

    fn enroll_entry(
        vault_id: AuthorityVaultId,
        parent: &AuthorityLogEntry,
        signer: &SigningKey,
        new_key_seed: u8,
        seq: u64,
        ts: u64,
    ) -> AuthorityLogEntry {
        let signer_key = authority_key_from_ed(signer);
        let new = ed_key(new_key_seed);
        let op = AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&new),
                ROLE_AGENT | ROLE_CLOUD,
                AuthorityTier::Software,
            ),
        };
        sign_ed(
            unsigned_entry(
                Some(vault_id),
                seq,
                vec![authority_entry_hash(parent).unwrap()],
                op,
                signer_key,
                ts,
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

        assert!(active_participant_keys(&state, &entry).is_err());
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
            fold_entry_state(&entry, hash, &BTreeMap::from([(parent, state)])),
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
            fold_entry_state(&entry, hash, &BTreeMap::from([(parent, state)])),
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
            fold_entry_state(&entry, hash, &BTreeMap::from([(parent, state)])),
            EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(issue_hash))
                if issue_hash == hash
        ));
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
            fold_entry_state(&entry, hash, &BTreeMap::from([(parent, state)])),
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

        let fold = fold_authority_log(&[
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

        let fold = fold_authority_log(&[revoke.clone(), enroll, genesis]);
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

        let fold = fold_authority_log(&[enroll_third, restrict_floor, enroll_second, genesis]);
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

        let fold = fold_authority_log(&[first_new_signer_entry, enroll_admin, genesis]);
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
    }
}
