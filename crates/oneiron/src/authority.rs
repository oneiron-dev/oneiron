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

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationDirectionScope, FederationPactScope, decode_federation_direction_scope_value,
    decode_federation_pact_scope_value, encode_federation_pact_scope,
    federation_direction_scope_value, federation_pact_scope_value,
};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::temporal::TimeRange;
use crate::unix_seconds_now;
use crate::vault::entity_id_from_type_index_key;

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

/// The DURABLE vault identity: 32 BLAKE3 bytes derived from the canonical
/// signed genesis entry (see [`genesis_vault_id`]).
///
/// This is the only thing that identifies a vault. A `vtN` presentation slug is
/// a display alias that RESOLVES to one of these
/// (`registry::IdNamespaceTarget::Vault`); it is not an identity, carries no
/// authority, and never appears in a hash, a transcript, or a signature.
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
const OP_KIND_CRITICAL_WRITE_CONFIRM: &str = "critical_write_confirm";
const OP_KIND_VETO_PENDING_WIDEN: &str = "veto_pending_widen";
const OP_KIND_FEDERATION_LIFECYCLE: &str = "federation_lifecycle";
const OP_KIND_BIND_ACTOR: &str = "bind_actor";
const OP_KIND_REBIND_ACTOR: &str = "rebind_actor";
const OP_KIND_REVOKE_ACTOR: &str = "revoke_actor";

/// The EXACT actor-class vocabulary a binding tuple may name (ONE-1604-D2).
///
/// Deliberately narrower than `SetCeiling`'s free-form class string: an
/// approximate class is the ESB-C defect, so anything outside this list fails
/// closed at `validate_op`. Mirrors `EdgeActorClass::gate_actor_class`.
const ACTOR_BINDING_CLASSES: [&str; 3] = ["human", "agent", "system"];

const CONFIRM_KIND_ACCEPT: &str = "accept";
const CONFIRM_KIND_RESCOPE: &str = "rescope";
const CONFIRM_KIND_A2A_CONNECT: &str = "a2a_connect";
const CONFIRM_KIND_REVOKE: &str = "revoke";

const LIFECYCLE_KIND_CONNECT: &str = "connect";
const LIFECYCLE_KIND_RESCOPE: &str = "rescope";
const LIFECYCLE_KIND_DISCONNECT: &str = "disconnect";
const LIFECYCLE_KIND_PROMOTE: &str = "promote";
const LIFECYCLE_KIND_DISSOLVE: &str = "dissolve";

/// Domain-separated transcript prefix for federation pact gestures.
pub const FEDERATION_PACT_DOMAIN: &[u8] = b"oneiron/federation/pact/v1";
/// Domain-separated prefix for the federation pact scope commitment.
pub const FEDERATION_SCOPE_COMMIT_DOMAIN: &[u8] = b"oneiron/federation/pact-scope/v1";
/// Upper bound for encoded federation pact scope bytes in a lifecycle op.
pub const MAX_PACT_SCOPE_BYTES: usize = 4096;

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

/// Federation relationship lifecycle kind (OF-156, option B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FederationLifecycleKind {
    /// Dual-signed pact creation.
    Connect,
    /// Dual-signed re-pact (epoch bump) or unilateral effective-scope narrow.
    Rescope,
    /// Unilateral terminal severance.
    Disconnect,
    /// Dual-signed terminal succession into a co-owned vault.
    Promote,
    /// Unilateral terminal dissolution.
    Dissolve,
}

impl FederationLifecycleKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => LIFECYCLE_KIND_CONNECT,
            Self::Rescope => LIFECYCLE_KIND_RESCOPE,
            Self::Disconnect => LIFECYCLE_KIND_DISCONNECT,
            Self::Promote => LIFECYCLE_KIND_PROMOTE,
            Self::Dissolve => LIFECYCLE_KIND_DISSOLVE,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            LIFECYCLE_KIND_CONNECT => Some(Self::Connect),
            LIFECYCLE_KIND_RESCOPE => Some(Self::Rescope),
            LIFECYCLE_KIND_DISCONNECT => Some(Self::Disconnect),
            LIFECYCLE_KIND_PROMOTE => Some(Self::Promote),
            LIFECYCLE_KIND_DISSOLVE => Some(Self::Dissolve),
            _ => None,
        }
    }
}

/// Peer owner's signed gesture over the pact transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactGesture {
    /// Peer owner authority key (Ed25519 or P-256).
    pub signer: AuthorityKey,
    /// Raw signature bytes over [`federation_pact_transcript`]; 64 bytes for
    /// both suites.
    pub signature: Vec<u8>,
}

/// Fold-verified federation lifecycle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationLifecycleAction {
    /// Lifecycle kind.
    pub kind: FederationLifecycleKind,
    /// Shared pact identifier — identical on both vaults' logs.
    pub pact_id: [u8; 32],
    /// Local FEDERATION_GRANT entity this pact governs.
    pub grant_ref: EntityId,
    /// Peer vault id (peer's genesis hash).
    pub peer_vault_id: AuthorityVaultId,
    /// Pact consent epoch: Connect == 1; repact/Promote == cur+1;
    /// narrow/Disconnect/Dissolve == cur.
    pub pact_epoch: u64,
    /// Full disclosed scope pair. Some for Connect and Rescope-repact only.
    pub pact_scope: Option<FederationPactScope>,
    /// Local-outbound effective scope. Some ONLY for Rescope-narrow.
    pub effective_scope: Option<FederationDirectionScope>,
    /// Keyed scope commitment. Some for Connect / Rescope-repact / Promote.
    pub scope_digest: Option<[u8; 32]>,
    /// Peer owner gesture. Some for Connect / Rescope-repact / Promote.
    pub gesture: Option<FederationPactGesture>,
    /// Successor co-owned vault id. Some ONLY for Promote.
    pub successor_vault_id: Option<AuthorityVaultId>,
    /// Pact nonce feeding the scope commitment and transcript. Never all-zero.
    pub pact_nonce: [u8; 16],
}

/// Fold-derived status of one federation pact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FederationPactStatus {
    /// Pact is live; its grant confers access.
    Active,
    /// Equivocation-shaped divergence detected; confers nothing until a fresh
    /// dual-signed re-pact heals it.
    Suspended,
    /// Terminal: succeeded by a co-owned vault.
    Promoted,
    /// Terminal: unilaterally severed.
    Disconnected,
    /// Terminal: unilaterally dissolved.
    Dissolved,
}

impl FederationPactStatus {
    /// Terminal statuses reject every further lifecycle op.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Promoted | Self::Disconnected | Self::Dissolved)
    }
}

/// Fold-derived state of one federation pact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactState {
    /// Current pact status.
    pub status: FederationPactStatus,
    /// Governed FEDERATION_GRANT entity.
    pub grant_ref: EntityId,
    /// Peer vault id.
    pub peer_vault_id: AuthorityVaultId,
    /// Peer owner key pinned at Connect (TOFU).
    pub peer_owner_key: AuthorityKey,
    /// Current pact consent epoch.
    pub pact_epoch: u64,
    /// Dual-signed scope commitment for the current ceiling.
    pub scope_digest: [u8; 32],
    /// Dual-signed ceiling scope pair.
    pub pact_scope: FederationPactScope,
    /// OUR outbound overlay, always ⊑ our half of the ceiling.
    pub effective_scope: FederationDirectionScope,
    /// Successor co-owned vault id, set by Promote.
    pub successor_vault_id: Option<AuthorityVaultId>,
    /// Epoch at which the pact went terminal.
    pub terminal_epoch: Option<u64>,
}

/// Activation of a federation grant against the fold-derived pact state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationGrantActivation {
    /// No lifecycle entries name this grant; legacy-allow.
    Unpacted,
    /// Pact-bound and Active.
    Active,
    /// Pact-bound and non-Active; confers nothing.
    Inactive(FederationPactStatus),
}

/// Deterministic per-entry rejection reason for lifecycle ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationLifecycleRejection {
    /// Non-Connect op names a pact absent from ancestry.
    UnknownPact,
    /// Connect names an already-known pact id.
    DuplicateConnect,
    /// Connect names a grant_ref already bound to a pact, or a lifecycle op
    /// names a grant_ref that conflicts with the pact's recorded binding.
    GrantAlreadyBound,
    /// Op targets a terminal (Promoted/Disconnected/Dissolved) pact.
    TerminalPact,
    /// Rescope-narrow/Promote on a suspended pact.
    SuspendedPact,
    /// Pact epoch violates the per-kind epoch rule.
    EpochMismatch,
    /// Required peer gesture is missing.
    GestureMissing,
    /// Peer gesture failed verification (bad signature, local-roster signer,
    /// or non-pinned signer).
    GestureInvalid,
    /// Scope digest does not commit to the carried scope, or Promote's digest
    /// differs from the stored one.
    ScopeDigestMismatch,
    /// Unilateral narrow escapes the dual-signed ceiling.
    WidenWithoutGesture,
    /// Op names a different peer vault than the pact records.
    PeerVaultMismatch,
    /// Carried scope failed structural validation.
    ScopeInvalid,
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

pub const CRITICAL_WRITE_CONFIRM_DOMAIN: &[u8] = b"oneiron/authority/critical-write-confirm/v1";
pub const CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriticalWriteConfirmDisposition {
    Clear,
    Decline,
}
impl CriticalWriteConfirmDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Decline => "decline",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "clear" => Some(Self::Clear),
            "decline" => Some(Self::Decline),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriticalWriteConfirmMethod {
    TokenReauth,
    PassphraseReentry,
}
impl CriticalWriteConfirmMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::TokenReauth => "token_reauth",
            Self::PassphraseReentry => "passphrase_reentry",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "token_reauth" => Some(Self::TokenReauth),
            "passphrase_reentry" => Some(Self::PassphraseReentry),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmAction {
    pub schema_version: u64,
    pub confirm_id: [u8; 32],
    pub gate_decision_id: [u8; 16],
    pub claim_id: EntityId,
    pub effect_digest: [u8; 32],
    pub read_frontier_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
    pub disposition: CriticalWriteConfirmDisposition,
    pub method: CriticalWriteConfirmMethod,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmState {
    pub action: CriticalWriteConfirmAction,
    pub signer: AuthorityKey,
    pub authority_entry_hash: AuthorityEntryHash,
}

/// Pinned operation vocabulary for AUTHORITY_LOG.
// The FederationLifecycle payload (scope pair + gesture) dominates the enum
// size; its unboxed shape is pinned by ONE-1408, so the skew is accepted.
#[allow(clippy::large_enum_variant)]
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
    EnrollDevice {
        device: DeviceAuthority,
    },
    /// Revokes an authority key.
    RevokeDevice {
        revoked_key: AuthorityKey,
    },
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
    SetTierFloor {
        tier_floor: AuthorityTier,
    },
    /// Rebootstraps authority after recovery.
    RecoveryReboot {
        new_genesis_nonce: [u8; 32],
        new_device: DeviceAuthority,
        tier_floor: AuthorityTier,
    },
    /// Federation confirm that travels with authority fold verification.
    FederationConfirm(AuthorityConfirmAction),
    CriticalWriteConfirm(CriticalWriteConfirmAction),
    /// Owner veto for a software-tier widen that is still pending.
    VetoPendingWiden {
        /// Target authority entry hash to suppress under most-restrictive-wins.
        pending_widen_hash: AuthorityEntryHash,
    },
    /// Federation relationship lifecycle op (OF-156, option B).
    FederationLifecycle(FederationLifecycleAction),
    /// Binds a roster authority key to a store actor entity at an EXACT actor
    /// class (ONE-1604-D2 tuple). Establishes `epoch` for this key's binding;
    /// rejected in the fold if a live binding already exists (use
    /// `RebindActor`) or the epoch does not advance past the revocation
    /// watermark.
    BindActor {
        /// Roster key the binding attaches to.
        authority_key: AuthorityKey,
        /// Store actor entity the key speaks for.
        actor_ref: EntityId,
        /// EXACT class: `"human"`, `"agent"`, or `"system"`.
        actor_class: String,
        /// Binding epoch; must advance past the revocation watermark.
        epoch: u64,
    },
    /// Replaces the live binding of `authority_key` with a new
    /// actor_ref/class/epoch. Rejected in the fold when no live binding exists.
    RebindActor {
        /// Roster key whose live binding is replaced.
        authority_key: AuthorityKey,
        /// New store actor entity.
        actor_ref: EntityId,
        /// New EXACT class.
        actor_class: String,
        /// New epoch; must be strictly greater than the live binding's.
        epoch: u64,
    },
    /// Revokes the binding of `authority_key` through `epoch` (inclusive
    /// watermark). Applies unconditionally — revocation is always
    /// most-restrictive-safe, in any arrival order.
    RevokeActor {
        /// Roster key whose binding is revoked.
        authority_key: AuthorityKey,
        /// Inclusive revocation watermark.
        epoch: u64,
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
    /// Entry lost deterministic selection to the winner of its equivocation group.
    EquivocationLoser {
        /// Losing entry hash.
        entry: AuthorityEntryHash,
        /// Equivocating authority key.
        signer: AuthorityKey,
        /// Conflicting signer sequence number.
        seq: u64,
        /// Deterministically selected entry hash.
        winner: AuthorityEntryHash,
    },
    /// Federation lifecycle entry rejected by the pact state machine.
    FederationLifecycleRejected {
        /// Rejected entry hash.
        entry: AuthorityEntryHash,
        /// Deterministic rejection reason.
        reason: FederationLifecycleRejection,
    },
    /// Distinct sibling entries collided on a critical confirmation id or nonce.
    CriticalWriteConfirmConflict {
        /// Deterministic surviving confirmation id.
        confirm_id: [u8; 32],
    },
    /// A Bind/Rebind/RevokeActor op failed the binding transition table.
    ActorBindingRejected {
        /// Rejected entry hash.
        entry: AuthorityEntryHash,
        /// Deterministic rejection reason.
        reason: ActorBindingRejection,
    },
}

/// Why the fold refused an actor-binding op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorBindingRejection {
    /// `BindActor` on a key that already holds a live binding (use rebind).
    BindingExists,
    /// `RebindActor` on a key with no live binding.
    BindingMissing,
    /// Epoch did not advance past the watermark or the prior binding.
    EpochNotAdvanced,
    /// Bound key is absent from, or revoked in, the ancestry roster.
    KeyNotInRoster,
    /// A `"human"`-class bind whose key lacks owner/admin consent capability.
    OwnerCapabilityRequired,
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
    /// Fold-derived federation pact states keyed by pact id.
    pub federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    pub critical_write_confirms: BTreeMap<[u8; 32], CriticalWriteConfirmState>,
    pub consumed_critical_write_confirm_nonces: BTreeSet<[u8; 16]>,
    /// Confirm ids made unusable by a deterministic sibling collision.
    pub conflicted_critical_write_confirms: BTreeSet<[u8; 32]>,
    /// Every (grant_ref → pact ids) binding a folded valid Connect has EVER
    /// established, merged by union across branches.
    ///
    /// Concurrent valid Connects can bind one pact id to two different
    /// grant_refs on divergent branches; the pact-state merge keeps a single
    /// deterministic binding, so this registry is what keeps the DISCARDED
    /// binding pact-bound: a grant that appears here never falls back to
    /// `Unpacted` legacy-allow.
    pub federation_grant_bindings: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// Folded actor-binding tuples keyed by authority key (ONE-1604-D2).
    pub actor_bindings: BTreeMap<AuthorityKey, FoldedActorBinding>,
    /// Fold diagnostics.
    pub issues: Vec<AuthorityFoldIssue>,
}

/// One folded `{signing_key_id, actor_ref, actor_class, epoch, status}` tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedActorBinding {
    /// Store actor entity the key speaks for.
    pub actor_ref: EntityId,
    /// EXACT bound class: `"human"`, `"agent"`, or `"system"`.
    pub actor_class: String,
    /// Binding epoch.
    pub epoch: u64,
    /// Whether this binding currently authorizes.
    pub status: ActorBindingStatus,
}

/// Liveness of a folded actor binding.
///
/// `Revoked` deliberately covers watermark-dead, merge-conflicted, AND
/// roster-dead bindings: one dead state, no taxonomy inflation. Callers only
/// ever need "does this bind authorize".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorBindingStatus {
    /// Binding authorizes: live epoch, unconflicted, live roster key.
    Active,
    /// Binding does not authorize, for any reason.
    Revoked,
}

/// True iff `actor_ref` holds an ACTIVE binding at EXACTLY `actor_class`.
///
/// This is the owner-verb predicate. Multiple keys may bind one actor, so any
/// Active hit passes. For class `"human"` the bound key must itself carry
/// owner capability (enforced at fold time — see the bind transition table),
/// so `Active` here is sufficient and callers need no second roster lookup.
#[must_use]
pub fn actor_binding_is_active(
    fold: &AuthorityFold,
    actor_ref: &EntityId,
    actor_class: &str,
) -> bool {
    fold.actor_bindings.values().any(|binding| {
        binding.status == ActorBindingStatus::Active
            && binding.actor_ref == *actor_ref
            && binding.actor_class == actor_class
    })
}

impl AuthorityFold {
    /// True when [`Self::vault_id`] is `None` because the log carries MORE THAN
    /// ONE independently rooted vault, not because it carries no root at all.
    ///
    /// The two `None`s mean opposite things to a caller: an unrooted log has
    /// declared no authority yet, while a multi-root log declared authority and
    /// then collapsed — the fold clears the roster, bindings, and pacts and
    /// keeps only the [`AuthorityFoldIssue::ConflictingVaultRoot`] rows. Every
    /// authority gate MUST fail closed on the second, so the distinction is
    /// exposed here rather than re-derived (and inevitably mis-derived) at each
    /// call site.
    #[must_use]
    pub fn vault_root_is_conflicted(&self) -> bool {
        self.vault_id.is_none()
            && self
                .issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
    }

    /// Pact state governing `grant_ref`, if any lifecycle entries name it.
    ///
    /// Concurrent Connects on divergent branches can bind one grant_ref under
    /// two pact ids; the MOST-RESTRICTIVE status wins (Dissolved >
    /// Disconnected > Promoted > Suspended > Active; ties: lowest pact id) so
    /// a grant shadowed by any non-Active pact never authorizes.
    #[must_use]
    pub fn pact_for_grant(&self, grant_ref: &EntityId) -> Option<&FederationPactState> {
        let mut best: Option<&FederationPactState> = None;
        for state in self.federation_pacts.values() {
            if state.grant_ref != *grant_ref {
                continue;
            }
            if best.is_none_or(|current| state.status > current.status) {
                best = Some(state);
            }
        }
        best
    }
}

/// Activation of `grant_ref` under the fold's pact states.
///
/// Grants without lifecycle entries stay `Unpacted` (legacy-allow). For
/// pact-bound grants the activation folds over EVERY pact the grant was ever
/// bound to (via [`AuthorityFold::federation_grant_bindings`], a superset of
/// the live pact states' operative `grant_ref`s) — never just the first live
/// pact naming it: a grant bound to any suspended or terminal pact is
/// `Inactive` regardless of another of its pacts being `Active`. `Active`
/// requires the grant to be the OPERATIVE binding of every pact it was ever
/// bound to, with all of them `Active`; a binding superseded by a
/// divergent-binding merge or an epoch bump therefore reports `Inactive`
/// (carrying the most restrictive live status, possibly `Active`) and never
/// returns to `Unpacted` or `Active`.
#[must_use]
pub fn federation_grant_activation(
    fold: &AuthorityFold,
    grant_ref: &EntityId,
) -> FederationGrantActivation {
    let Some(pact_ids) = fold.federation_grant_bindings.get(grant_ref) else {
        return FederationGrantActivation::Unpacted;
    };
    let mut every_binding_operative_active = true;
    let mut most_restrictive: Option<FederationPactStatus> = None;
    for pact_id in pact_ids {
        // The fold never registers a binding without its pact state; a
        // missing state fails closed as a suspended, non-operative binding.
        let (status, operative) = match fold.federation_pacts.get(pact_id) {
            Some(state) => (state.status, state.grant_ref == *grant_ref),
            None => (FederationPactStatus::Suspended, false),
        };
        if status != FederationPactStatus::Active || !operative {
            every_binding_operative_active = false;
        }
        most_restrictive = Some(most_restrictive.map_or(status, |worst| worst.max(status)));
    }
    match most_restrictive {
        Some(_) if every_binding_operative_active => FederationGrantActivation::Active,
        Some(status) => FederationGrantActivation::Inactive(status),
        // Registered binding sets are never empty; fail closed if one is.
        None => FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
    }
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
    /// Keys revoked by operations allowed to resolve authority forks.
    ///
    /// Rotation revocations are deliberately excluded: a forked signer cannot
    /// clear its own alarm by making a self-rotation the equivocation winner.
    fork_resolution_revocations: BTreeSet<AuthorityKey>,
    authority_forks: BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    critical_write_confirms: BTreeMap<[u8; 32], CriticalWriteConfirmState>,
    consumed_critical_write_confirm_nonces: BTreeSet<[u8; 16]>,
    conflicted_critical_write_confirms: BTreeSet<[u8; 32]>,
    federation_grant_bindings: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// Live binding content per authority key (`RevokeActor` never edits this).
    ///
    /// Kept SEPARATE from the revocation watermarks so a `RevokeActor` folding
    /// on a branch that never saw the bind needs no placeholder content.
    actor_bindings: BTreeMap<AuthorityKey, ActorBindingState>,
    /// Inclusive revocation watermark per authority key, merged by max.
    actor_binding_revocations: BTreeMap<AuthorityKey, u64>,
    seqs: BTreeMap<AuthorityKey, u64>,
}

/// Fold-internal binding content for one authority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorBindingState {
    /// Store actor entity the key speaks for.
    pub actor_ref: EntityId,
    /// EXACT bound class.
    pub actor_class: String,
    /// Binding epoch.
    pub epoch: u64,
    /// Set when divergent same-epoch bindings merged — fail-closed dead.
    pub conflicted: bool,
}

impl FoldState {
    /// A binding is live iff it out-epochs the revocation watermark and no
    /// divergent same-epoch merge poisoned it. Liveness is DERIVED, never
    /// stored, so revoke and bind can arrive in any order.
    fn live_actor_binding(&self, key: &AuthorityKey) -> Option<&ActorBindingState> {
        let binding = self.actor_bindings.get(key)?;
        let watermark = self
            .actor_binding_revocations
            .get(key)
            .copied()
            .unwrap_or(0);
        (binding.epoch > watermark && !binding.conflicted).then_some(binding)
    }
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

/// Content-addressed store key for an AUTHORITY_LOG row: the first 16 bytes
/// of the BLAKE3 [`authority_entry_hash`] (ONE-1604-D1). The store key is a
/// pure function of the canonical signed body, so replacement-at-key cannot
/// edit fold history; `signer + seq` remains the fold GROUPING key (two keys,
/// two jobs). Fails closed on the negligible reserved-sentinel collision.
pub fn authority_log_entity_id_from_hash(hash: &AuthorityEntryHash) -> Result<EntityId> {
    let mut bytes = [0u8; crate::entity_id::ENTITY_ID_LEN];
    bytes.copy_from_slice(&hash[..crate::entity_id::ENTITY_ID_LEN]);
    EntityId::from_bytes(bytes).map_err(|_| {
        Error::InvalidAuthorityLogBody("authority entry hash collides with a reserved entity id")
    })
}

/// Derives the content-addressed entity id for a signed authority entry.
pub fn authority_log_entity_id(entry: &AuthorityLogEntry) -> Result<EntityId> {
    authority_log_entity_id_from_hash(&authority_entry_hash(entry)?)
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

/// Domain-separated, side-symmetric transcript both pact owners sign.
///
/// `vault_a`/`vault_b` may be passed in either order; the transcript sorts
/// them ascending byte-wise into `vault_lo`/`vault_hi`, so both sides sign
/// byte-identical bytes. `successor_vault_id` must be `Some` exactly for
/// [`FederationLifecycleKind::Promote`].
#[allow(clippy::too_many_arguments)]
pub fn federation_pact_transcript(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor_vault_id: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
) -> Result<Vec<u8>> {
    if (kind == FederationLifecycleKind::Promote) != successor_vault_id.is_some() {
        return Err(invalid_authority());
    }
    let (vault_lo, vault_hi) = if vault_a <= vault_b {
        (vault_a, vault_b)
    } else {
        (vault_b, vault_a)
    };
    let value = Value::Map(vec![
        (Value::from("kind"), Value::from(kind.as_str())),
        (Value::from("pact_id"), binary_value(*pact_id)),
        (Value::from("vault_lo"), binary_value(*vault_lo)),
        (Value::from("vault_hi"), binary_value(*vault_hi)),
        (Value::from("pact_epoch"), Value::from(pact_epoch)),
        (Value::from("scope_digest"), binary_value(*scope_digest)),
        (
            Value::from("successor_vault_id"),
            successor_vault_id.map_or(Value::Nil, |successor| binary_value(*successor)),
        ),
        (Value::from("pact_nonce"), binary_value_16(*pact_nonce)),
    ]);
    let unsigned = encode_value(&value)?;
    let mut transcript = Vec::with_capacity(FEDERATION_PACT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(FEDERATION_PACT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

/// Domain-separated nonce commitment over canonical pact scope bytes.
///
/// `blake3(FEDERATION_SCOPE_COMMIT_DOMAIN || pact_nonce || canonical_scope)`;
/// the gesture transcript carries only this digest, so a gesture shown to a
/// third party does not disclose scope contents.
#[must_use]
pub fn federation_scope_digest(pact_nonce: &[u8; 16], canonical_scope: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        FEDERATION_SCOPE_COMMIT_DOMAIN.len() + pact_nonce.len() + canonical_scope.len(),
    );
    material.extend_from_slice(FEDERATION_SCOPE_COMMIT_DOMAIN);
    material.extend_from_slice(pact_nonce);
    material.extend_from_slice(canonical_scope);
    *blake3::hash(&material).as_bytes()
}

/// Builds a peer gesture by signing the pact transcript with `signer`.
///
/// Pure helper usable from either side of the pact; the closure signs the
/// domain-prefixed transcript bytes (the `sign_guest_share_envelope` pattern).
#[allow(clippy::too_many_arguments)]
pub fn sign_federation_pact_gesture<S>(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor_vault_id: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
    signer_key: AuthorityKey,
    signer: S,
) -> Result<FederationPactGesture>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let transcript = federation_pact_transcript(
        kind,
        pact_id,
        vault_a,
        vault_b,
        pact_epoch,
        scope_digest,
        successor_vault_id,
        pact_nonce,
    )?;
    let signature = signer(&transcript)?;
    Ok(FederationPactGesture {
        signer: signer_key,
        signature,
    })
}

#[derive(Clone, Copy)]
struct FoldContext<'a> {
    first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
    vetoed_widens: &'a BTreeSet<AuthorityEntryHash>,
    authority_forks: &'a BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    authority_fork_vault_ids: &'a BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    equivocation_groups: &'a BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>,
    unresolved_equivocation_groups: &'a BTreeSet<(AuthorityKey, u64)>,
    entry_ancestors: Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
    chain_validated_fork_candidates: Option<&'a BTreeSet<AuthorityEntryHash>>,
    /// Consent roots of every ADMITTED PEER roster, keyed by peer vault id.
    ///
    /// EVIDENCE for FED-01 gesture acceptance, never a local consent
    /// constituency: nothing in this map can admit a local entry, hold local
    /// quorum, or enter the local roster. EMPTY on every fold path that has not
    /// been handed admitted peer logs — including the peer-side fold itself,
    /// which has no peers of its own.
    peer_consent_roots: &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// Which consent predicate this fold run admits entries under.
    ///
    /// [`folded_device_can_authority_consent`] on every LOCAL path;
    /// [`folded_peer_device_is_consent_root`] only inside
    /// [`fold_peer_authority_log`].
    consent_arm: fn(&FoldedDevice) -> bool,
}

impl FoldContext<'_> {
    fn device_can_consent(self, device: &FoldedDevice) -> bool {
        (self.consent_arm)(device)
    }
}

/// Folds a set of authority entries into a deterministic roster.
///
/// Entries missing local first-seen timestamps remain pending; callers with
/// local seen-time data should use [`fold_authority_log_with_seen_times`].
pub fn fold_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        Some(0),
        true,
        &peer_consent_roots,
        folded_device_can_authority_consent,
    )
}

#[cfg(test)]
fn fold_authority_log_without_seen_time_delay(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        false,
        &peer_consent_roots,
        folded_device_can_authority_consent,
    )
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
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_with_peer_consent_roots(
        entries,
        first_seen_at_secs,
        now_secs,
        &peer_consent_roots,
    )
}

/// [`fold_authority_log_with_seen_times`] with the consent roots of every
/// admitted peer roster in scope for FED-01 gesture acceptance.
///
/// The local fold is otherwise IDENTICAL — same consent arm, same roster, same
/// vault id. `peer_consent_roots` only widens which peer signature a lifecycle
/// gesture may carry, and only for the peer vault the gesture already names.
pub(crate) fn fold_authority_log_with_peer_consent_roots(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        true,
        peer_consent_roots,
        folded_device_can_authority_consent,
    )
}

/// Peer-side roster fold: same fold machinery, same transcript domain, two
/// swaps.
///
/// The consent arm becomes the unfiltered host-root predicate
/// ([`folded_peer_device_is_consent_root`]), and there are no seen-times: a
/// peer's widen is not a LOCAL observation, so it can never force a local
/// pending state. Peer entries carry no local first-observation time and stay
/// inside the peer fold's own epoch semantics.
///
/// The output is evidence, not authority: it never enters the local roster.
#[must_use]
pub fn fold_peer_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        false,
        &peer_consent_roots,
        folded_peer_device_is_consent_root,
    )
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

/// Verdict text carried by the [`Error::CorruptedIndex`] a readonly fold raises
/// when the one-shot first-seen migration has ALREADY run and an AUTHORITY_LOG
/// row still has no readable first-seen sidecar.
///
/// The migration is one-shot by its marker, so it will never regenerate that
/// row: the delay clock for the affected entry is unrecoverable in place. A
/// fold cannot then decide whether a delayable widen — a rotation, a recovery
/// reboot — has elapsed, and BOTH guesses are unsafe (assume elapsed and a
/// widen skips its veto window; assume pending and a rotation's RETIRED key
/// stays live). The only sound answer is to refuse the fold and let the caller
/// suspend whatever it was about to authorize.
pub(crate) const AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT: &str =
    "authority first-seen sidecar missing or unreadable after backfill";

/// Whether `err` is the corrupt-sidecar verdict above.
pub(crate) fn is_corrupt_first_seen_sidecar(err: &Error) -> bool {
    matches!(err, Error::CorruptedIndex(msg) if *msg == AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT)
}

/// Verdict text carried when a readonly fold's delay decision would rest on a
/// first-seen time this vault has never actually OBSERVED.
///
/// First-seen is a LOCAL observation, and the only local record of it is the
/// sidecar. Before the one-shot migration runs there is no such record for a
/// legacy row, so the readonly fold can only guess — and the peer-claimed
/// `learned_at` in the entity header is not a permissible guess: it is written
/// by whoever shipped the row. A legacy `EnrollDevice` carrying `learned_at =
/// 0` would otherwise read as first seen in 1970, i.e. matured before it
/// arrived, and a child `BindActor` on the newly owner-capable key would fold
/// ACTIVE with no veto window at all.
///
/// So the fold assumes the safe end — first seen NOW, the maximum remaining
/// delay — and that leaves every affected delayable widen pending. Pending is
/// fail-closed for the ops that only GRANT, but `RotateKey` and
/// `RecoveryReboot` also REVOKE: an un-applied rotation keeps the RETIRED key
/// in the roster with its actor binding live. Whenever an indeterminate row
/// actually lands in `pending_widens`, the fold therefore refuses instead of
/// authorizing on a roster it cannot pin down.
///
/// Unlike [`AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT`] this state is recoverable
/// and self-healing: one [`Vault::authority_fold`] runs the migration, records
/// the local observation, and the delay runs out from there.
pub(crate) const AUTHORITY_FIRST_SEEN_INDETERMINATE: &str =
    "authority first-seen time is not locally observed yet (pre-migration authority log)";

/// Whether `err` is the indeterminate-first-seen verdict above.
pub(crate) fn is_indeterminate_first_seen(err: &Error) -> bool {
    matches!(err, Error::CorruptedIndex(msg) if *msg == AUTHORITY_FIRST_SEEN_INDETERMINATE)
}

/// One clock domain's monotonic ANCHOR: the observed second count
/// `anchor_secs` and the [`Instant`] `anchor_instant` it was taken at.
///
/// The pair is an anchor, NOT a running total, and that is the whole point.
/// `Duration::as_secs` truncates, so a fold at 09:00:00.4 and another at
/// 09:00:00.9 each measure zero elapsed WHOLE seconds. Advancing the anchor on
/// every call would bank those zeros and discard the 0.4 s and 0.5 s remainders
/// forever — a caller folding faster than 1 Hz would freeze `now_secs` at its
/// first observation, so no veto delay would ever mature and every owner verb
/// resting on a delayable widen would wedge (fail-safe, but an availability
/// hole). Keeping the anchor fixed makes each call measure real elapsed time
/// from ONE origin, so the sub-second remainders accumulate and the second
/// boundary is crossed exactly when it is crossed in wall time.
struct AuthorityLocalClock {
    anchor_instant: Instant,
    anchor_secs: u64,
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
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match clocks.get_mut(&clock_domain) {
        Some(clock) => {
            let elapsed = now
                .saturating_duration_since(clock.anchor_instant)
                .as_secs();
            let anchored = clock.anchor_secs.saturating_add(elapsed);
            // The persisted floor is the only thing that may REBASE the anchor:
            // a floor above the anchor-derived value means another writer (or a
            // reopen) advanced local observation past this domain's origin, so
            // the floor becomes the new origin and `now` its instant. Rebasing
            // here is safe precisely because it is monotone upward — it can
            // delay a widen, never skip one.
            if previous_floor > anchored {
                clock.anchor_secs = previous_floor;
                clock.anchor_instant = now;
                return previous_floor;
            }
            anchored
        }
        None => {
            let observed = candidate_wall_secs.max(previous_floor);
            clocks.insert(
                clock_domain,
                AuthorityLocalClock {
                    anchor_instant: now,
                    anchor_secs: observed,
                },
            );
            observed
        }
    }
}

pub(crate) fn release_authority_clock_domain(clock_domain: usize) {
    let mut clocks = authority_local_clocks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
) -> AuthorityFold {
    let mut vetoed_widens = BTreeSet::new();
    let mut authority_forks = BTreeMap::new();
    let mut authority_fork_vault_ids = BTreeMap::new();
    let empty_equivocation_groups = BTreeMap::new();
    let empty_unresolved_equivocation_groups = BTreeSet::new();
    let (mut fold, mut folded_authority_fork_vault_ids) = fold_authority_log_once(
        entries,
        FoldContext {
            first_seen_at_secs,
            now_secs,
            enforce_seen_time_delay,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            authority_fork_vault_ids: &authority_fork_vault_ids,
            equivocation_groups: &empty_equivocation_groups,
            unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
            entry_ancestors: None,
            chain_validated_fork_candidates: None,
            peer_consent_roots,
            consent_arm,
        },
    );
    for _ in 0..=entries.len() {
        // Every fork discovered by the pass becomes quarantined input to the
        // next pass, even when a later sibling resolved its reported row. The
        // seeded quarantine is positional: entries outside the resolver's
        // ancestry are re-checked without the forked key, while folding the
        // resolver lifts the quarantine only for its descendants. Scope sets
        // keep this safe when the same fork spans conflicting vault roots.
        let mut next_authority_forks = BTreeMap::new();
        let mut next_authority_fork_vault_ids = BTreeMap::new();
        for fork in &fold.authority_forks {
            let key = (fork.signer.clone(), fork.seq);
            if let Some(fork_vault_ids) = folded_authority_fork_vault_ids.get(&key) {
                let mut quarantined = fork.clone();
                quarantined.status = AuthorityForkStatus::Quarantined;
                next_authority_forks.insert(key.clone(), quarantined);
                next_authority_fork_vault_ids.insert(key, fork_vault_ids.clone());
            }
        }
        if fold.vetoed_widens == vetoed_widens
            && next_authority_forks == authority_forks
            && next_authority_fork_vault_ids == authority_fork_vault_ids
        {
            return fold;
        }
        vetoed_widens = fold.vetoed_widens.clone();
        authority_forks = next_authority_forks;
        authority_fork_vault_ids = next_authority_fork_vault_ids;
        (fold, folded_authority_fork_vault_ids) = fold_authority_log_once(
            entries,
            FoldContext {
                first_seen_at_secs,
                now_secs,
                enforce_seen_time_delay,
                vetoed_widens: &vetoed_widens,
                authority_forks: &authority_forks,
                authority_fork_vault_ids: &authority_fork_vault_ids,
                equivocation_groups: &empty_equivocation_groups,
                unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
                entry_ancestors: None,
                chain_validated_fork_candidates: None,
                peer_consent_roots,
                consent_arm,
            },
        );
    }
    fold
}

fn fold_authority_log_once(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
) -> (
    AuthorityFold,
    BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
) {
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
            if restore_prefix_divergence(&hashes, &by_hash, &entry_ancestors, context) {
                continue;
            }
            for hash in &hashes {
                equivocation_by_hash.insert(*hash, (signer.clone(), seq));
            }
            equivocation_groups.insert((signer.clone(), seq), hashes);
        }
    }
    // `entry_ancestors` is deliberately a raw graph index: fold scheduling
    // needs claimed ancestry to avoid making a parent wait on the candidate
    // that names it. It is not sufficient evidence that an entry predates a
    // fork, because signature-valid but chain-invalid candidates also
    // contribute arbitrary parent claims. Restrict that security-sensitive
    // exemption to candidates that independently fold over their complete
    // available ancestry.
    let chain_validated_fork_candidates = equivocation_groups
        .values()
        .flatten()
        .filter(|hash| {
            entry_folds_on_available_ancestry(**hash, &by_hash, &entry_ancestors, context)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let mut authority_forks = context.authority_forks.clone();
    let mut authority_fork_vault_ids = context.authority_fork_vault_ids.clone();
    let mut reported_authority_forks = BTreeMap::<(AuthorityKey, u64), AuthorityFork>::new();
    let mut reported_authority_fork_resolved_vault_ids =
        BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>::new();
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
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(&entry_ancestors),
                    chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
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
                        fork,
                        fork_vault_ids,
                        issues: group_issues,
                    } => {
                        // The per-round hash snapshot can revisit a second
                        // member of an already-resolved group; only the first
                        // resolution may emit facts, or every group member
                        // duplicates the detection and loser issues.
                        if !unresolved_equivocation_groups.remove(&group_key) {
                            continue;
                        }
                        if let Some(fork) = fork {
                            authority_forks.insert(group_key.clone(), fork.clone());
                            reported_authority_forks.insert(group_key.clone(), fork);
                            authority_fork_vault_ids.insert(group_key.clone(), fork_vault_ids);
                        }
                        if let Some((winner_hash, state)) = winner {
                            issues.push(AuthorityFoldIssue::EquivocationDetected {
                                signer: group_key.0.clone(),
                                seq: group_key.1,
                            });
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
                authority_fork_vault_ids: &authority_fork_vault_ids,
                equivocation_groups: &equivocation_groups,
                unresolved_equivocation_groups: &unresolved_equivocation_groups,
                entry_ancestors: Some(&entry_ancestors),
                chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
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
        if !progressed {
            // The round made no progress, so every hash still pending is stuck
            // for good under ordinary rules. ONLY here — never while entries may
            // still be waiting their turn — may a revocation resolve against the
            // ancestry ABOVE a parent that will never fold.
            let stalled: Vec<_> = pending.iter().copied().collect();
            for hash in stalled {
                if equivocation_by_hash.contains_key(&hash) {
                    continue;
                }
                let entry = &by_hash[&hash];
                let fold_context = FoldContext {
                    authority_forks: &authority_forks,
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(&entry_ancestors),
                    chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
                    ..context
                };
                let Some(bypass_states) =
                    revocation_bypass_states(entry, &by_hash, &states, &pending, fold_context)
                else {
                    continue;
                };
                // Ready only. A revocation the bypass cannot justify stays
                // pending and is reported as `InvalidAncestry` below, exactly as
                // before — the bypass may rescue a revocation, never admit one.
                if let EntryFold::Ready(state) =
                    fold_entry_state(entry, hash, &bypass_states, fold_context)
                {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
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
        for state in states.values() {
            reconcile_reported_authority_forks(
                &mut reported_authority_forks,
                &authority_fork_vault_ids,
                &mut reported_authority_fork_resolved_vault_ids,
                state,
            );
        }
        let authority_forks: Vec<_> = reported_authority_forks.values().cloned().collect();
        let fork_alarms = build_fork_alarms(&authority_forks);
        return (
            AuthorityFold {
                vault_id: None,
                valid_entries: BTreeSet::new(),
                roster: BTreeMap::new(),
                tier_floor: None,
                pending_widens: BTreeMap::new(),
                vetoed_widens: BTreeSet::new(),
                authority_forks,
                fork_alarms,
                federation_pacts: BTreeMap::new(),
                critical_write_confirms: BTreeMap::new(),
                consumed_critical_write_confirm_nonces: BTreeSet::new(),
                conflicted_critical_write_confirms: BTreeSet::new(),
                federation_grant_bindings: BTreeMap::new(),
                actor_bindings: BTreeMap::new(),
                issues,
            },
            authority_fork_vault_ids,
        );
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

    if let Some(state) = &merged {
        reconcile_reported_authority_forks(
            &mut reported_authority_forks,
            &authority_fork_vault_ids,
            &mut reported_authority_fork_resolved_vault_ids,
            state,
        );
    }
    let authority_forks: Vec<_> = reported_authority_forks.into_values().collect();
    let fork_alarms = build_fork_alarms(&authority_forks);
    // Collision poison is part of the externally auditable fold result, not
    // merely a settlement-time guard. Emit one deterministic issue per id.
    if let Some(state) = &merged {
        issues.extend(
            state
                .conflicted_critical_write_confirms
                .iter()
                .map(
                    |confirm_id| AuthorityFoldIssue::CriticalWriteConfirmConflict {
                        confirm_id: *confirm_id,
                    },
                ),
        );
    }
    let actor_bindings = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        folded_actor_bindings(state, &authority_forks)
    });

    (
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
            federation_pacts: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.federation_pacts.clone()),
            critical_write_confirms: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.critical_write_confirms.clone()),
            consumed_critical_write_confirm_nonces: merged
                .as_ref()
                .map_or_else(BTreeSet::new, |state| {
                    state.consumed_critical_write_confirm_nonces.clone()
                }),
            conflicted_critical_write_confirms: merged
                .as_ref()
                .map_or_else(BTreeSet::new, |state| {
                    state.conflicted_critical_write_confirms.clone()
                }),
            federation_grant_bindings: merged.as_ref().map_or_else(BTreeMap::new, |state| {
                state.federation_grant_bindings.clone()
            }),
            actor_bindings,
            issues,
        },
        authority_fork_vault_ids,
    )
}

/// Projects fold-internal binding state onto the public tuple.
///
/// Status is computed HERE rather than stored, so roster death propagates for
/// free: `RevokeDevice`/`RotateKey`/`RecoveryReboot` kill dependent bindings
/// automatically and order-independently, with no cascade written into binding
/// state. A rotation deliberately does NOT migrate a binding — the old binding
/// dies with the old key and the new key needs a fresh `BindActor`.
///
/// Roster presence alone is NOT enough. The projection re-runs the bind
/// transition table's key predicate against the MERGED roster, because two
/// things can invalidate a key AFTER a valid bind folded:
///
/// * The merge's most-restrictive `roles &=` can strip the OWNER|ADMIN bits (or
///   demote the tier) that admitted a `"human"` bind on a divergent branch. A
///   binding whose key can no longer give owner consent must not keep backing
///   the owner class.
/// * AUTH-5 equivocation quarantines the key itself. A key that signed
///   divergent content at one sequence is exactly the key an attacker holds;
///   letting it keep speaking for a human owner is the fail-open the quarantine
///   exists to prevent. Quarantine is a live-fork property, so it is read from
///   the reported forks rather than from roster state.
fn folded_actor_bindings(
    state: &FoldState,
    authority_forks: &[AuthorityFork],
) -> BTreeMap<AuthorityKey, FoldedActorBinding> {
    state
        .actor_bindings
        .iter()
        .map(|(key, binding)| {
            let status = if folded_binding_key_still_qualifies(state, authority_forks, key, binding)
                && state.live_actor_binding(key).is_some()
            {
                ActorBindingStatus::Active
            } else {
                ActorBindingStatus::Revoked
            };
            (
                key.clone(),
                FoldedActorBinding {
                    actor_ref: binding.actor_ref,
                    actor_class: binding.actor_class.clone(),
                    epoch: binding.epoch,
                    status,
                },
            )
        })
        .collect()
}

/// The bind transition table's key predicate, re-evaluated post-merge.
///
/// Mirrors `apply_actor_binding` exactly — live roster row for every class,
/// plus owner-consent capability for `"human"` — so a role/tier restriction
/// that would have REJECTED the bind also kills it retroactively. Any key with
/// a still-quarantined fork fails outright, whatever its roles.
fn folded_binding_key_still_qualifies(
    state: &FoldState,
    authority_forks: &[AuthorityFork],
    key: &AuthorityKey,
    binding: &ActorBindingState,
) -> bool {
    if authority_forks
        .iter()
        .any(|fork| fork.signer == *key && fork.status == AuthorityForkStatus::Quarantined)
    {
        return false;
    }
    let Some(device) = state.roster.get(key).filter(|device| !device.revoked) else {
        return false;
    };
    binding.actor_class != "human" || folded_device_can_authority_consent(device)
}

fn reconcile_reported_authority_forks(
    reported: &mut BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    authority_fork_vault_ids: &BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    resolved_vault_ids: &mut BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    state: &FoldState,
) {
    for (key, fork) in reported.iter() {
        let applies_to_state = authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id));
        let state_records_resolution = state
            .authority_forks
            .get(key)
            .is_some_and(|state_fork| state_fork.status == AuthorityForkStatus::Resolved);
        if applies_to_state
            && (state.fork_resolution_revocations.contains(&fork.signer)
                || state_records_resolution)
        {
            resolved_vault_ids
                .entry(key.clone())
                .or_default()
                .insert(state.vault_id);
        }
    }
    for (key, fork) in &state.authority_forks {
        if !authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id))
        {
            continue;
        }
        if fork.status == AuthorityForkStatus::Resolved {
            resolved_vault_ids
                .entry(key.clone())
                .or_default()
                .insert(state.vault_id);
        }
        reported
            .entry(key.clone())
            .or_insert_with(|| AuthorityFork {
                status: AuthorityForkStatus::Quarantined,
                ..fork.clone()
            });
    }
    for (key, fork) in reported.iter_mut() {
        // A non-empty scope is resolved only after every named vault has a
        // real RevokeDevice/RecoveryReboot resolution in that vault. Empty
        // scope means universal: a local real revocation lifts only that
        // state's gate, while the global alarm remains quarantined because no
        // finite set of vaults can prove universal resolution.
        fork.status = if authority_fork_vault_ids.get(key).is_some_and(|vault_ids| {
            !vault_ids.is_empty()
                && resolved_vault_ids
                    .get(key)
                    .is_some_and(|resolved| vault_ids.is_subset(resolved))
        }) {
            AuthorityForkStatus::Resolved
        } else {
            AuthorityForkStatus::Quarantined
        };
    }
}

fn build_fork_alarms(forks: &[AuthorityFork]) -> Vec<AuthorityForkAlarm> {
    forks
        .iter()
        .map(|fork| AuthorityForkAlarm {
            signer: fork.signer.clone(),
            seq: fork.seq,
            first_hash: fork.first_hash,
            second_hash: fork.second_hash,
        })
        .collect()
}

enum EntryFold {
    Ready(FoldState),
    Waiting,
    Invalid(AuthorityFoldIssue),
}

#[expect(
    clippy::large_enum_variant,
    reason = "transient per-group resolution value; one instance lives on the stack at a time"
)]
enum EquivocationResolution {
    Resolved {
        winner: Option<(AuthorityEntryHash, Box<FoldState>)>,
        fork: Option<AuthorityFork>,
        fork_vault_ids: BTreeSet<AuthorityVaultId>,
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
    let mut invalid_candidates = Vec::new();
    let mut issues = Vec::new();
    for hash in group {
        let entry = &by_hash[hash];
        match fold_entry_state(entry, *hash, states, context) {
            EntryFold::Ready(state) => {
                let rank_state = equivocation_rank_state(entry, *hash, &state);
                ready.push((*hash, state, rank_state));
            }
            EntryFold::Invalid(issue) => {
                invalid_candidates.push(*hash);
                issues.push(issue);
            }
            EntryFold::Waiting
                if entry_waits_on_pending_parent_outside_group(entry, states, pending, group) =>
            {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting if entry_waits_on_unresolved_equivocation(entry, *hash, context) => {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting => {
                invalid_candidates.push(*hash);
                issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
            }
        }
    }

    if ready.is_empty() {
        let mut fork = authority_fork_from_group(&group_key.0, group_key.1, group);
        if fork_group_signer_has_resolution_revocation_in_folded_ancestry(
            &group_key.0,
            group,
            by_hash,
            states,
        ) && let Some(fork) = &mut fork
        {
            fork.status = AuthorityForkStatus::Resolved;
        }
        return EquivocationResolution::Resolved {
            winner: None,
            fork,
            fork_vault_ids: authority_fork_vault_ids_from_group(group, by_hash, states, None),
            issues,
        };
    }

    ready.sort_by(compare_fork_rank);
    let mut ready = ready.into_iter();
    let mut winner = None;
    let mut rejected_candidates = Vec::new();
    for (candidate_hash, mut candidate_state, _) in ready.by_ref() {
        record_authority_fork(&mut candidate_state, &group_key.0, group_key.1, group);
        if matches!(
            &by_hash[&candidate_hash].op,
            AuthorityOp::RevokeDevice { revoked_key } if revoked_key == &group_key.0
        ) {
            resolve_recorded_authority_fork(&mut candidate_state, &group_key.0, group_key.1);
        }
        if let Some(issue) = fork_winner_post_quarantine_issue(
            &candidate_state,
            states,
            context,
            candidate_hash,
            &by_hash[&candidate_hash],
            &group_key.0,
        ) {
            issues.push(issue);
            rejected_candidates.push(candidate_hash);
            continue;
        }
        winner = Some((candidate_hash, Box::new(candidate_state)));
        break;
    }
    if let Some((winner_hash, _)) = &winner {
        for loser in rejected_candidates
            .into_iter()
            .chain(invalid_candidates)
            .chain(ready.map(|(loser, _, _)| loser))
        {
            issues.push(AuthorityFoldIssue::EquivocationLoser {
                entry: loser,
                signer: group_key.0.clone(),
                seq: group_key.1,
                winner: *winner_hash,
            });
        }
    }
    let fork = winner
        .as_ref()
        .and_then(|(_, state)| state.authority_forks.get(group_key).cloned())
        .or_else(|| authority_fork_from_group(&group_key.0, group_key.1, group));
    let fork_vault_ids = authority_fork_vault_ids_from_group(
        group,
        by_hash,
        states,
        winner.as_ref().map(|(_, state)| state.as_ref()),
    );
    EquivocationResolution::Resolved {
        winner,
        fork,
        fork_vault_ids,
        issues,
    }
}

fn authority_fork_vault_ids_from_group(
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    winner: Option<&FoldState>,
) -> BTreeSet<AuthorityVaultId> {
    // Fail closed across every plausible attack scope. Folded parent vaults
    // identify logs the candidates tried to extend, while claimed ids cover
    // missing-parent groups; a winner's vault covers entries without a claim.
    let mut vault_ids: BTreeSet<_> = group
        .iter()
        .filter_map(|hash| by_hash.get(hash))
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter_map(|parent| states.get(parent).map(|state| state.vault_id))
        .collect();
    vault_ids.extend(
        group
            .iter()
            .filter_map(|hash| by_hash.get(hash).and_then(|entry| entry.vault_id)),
    );
    if let Some(winner) = winner {
        vault_ids.insert(winner.vault_id);
    }
    vault_ids
}

fn fork_group_signer_has_resolution_revocation_in_folded_ancestry(
    signer: &AuthorityKey,
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> bool {
    group.iter().all(|hash| {
        let entry = &by_hash[hash];
        let mut parent_states = entry.parent_hashes.iter().map(|parent| states.get(parent));
        let Some(Some(first_parent)) = parent_states.next() else {
            return false;
        };
        let vault_id = first_parent.vault_id;
        let mut signer_has_resolution_revocation =
            first_parent.fork_resolution_revocations.contains(signer);
        for parent_state in parent_states {
            let Some(parent_state) = parent_state else {
                return false;
            };
            if parent_state.vault_id != vault_id {
                return false;
            }
            signer_has_resolution_revocation |=
                parent_state.fork_resolution_revocations.contains(signer);
        }
        signer_has_resolution_revocation
    })
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

fn fork_winner_post_quarantine_issue(
    state: &FoldState,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    forked_key: &AuthorityKey,
) -> Option<AuthorityFoldIssue> {
    match &entry.op {
        AuthorityOp::RevokeDevice { .. } => {
            if active_roster_count_after_fork_quarantine(state, entry, context, hash, forked_key)
                < 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
            if !state_has_authority_consent_after_fork_quarantine(
                state, entry, context, hash, forked_key,
            ) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
        }
        AuthorityOp::RecoveryReboot { .. } if entry_participants_include_key(entry, forked_key) => {
            let Some(parent_state) = folded_parent_state_for_entry(entry, states) else {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            };
            let independent_participants = participants_without_key(entry, forked_key);
            if independent_participants.len() < 2
                || active_roster_count_after_fork_quarantine(
                    &parent_state,
                    entry,
                    context,
                    hash,
                    forked_key,
                ) < 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
            if !has_authority_consent(&parent_state, &independent_participants, context) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
        }
        // Binding ops MINT or MOVE actor identity, and a fork winner's signer
        // is by construction the forked key — precisely the signature an
        // attacker holds. fix-1 already kills a binding whose BOUND key is
        // quarantined; that leaves the sibling hole this arm closes, where the
        // quarantined key spends its last pre-quarantine act binding owner
        // class onto a DIFFERENT, clean, owner-capable roster key. Nothing
        // downstream can see that: `folded_actor_bindings` judges the bound
        // key, which is spotless.
        //
        // The re-derivation demands NOTHING new — it is the entry's own two
        // admission rules (`has_authority_consent` over its participants, and
        // the peer-cosign quorum rule) run again with the forked key deleted
        // from both sides. A bind an untainted owner-capable cosigner
        // independently backs still stands; a bind whose only owner authority
        // WAS the forked key does not.
        AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. } => {
            let independent_participants = participants_without_key(entry, forked_key);
            if !has_authority_consent(state, &independent_participants, context) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
            if independent_participants.len() < 2
                && active_roster_count_after_fork_quarantine(state, entry, context, hash, forked_key)
                    >= 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
        }
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::RecoveryReboot { .. }
        | AuthorityOp::FederationConfirm(_) | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        // RevokeActor only raises a revocation watermark: it strips authority
        // and can never mint it, so re-scrutinizing it could only resurrect a
        // binding the quarantined key wanted gone.
        | AuthorityOp::RevokeActor { .. } => {}
    }
    None
}

fn entry_participants_include_key(entry: &AuthorityLogEntry, key: &AuthorityKey) -> bool {
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .any(|signature| signature.public_key == *key)
}

/// The entry's signer + cosigners with `key` deleted — the participant set a
/// post-quarantine re-check must judge the entry on.
fn participants_without_key(
    entry: &AuthorityLogEntry,
    key: &AuthorityKey,
) -> BTreeSet<AuthorityKey> {
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .map(|signature| &signature.public_key)
        .filter(|participant| *participant != key)
        .cloned()
        .collect()
}

fn folded_parent_state_for_entry(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> Option<FoldState> {
    let mut parent_state = None;
    for parent in &entry.parent_hashes {
        let state = states.get(parent)?;
        if parent_state
            .as_ref()
            .is_some_and(|current: &FoldState| current.vault_id != state.vault_id)
        {
            return None;
        }
        parent_state = Some(match parent_state {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }
    parent_state
}

fn active_roster_count_after_fork_quarantine(
    state: &FoldState,
    entry: &AuthorityLogEntry,
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
                && !key_is_quarantined_for_entry(
                    state,
                    context,
                    key,
                    hash,
                    Some((entry.signer_key(), entry.seq)),
                )
        })
        .count()
}

fn state_has_authority_consent_after_fork_quarantine(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    forked_key: &AuthorityKey,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        key != forked_key
            && context.device_can_consent(device)
            && !key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
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
        if &key.0 == revoked_key
            && context
                .authority_fork_vault_ids
                .get(key)
                .is_some_and(|vault_ids| {
                    vault_ids.is_empty() || vault_ids.contains(&state.vault_id)
                })
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

fn resolve_global_forks_for_recovery_reboot(state: &mut FoldState, context: FoldContext<'_>) {
    for (key, fork) in context.authority_forks {
        if context
            .authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id))
            && state.fork_resolution_revocations.contains(&fork.signer)
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

/// `prefork` carries the validated entry's own `(signer, seq)` when the
/// caller is judging that entry's participants. The forked signer's entries
/// at a chain position strictly before the fork seq are pre-fork by
/// construction (seq continuity is enforced against the folded parent
/// state), which matters when the fork candidates' ancestry is unresolvable
/// (missing parents) and the ancestor-based exemption cannot see them.
/// The exemption covers the entry SIGNER only: a cosign carries no chain
/// position, so cosigned entries need an ancestry proof or fail closed.
/// Scans without a concrete entry context pass `None` and stay fail-closed.
fn key_is_quarantined_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    key: &AuthorityKey,
    entry_hash: AuthorityEntryHash,
    prefork: Option<(&AuthorityKey, u64)>,
) -> bool {
    state
        .authority_forks
        .values()
        .any(|fork| fork_quarantines_key_for_entry(state, context, fork, key, entry_hash, prefork))
        || context.authority_forks.iter().any(|(fork_key, fork)| {
            context
                .authority_fork_vault_ids
                .get(fork_key)
                .is_some_and(|vault_ids| {
                    vault_ids.is_empty() || vault_ids.contains(&state.vault_id)
                })
                && fork_quarantines_key_for_entry(state, context, fork, key, entry_hash, prefork)
        })
}

fn fork_quarantines_key_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    fork: &AuthorityFork,
    key: &AuthorityKey,
    entry_hash: AuthorityEntryHash,
    prefork: Option<(&AuthorityKey, u64)>,
) -> bool {
    let signer_at_or_after_fork =
        prefork.is_some_and(|(signer, entry_seq)| signer == key && entry_seq >= fork.seq);
    fork.signer == *key
        && fork.status == AuthorityForkStatus::Quarantined
        && !fork_resolved_in_state(state, key, fork.seq)
        // A fork candidate itself must remain evaluable. For every other
        // entry signed by the forked key, its own chain position is decisive:
        // seq >= fork.seq is post-fork and may not use any ancestry claim as
        // a prefork exemption.
        && !entry_is_fork_candidate(context, key, fork.seq, entry_hash)
        && (signer_at_or_after_fork
            || !entry_is_validated_prefork_ancestor(context, key, fork.seq, entry_hash))
        // Only the entry signer's own seq orders the entry against the fork
        // point (seq continuity: a second entry at the same seq would form
        // its own equivocation group). A cosign carries no chain position —
        // a folded-state seq below the fork proves only that the cosigner's
        // SIGNING chain stalled prefork, not that the cosign happened
        // prefork, and a quarantined key could keep cosigning new entries
        // forever without ever advancing it. Cosigned entries are therefore
        // exempt only via chain-validated ancestry proof above; without one
        // they fail closed.
        && !prefork.is_some_and(|(signer, seq)| signer == key && seq < fork.seq)
}

fn fork_resolved_in_state(state: &FoldState, key: &AuthorityKey, seq: u64) -> bool {
    state
        .authority_forks
        .get(&(key.clone(), seq))
        .is_some_and(|fork| fork.status == AuthorityForkStatus::Resolved)
}

fn entry_is_fork_candidate(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    context
        .equivocation_groups
        .get(&lookup)
        .is_some_and(|group| group.contains(&entry_hash))
}

fn entry_is_validated_prefork_ancestor(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(chain_validated_candidates) = context.chain_validated_fork_candidates else {
        return false;
    };
    group.iter().any(|fork_hash| {
        chain_validated_candidates.contains(fork_hash)
            && ancestors
                .get(fork_hash)
                .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

fn entry_is_claimed_prefork_or_fork_candidate(
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
            // Raw claimed ancestry is sufficient only for scheduling: a
            // candidate must not make the parent it claims wait on that same
            // candidate. Quarantine exemptions use chain-validated ancestry.
            if entry_is_claimed_prefork_or_fork_candidate(context, fork_key, *fork_seq, hash) {
                return false;
            }
            (fork_key == signer && *fork_seq < entry.seq)
                || entry
                    .cosigns
                    .iter()
                    .any(|signature| signature.public_key == *fork_key)
                || matches!(&entry.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == fork_key)
                || (*fork_seq < entry.seq
                    && recovery_reboot_is_entangled_with_fork(entry, fork_key))
        })
}

fn recovery_reboot_is_entangled_with_fork(
    entry: &AuthorityLogEntry,
    fork_key: &AuthorityKey,
) -> bool {
    if !matches!(&entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    // Resolve earlier groups involving a reboot participant first so
    // quarantined authority cannot authorize recovery. Unrelated groups and
    // later groups do not affect this candidate's current admissibility.
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .any(|signature| signature.public_key == *fork_key)
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

/// Substitute parent states that let a stalled `RevokeActor` fold against its
/// nearest READY ancestry, or `None` when the bypass does not apply.
///
/// THE HOLE THIS CLOSES. `op_applies_despite_pending_widen` exempts a
/// revocation from the pending-widen freeze, but that exemption is tested
/// AFTER `fold_entry_state` has resolved parents, and an unresolved parent
/// returns `Waiting` first. So a compromised key stalls its own revocation by
/// parenting it on a grant the key itself filed under an unrelated pending
/// widen: the grant defers (correctly — grants must freeze), and the child
/// revocation inherits the wait for the whole veto window. The withdrawal of
/// consent is exactly the operation that must not be delayable by its target.
///
/// WHY IT IS SAFE. Substituting an ancestry state that predates the frozen
/// parent cannot manufacture authority for the revocation:
///
/// * `RevokeActor` is authority-REMOVING only. Applying it raises
///   `actor_binding_revocations[key]` to at least `epoch` and touches nothing
///   else, so the worst a stale base state can do is withhold the revocation's
///   effect — the pre-fix behavior — never widen anything.
/// * The watermark merges by MAX, so once the frozen parent does fold the
///   revocation stays in force: no ordering can lower a raised watermark.
/// * The substituted states are real folded states of real ancestors, so every
///   other gate the entry passes through (signature, vault, roster, consent,
///   quorum, seq) still runs against genuinely folded authority.
///
/// WHY IT STAYS ONE OP WIDE, AND ONE CAUSE DEEP. Two independent narrowings,
/// because the bypass is the only place a fold walks past an unfolded entry:
///
/// * Only `RevokeActor` may USE it. A grant folded against a pre-widen roster
///   is precisely what the freeze exists to prevent, so `BindActor` and
///   `RebindActor` keep waiting.
/// * Only a parent FROZEN BY THE WIDEN may be stepped over — see
///   [`entry_is_frozen_by_pending_widen`]. A parent that is waiting for any
///   other reason, was ruled `Invalid`, or is simply absent from the log
///   refuses the whole bypass, so a revocation can never be folded over
///   ancestry this vault has not validated. The skipped parent is stepped over,
///   never applied.
///
/// The walk is bounded by the ancestry it traverses and introduces no clock
/// dependency: a revocation is not time-based, and this decides nothing about
/// when any pending widen matures.
///
/// KNOWN DURABILITY RESIDUAL. A revocation rescued by this bypass survives the
/// widen merely maturing
/// (`revocation_folded_past_a_freeze_survives_the_widen_maturing`), but NOT the
/// skipped grant later becoming retroactively invalid through the matured
/// state — that durability is a GATE-2 packet item, not an in-lane fix. Closing
/// it needs a representation in which an accepted revocation's effect outlives
/// ancestry invalidation of the entries above it (a journal, or per-hash bypass
/// state), which is a design surface rather than a change to this function.
fn revocation_bypass_states(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, FoldState>> {
    if !matches!(entry.op, AuthorityOp::RevokeActor { .. }) {
        return None;
    }
    let mut substitutes = BTreeMap::new();
    for parent in &entry.parent_hashes {
        if states.contains_key(parent) {
            continue;
        }
        let nearest = nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)?;
        substitutes.insert(*parent, nearest);
    }
    // No unresolved parent means the entry stalled on something else entirely
    // (equivocation, seq, consent); leave every other path exactly as it was.
    if substitutes.is_empty() {
        return None;
    }
    let mut merged = states.clone();
    merged.extend(substitutes);
    Some(merged)
}

/// Walks up from a frozen entry to the merge of the nearest folded states.
///
/// Every branch must terminate in a READY ancestor, crossing only entries the
/// pending-widen freeze is holding. Anything else — an invalid ancestor, a
/// missing one, a root that never folded, a parent waiting for some other
/// reason — refuses the bypass outright.
fn nearest_unfrozen_ancestor_state(
    start: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut resolved: Option<FoldState> = None;
    let mut visited = BTreeSet::new();
    let mut frontier = vec![start];
    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(state) = states.get(&hash) {
            resolved = Some(match resolved {
                Some(current) if current.vault_id != state.vault_id => return None,
                Some(current) => merge_states(&current, state),
                None => state.clone(),
            });
            continue;
        }
        let entry = by_hash.get(&hash)?;
        if !pending.contains(&hash)
            || entry.parent_hashes.is_empty()
            || !entry_is_frozen_by_pending_widen(entry, by_hash, states, pending, context)
        {
            return None;
        }
        frontier.extend(entry.parent_hashes.iter().copied());
    }
    resolved
}

/// Whether `entry` is stalled by the pending-widen freeze specifically.
///
/// This is the bypass's load-bearing narrowing, so it is decided POSITIVELY
/// rather than by elimination: the entry's own ancestry must resolve, that
/// ancestry must actually carry a pending widen, and the entry's op must be one
/// the freeze defers. An entry that is waiting for any other reason fails this
/// and stops the walk.
///
/// The classification is read off the MERGED ancestry, because that is the only
/// picture the freeze itself ever sees. `fold_entry_state` merges every parent
/// state before testing `!state.pending_widens.is_empty()`, so a single
/// widen-bearing branch parks the entry no matter how many clean siblings it
/// has. Asking instead whether EVERY branch carries a widen would answer a
/// question the fold never poses, and the disagreement is attacker-selectable:
/// hanging one ordinary already-folded parent off a stall grant would make the
/// classifier call a frozen entry unfrozen and collapse the bypass
/// (`revoke_actor_folds_past_a_grant_frozen_through_only_one_of_its_parents`).
///
/// Every parent must still RESOLVE. That is the narrowing this shares with
/// [`nearest_unfrozen_ancestor_state`]: a branch that dead-ends in an invalid,
/// missing, or otherwise-waiting ancestor refuses the classification outright,
/// so "frozen" never widens to mean "stuck for some reason we did not identify."
fn entry_is_frozen_by_pending_widen(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> bool {
    if !context.enforce_seen_time_delay || op_applies_despite_pending_widen(&entry.op) {
        return false;
    }
    let mut merged: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) =
            nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)
        else {
            return false;
        };
        merged = Some(match merged {
            Some(current) if current.vault_id != state.vault_id => return false,
            Some(current) => merge_states(&current, &state),
            None => state,
        });
    }
    merged.is_some_and(|state| !state.pending_widens.is_empty())
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
    context: FoldContext<'_>,
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
            context,
        );
    }
    if right_ancestors.is_subset(left_ancestors) && right_ancestors != left_ancestors {
        return branch_divergent_suffix_has_restore_marker(
            left,
            right_ancestors,
            by_hash,
            ancestors,
            context,
        );
    }
    false
}

fn branch_divergent_suffix_has_restore_marker(
    longer_hash: AuthorityEntryHash,
    shorter_ancestors: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    restore_marker_is_fold_admissible(longer_hash, by_hash, ancestors, context)
        || ancestors.get(&longer_hash).is_some_and(|branch_ancestors| {
            branch_ancestors
                .iter()
                .filter(|ancestor| !shorter_ancestors.contains(*ancestor))
                .any(|ancestor| {
                    restore_marker_is_fold_admissible(*ancestor, by_hash, ancestors, context)
                })
        })
}

fn restore_marker_is_fold_admissible(
    hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    let Some(entry) = by_hash.get(&hash) else {
        return false;
    };
    if !matches!(entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    entry_folds_on_available_ancestry(hash, by_hash, ancestors, context)
}

/// Chain-validation probe: re-folds `target_hash` over its own complete
/// ancestry with fork state deliberately cleared.
///
/// It inherits exactly TWO things from the enclosing fold — the consent arm and
/// the admitted peer consent roots — because those define what "folds" MEANS.
/// A probe answering under different consent semantics than the fold it serves
/// would quietly disagree with it about which fork candidates are chain-valid.
fn entry_folds_on_available_ancestry(
    target_hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
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
    let authority_fork_vault_ids = BTreeMap::new();
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
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(ancestors),
                    chain_validated_fork_candidates: None,
                    ..context
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
        apply_op(&mut rank_state, &entry.op, hash, true, entry.signer_key());
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
            fork_resolution_revocations: BTreeSet::new(),
            authority_forks: BTreeMap::new(),
            federation_pacts: BTreeMap::new(),
            critical_write_confirms: BTreeMap::new(),
            consumed_critical_write_confirm_nonces: BTreeSet::new(),
            conflicted_critical_write_confirms: BTreeSet::new(),
            federation_grant_bindings: BTreeMap::new(),
            actor_bindings: BTreeMap::new(),
            actor_binding_revocations: BTreeMap::new(),
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
    if context.enforce_seen_time_delay
        && !state.pending_widens.is_empty()
        && !op_applies_despite_pending_widen(&entry.op)
    {
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
    if matches!(entry.op, AuthorityOp::CriticalWriteConfirm(_))
        && !state
            .roster
            .get(&signer)
            .is_some_and(folded_signer_can_critical_write_confirm)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if !has_authority_consent(&state, &participants, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if entry_requires_peer_cosign(entry)
        && active_roster_count_for_entry(&state, entry, context, hash) >= 2
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
    if let AuthorityOp::CriticalWriteConfirm(action) = &entry.op
        && (state
            .critical_write_confirms
            .contains_key(&action.confirm_id)
            || state
                .consumed_critical_write_confirm_nonces
                .contains(&action.nonce))
    {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if let AuthorityOp::FederationLifecycle(action) = &entry.op {
        if let Err(reason) = apply_federation_lifecycle(&mut state, action, context) {
            return EntryFold::Invalid(AuthorityFoldIssue::FederationLifecycleRejected {
                entry: hash,
                reason,
            });
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if matches!(
        entry.op,
        AuthorityOp::BindActor { .. }
            | AuthorityOp::RebindActor { .. }
            | AuthorityOp::RevokeActor { .. }
    ) {
        if let Err(reason) = apply_actor_binding(&mut state, &entry.op) {
            return EntryFold::Invalid(AuthorityFoldIssue::ActorBindingRejected {
                entry: hash,
                reason,
            });
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
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
        apply_op(&mut eventual_state, &entry.op, hash, true, &signer);
        if !state_has_authority_consent_for_entry(&eventual_state, entry, context, hash) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        state.pending_widens.insert(hash, pending_widen);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    let applied_delayed_widen =
        context.enforce_seen_time_delay && op_is_delayable_widen(&state, &entry.op, &participants);
    apply_op(&mut state, &entry.op, hash, applied_delayed_widen, &signer);
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
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => {}
    }
    if !state_has_authority_consent_for_entry(&state, entry, context, hash) {
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
        if key_is_quarantined_for_entry(
            state,
            context,
            key,
            hash,
            Some((entry.signer_key(), entry.seq)),
        ) || (!active_member
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
            || key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
}

fn has_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(|device| context.device_can_consent(device))
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
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        context.device_can_consent(device)
            && !key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
    })
}

fn folded_device_can_authority_consent(device: &FoldedDevice) -> bool {
    !device.revoked
        && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
        && (device.roles & ROLE_CLOUD) == 0
        && device.tier != AuthorityTier::CloudCustodial
}

/// Critical confirmations are owner acts; this intentionally has no tier/custody arm.
fn folded_signer_can_critical_write_confirm(device: &FoldedDevice) -> bool {
    !device.revoked && (device.roles & ROLE_OWNER) != 0 && (device.roles & ROLE_CLOUD) == 0
}

/// The host-key-premise consent predicate: owner/admin and-not-revoked IS the
/// whole test, with `ROLE_CLOUD` and `CloudCustodial` markings IGNORED.
///
/// Sits BESIDE [`folded_device_can_authority_consent`] and never replaces it —
/// the local fold's consent semantics do not change. The inversion is confined
/// to the PEER side because that is where it is forced: under host-root
/// (S-AUTH1B) the peer host's genesis key is the peer's trust root, and a
/// predicate that selects peer consent keys by EXCLUDING host/cloud markings
/// would admit every user device the peer enrolled while excluding exactly the
/// key host-root makes the root.
pub(crate) fn folded_peer_device_is_consent_root(device: &FoldedDevice) -> bool {
    !device.revoked && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
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

/// Whether `op` still folds while an UNRELATED widen is pending.
///
/// A pending widen freezes the log: every later entry waits, because the widen
/// may yet be vetoed and folding on a roster that might change would decide the
/// entry against the wrong state. That is the right default for anything that
/// GRANTS — the grant can afford to wait out the veto window, and waiting is the
/// conservative direction.
///
/// It is the wrong default for `RevokeActor`. A revocation is the operator's
/// emergency brake: it WITHDRAWS consent, and withdrawal of consent is
/// unconditional — no roster the pending widen could produce makes a revoked
/// actor's authority legitimate again. Deferring it hands the widen's clock (up
/// to `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`) to the revocation, so an owner who
/// files a revocation because a key is compromised watches that key keep every
/// owner verb until an unrelated enrollment matures. Worse, the attacker chooses
/// the delay: filing any delayable widen of their own extends their own
/// authority.
///
/// The asymmetry is deliberate and narrow. `BindActor`/`RebindActor` GRANT
/// identity, so they keep the deferral; only the withdrawal skips it. Skipping
/// is safe because a revocation cannot widen anything: it only raises a
/// per-key watermark that kills bindings at or below it, so folding it early
/// can strictly REMOVE authority from the derived roster, never add it — and
/// the pending widen still matures on its own clock, unaffected.
///
/// SEAM — this exemption has a SECOND half, [`revocation_bypass_states`]. The
/// check here runs after parents are resolved, so on its own it does nothing
/// for a revocation whose PARENT is the frozen entry: an unresolved parent
/// returns `Waiting` before this line is reached, and a compromised key can
/// manufacture exactly that parent. The ancestry bypass closes that path by
/// letting a stalled revocation — and only a revocation — resolve against its
/// nearest ready ancestor. Same ruling, same blast radius (removal-only,
/// monotone watermark); read the two together before changing either.
fn op_applies_despite_pending_widen(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::RevokeActor { .. } => true,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::RecoveryReboot { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. } => false,
    }
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
        | AuthorityOp::FederationConfirm(_) | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        // Bind ops are instant, never delayed-vetoable widens: the widen
        // ceremony already ran when the KEY was enrolled, and a human-class
        // bind additionally demands an owner-capable signer AND an
        // owner-capable bound key, so no authority widens at bind time.
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => false,
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
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => false,
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
    let active_before = active_roster_count_for_entry(state, entry, context, hash);
    let revoked_was_active = state.roster.get(revoked_key).is_some_and(|device| {
        !device.revoked
            && device.roles != 0
            && !key_is_quarantined_for_entry(
                state,
                context,
                revoked_key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
    });
    let active_after = active_before.saturating_sub(usize::from(revoked_was_active));
    participants.len() < 2 || active_after < 2
}

fn active_roster_count_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            !device.revoked
                && device.roles != 0
                && !key_is_quarantined_for_entry(
                    state,
                    context,
                    key,
                    hash,
                    Some((entry.signer_key(), entry.seq)),
                )
        })
        .count()
}

fn merge_states(left: &FoldState, right: &FoldState) -> FoldState {
    debug_assert_eq!(left.vault_id, right.vault_id);
    let mut merged = left.clone();
    merged
        .consumed_critical_write_confirm_nonces
        .extend(right.consumed_critical_write_confirm_nonces.iter().copied());
    merged
        .conflicted_critical_write_confirms
        .extend(right.conflicted_critical_write_confirms.iter().copied());
    for (id, candidate) in &right.critical_write_confirms {
        if let Some(existing) = merged.critical_write_confirms.get(id)
            && existing.authority_entry_hash != candidate.authority_entry_hash
        {
            merged.conflicted_critical_write_confirms.insert(*id);
        }
        for (other_id, existing) in &merged.critical_write_confirms {
            if *other_id != *id
                && existing.action.nonce == candidate.action.nonce
                && existing.authority_entry_hash != candidate.authority_entry_hash
            {
                merged.conflicted_critical_write_confirms.insert(*other_id);
                merged.conflicted_critical_write_confirms.insert(*id);
            }
        }
        match merged.critical_write_confirms.get(id) {
            Some(existing) if existing.authority_entry_hash <= candidate.authority_entry_hash => {}
            _ => {
                merged
                    .critical_write_confirms
                    .insert(*id, candidate.clone());
            }
        }
    }
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
    merged
        .fork_resolution_revocations
        .extend(right.fork_resolution_revocations.iter().cloned());
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
    for (pact_id, right_pact) in &right.federation_pacts {
        match merged.federation_pacts.get_mut(pact_id) {
            Some(left_pact) => {
                *left_pact = merge_pact_states(left_pact, right_pact);
            }
            None => {
                merged.federation_pacts.insert(*pact_id, right_pact.clone());
            }
        }
    }
    for (grant_ref, pact_ids) in &right.federation_grant_bindings {
        merged
            .federation_grant_bindings
            .entry(*grant_ref)
            .or_default()
            .extend(pact_ids.iter().copied());
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
    for (key, epoch) in &right.actor_binding_revocations {
        merged
            .actor_binding_revocations
            .entry(key.clone())
            .and_modify(|current| *current = (*current).max(*epoch))
            .or_insert(*epoch);
    }
    for (key, binding) in &right.actor_bindings {
        match merged.actor_bindings.get_mut(key) {
            Some(existing) => *existing = merge_actor_bindings(existing, binding),
            None => {
                merged.actor_bindings.insert(key.clone(), binding.clone());
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

/// Higher epoch wins; conflict poison is per-epoch, carried by the winner.
///
/// Equal epoch with divergent content is the dangerous case: two branches each
/// believe a different actor holds this key. Keeping the byte-wise smaller
/// tuple makes the merge deterministic in every arrival order, and
/// `conflicted` makes it never Active — a fork over identity fails closed
/// rather than silently picking a winner.
///
/// Poison deliberately does NOT leak across epochs: a strictly higher epoch
/// supersedes the conflicted state outright. It has to, or one historical
/// divergence would brick the key forever with no way to rebind. The
/// fail-closed property survives because two branches that each advance past
/// a conflict must themselves land on the same epoch to be concurrent, and
/// that tie re-poisons at the new epoch.
fn merge_actor_bindings(left: &ActorBindingState, right: &ActorBindingState) -> ActorBindingState {
    match left.epoch.cmp(&right.epoch) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal => {
            let left_tuple = (left.actor_ref, left.actor_class.as_str());
            let right_tuple = (right.actor_ref, right.actor_class.as_str());
            let mut winner = if left_tuple <= right_tuple {
                left.clone()
            } else {
                right.clone()
            };
            winner.conflicted |= left_tuple != right_tuple || left.conflicted || right.conflicted;
            winner
        }
    }
}

fn apply_op(
    state: &mut FoldState,
    op: &AuthorityOp,
    entry_hash: AuthorityEntryHash,
    applied_delayed_widen: bool,
    signer: &AuthorityKey,
) {
    match op {
        AuthorityOp::Genesis { .. } => {}
        AuthorityOp::EnrollDevice { device } => upsert_device(state, device),
        AuthorityOp::RevokeDevice { revoked_key } => {
            state
                .fork_resolution_revocations
                .insert(revoked_key.clone());
            revoke_key(state, revoked_key);
            for fork in state.authority_forks.values_mut() {
                if fork.signer == *revoked_key && fork.status == AuthorityForkStatus::Quarantined {
                    fork.status = AuthorityForkStatus::Resolved;
                }
            }
        }
        AuthorityOp::SetCeiling { .. } | AuthorityOp::FederationConfirm(_) => {}
        AuthorityOp::CriticalWriteConfirm(action) => {
            state
                .consumed_critical_write_confirm_nonces
                .insert(action.nonce);
            state
                .critical_write_confirms
                .entry(action.confirm_id)
                .or_insert_with(|| CriticalWriteConfirmState {
                    action: action.clone(),
                    signer: signer.clone(),
                    authority_entry_hash: entry_hash,
                });
        }
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
            state
                .fork_resolution_revocations
                .extend(revoked_keys.iter().cloned());
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
        // The VetoPendingWiden precedent: `apply_op` returns `()` and cannot
        // emit rejections; all lifecycle validation and state transitions
        // live in `fold_entry_state`'s lifecycle arm.
        AuthorityOp::FederationLifecycle(_) => {}
        // Same precedent: the binding arm in `fold_entry_state` returns before
        // reaching here, so these are unreachable for Ready entries.
        AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => {}
    }
}

/// The actor-binding transition table (ONE-1604-D2).
///
/// Evaluated against the MERGED ancestry state — the fold is the ordering, so
/// these rows never consult wall-clock or arrival sequence. Bind/Rebind are
/// ancestry-validated; Revoke is deliberately asymmetric and never rejected
/// for absence, because a revocation that fails to apply is the only
/// unrecoverable outcome here.
fn apply_actor_binding(
    state: &mut FoldState,
    op: &AuthorityOp,
) -> std::result::Result<(), ActorBindingRejection> {
    let (authority_key, actor_ref, actor_class, epoch, is_rebind) = match op {
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => {
            let watermark = state
                .actor_binding_revocations
                .entry(authority_key.clone())
                .or_insert(0);
            *watermark = (*watermark).max(*epoch);
            return Ok(());
        }
        AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => (authority_key, actor_ref, actor_class, *epoch, false),
        AuthorityOp::RebindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => (authority_key, actor_ref, actor_class, *epoch, true),
        _ => return Ok(()),
    };

    // The linkage teeth: a binding may only attach to a key the roster still
    // vouches for. Without this, any signed entry could mint identity for a
    // key that was never enrolled.
    let Some(device) = state.roster.get(authority_key).filter(|d| !d.revoked) else {
        return Err(ActorBindingRejection::KeyNotInRoster);
    };
    // Closes the bind-an-agent-key-as-human hole: human class is the owner
    // class, so the bound key must itself be able to give owner consent.
    // Agent/system bindings may target ROLE_AGENT keys (the 1634 seam).
    if actor_class == "human" && !folded_device_can_authority_consent(device) {
        return Err(ActorBindingRejection::OwnerCapabilityRequired);
    }

    let live = state.live_actor_binding(authority_key);
    match (is_rebind, live) {
        (false, Some(_)) => return Err(ActorBindingRejection::BindingExists),
        (true, None) => return Err(ActorBindingRejection::BindingMissing),
        (true, Some(existing)) if epoch <= existing.epoch => {
            return Err(ActorBindingRejection::EpochNotAdvanced);
        }
        _ => {}
    }
    // A fresh bind must clear BOTH the revocation watermark and any dead
    // binding still parked on this key, so a revoked epoch can never be
    // resurrected by replaying the original bind.
    let floor = state
        .actor_binding_revocations
        .get(authority_key)
        .copied()
        .unwrap_or(0)
        .max(
            state
                .actor_bindings
                .get(authority_key)
                .map_or(0, |binding| binding.epoch),
        );
    if epoch <= floor {
        return Err(ActorBindingRejection::EpochNotAdvanced);
    }
    state.actor_bindings.insert(
        authority_key.clone(),
        ActorBindingState {
            actor_ref: *actor_ref,
            actor_class: actor_class.clone(),
            epoch,
            conflicted: false,
        },
    );
    Ok(())
}

/// Local-outbound half of a pact scope pair.
///
/// `lo_to_hi` when the local vault id is the byte-wise smaller of the pair,
/// else `hi_to_lo`. Inverting this is a SILENT reciprocal overshare — every
/// arm resolves its outbound half through this one helper.
fn local_outbound_scope(
    local_vault_id: &AuthorityVaultId,
    peer_vault_id: &AuthorityVaultId,
    scope: &FederationPactScope,
) -> FederationDirectionScope {
    if local_vault_id <= peer_vault_id {
        scope.lo_to_hi.clone()
    } else {
        scope.hi_to_lo.clone()
    }
}

fn verify_pact_scope_digest(
    scope: &FederationPactScope,
    pact_nonce: &[u8; 16],
    claimed_digest: &[u8; 32],
) -> std::result::Result<(), FederationLifecycleRejection> {
    let canonical_scope = encode_federation_pact_scope(scope)
        .map_err(|_| FederationLifecycleRejection::ScopeInvalid)?;
    if federation_scope_digest(pact_nonce, &canonical_scope) == *claimed_digest {
        Ok(())
    } else {
        Err(FederationLifecycleRejection::ScopeDigestMismatch)
    }
}

/// Verifies the embedded peer gesture against the side-symmetric transcript.
///
/// `pinned_peer_key` is `None` only for Connect (TOFU — the trust event is
/// approving the connection); every later gesture must verify under the pinned
/// peer owner key OR a key the peer's own admitted authority log currently
/// makes a consent root (FED-03: the peer rotates its owner devices without
/// re-pinning, and the roster that says so is refolded locally from relayed
/// bytes, never asserted by the relay). A signer present in the LOCAL roster is
/// always rejected: a local device must never impersonate the peer.
fn verify_lifecycle_gesture(
    state: &FoldState,
    action: &FederationLifecycleAction,
    scope_digest: &[u8; 32],
    pinned_peer_key: Option<&AuthorityKey>,
    context: FoldContext<'_>,
) -> std::result::Result<AuthorityKey, FederationLifecycleRejection> {
    let Some(gesture) = &action.gesture else {
        return Err(FederationLifecycleRejection::GestureMissing);
    };
    if state.roster.contains_key(&gesture.signer) {
        return Err(FederationLifecycleRejection::GestureInvalid);
    }
    if pinned_peer_key.is_some_and(|pinned| *pinned != gesture.signer)
        && !peer_roster_authorizes_gesture(context, &action.peer_vault_id, &gesture.signer)
    {
        return Err(FederationLifecycleRejection::GestureInvalid);
    }
    let transcript = federation_pact_transcript(
        action.kind,
        &action.pact_id,
        &state.vault_id,
        &action.peer_vault_id,
        action.pact_epoch,
        scope_digest,
        action.successor_vault_id.as_ref(),
        &action.pact_nonce,
    )
    .map_err(|_| FederationLifecycleRejection::GestureInvalid)?;
    let signature = AuthoritySignature {
        suite: gesture.signer.suite(),
        public_key: gesture.signer.clone(),
        signature: gesture.signature.clone(),
    };
    if verify_authority_signature(&signature, &transcript) {
        Ok(gesture.signer.clone())
    } else {
        Err(FederationLifecycleRejection::GestureInvalid)
    }
}

/// True when `signer` is a consent root of the ADMITTED authority log of the
/// peer vault this action names.
///
/// The map is empty unless the caller admitted that peer's log locally, so a
/// vault with no admitted peer rows keeps pinned-key-only FED-01 behaviour.
fn peer_roster_authorizes_gesture(
    context: FoldContext<'_>,
    peer_vault_id: &AuthorityVaultId,
    signer: &AuthorityKey,
) -> bool {
    context
        .peer_consent_roots
        .get(peer_vault_id)
        .is_some_and(|roots| roots.contains(signer))
}

/// Full D5 transition table, evaluated against the merged ancestry state.
fn apply_federation_lifecycle(
    state: &mut FoldState,
    action: &FederationLifecycleAction,
    context: FoldContext<'_>,
) -> std::result::Result<(), FederationLifecycleRejection> {
    let local_vault_id = state.vault_id;
    let Some(pact) = state.federation_pacts.get(&action.pact_id).cloned() else {
        if action.kind != FederationLifecycleKind::Connect {
            return Err(FederationLifecycleRejection::UnknownPact);
        }
        // Re-connection is a NEW pact_id AND a new grant: a grant_ref that
        // has EVER appeared in a pact binding (the registry is a superset of
        // the live pact states' grant_refs — every binding enters through a
        // Connect) is never re-covered by a fresh pact, including bindings
        // discarded by a divergent-binding merge.
        if state
            .federation_grant_bindings
            .contains_key(&action.grant_ref)
        {
            return Err(FederationLifecycleRejection::GrantAlreadyBound);
        }
        if action.pact_epoch != 1 {
            return Err(FederationLifecycleRejection::EpochMismatch);
        }
        let scope = action
            .pact_scope
            .as_ref()
            .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
        let claimed_digest = action
            .scope_digest
            .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
        verify_pact_scope_digest(scope, &action.pact_nonce, &claimed_digest)?;
        let peer_owner_key =
            verify_lifecycle_gesture(state, action, &claimed_digest, None, context)?;
        let effective_scope = local_outbound_scope(&local_vault_id, &action.peer_vault_id, scope);
        state
            .federation_grant_bindings
            .entry(action.grant_ref)
            .or_default()
            .insert(action.pact_id);
        state.federation_pacts.insert(
            action.pact_id,
            FederationPactState {
                status: FederationPactStatus::Active,
                grant_ref: action.grant_ref,
                peer_vault_id: action.peer_vault_id,
                peer_owner_key,
                pact_epoch: action.pact_epoch,
                scope_digest: claimed_digest,
                pact_scope: scope.clone(),
                effective_scope,
                successor_vault_id: None,
                terminal_epoch: None,
            },
        );
        return Ok(());
    };

    if pact.status.is_terminal() {
        return Err(FederationLifecycleRejection::TerminalPact);
    }
    if action.kind == FederationLifecycleKind::Connect {
        return Err(FederationLifecycleRejection::DuplicateConnect);
    }
    if action.peer_vault_id != pact.peer_vault_id {
        return Err(FederationLifecycleRejection::PeerVaultMismatch);
    }
    if action.grant_ref != pact.grant_ref {
        return Err(FederationLifecycleRejection::GrantAlreadyBound);
    }

    let mut pact = pact;
    match action.kind {
        FederationLifecycleKind::Connect => {
            return Err(FederationLifecycleRejection::DuplicateConnect);
        }
        FederationLifecycleKind::Rescope if action.effective_scope.is_some() => {
            // Narrow form: unilateral effective-scope overlay under the
            // dual-signed ceiling; epoch unchanged.
            if pact.status == FederationPactStatus::Suspended {
                return Err(FederationLifecycleRejection::SuspendedPact);
            }
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            let effective = action
                .effective_scope
                .as_ref()
                .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
            let ceiling =
                local_outbound_scope(&local_vault_id, &pact.peer_vault_id, &pact.pact_scope);
            if !effective.is_narrowing_of(&ceiling) {
                return Err(FederationLifecycleRejection::WidenWithoutGesture);
            }
            pact.effective_scope = effective.clone();
        }
        FederationLifecycleKind::Rescope => {
            // Repact form: dual-signed epoch bump; heals a suspended pact.
            if action.pact_epoch.checked_sub(1) != Some(pact.pact_epoch) {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            let scope = action
                .pact_scope
                .as_ref()
                .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
            let claimed_digest = action
                .scope_digest
                .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
            verify_pact_scope_digest(scope, &action.pact_nonce, &claimed_digest)?;
            verify_lifecycle_gesture(
                state,
                action,
                &claimed_digest,
                Some(&pact.peer_owner_key),
                context,
            )?;
            pact.status = FederationPactStatus::Active;
            pact.pact_epoch = action.pact_epoch;
            pact.scope_digest = claimed_digest;
            pact.pact_scope = scope.clone();
            pact.effective_scope =
                local_outbound_scope(&local_vault_id, &pact.peer_vault_id, scope);
        }
        FederationLifecycleKind::Promote => {
            if pact.status == FederationPactStatus::Suspended {
                return Err(FederationLifecycleRejection::SuspendedPact);
            }
            if action.pact_epoch.checked_sub(1) != Some(pact.pact_epoch) {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            // Promote carries no scope bytes: its digest must EQUAL the
            // stored one (byte equality, no recompute).
            let claimed_digest = action
                .scope_digest
                .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
            if claimed_digest != pact.scope_digest {
                return Err(FederationLifecycleRejection::ScopeDigestMismatch);
            }
            verify_lifecycle_gesture(
                state,
                action,
                &claimed_digest,
                Some(&pact.peer_owner_key),
                context,
            )?;
            pact.status = FederationPactStatus::Promoted;
            pact.pact_epoch = action.pact_epoch;
            pact.successor_vault_id = action.successor_vault_id;
            pact.terminal_epoch = Some(action.pact_epoch);
        }
        FederationLifecycleKind::Disconnect => {
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            pact.status = FederationPactStatus::Disconnected;
            pact.terminal_epoch = Some(pact.pact_epoch);
        }
        FederationLifecycleKind::Dissolve => {
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            pact.status = FederationPactStatus::Dissolved;
            pact.terminal_epoch = Some(pact.pact_epoch);
        }
    }
    state.federation_pacts.insert(action.pact_id, pact);
    Ok(())
}

/// Deterministic, commutative pick between two equally ranked pact states:
/// the lexicographic-min (scope_digest, grant_ref) side. The pair is always
/// discriminating for divergent states, since divergence implies at least one
/// of the two fields differs.
fn pact_merge_tiebreak_side<'a>(
    left: &'a FederationPactState,
    right: &'a FederationPactState,
) -> &'a FederationPactState {
    if (left.scope_digest, left.grant_ref) <= (right.scope_digest, right.grant_ref) {
        left
    } else {
        right
    }
}

/// Commutative, associative, idempotent per-pact merge join.
///
/// Terminal-wins regardless of epoch (revocations-win); two terminals resolve
/// by fixed precedence Dissolved > Disconnected > Promoted; non-terminals
/// resolve by max epoch. Equal-epoch non-terminals fold as a COMPETITOR SET
/// keyed by (scope_digest, grant_ref): equal keys combine (effective scopes
/// intersect, min peer key, Suspended if either side is); divergent keys
/// suspend fail-closed and carry the lexicographic-min key's fields. Because
/// every pairwise step re-takes the min — a Suspended side is never absorbed
/// verbatim past an Active competitor — any merge tree folds a 3+-way
/// divergence to the GLOBAL lex-min, so the heal target (the grant_ref an
/// epoch+1 repact must name) is independent of merge topology and hash
/// order. Every binding discarded by a pick stays denied through
/// `FoldState::federation_grant_bindings` (union-merged), so no grant that
/// ever appeared in a pact binding regains `Unpacted` legacy-allow.
fn merge_pact_states(
    left: &FederationPactState,
    right: &FederationPactState,
) -> FederationPactState {
    let left_terminal = left.status.is_terminal();
    let right_terminal = right.status.is_terminal();
    if left_terminal != right_terminal {
        return if left_terminal {
            left.clone()
        } else {
            right.clone()
        };
    }
    if left_terminal && right_terminal {
        if left.status != right.status {
            return if left.status > right.status {
                left.clone()
            } else {
                right.clone()
            };
        }
        if left.pact_epoch != right.pact_epoch {
            return if left.pact_epoch > right.pact_epoch {
                left.clone()
            } else {
                right.clone()
            };
        }
        return pact_merge_tiebreak_side(left, right).clone();
    }
    if left.pact_epoch != right.pact_epoch {
        return if left.pact_epoch > right.pact_epoch {
            left.clone()
        } else {
            right.clone()
        };
    }
    // Both non-terminal at the same consent epoch: fold the competitor set.
    if (left.scope_digest, left.grant_ref) == (right.scope_digest, right.grant_ref) {
        let mut merged = left.clone();
        // Concurrent unilateral narrows are both honored.
        merged.effective_scope = left.effective_scope.intersect(&right.effective_scope);
        // Concurrent duplicate Connects can pin different verified peer
        // roster keys; the pick is determinism-only.
        merged.peer_owner_key = left
            .peer_owner_key
            .clone()
            .min(right.peer_owner_key.clone());
        // Same discipline for the peer vault id (duplicate Connects can be
        // dual-signed with different peers), and — reachable only through a
        // digest collision — for divergent scope bytes via their canonical
        // encoding, so this arm stays commutative, associative, and
        // idempotent on every field it carries.
        merged.peer_vault_id = left.peer_vault_id.min(right.peer_vault_id);
        if left.pact_scope != right.pact_scope {
            let left_scope_bytes =
                encode_federation_pact_scope(&left.pact_scope).unwrap_or_default();
            let right_scope_bytes =
                encode_federation_pact_scope(&right.pact_scope).unwrap_or_default();
            if right_scope_bytes < left_scope_bytes {
                merged.pact_scope = right.pact_scope.clone();
            }
        }
        // A suspension carried by either side persists under an agreeing
        // competitor: the conflict that caused it is still unhealed.
        merged.status = left.status.max(right.status);
        return merged;
    }
    // Divergent concurrent re-pacts (digest) or concurrent Connects binding
    // one pact id to two different grants (grant_ref): both are
    // equivocation-shaped conflicts on the consent axis. Fail closed at the
    // shared epoch and carry the min-key side, RE-TAKING the min even when
    // one side is already Suspended; heals via a fresh dual-signed Rescope
    // at epoch+1 naming the surviving binding. The losing grant_ref stays
    // denied via the grant-binding registry.
    let mut merged = pact_merge_tiebreak_side(left, right).clone();
    merged.status = FederationPactStatus::Suspended;
    merged.successor_vault_id = None;
    merged.terminal_epoch = None;
    merged
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
        AuthorityOp::CriticalWriteConfirm(action) => {
            if action.schema_version != CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION
                || action.confirm_id.iter().all(|b| *b == 0)
                || action.gate_decision_id.iter().all(|b| *b == 0)
                || action.effect_digest.iter().all(|b| *b == 0)
                || action.read_frontier_hash.iter().all(|b| *b == 0)
                || action.nonce.iter().all(|b| *b == 0)
                || action.expires_at == 0
            {
                Err(invalid_authority())
            } else {
                Ok(())
            }
        }
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
        AuthorityOp::FederationLifecycle(action) => validate_federation_lifecycle_action(action),
        AuthorityOp::BindActor {
            authority_key,
            actor_class,
            epoch,
            ..
        }
        | AuthorityOp::RebindActor {
            authority_key,
            actor_class,
            epoch,
            ..
        } => {
            // EXACT class vocabulary, not SetCeiling's free-form string: an
            // unrecognized class must never fold into a binding that some
            // future reader treats as equivalent to "human".
            if !ACTOR_BINDING_CLASSES.contains(&actor_class.as_str()) || *epoch == 0 {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => {
            if *epoch == 0 {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
    }
}

fn validate_federation_lifecycle_action(action: &FederationLifecycleAction) -> Result<()> {
    if action.pact_id.iter().all(|byte| *byte == 0)
        || action.pact_nonce.iter().all(|byte| *byte == 0)
        || action.peer_vault_id.iter().all(|byte| *byte == 0)
        || action.pact_epoch == 0
    {
        return Err(invalid_authority());
    }
    let present = (
        action.pact_scope.is_some(),
        action.effective_scope.is_some(),
        action.scope_digest.is_some(),
        action.gesture.is_some(),
        action.successor_vault_id.is_some(),
    );
    // Per-kind optional matrix; Rescope forms are discriminated purely by key
    // presence (repact = pact_scope+scope_digest+gesture, narrow =
    // effective_scope) and a mix fails both.
    let matrix_ok = match action.kind {
        FederationLifecycleKind::Connect => present == (true, false, true, true, false),
        FederationLifecycleKind::Rescope => {
            present == (true, false, true, true, false)
                || present == (false, true, false, false, false)
        }
        FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => {
            present == (false, false, false, false, false)
        }
        FederationLifecycleKind::Promote => present == (false, false, true, true, true),
    };
    if !matrix_ok {
        return Err(invalid_authority());
    }
    if let Some(scope) = &action.pact_scope {
        let encoded = encode_federation_pact_scope(scope).map_err(|_| invalid_authority())?;
        if encoded.len() > MAX_PACT_SCOPE_BYTES {
            return Err(invalid_authority());
        }
    }
    if let Some(effective) = &action.effective_scope {
        effective.validate().map_err(|_| invalid_authority())?;
    }
    if let Some(successor) = &action.successor_vault_id
        && successor.iter().all(|byte| *byte == 0)
    {
        return Err(invalid_authority());
    }
    if let Some(gesture) = &action.gesture {
        gesture.signer.validate()?;
        if gesture.signature.len() != 64 {
            return Err(invalid_authority());
        }
    }
    Ok(())
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
        AuthorityOp::CriticalWriteConfirm(action) => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_CRITICAL_WRITE_CONFIRM),
            ),
            (
                Value::from("schema_version"),
                Value::from(action.schema_version),
            ),
            (Value::from("confirm_id"), binary_value(action.confirm_id)),
            (
                Value::from("gate_decision_id"),
                binary_value_16(action.gate_decision_id),
            ),
            (
                Value::from("claim_id"),
                binary_value_16(*action.claim_id.as_bytes()),
            ),
            (
                Value::from("effect_digest"),
                binary_value(action.effect_digest),
            ),
            (
                Value::from("read_frontier_hash"),
                binary_value(action.read_frontier_hash),
            ),
            (Value::from("nonce"), binary_value_16(action.nonce)),
            (Value::from("expires_at"), Value::from(action.expires_at)),
            (
                Value::from("disposition"),
                Value::from(action.disposition.as_str()),
            ),
            (Value::from("method"), Value::from(action.method.as_str())),
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
        AuthorityOp::FederationLifecycle(action) => {
            let mut fields = vec![
                (
                    Value::from(OP_KEY_KIND),
                    Value::from(OP_KIND_FEDERATION_LIFECYCLE),
                ),
                (
                    Value::from("lifecycle_kind"),
                    Value::from(action.kind.as_str()),
                ),
                (Value::from("pact_id"), binary_value(action.pact_id)),
                (
                    Value::from("grant_ref"),
                    Value::from(action.grant_ref.to_hex()),
                ),
                (
                    Value::from("peer_vault_id"),
                    binary_value(action.peer_vault_id),
                ),
                (Value::from("pact_epoch"), Value::from(action.pact_epoch)),
                (
                    Value::from("pact_nonce"),
                    binary_value_16(action.pact_nonce),
                ),
            ];
            if let Some(scope) = &action.pact_scope {
                fields.push((
                    Value::from("pact_scope"),
                    federation_pact_scope_value(scope),
                ));
            }
            if let Some(effective) = &action.effective_scope {
                fields.push((
                    Value::from("effective_scope"),
                    federation_direction_scope_value(effective),
                ));
            }
            if let Some(digest) = &action.scope_digest {
                fields.push((Value::from("scope_digest"), binary_value(*digest)));
            }
            if let Some(gesture) = &action.gesture {
                fields.push((Value::from("gesture"), gesture_value(gesture)));
            }
            if let Some(successor) = &action.successor_vault_id {
                fields.push((Value::from("successor_vault_id"), binary_value(*successor)));
            }
            Value::Map(fields)
        }
        AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => actor_binding_op_value(
            OP_KIND_BIND_ACTOR,
            authority_key,
            actor_ref,
            actor_class,
            *epoch,
        ),
        AuthorityOp::RebindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => actor_binding_op_value(
            OP_KIND_REBIND_ACTOR,
            authority_key,
            actor_ref,
            actor_class,
            *epoch,
        ),
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_REVOKE_ACTOR)),
            (Value::from("authority_key"), key_value(authority_key)),
            (Value::from("epoch"), Value::from(*epoch)),
        ]),
    }
}

/// Canonical field order for bind/rebind:
/// `(kind, authority_key, actor_ref, actor_class, epoch)` — byte-pinned by the
/// golden vectors. `actor_ref` rides as 32-hex like the `grant_ref` precedent.
fn actor_binding_op_value(
    kind: &str,
    authority_key: &AuthorityKey,
    actor_ref: &EntityId,
    actor_class: &str,
    epoch: u64,
) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(kind)),
        (Value::from("authority_key"), key_value(authority_key)),
        (Value::from("actor_ref"), Value::from(actor_ref.to_hex())),
        (Value::from("actor_class"), Value::from(actor_class)),
        (Value::from("epoch"), Value::from(epoch)),
    ])
}

fn gesture_value(gesture: &FederationPactGesture) -> Value {
    Value::Map(vec![
        (Value::from("signer"), key_value(&gesture.signer)),
        (
            Value::from("signature"),
            Value::Binary(gesture.signature.clone()),
        ),
    ])
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
        OP_KIND_CRITICAL_WRITE_CONFIRM => {
            validate_keys(
                entries,
                &[
                    OP_KEY_KIND,
                    "schema_version",
                    "confirm_id",
                    "gate_decision_id",
                    "claim_id",
                    "effect_digest",
                    "read_frontier_hash",
                    "nonce",
                    "expires_at",
                    "disposition",
                    "method",
                ],
            )?;
            let claim = EntityId::from_bytes(decode_16(required(entries, "claim_id")?)?)
                .map_err(|_| invalid_authority())?;
            let action = CriticalWriteConfirmAction {
                schema_version: required(entries, "schema_version")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                confirm_id: decode_hash(required(entries, "confirm_id")?)?,
                gate_decision_id: decode_16(required(entries, "gate_decision_id")?)?,
                claim_id: claim,
                effect_digest: decode_hash(required(entries, "effect_digest")?)?,
                read_frontier_hash: decode_hash(required(entries, "read_frontier_hash")?)?,
                nonce: decode_16(required(entries, "nonce")?)?,
                expires_at: required(entries, "expires_at")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                disposition: required(entries, "disposition")?
                    .as_str()
                    .and_then(CriticalWriteConfirmDisposition::parse)
                    .ok_or_else(invalid_authority)?,
                method: required(entries, "method")?
                    .as_str()
                    .and_then(CriticalWriteConfirmMethod::parse)
                    .ok_or_else(invalid_authority)?,
            };
            Ok(AuthorityOp::CriticalWriteConfirm(action))
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
        OP_KIND_FEDERATION_LIFECYCLE => decode_federation_lifecycle_op(entries),
        OP_KIND_BIND_ACTOR | OP_KIND_REBIND_ACTOR => {
            let (authority_key, actor_ref, actor_class, epoch) = decode_actor_binding_op(entries)?;
            if kind == OP_KIND_BIND_ACTOR {
                Ok(AuthorityOp::BindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                })
            } else {
                Ok(AuthorityOp::RebindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                })
            }
        }
        OP_KIND_REVOKE_ACTOR => {
            validate_keys(entries, &[OP_KEY_KIND, "authority_key", "epoch"])?;
            Ok(AuthorityOp::RevokeActor {
                authority_key: decode_key(required(entries, "authority_key")?)?,
                epoch: required(entries, "epoch")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
            })
        }
        _ => Err(invalid_authority()),
    }
}

fn decode_actor_binding_op(
    entries: &[(Value, Value)],
) -> Result<(AuthorityKey, EntityId, String, u64)> {
    validate_keys(
        entries,
        &[
            OP_KEY_KIND,
            "authority_key",
            "actor_ref",
            "actor_class",
            "epoch",
        ],
    )?;
    let actor_ref_hex = required(entries, "actor_ref")?
        .as_str()
        .ok_or_else(invalid_authority)?;
    // `from_hex` routes `from_bytes`, so reserved sentinel ids fail closed; the
    // round-trip check rejects non-canonical hex (the `grant_ref` precedent).
    let actor_ref = EntityId::from_hex(actor_ref_hex).map_err(|_| invalid_authority())?;
    if actor_ref.to_hex() != actor_ref_hex {
        return Err(invalid_authority());
    }
    Ok((
        decode_key(required(entries, "authority_key")?)?,
        actor_ref,
        required(entries, "actor_class")?
            .as_str()
            .ok_or_else(invalid_authority)?
            .to_owned(),
        required(entries, "epoch")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
    ))
}

fn decode_federation_lifecycle_op(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let kind = required(entries, "lifecycle_kind")?
        .as_str()
        .and_then(FederationLifecycleKind::parse)
        .ok_or_else(invalid_authority)?;
    let mut expected = vec![
        OP_KEY_KIND,
        "lifecycle_kind",
        "pact_id",
        "grant_ref",
        "peer_vault_id",
        "pact_epoch",
        "pact_nonce",
    ];
    match kind {
        FederationLifecycleKind::Connect => {
            expected.extend(["pact_scope", "scope_digest", "gesture"]);
        }
        FederationLifecycleKind::Rescope => {
            // The two-form discriminator: `effective_scope` present = narrow
            // form; otherwise the repact key set applies. A mix (or neither)
            // fails both forms' strict key sets below.
            if optional(entries, "effective_scope").is_some() {
                expected.push("effective_scope");
            } else {
                expected.extend(["pact_scope", "scope_digest", "gesture"]);
            }
        }
        FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => {}
        FederationLifecycleKind::Promote => {
            expected.extend(["scope_digest", "gesture", "successor_vault_id"]);
        }
    }
    validate_keys(entries, &expected)?;
    let grant_ref_hex = required(entries, "grant_ref")?
        .as_str()
        .ok_or_else(invalid_authority)?;
    let grant_ref = EntityId::from_hex(grant_ref_hex).map_err(|_| invalid_authority())?;
    if grant_ref.to_hex() != grant_ref_hex {
        return Err(invalid_authority());
    }
    let pact_scope = optional(entries, "pact_scope")
        .map(|value| decode_federation_pact_scope_value(value).map_err(|_| invalid_authority()))
        .transpose()?;
    let effective_scope = optional(entries, "effective_scope")
        .map(|value| {
            decode_federation_direction_scope_value(value).map_err(|_| invalid_authority())
        })
        .transpose()?;
    let scope_digest = optional(entries, "scope_digest")
        .map(decode_hash)
        .transpose()?;
    let gesture = optional(entries, "gesture")
        .map(decode_gesture)
        .transpose()?;
    let successor_vault_id = optional(entries, "successor_vault_id")
        .map(decode_hash)
        .transpose()?;
    Ok(AuthorityOp::FederationLifecycle(
        FederationLifecycleAction {
            kind,
            pact_id: decode_hash(required(entries, "pact_id")?)?,
            grant_ref,
            peer_vault_id: decode_hash(required(entries, "peer_vault_id")?)?,
            pact_epoch: required(entries, "pact_epoch")?
                .as_u64()
                .ok_or_else(invalid_authority)?,
            pact_scope,
            effective_scope,
            scope_digest,
            gesture,
            successor_vault_id,
            pact_nonce: decode_16(required(entries, "pact_nonce")?)?,
        },
    ))
}

fn decode_gesture(value: &Value) -> Result<FederationPactGesture> {
    let entries = map_entries(value)?;
    validate_keys(entries, &["signer", "signature"])?;
    Ok(FederationPactGesture {
        signer: decode_key(required(entries, "signer")?)?,
        signature: bytes(required(entries, "signature")?)?.to_vec(),
    })
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

/// Whether `entry` carries a federation lifecycle op with a TERMINAL kind.
///
/// A cheap shape test on the appended entry, not a transition verdict — whether
/// the op actually applied is the fold's call, and
/// [`crate::federation::apply_federation_stale_stamps`] asks the fold.
fn is_terminal_federation_lifecycle(entry: &AuthorityLogEntry) -> bool {
    matches!(
        &entry.op,
        AuthorityOp::FederationLifecycle(action)
            if matches!(
                action.kind,
                FederationLifecycleKind::Disconnect
                    | FederationLifecycleKind::Dissolve
                    | FederationLifecycleKind::Promote
            )
    )
}

impl Vault {
    /// Engine-authored write door for signed AUTHORITY_LOG entries.
    ///
    /// The entity id is DERIVED from the entry's content hash (ONE-1604-D1;
    /// never caller-chosen) and returned. Generic public puts for
    /// `ENTITY_TYPE_AUTHORITY_LOG` stay rejected with
    /// `MaintenanceKindNotWritable`; this method validates canonical bytes and
    /// the origin signature before using the internal maintenance path.
    ///
    /// A stored terminal `FederationLifecycle` entry additionally triggers the
    /// ONE-1411 stale-stamp sweep (see below). Fold semantics are untouched:
    /// the sweep only reads the fold this door's own append produced.
    pub fn put_authority_log_entry(
        &self,
        entry: &AuthorityLogEntry,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let ids = self.put_authority_log_entries(&[(entry.clone(), occurred, learned_at)])?;
        let id = ids.into_iter().next().ok_or(Error::EntityNotFound)?;
        // ONE-1411: a terminal federation transition marks the worlds that pact
        // delivered as no longer refreshing. The trigger is a SHAPE test and the
        // sweep is global: it stamps exactly what the FOLD reports terminal, so
        // a fold-REJECTED entry can never justify a stamp of its own (though the
        // sweep it triggers still writes any stamp the fold already justifies,
        // e.g. a world registered late to an already-terminal pact). The write
        // path therefore never duplicates the transition table.
        if is_terminal_federation_lifecycle(entry) {
            crate::federation::apply_federation_stale_stamps(self)?;
        }
        Ok(id)
    }

    /// Appends N AUTHORITY_LOG entries in ONE transaction, all-or-nothing.
    ///
    /// Every id is derived from entry content (ONE-1604-D1), exactly as the
    /// single-entry door does. Encoding, validation, and derivation all happen
    /// BEFORE the write transaction opens, so a bad entry anywhere in the
    /// batch stores nothing at all.
    ///
    /// This is what makes a genesis owner-binding a single ceremony: a host
    /// composes `[genesis, bind]` and either both land or neither does. The
    /// door does NOT require a binding to accompany a genesis — enforcement
    /// lives at the facade, where a rooted vault without an owner binding
    /// fail-closes owner verbs.
    pub fn put_authority_log_entries(
        &self,
        entries: &[(AuthorityLogEntry, TimeRange, u64)],
    ) -> Result<Vec<EntityId>> {
        let mut wtxn = self.store.env.write_txn()?;
        let ids = self.put_authority_log_entries_in_txn(&mut wtxn, entries)?;
        wtxn.commit()?;
        Ok(ids)
    }

    /// [`Self::put_authority_log_entries`] against a CALLER-OWNED write
    /// transaction, for composing an authority append with other writes that
    /// must land atomically with it — and for tests that need to commit an
    /// authority change at a precise instant relative to another thread.
    pub(crate) fn put_authority_log_entries_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entries: &[(AuthorityLogEntry, TimeRange, u64)],
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::with_capacity(entries.len());
        let mut ops = Vec::with_capacity(entries.len());
        for (entry, occurred, learned_at) in entries {
            let data = encode_authority_log_entry_body(entry)?;
            crate::authority::validate_authority_log_entry_body_bytes(&data)?;
            let id = authority_log_entity_id(entry)?;
            ids.push(id);
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_AUTHORITY_LOG,
                occurred: *occurred,
                learned_at: *learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        if ops.is_empty() {
            return Ok(ids);
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(ids)
    }

    /// Reads and decodes one AUTHORITY_LOG entry by entity id.
    pub fn get_authority_log_entry(&self, id: &EntityId) -> Result<Option<AuthorityLogEntry>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn backfill_authority_first_seen_sidecars(&self) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        let already_backfilled = self
            .store
            .sync_state
            .get(&rtxn, authority_first_seen_backfill_sync_key())?
            .is_some();
        drop(rtxn);
        if already_backfilled {
            return Ok(());
        }

        self.with_write_txn(|wtxn| {
            if self
                .store
                .sync_state
                .get(wtxn, authority_first_seen_backfill_sync_key())?
                .is_some()
            {
                return Ok(());
            }

            let floor_key = authority_first_seen_clock_sync_key();
            let previous_floor = self
                .store
                .sync_state
                .get(wtxn, floor_key)?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
                .unwrap_or(0);
            let observed_floor = authority_observation_secs_for_domain(
                self.store.authority_clock_domain,
                previous_floor,
                unix_seconds_now(),
            );
            if observed_floor != previous_floor {
                let encoded = encode_authority_first_seen_secs(observed_floor);
                self.store.sync_state.put(wtxn, floor_key, &encoded)?;
            }

            let mut missing_sidecars = Vec::new();
            for entry in self
                .store
                .type_index
                .prefix_iter(wtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
            {
                let (key, _) = entry?;
                let id = entity_id_from_type_index_key(&key)?;
                let raw = self
                    .store
                    .entities
                    .get(wtxn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("type index row without entity"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                    return Err(Error::CorruptedIndex("type index row kind mismatch"));
                }
                let authority_entry =
                    decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                let hash = authority_entry_hash(&authority_entry)?;
                let sidecar_key = authority_first_seen_sync_key(&hash);
                if self
                    .store
                    .sync_state
                    .get(wtxn, sidecar_key.as_str())?
                    .is_none()
                {
                    // fix-leg 4: the persisted value is THIS vault's local
                    // observation time, never `header.learned_at`. The header
                    // field is entity metadata written by whichever peer
                    // shipped the row, so trusting it lets a legacy
                    // sidecar-less `EnrollDevice(learned_at = 0)` claim it was
                    // first seen in 1970 — instantly past its veto delay, with
                    // a child `BindActor` on the freshly owner-capable key
                    // folding ACTIVE on arrival. `observed_floor` clamps
                    // FUTURE claims only; the whole past is unclamped, and the
                    // past is the dangerous direction.
                    //
                    // Migrating at the observation time means an
                    // already-imported widen serves its full delay from HERE
                    // rather than from a claim, which delays a legitimate
                    // legacy widen once and never skips one.
                    missing_sidecars.push((
                        sidecar_key,
                        encode_authority_first_seen_secs(observed_floor),
                    ));
                }
            }
            for (sidecar_key, first_seen) in missing_sidecars {
                self.store
                    .sync_state
                    .put(wtxn, sidecar_key.as_str(), &first_seen)?;
            }

            self.store
                .sync_state
                .put(wtxn, authority_first_seen_backfill_sync_key(), &[1])?;
            Ok(())
        })
    }

    /// Folds all stored AUTHORITY_LOG entries into the current authority roster.
    ///
    /// The fold is the authority boundary: replay doors only admit canonical,
    /// origin-signed records; signer ancestry, sequence, quorum, and roster
    /// semantics are recomputed here from the stored log. Software-tier widens
    /// are evaluated against this device's local first-seen timestamps.
    ///
    /// Admitted PEER authority logs (FED-03) are refolded alongside, and their
    /// consent roots enter as gesture evidence only: they never join the local
    /// roster, hold local quorum, or change this vault's id.
    pub fn authority_fold(&self) -> Result<AuthorityFold> {
        self.backfill_authority_first_seen_sidecars()?;
        let rtxn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        let mut first_seen_at_secs = std::collections::BTreeMap::new();
        let previous_floor = self
            .store
            .sync_state
            .get(&rtxn, authority_first_seen_clock_sync_key())?
            .and_then(|raw| decode_authority_first_seen_secs(&raw))
            .unwrap_or(0);
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let hash = authority_entry_hash(&entry)?;
            if let Some(first_seen) = self
                .store
                .sync_state
                .get(&rtxn, authority_first_seen_sync_key(&hash).as_str())?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
            {
                first_seen_at_secs.insert(hash, first_seen);
            }
            entries.push(entry);
        }
        let peer_consent_roots =
            crate::federation::admitted_peer_consent_roots_in_txn(self, &rtxn)?;
        drop(rtxn);
        let now_secs = self.with_write_txn(|wtxn| {
            let previous_floor = self
                .store
                .sync_state
                .get(wtxn, authority_first_seen_clock_sync_key())?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
                .unwrap_or(previous_floor);
            let now_secs = authority_observation_secs_for_domain(
                self.store.authority_clock_domain,
                previous_floor,
                unix_seconds_now(),
            );
            if now_secs != previous_floor {
                let encoded = encode_authority_first_seen_secs(now_secs);
                self.store
                    .sync_state
                    .put(wtxn, authority_first_seen_clock_sync_key(), &encoded)?;
            }
            Ok(now_secs)
        })?;
        Ok(fold_authority_log_with_peer_consent_roots(
            &entries,
            &first_seen_at_secs,
            now_secs,
            &peer_consent_roots,
        ))
    }

    /// Folds the stored AUTHORITY_LOG inside a CALLER-OWNED read transaction.
    ///
    /// [`Vault::authority_fold`] opens its own transactions — including a WRITE
    /// txn for the first-seen clock and the sidecar backfill — so it cannot be
    /// called from inside an open transaction under LMDB's single-writer rule.
    /// This variant writes nothing at all: no persisted clock write, no
    /// backfill, no transaction of its own. It reproduces both write-side
    /// effects in its snapshot instead.
    ///
    /// The observation time is deliberately NOT the raw wall clock. Widen
    /// maturity is an AUTHORIZATION decision here — the facade's owner-verb
    /// gate consumes this fold — so it runs on the same monotonic clock
    /// [`Vault::authority_fold`] uses: the persisted floor read through `txn`,
    /// raised through [`authority_observation_secs_for_domain`]. On the raw
    /// wall clock a forward jump would mature a pending owner enrollment early
    /// and expose an Active human binding INSIDE the veto window, while a jump
    /// backward below the persisted floor would un-apply an elapsed rotation
    /// and resurrect the retired key's binding. The derived value is not
    /// written back — the floor advances only on write paths, and a lagging
    /// floor can delay a widen but never skip the delay.
    ///
    /// The other divergence the full fold hides is a MISSING sidecar, and
    /// omitting it here is not the conservative default it looks like — see
    /// [`Self::readonly_first_seen_for`] for why an omitted sidecar can leave a
    /// retired owner key live, and what this fold does instead. Where that
    /// leaves a delayable widen resting on an UNOBSERVED first-seen time, this
    /// fold refuses with [`AUTHORITY_FIRST_SEEN_INDETERMINATE`] rather than pick
    /// a roster; the refusal clears the moment one write-path fold records the
    /// observation.
    pub(crate) fn authority_fold_readonly_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<AuthorityFold> {
        let mut entries = Vec::new();
        let mut first_seen_at_secs = BTreeMap::new();
        let mut indeterminate = BTreeSet::new();
        let persisted_floor = self
            .store
            .sync_state
            .get(txn, authority_first_seen_clock_sync_key())?
            .and_then(|raw| decode_authority_first_seen_secs(&raw))
            .unwrap_or(0);
        // Read ONCE, before the row scan: the synthesized-first-seen rule below
        // must be the same for every entry in one fold, and this also decides
        // whether an absent sidecar is a pre-migration gap or genuine corruption.
        let backfilled = self
            .store
            .sync_state
            .get(txn, authority_first_seen_backfill_sync_key())?
            .is_some();
        let now_secs = authority_observation_secs_for_domain(
            self.store.authority_clock_domain,
            persisted_floor,
            unix_seconds_now(),
        );
        for row in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_AUTHORITY_LOG])?
        {
            let (key, _) = row?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let hash = authority_entry_hash(&entry)?;
            let (first_seen, observed_locally) =
                self.readonly_first_seen_for(txn, &hash, backfilled, now_secs)?;
            if !observed_locally {
                indeterminate.insert(hash);
            }
            first_seen_at_secs.insert(hash, first_seen);
            entries.push(entry);
        }
        // Peer consent roots ride BOTH folds. This one authorizes, and a fold
        // used for authorization must never be weaker OR stronger than the one
        // used for truth: omitting them here would silently reject a lifecycle
        // entry the full fold accepts.
        let peer_consent_roots = crate::federation::admitted_peer_consent_roots_in_txn(self, txn)?;
        let fold = fold_authority_log_with_peer_consent_roots(
            &entries,
            &first_seen_at_secs,
            now_secs,
            &peer_consent_roots,
        );
        // An indeterminate row is only a problem where its delay actually
        // decides something. `now_secs` is the maximum-delay assumption, so any
        // affected DELAYABLE widen lands in `pending_widens` — and pending is
        // fail-OPEN for `RotateKey`/`RecoveryReboot`, which revoke as they
        // grant. Refuse there rather than authorize against a roster still
        // holding a key a matured rotation may already have retired. Rows whose
        // first-seen time the fold never consults (every non-delayable op, and
        // widens a veto already killed) are unaffected, so a legacy vault whose
        // log carries no live delayable widen keeps working untouched.
        if fold
            .pending_widens
            .keys()
            .any(|hash| indeterminate.contains(hash))
        {
            return Err(Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_INDETERMINATE));
        }
        Ok(fold)
    }

    /// First-seen seconds for ONE entry inside a readonly fold, reproducing the
    /// one-shot migration's semantics without writing anything.
    ///
    /// Returns `(first_seen_secs, observed_locally)`. `observed_locally` is
    /// false when the value is an ASSUMPTION rather than a record of local
    /// observation; the caller escalates that to a refusal only where the value
    /// actually decided a pending widen.
    ///
    /// Omitting an entry from `first_seen_at_secs` is NOT fail-closed, which is
    /// what the naive version got wrong. A sidecar-less delayable widen folds to
    /// `eligible_at_secs: None`, which pins it PENDING forever — and "pending"
    /// is only conservative for widens that GRANT (EnrollDevice, SetTierFloor).
    /// `RotateKey` and `RecoveryReboot` also REVOKE: an un-applied rotation
    /// leaves the retired owner key in the roster with its actor binding Active.
    /// On a legacy vault whose matured rotation K→K2 never got a sidecar, an
    /// attacker still holding K could file a sibling `BindActor(K, …, "human")`
    /// parented before the rotation, and this fold would hand them every owner
    /// verb — while [`Vault::authority_fold`] (which backfills first) revokes K.
    /// A fold used for AUTHORIZATION must not be weaker than the one used for
    /// truth.
    ///
    /// Two states, two answers:
    ///
    /// - backfill marker ABSENT — the migration has not run in a write txn yet,
    ///   so this vault has NO local record of when it first saw the row. The
    ///   header's `learned_at` is not a substitute: it is peer-written entity
    ///   metadata, and a legacy `EnrollDevice` shipped with `learned_at = 0`
    ///   would read as first seen in 1970, i.e. matured before it ever arrived.
    ///   The answer is `now_secs` — the same value
    ///   [`Vault::backfill_authority_first_seen_sidecars`] will persist when it
    ///   next runs, and the maximum remaining delay — flagged indeterminate.
    /// - marker PRESENT and the sidecar still missing, or the row present but
    ///   undecodable under EITHER marker state — the one-shot pass can never
    ///   regenerate it (it is gated by the marker, and it skips keys that
    ///   already hold a row), so the entry's delay clock is unrecoverable in
    ///   place. Refuse the fold with [`AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT`];
    ///   the facade turns that into an invalid-state suspension of owner verbs
    ///   rather than authorizing on a fold it cannot compute.
    ///
    /// The assumed value never MATURES anything: it equals the `now_secs` the
    /// maturity comparison uses, so `now + delay > now` holds for every positive
    /// delay and the widen stays pending until a real observation is recorded.
    fn readonly_first_seen_for(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: &AuthorityEntryHash,
        backfilled: bool,
        now_secs: u64,
    ) -> Result<(u64, bool)> {
        let corrupt = || Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT);
        match self
            .store
            .sync_state
            .get(txn, authority_first_seen_sync_key(hash).as_str())?
        {
            Some(raw) => decode_authority_first_seen_secs(&raw)
                .ok_or_else(corrupt)
                .map(|secs| (secs, true)),
            None if backfilled => Err(corrupt()),
            None => Ok((now_secs, false)),
        }
    }
}

#[cfg(test)]
mod tests;
