//! Pinned AUTHORITY_LOG constant table.
//!
//! Schema version, transcript domains, role bitmasks, canonical wire key
//! names, op-kind strings, and size limits. No logic lives here.

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
pub(super) const ROLE_DEFINED_MASK: u16 =
    ROLE_OWNER | ROLE_ADMIN | ROLE_AGENT | ROLE_CLOUD | ROLE_RECOVERY;

/// Owner-facing alarm kind emitted when AUTH-5 detects key equivocation.
pub const AUTHORITY_FORK_ALARM_KIND: &str = "AUTHORITY FORK DETECTED";

/// Content hash of a canonical authority entry.
pub type AuthorityEntryHash = [u8; AUTHORITY_HASH_LEN];

/// The DURABLE vault identity: 32 BLAKE3 bytes derived from the canonical
/// signed genesis entry (see [`super::genesis_vault_id`]).
///
/// This is the only thing that identifies a vault. A `vtN` presentation slug is
/// a display alias that RESOLVES to one of these
/// (`registry::IdNamespaceTarget::Vault`); it is not an identity, carries no
/// authority, and never appears in a hash, a transcript, or a signature.
pub type AuthorityVaultId = [u8; AUTHORITY_HASH_LEN];

pub(super) const AUTHORITY_ENTRY_KEYS: [&str; 8] = [
    "schema_version",
    "vault_id",
    "seq",
    "parent_hashes",
    "op",
    "signer",
    "cosigns",
    "ts",
];
pub(super) const KEY_SCHEMA_VERSION: &str = AUTHORITY_ENTRY_KEYS[0];
pub(super) const KEY_VAULT_ID: &str = AUTHORITY_ENTRY_KEYS[1];
pub(super) const KEY_SEQ: &str = AUTHORITY_ENTRY_KEYS[2];
pub(super) const KEY_PARENT_HASHES: &str = AUTHORITY_ENTRY_KEYS[3];
pub(super) const KEY_OP: &str = AUTHORITY_ENTRY_KEYS[4];
pub(super) const KEY_SIGNER: &str = AUTHORITY_ENTRY_KEYS[5];
pub(super) const KEY_COSIGNS: &str = AUTHORITY_ENTRY_KEYS[6];
pub(super) const KEY_TS: &str = AUTHORITY_ENTRY_KEYS[7];

pub(super) const SIGNATURE_KEYS: [&str; 3] = ["suite", "public_key", "signature"];
pub(super) const KEY_SUITE: &str = SIGNATURE_KEYS[0];
pub(super) const KEY_PUBLIC_KEY: &str = SIGNATURE_KEYS[1];
pub(super) const KEY_SIGNATURE: &str = SIGNATURE_KEYS[2];

pub(super) const ATTESTATION_KEYS: [&str; 2] = ["kind", "evidence"];
pub(super) const KEY_ATTEST_KIND: &str = ATTESTATION_KEYS[0];
pub(super) const KEY_ATTEST_EVIDENCE: &str = ATTESTATION_KEYS[1];

pub(super) const OP_KEY_KIND: &str = "kind";
pub(super) const OP_KIND_GENESIS: &str = "genesis";
pub(super) const OP_KIND_ENROLL_DEVICE: &str = "enroll_device";
pub(super) const OP_KIND_REVOKE_DEVICE: &str = "revoke_device";
pub(super) const OP_KIND_SET_CEILING: &str = "set_ceiling";
pub(super) const OP_KIND_ROTATE_KEY: &str = "rotate_key";
pub(super) const OP_KIND_SET_TIER_FLOOR: &str = "set_tier_floor";
pub(super) const OP_KIND_RECOVERY_REBOOT: &str = "recovery_reboot";
pub(super) const OP_KIND_FEDERATION_CONFIRM: &str = "federation_confirm";
pub(super) const OP_KIND_CRITICAL_WRITE_CONFIRM: &str = "critical_write_confirm";
pub(super) const OP_KIND_VETO_PENDING_WIDEN: &str = "veto_pending_widen";
pub(super) const OP_KIND_FEDERATION_LIFECYCLE: &str = "federation_lifecycle";
pub(super) const OP_KIND_BIND_ACTOR: &str = "bind_actor";
pub(super) const OP_KIND_REBIND_ACTOR: &str = "rebind_actor";
pub(super) const OP_KIND_REVOKE_ACTOR: &str = "revoke_actor";

/// The EXACT actor-class vocabulary a binding tuple may name (ONE-1604-D2).
///
/// Deliberately narrower than `SetCeiling`'s free-form class string: an
/// approximate class is the ESB-C defect, so anything outside this list fails
/// closed at `validate_op`. Mirrors `EdgeActorClass::gate_actor_class`.
pub(super) const ACTOR_BINDING_CLASSES: [&str; 3] = ["human", "agent", "system"];

pub(super) const CONFIRM_KIND_ACCEPT: &str = "accept";
pub(super) const CONFIRM_KIND_RESCOPE: &str = "rescope";
pub(super) const CONFIRM_KIND_A2A_CONNECT: &str = "a2a_connect";
pub(super) const CONFIRM_KIND_REVOKE: &str = "revoke";

pub(super) const LIFECYCLE_KIND_CONNECT: &str = "connect";
pub(super) const LIFECYCLE_KIND_RESCOPE: &str = "rescope";
pub(super) const LIFECYCLE_KIND_DISCONNECT: &str = "disconnect";
pub(super) const LIFECYCLE_KIND_PROMOTE: &str = "promote";
pub(super) const LIFECYCLE_KIND_DISSOLVE: &str = "dissolve";

/// Domain-separated transcript prefix for federation pact gestures.
pub const FEDERATION_PACT_DOMAIN: &[u8] = b"oneiron/federation/pact/v1";
/// Domain-separated prefix for the federation pact scope commitment.
pub const FEDERATION_SCOPE_COMMIT_DOMAIN: &[u8] = b"oneiron/federation/pact-scope/v1";
/// Upper bound for encoded federation pact scope bytes in a lifecycle op.
pub const MAX_PACT_SCOPE_BYTES: usize = 4096;

pub(super) const MAX_PARENTS: usize = 32;
pub(super) const MAX_COSIGNS: usize = 8;
pub(super) const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 4096;
pub(super) const MAX_ACTOR_CLASS_BYTES: usize = 64;

/// Lower bound for the default software-tier pending-widen delay (24h).
pub const MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 24 * 60 * 60;
/// Upper bound for the default software-tier pending-widen delay (48h).
pub const MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 48 * 60 * 60;
/// Default local seen-time delay for software-tier widens.
pub const DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS;
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS >= MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS);
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS <= MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS);
