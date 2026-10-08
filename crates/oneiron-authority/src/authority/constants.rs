//! Pinned AUTHORITY_LOG constant table.
//!
//! Schema version, transcript domains, role bitmasks, canonical wire key
//! names, op-kind strings, and size limits. No logic lives here.

/// Current AUTHORITY_LOG body schema version.
pub const AUTHORITY_LOG_SCHEMA_VERSION: u64 = 1;

/// Domain-separated signature transcript for authority-log self-mutations.
pub const AUTHORITY_TRANSCRIPT_DOMAIN: &[u8] = b"oneiron/authority/v1";

/// The entry hash length and type are defined in `oneiron-contracts`: the write actor
/// names them.
pub use oneiron_contracts::authority::{AUTHORITY_HASH_LEN, AuthorityEntryHash};

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
pub const ROLE_DEFINED_MASK: u16 =
    ROLE_OWNER | ROLE_ADMIN | ROLE_AGENT | ROLE_CLOUD | ROLE_RECOVERY;

/// The DURABLE vault identity: 32 BLAKE3 bytes derived from the canonical
/// signed genesis entry (see [`super::genesis_vault_id`]).
///
/// This is the only thing that identifies a vault. A `vtN` presentation slug is
/// a display alias that RESOLVES to one of these
/// (`registry::IdNamespaceTarget::Vault`); it is not an identity, carries no
/// authority, and never appears in a hash, a transcript, or a signature.
pub type AuthorityVaultId = [u8; AUTHORITY_HASH_LEN];

pub const AUTHORITY_ENTRY_KEYS: [&str; 8] = [
    "schema_version",
    "vault_id",
    "seq",
    "parent_hashes",
    "op",
    "signer",
    "cosigns",
    "ts",
];
pub const KEY_SCHEMA_VERSION: &str = AUTHORITY_ENTRY_KEYS[0];
pub const KEY_VAULT_ID: &str = AUTHORITY_ENTRY_KEYS[1];
pub const KEY_SEQ: &str = AUTHORITY_ENTRY_KEYS[2];
pub const KEY_PARENT_HASHES: &str = AUTHORITY_ENTRY_KEYS[3];
pub const KEY_OP: &str = AUTHORITY_ENTRY_KEYS[4];
pub const KEY_SIGNER: &str = AUTHORITY_ENTRY_KEYS[5];
pub const KEY_COSIGNS: &str = AUTHORITY_ENTRY_KEYS[6];
pub const KEY_TS: &str = AUTHORITY_ENTRY_KEYS[7];

pub const SIGNATURE_KEYS: [&str; 3] = ["suite", "public_key", "signature"];
pub const KEY_SUITE: &str = SIGNATURE_KEYS[0];
pub const KEY_PUBLIC_KEY: &str = SIGNATURE_KEYS[1];
pub const KEY_SIGNATURE: &str = SIGNATURE_KEYS[2];

pub const ATTESTATION_KEYS: [&str; 2] = ["kind", "evidence"];
pub const KEY_ATTEST_KIND: &str = ATTESTATION_KEYS[0];
pub const KEY_ATTEST_EVIDENCE: &str = ATTESTATION_KEYS[1];

pub const OP_KEY_KIND: &str = "kind";
pub const OP_KIND_GENESIS: &str = "genesis";
pub const OP_KIND_ENROLL_DEVICE: &str = "enroll_device";
pub const OP_KIND_REVOKE_DEVICE: &str = "revoke_device";
pub const OP_KIND_RETIRED_CEILING: &str = "set_ceiling";
pub const OP_KIND_ROTATE_KEY: &str = "rotate_key";
pub const OP_KIND_SET_TIER_FLOOR: &str = "set_tier_floor";
pub const OP_KIND_RE_ROOT: &str = "re_root";
pub const OP_KIND_FEDERATION_CONFIRM: &str = "federation_confirm";
pub const OP_KIND_CRITICAL_WRITE_CONFIRM: &str = "critical_write_confirm";
pub const OP_KIND_VETO_PENDING_WIDEN: &str = "veto_pending_widen";
pub const OP_KIND_FEDERATION_LIFECYCLE: &str = "federation_lifecycle";
pub const OP_KIND_BIND_ACTOR: &str = "bind_actor";
pub const OP_KIND_REBIND_ACTOR: &str = "rebind_actor";
pub const OP_KIND_REVOKE_ACTOR: &str = "revoke_actor";

/// The EXACT actor-class vocabulary a binding tuple may name (ONE-1604-D2).
///
/// Deliberately narrower than `RetiredCeiling`'s free-form class string: an
/// approximate class is the ESB-C defect, so anything outside this list fails
/// closed at `validate_op`. Mirrors `EdgeActorClass::gate_actor_class`.
pub const ACTOR_CLASS_HUMAN: &str = "human";
pub const ACTOR_BINDING_CLASSES: [&str; 3] = [ACTOR_CLASS_HUMAN, "agent", "system"];

pub const CONFIRM_KIND_ACCEPT: &str = "accept";
pub const CONFIRM_KIND_RESCOPE: &str = "rescope";
pub const CONFIRM_KIND_A2A_CONNECT: &str = "a2a_connect";
pub const CONFIRM_KIND_REVOKE: &str = "revoke";

pub const LIFECYCLE_KIND_CONNECT: &str = "connect";
pub const LIFECYCLE_KIND_RESCOPE: &str = "rescope";
pub const LIFECYCLE_KIND_DISCONNECT: &str = "disconnect";
pub const LIFECYCLE_KIND_PROMOTE: &str = "promote";
pub const LIFECYCLE_KIND_DISSOLVE: &str = "dissolve";

/// Domain-separated transcript prefix for federation pact gestures.
pub const FEDERATION_PACT_DOMAIN: &[u8] = b"oneiron/federation/pact/v1";
/// Domain-separated prefix for the federation pact scope commitment.
pub const FEDERATION_SCOPE_COMMIT_DOMAIN: &[u8] = b"oneiron/federation/pact-scope/v1";
/// Upper bound for encoded federation pact scope bytes in a lifecycle op.
pub const MAX_PACT_SCOPE_BYTES: usize = 4096;

pub const MAX_PARENTS: usize = 32;
pub const MAX_COSIGNS: usize = 8;
pub const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 4096;
pub const MAX_ACTOR_CLASS_BYTES: usize = 64;

/// Lower bound (24h) accepted for the legacy signed
/// `Genesis.pending_widen_delay_secs` field.
///
/// Wire validation only: the field has no fold effect. The delayed-widen
/// ceremony it configured died 2026-08-05 (identity canon, "Device-key widen
/// ceremony (dead 2026-08-05)"; ARCH-0040 ONE-AUTHLOG-F6); widening is owner
/// action through the host and lands at once. The band is kept so old and new
/// peers agree on which genesis entries are valid.
pub const MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 24 * 60 * 60;
/// Upper bound (48h) accepted for the legacy signed
/// `Genesis.pending_widen_delay_secs` field. Wire validation only.
pub const MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = 48 * 60 * 60;
/// Value new genesis entries write into the legacy
/// `Genesis.pending_widen_delay_secs` field (and the value the legacy compact
/// genesis encoding implies). No fold effect.
pub const DEFAULT_PENDING_WIDEN_DELAY_SECS: u64 = MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS;
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS >= MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS);
const _: () = assert!(DEFAULT_PENDING_WIDEN_DELAY_SECS <= MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS);

pub const OP_KIND_SLIP_MINT: &str = "slip_mint";
pub const OP_KIND_SLIP_REVOKE: &str = "slip_revoke";
pub const OP_KIND_SLIP_CONSUME: &str = "slip_consume";
pub const SLIP_KEY_SLIP_ID: &str = "slip_id";
pub const SLIP_KEY_VAULT_ID: &str = "vault_id";
pub const SLIP_KEY_PARENT_ID: &str = "parent_id";
pub const SLIP_KEY_HOLDER_REF: &str = "holder_ref";
pub const SLIP_KEY_BINDING_KEY: &str = "binding_key";
pub const SLIP_KEY_SCOPE: &str = "scope";
pub const SLIP_KEY_ISSUED_AT: &str = "issued_at";
pub const SLIP_KEY_EXPIRES_AT: &str = "expires_at";
pub const SLIP_KEY_TTL_SECS: &str = "ttl_secs";
pub const SLIP_KEY_SINGLE_USE: &str = "single_use";
pub const SLIP_KEY_RECORDS: &str = "records";
pub const SLIP_KEY_CHANNELS: &str = "channels";
pub const SLIP_KEY_ACTOR_CLASS: &str = "actor_class";
pub const SLIP_KEY_ORG_REF: &str = "org_ref";
pub const SLIP_MINT_KEYS: [&str; 15] = [
    OP_KEY_KIND,
    SLIP_KEY_SLIP_ID,
    SLIP_KEY_VAULT_ID,
    SLIP_KEY_PARENT_ID,
    SLIP_KEY_HOLDER_REF,
    SLIP_KEY_BINDING_KEY,
    SLIP_KEY_SCOPE,
    SLIP_KEY_ISSUED_AT,
    SLIP_KEY_EXPIRES_AT,
    SLIP_KEY_TTL_SECS,
    SLIP_KEY_SINGLE_USE,
    SLIP_KEY_RECORDS,
    SLIP_KEY_CHANNELS,
    SLIP_KEY_ACTOR_CLASS,
    SLIP_KEY_ORG_REF,
];
pub const SLIP_SCOPE_KEYS: [&str; 6] = [
    SCOPE_KEY_WORLDS,
    SCOPE_KEY_FACETS,
    SCOPE_KEY_BANDS,
    SCOPE_KEY_AUDIENCE,
    SCOPE_KEY_VERBS,
    SCOPE_KEY_SENSITIVITY,
];
pub const SCOPE_KEY_WORLDS: &str = "worlds";
pub const SCOPE_KEY_FACETS: &str = "facets";
pub const SCOPE_KEY_BANDS: &str = "bands";
pub const SCOPE_KEY_AUDIENCE: &str = "audience";
pub const SCOPE_KEY_VERBS: &str = "verbs";
pub const SCOPE_KEY_SENSITIVITY: &str = "sensitivity";
