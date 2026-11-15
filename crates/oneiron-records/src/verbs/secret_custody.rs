//! Moved from `crates/oneiron/src/verbs/secret_custody.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::secret_custody::SecretCustodyGetRequest;
pub use oneiron_verb_wire::verbs::secret_custody::SecretManifestSource;
pub use oneiron_verb_wire::verbs::secret_custody::SecretRegisterBinding;
pub use oneiron_verb_wire::verbs::secret_custody::SecretRegisterRequest;
pub use oneiron_verb_wire::verbs::secret_custody::SecretRevokeRequest;
pub use oneiron_verb_wire::verbs::secret_custody::SecretRewrapRequest;
pub use oneiron_verb_wire::verbs::secret_custody::SecretRotateRequest;
use serde::Deserialize;
use serde::Serialize;

/// A stored binding, its rung on the wire's 0 to 2 grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisteredBinding {
    pub effector: String,
    pub tier_ceiling: u8,
    pub scopes: Vec<String>,
}

/// What a rotation changed: the generation moved, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRotationReceipt {
    pub receipt_id: String,
    pub name: String,
    pub from_generation: u32,
    pub to_generation: u32,
    pub rotated_at: u64,
    /// The receipt's own kind, `rotated`.
    pub kind: String,
}

/// One install a surface may offer as holder or recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyCandidateReply {
    /// The install, as 32 hex.
    pub machine: String,
    /// The profile entry a permit binds, as 64 hex.
    pub profile: String,
    /// The encryption key digest a permit binds, as 64 hex.
    pub encryption_key_digest: String,
    /// The key a surface seals an input to: its suite and public bytes.
    pub suite: u16,
    pub encryption_key_base64: String,
    pub this_install: bool,
}

pub fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
