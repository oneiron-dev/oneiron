//! Hashes that tie a verdict to the exact content and policy state it was
//! decided against, so a stale verdict can be recognized rather than trusted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::gate::PolicyManifestResolution;

use super::request::{PolicyClassifyRequest, PolicyModelConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyContentBinding {
    pub content_hash: [u8; 32],
    pub read_frontier_hash: [u8; 32],
}

impl PolicyContentBinding {
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.content_hash)
    }

    #[must_use]
    pub fn read_frontier_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.read_frontier_hash)
    }
}

/// Binding for a vault-egress classify: content, the world it was scoped to,
/// and the safeguard model that judged it.
pub(crate) fn content_binding(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
    config: &PolicyModelConfig,
) -> Result<PolicyContentBinding> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.policy_model.classify.content.v1");
    hash_binding_str(&mut hasher, "subject", request.subject.as_str());
    hash_binding_str(&mut hasher, "content", &request.content);
    hash_binding_opt_str(&mut hasher, "world_ref", request.world_ref.as_deref());
    hash_binding_str(
        &mut hasher,
        "safeguard_binding",
        &config.safeguard_binding.selector(),
    );
    Ok(PolicyContentBinding {
        content_hash: hasher.finalize().into(),
        read_frontier_hash: policy.read_frontier_hash()?,
    })
}

/// Identity-free binding the relay recomputes locally to verify a vault-side
/// receipt. It deliberately omits `world_ref` and the safeguard selector so a
/// relay can key a lookup on content alone.
pub(crate) fn relay_verify_content_binding(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Result<PolicyContentBinding> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.policy_model.relay.verify.content.v1");
    hash_binding_str(&mut hasher, "subject", request.subject.as_str());
    hash_binding_str(&mut hasher, "content", &request.content);
    Ok(PolicyContentBinding {
        content_hash: hasher.finalize().into(),
        read_frontier_hash: policy.read_frontier_hash()?,
    })
}

/// Binding for a trust-domain SKIP. A skip never classified against policy
/// state, so its frontier is zeroed — an honest "did not run" marker rather
/// than a hash that would imply it did.
pub(crate) fn relay_skip_content_binding(request: &PolicyClassifyRequest) -> PolicyContentBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.policy_model.relay.skip.content.v1");
    hash_binding_str(&mut hasher, "subject", request.subject.as_str());
    hash_binding_str(&mut hasher, "content", &request.content);
    PolicyContentBinding {
        content_hash: hasher.finalize().into(),
        read_frontier_hash: [0; 32],
    }
}

fn hash_binding_opt_str(hasher: &mut Sha256, label: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_binding_str(hasher, label, "some");
            hash_binding_str(hasher, label, value);
        }
        None => hash_binding_str(hasher, label, "none"),
    }
}

fn hash_binding_str(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    // Eight bytes on every architecture. A relay recomputes this hash locally
    // and compares it against one a VAULT produced, so a bare `usize` — four
    // bytes on a 32-bit target, eight on a 64-bit one — would make the two
    // machines disagree about identical content. Same rule as the policy hash.
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.update([0xff]);
}
