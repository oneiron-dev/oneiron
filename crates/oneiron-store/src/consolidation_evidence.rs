//! Domain-separated content hashes of consolidation source bytes.

/// Domain for swarm evidence content hashes (pinned, design D10).
pub const DREAMER_EVIDENCE_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-evidence:v1";

/// Domain-separated hash over the bytes the orchestrator actually read.
#[must_use]
pub fn swarm_evidence_content_hash(entity_body_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_EVIDENCE_HASH_DOMAIN);
    hasher.update(entity_body_bytes);
    *hasher.finalize().as_bytes()
}
